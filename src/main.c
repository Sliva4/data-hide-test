// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/errno.h>
#include <linux/xarray.h>
#include <linux/spinlock.h>

#ifndef __aarch64__
#error "This module targets arm64 only"
#endif

#define APP_UID_MIN 10000
#define APP_UID_MAX 19999

static bool debug_verbose = true;
module_param(debug_verbose, bool, 0644);

static struct super_block *data_sb;
static DEFINE_XARRAY(hide_dd_guard_xa);

static bool hide_dd_guard_enter(void)
{
	void *old;

	if (xa_load(&hide_dd_guard_xa, (unsigned long)current))
		return false;
	old = xa_store(&hide_dd_guard_xa, (unsigned long)current,
		       current, GFP_ATOMIC);
	return !IS_ERR(old);
}

static void hide_dd_guard_exit(void)
{
	xa_erase(&hide_dd_guard_xa, (unsigned long)current);
}

static inline bool is_app_uid(kuid_t uid)
{
	uid_t v = __kuid_val(uid);
	return v >= APP_UID_MIN && v <= APP_UID_MAX;
}

static struct dentry *inode_first_dentry(struct inode *inode)
{
	struct dentry *dentry = NULL;

	spin_lock(&inode->i_lock);
	if (!hlist_empty(&inode->i_dentry)) {
		dentry = hlist_entry(inode->i_dentry.first,
				     struct dentry, d_u.d_alias);
		if (dentry)
			lockref_get_not_dead(&dentry->d_lockref);
	}
	spin_unlock(&inode->i_lock);

	return dentry;
}

static bool is_under_data_data(struct dentry *d)
{
	struct dentry *p, *pp;

	if (!data_sb || !d)
		return false;

	if (d->d_sb != data_sb)
		return false;

	p = d->d_parent;
	if (!p || p == d)
		return false;

	if (p->d_name.len == 4 &&
	    memcmp(p->d_name.name, "data", 4) == 0) {
		pp = p->d_parent;
		if (pp && pp == data_sb->s_root)
			return true;
	}

	if (p->d_name.len == 1 &&
	    p->d_name.name[0] >= '0' && p->d_name.name[0] <= '9') {
		struct dentry *user_d = p->d_parent;

		if (user_d && user_d->d_name.len == 4 &&
		    memcmp(user_d->d_name.name, "user", 4) == 0) {
			if (user_d->d_parent == data_sb->s_root)
				return true;
		}
	}

	return false;
}

static bool is_foreign_pkg_dir(struct inode *inode)
{
	kuid_t caller, owner;
	struct dentry *d;
	bool ret = false;

	if (!inode)
		return false;

	caller = current_fsuid();
	if (!is_app_uid(caller))
		return false;

	if (!S_ISDIR(inode->i_mode))
		return false;

	owner = inode->i_uid;
	if (!is_app_uid(owner))
		return false;

	if (uid_eq(owner, caller))
		return false;

	d = inode_first_dentry(inode);
	if (!d)
		return false;

	ret = is_under_data_data(d);
	dput(d);

	if (ret && debug_verbose)
		pr_info("hide_dd: MATCH-DD ino_uid=%u caller=%u\n",
			__kuid_val(owner), __kuid_val(caller));

	return ret;
}

struct hide_data {
	bool hide;
};

static int perm_entry_handler(struct kretprobe_instance *ri,
			      struct pt_regs *regs)
{
	struct hide_data *data = (struct hide_data *)ri->data;
	struct inode *inode;

	data->hide = false;

	if (!hide_dd_guard_enter())
		return 0;

	inode = (struct inode *)regs->regs[1];

	if (debug_verbose && inode) {
		pr_info("hide_dd: perm caller=%u ino_uid=%u mode=0%o comm=%s\n",
			__kuid_val(current_fsuid()),
			__kuid_val(inode->i_uid),
			inode->i_mode & S_IFMT,
			current->comm);
	}

	if (is_foreign_pkg_dir(inode)) {
		data->hide = true;
		pr_info("hide_dd: HIDE ino_uid=%u caller=%u comm=%s\n",
			__kuid_val(inode->i_uid),
			__kuid_val(current_fsuid()),
			current->comm);
	}

	return 0;
}

static int perm_ret_handler(struct kretprobe_instance *ri,
			    struct pt_regs *regs)
{
	struct hide_data *data = (struct hide_data *)ri->data;
	long orig = (long)regs->regs[0];

	if (data->hide) {
		if (orig == -EPERM || orig == -EACCES) {
			regs->regs[0] = (unsigned long)(-ENOENT);
			pr_info("hide_dd: rewrote %ld -> -ENOENT\n", orig);
		} else if (debug_verbose) {
			pr_info("hide_dd: ret orig=%ld (not rewritten)\n", orig);
		}
	}

	hide_dd_guard_exit();
	return 0;
}

static struct kretprobe perm_krp = {
	.kp.symbol_name = "inode_permission",
	.entry_handler  = perm_entry_handler,
	.handler        = perm_ret_handler,
	.data_size      = sizeof(struct hide_data),
	.maxactive      = 512,
};

static int save_data_sb(void)
{
	struct path path;
	int ret;

	ret = kern_path("/data", LOOKUP_FOLLOW, &path);
	if (ret) {
		pr_err("hide_dd: kern_path(/data) failed: %d\n", ret);
		return ret;
	}

	data_sb = path.dentry->d_sb;
	pr_info("hide_dd: /data sb=%p s_root=%p\n",
		data_sb, data_sb->s_root);
	path_put(&path);
	return 0;
}

static int hide_dd_register(void)
{
	int ret;
	unsigned long addr;

	perm_krp.kp.symbol_name = "inode_permission";
	perm_krp.kp.addr = NULL;
	ret = register_kretprobe(&perm_krp);
	if (ret == 0) {
		pr_info("hide_dd: kretprobe on inode_permission\n");
		return 0;
	}

	pr_info("hide_dd: symbol-based failed (%d), trying addr\n", ret);

	addr = kallsyms_lookup_name("inode_permission");
	if (!addr) {
		pr_err("hide_dd: inode_permission not found\n");
		return -ENOENT;
	}

	perm_krp.kp.symbol_name = NULL;
	perm_krp.kp.addr = (kprobe_opcode_t *)addr;
	ret = register_kretprobe(&perm_krp);
	if (ret == 0) {
		pr_info("hide_dd: kretprobe on inode_permission @ 0x%lx\n", addr);
		return 0;
	}

	pr_err("hide_dd: addr-based failed (%d)\n", ret);
	return ret;
}

static int __init hide_dd_init(void)
{
	int ret;

	ret = save_data_sb();
	if (ret)
		return ret;

	ret = hide_dd_register();
	if (ret < 0) {
		pr_err("hide_dd: register_kretprobe failed: %d\n", ret);
		return ret;
	}

	pr_info("hide_dd: loaded (uid %d..%d)\n", APP_UID_MIN, APP_UID_MAX);
	return 0;
}

static void __exit hide_dd_exit(void)
{
	unregister_kretprobe(&perm_krp);
	pr_info("hide_dd: unloaded\n");
}

module_init(hide_dd_init);
module_exit(hide_dd_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hide /data/data/<other_uid> from app processes");
MODULE_VERSION("2.3");