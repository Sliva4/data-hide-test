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
#include <linux/spinlock.h>
#include <linux/types.h>

#ifndef __aarch64__
#error "This module targets arm64 only"
#endif

#define APP_UID_MIN 10000
#define APP_UID_MAX 19999

static bool debug_verbose = false;
module_param(debug_verbose, bool, 0644);

static struct super_block *data_sb;

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
	bool ret;

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
	return ret;
}

struct hide_data {
	bool hide;
};

/* ---------------- inode_permission ---------------- */

static int perm_entry_handler(struct kretprobe_instance *ri,
			      struct pt_regs *regs)
{
	struct hide_data *data = (struct hide_data *)ri->data;
	struct inode *inode;

	data->hide = false;

	inode = (struct inode *)regs->regs[1];
	if (is_foreign_pkg_dir(inode)) {
		data->hide = true;
		if (debug_verbose)
			pr_info("hide_dd: PERM-HIDE ino_uid=%u caller=%u comm=%s\n",
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

	if (data->hide) {
		regs->regs[0] = (unsigned long)(long)(s32)(-ENOENT);
		if (debug_verbose)
			pr_info("hide_dd: perm -> -ENOENT comm=%s\n",
				current->comm);
	}
	return 0;
}

static struct kretprobe perm_krp = {
	.kp.symbol_name = "inode_permission",
	.entry_handler  = perm_entry_handler,
	.handler        = perm_ret_handler,
	.data_size      = sizeof(struct hide_data),
	.maxactive      = 4096,
};

/* ---------------- vfs_getattr ---------------- */

static int getattr_entry_handler(struct kretprobe_instance *ri,
				 struct pt_regs *regs)
{
	struct hide_data *data = (struct hide_data *)ri->data;
	const struct path *path;
	struct inode *inode;

	data->hide = false;

	path = (const struct path *)regs->regs[0];
	if (!path || !path->dentry)
		return 0;

	inode = d_inode(path->dentry);
	if (is_foreign_pkg_dir(inode)) {
		data->hide = true;
		if (debug_verbose)
			pr_info("hide_dd: GETATTR-HIDE ino_uid=%u caller=%u comm=%s\n",
				__kuid_val(inode->i_uid),
				__kuid_val(current_fsuid()),
				current->comm);
	}
	return 0;
}

static int getattr_ret_handler(struct kretprobe_instance *ri,
			       struct pt_regs *regs)
{
	struct hide_data *data = (struct hide_data *)ri->data;

	if (data->hide) {
		regs->regs[0] = (unsigned long)(long)(s32)(-ENOENT);
		if (debug_verbose)
			pr_info("hide_dd: getattr -> -ENOENT comm=%s\n",
				current->comm);
	}
	return 0;
}

static struct kretprobe getattr_krp = {
	.kp.symbol_name = "vfs_getattr",
	.entry_handler  = getattr_entry_handler,
	.handler        = getattr_ret_handler,
	.data_size      = sizeof(struct hide_data),
	.maxactive      = 4096,
};

/* ---------------- registration ---------------- */

static int register_one(struct kretprobe *krp, const char *name)
{
	int ret;
	unsigned long addr;

	krp->kp.symbol_name = name;
	krp->kp.addr = NULL;
	ret = register_kretprobe(krp);
	if (ret == 0) {
		pr_info("hide_dd: kretprobe on %s\n", name);
		return 0;
	}

	pr_info("hide_dd: %s symbol-based failed (%d), trying addr\n",
		name, ret);

	addr = kallsyms_lookup_name(name);
	if (!addr) {
		pr_err("hide_dd: %s not found\n", name);
		return -ENOENT;
	}

	krp->kp.symbol_name = NULL;
	krp->kp.addr = (kprobe_opcode_t *)addr;
	ret = register_kretprobe(krp);
	if (ret == 0) {
		pr_info("hide_dd: kretprobe on %s @ 0x%lx\n", name, addr);
		return 0;
	}
	pr_err("hide_dd: %s addr-based failed (%d)\n", name, ret);
	return ret;
}

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

static int __init hide_dd_init(void)
{
	int ret;

	ret = save_data_sb();
	if (ret)
		return ret;

	ret = register_one(&perm_krp, "inode_permission");
	if (ret)
		return ret;

	ret = register_one(&getattr_krp, "vfs_getattr");
	if (ret) {
		unregister_kretprobe(&perm_krp);
		return ret;
	}

	pr_info("hide_dd: loaded (uid %d..%d)\n", APP_UID_MIN, APP_UID_MAX);
	return 0;
}

static void __exit hide_dd_exit(void)
{
	unregister_kretprobe(&getattr_krp);
	unregister_kretprobe(&perm_krp);
	pr_info("hide_dd: unloaded\n");
}

module_init(hide_dd_init);
module_exit(hide_dd_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hide /data/data/<other_uid> from app processes");
MODULE_VERSION("3.0");