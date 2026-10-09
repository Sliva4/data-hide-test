// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/errno.h>
#include <linux/xarray.h>
#include <linux/version.h>

#ifndef __aarch64__
#error "This module targets arm64 only"
#endif

#define APP_UID_MIN 10000
#define APP_UID_MAX 19999
#define DENTRY_WALK_MAX 12

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

static struct dentry *find_pkg_dentry(struct dentry *d)
{
	struct dentry *cur = d;
	int depth = 0;

	while (cur && depth < DENTRY_WALK_MAX) {
		struct dentry *p  = cur->d_parent;
		struct dentry *pp;

		if (!p || p == cur)
			return NULL;
		pp = p->d_parent;

		if (p->d_name.len == 4 &&
		    memcmp(p->d_name.name, "data", 4) == 0 &&
		    pp && pp->d_name.len == 4 &&
		    memcmp(pp->d_name.name, "data", 4) == 0)
			return cur;

		if (p->d_name.len >= 1 &&
		    p->d_name.name[0] >= '0' && p->d_name.name[0] <= '9' &&
		    pp && pp->d_name.len == 4 &&
		    memcmp(pp->d_name.name, "user", 4) == 0) {
			struct dentry *ppp = pp->d_parent;
			if (ppp && ppp->d_name.len == 4 &&
			    memcmp(ppp->d_name.name, "data", 4) == 0)
				return cur;
		}

		cur = p;
		depth++;
	}
	return NULL;
}

static bool should_hide(const struct path *path)
{
	struct dentry *pkg;
	struct inode *inode;
	kuid_t caller, owner;

	if (!path || !path->dentry)
		return false;

	caller = current_fsuid();
	if (!is_app_uid(caller))
		return false;

	pkg = find_pkg_dentry(path->dentry);
	if (!pkg)
		return false;

	inode = d_inode(pkg);
	if (!inode)
		return false;

	owner = inode->i_uid;
	if (uid_eq(owner, caller))
		return false;

	return true;
}

struct hide_data {
	bool hide;
};

static int hide_entry_handler(struct kretprobe_instance *ri,
			      struct pt_regs *regs)
{
	struct hide_data *data = (struct hide_data *)ri->data;
	const struct path *path;

	data->hide = false;

	if (!hide_dd_guard_enter())
		return 0;

	path = (const struct path *)regs->regs[0];
	data->hide = should_hide(path);
	return 0;
}

static int hide_ret_handler(struct kretprobe_instance *ri,
			    struct pt_regs *regs)
{
	struct hide_data *data = (struct hide_data *)ri->data;
	long orig;

	orig = (long)regs->regs[0];

	if (data->hide && (orig == -EPERM || orig == -EACCES)) {
		regs->regs[0] = (unsigned long)(-ENOENT);
	}

	hide_dd_guard_exit();
	return 0;
}

static struct kretprobe hide_krp = {
	.kp.symbol_name = "vfs_getattr",
	.entry_handler  = hide_entry_handler,
	.handler        = hide_ret_handler,
	.data_size      = sizeof(struct hide_data),
	.maxactive      = 512,
};

static int hide_dd_register(void)
{
	int ret;

	ret = register_kretprobe(&hide_krp);
	if (ret == 0)
		return 0;

	if (ret == -EINVAL) {
		unsigned long addr = kallsyms_lookup_name("vfs_getattr");

		if (addr) {
			pr_info("hide_dd: symbol probe rejected (%d), trying addr 0x%lx\n",
				ret, addr);
			hide_krp.kp.symbol_name = NULL;
			hide_krp.kp.addr = (kprobe_opcode_t *)addr;
			ret = register_kretprobe(&hide_krp);
		}
	}

	return ret;
}

static int __init hide_dd_init(void)
{
	int ret = hide_dd_register();

	if (ret < 0) {
		pr_err("hide_dd: register_kretprobe failed: %d\n", ret);
		return ret;
	}

	pr_info("hide_dd: loaded, hooking vfs_getattr (uid %d..%d)\n",
		APP_UID_MIN, APP_UID_MAX);
	return 0;
}

static void __exit hide_dd_exit(void)
{
	unregister_kretprobe(&hide_krp);
	pr_info("hide_dd: unloaded\n");
}

module_init(hide_dd_init);
module_exit(hide_dd_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hide /data/data/<other_uid> from app processes");
MODULE_AUTHOR("Sliva4");
MODULE_VERSION("1.0");