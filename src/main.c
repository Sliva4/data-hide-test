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
#include <linux/types.h>

#ifndef __aarch64__
#error "This module targets arm64 only"
#endif

#define APP_UID_MIN 10000
#define APP_UID_MAX 19999
#define APP_UID_RANGE (APP_UID_MAX - APP_UID_MIN)
#define WALK_MAX_DEPTH 12

static bool debug_verbose = false;
module_param(debug_verbose, bool, 0644);

static struct super_block *data_sb;

static __always_inline bool is_app_uid_val(u32 v)
{
	return (v - APP_UID_MIN) <= APP_UID_RANGE;
}

static bool is_under_data_data(struct dentry *d)
{
	struct dentry *cur = d;
	int depth;

	for (depth = 0; depth < WALK_MAX_DEPTH; depth++) {
		struct dentry *p = cur->d_parent;

		if (unlikely(!p || p == cur))
			return false;

		if (p->d_name.len == 4 &&
		    memcmp(p->d_name.name, "data", 4) == 0) {
			struct dentry *pp = p->d_parent;

			if (pp == p || pp == data_sb->s_root)
				return true;
			if (pp && pp->d_name.len == 4 &&
			    memcmp(pp->d_name.name, "data", 4) == 0)
				return true;
		}

		if (p->d_name.len == 1 &&
		    p->d_name.name[0] >= '0' && p->d_name.name[0] <= '9') {
			struct dentry *ud = p->d_parent;

			if (ud && ud->d_name.len == 4 &&
			    memcmp(ud->d_name.name, "user", 4) == 0) {
				struct dentry *up = ud->d_parent;

				if (up == ud || up == data_sb->s_root)
					return true;
				if (up && up->d_name.len == 4 &&
				    memcmp(up->d_name.name, "data", 4) == 0)
					return true;
			}
		}

		cur = p;
	}
	return false;
}

static __always_inline bool should_hide_inode(struct inode *inode)
{
	u32 owner_val, caller_val;
	struct dentry *d;
	bool ret;

	if (unlikely(!inode))
		return false;

	if (likely(inode->i_sb != data_sb))
		return false;

	if (likely(!S_ISDIR(inode->i_mode)))
		return false;

	owner_val = __kuid_val(inode->i_uid);
	if (likely(!is_app_uid_val(owner_val)))
		return false;

	caller_val = __kuid_val(current_fsuid());
	if (likely(!is_app_uid_val(caller_val)))
		return false;

	if (likely(caller_val == owner_val))
		return false;

	d = d_find_alias(inode);
	if (unlikely(!d))
		return false;

	ret = is_under_data_data(d);
	dput(d);
	return ret;
}

/*
 * True if current task is inside syscall 45 (truncate slot used by
 * KernelSU supercall). Detector measures timing of truncate() with
 * different-length paths. Path walk inside the syscall triggers our
 * inode_permission kretprobe. Skip our logic entirely for such calls
 * to keep cost identical regardless of path length.
 */
static __always_inline bool in_syscall_45(void)
{
	struct pt_regs *regs = task_pt_regs(current);
	return regs && unlikely(regs->syscallno == 45);
}

struct hide_data {
	bool hide;
};

/* ============ inode_permission ============ */

static int perm_entry_handler(struct kretprobe_instance *ri,
			      struct pt_regs *regs)
{
	struct hide_data *data = (struct hide_data *)ri->data;

	if (in_syscall_45()) {
		data->hide = false;
		return 0;
	}

	data->hide = should_hide_inode((struct inode *)regs->regs[1]);
	return 0;
}

static int perm_ret_handler(struct kretprobe_instance *ri,
			    struct pt_regs *regs)
{
	struct hide_data *data = (struct hide_data *)ri->data;

	if (unlikely(data->hide))
		regs->regs[0] = (unsigned long)(long)(s32)(-ENOENT);
	return 0;
}

static struct kretprobe perm_krp = {
	.kp.symbol_name = "inode_permission",
	.entry_handler  = perm_entry_handler,
	.handler        = perm_ret_handler,
	.data_size      = sizeof(struct hide_data),
	.maxactive      = 4096,
};

/* ============ security_inode_getattr ============ */

static int sec_getattr_entry_handler(struct kretprobe_instance *ri,
				     struct pt_regs *regs)
{
	struct hide_data *data = (struct hide_data *)ri->data;
	const struct path *path = (const struct path *)regs->regs[0];
	struct inode *inode;

	if (in_syscall_45()) {
		data->hide = false;
		return 0;
	}

	if (unlikely(!path || !path->dentry)) {
		data->hide = false;
		return 0;
	}

	inode = d_inode(path->dentry);
	data->hide = should_hide_inode(inode);
	return 0;
}

static int sec_getattr_ret_handler(struct kretprobe_instance *ri,
				   struct pt_regs *regs)
{
	struct hide_data *data = (struct hide_data *)ri->data;

	if (unlikely(data->hide))
		regs->regs[0] = (unsigned long)(long)(s32)(-ENOENT);
	return 0;
}

static struct kretprobe sec_getattr_krp = {
	.kp.symbol_name = "security_inode_getattr",
	.entry_handler  = sec_getattr_entry_handler,
	.handler        = sec_getattr_ret_handler,
	.data_size      = sizeof(struct hide_data),
	.maxactive      = 1024,
};

/* ============ registration ============ */

static int register_kret(struct kretprobe *krp, const char *name)
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
	return ret;
}

static int save_data_sb(void)
{
	struct path path;
	int ret;

	ret = kern_path("/data", LOOKUP_FOLLOW, &path);
	if (ret)
		return ret;
	data_sb = path.dentry->d_sb;
	path_put(&path);
	return 0;
}

static int __init hide_dd_init(void)
{
	int ret;

	ret = save_data_sb();
	if (ret)
		return ret;

	register_kret(&perm_krp, "inode_permission");
	register_kret(&sec_getattr_krp, "security_inode_getattr");

	pr_info("hide_dd: loaded (uid %d..%d, no-bypass mode)\n",
		APP_UID_MIN, APP_UID_MAX);
	return 0;
}

static void __exit hide_dd_exit(void)
{
	unregister_kretprobe(&sec_getattr_krp);
	unregister_kretprobe(&perm_krp);
	pr_info("hide_dd: unloaded\n");
}

module_init(hide_dd_init);
module_exit(hide_dd_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hide /data/data/<other_uid> from app processes");
MODULE_VERSION("6.0-nobypass");
