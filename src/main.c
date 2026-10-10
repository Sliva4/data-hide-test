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
#include <asm/ptrace.h>

#ifndef __aarch64__
#error "This module targets arm64 only"
#endif

#define APP_UID_MIN 10000
#define APP_UID_MAX 19999
#define APP_UID_RANGE (APP_UID_MAX - APP_UID_MIN)

static bool debug_verbose = false;
module_param(debug_verbose, bool, 0644);

static struct super_block *data_sb;

static __always_inline bool is_app_uid_val(u32 v)
{
	return (v - APP_UID_MIN) <= APP_UID_RANGE;
}

static __always_inline bool should_hide_dir(struct inode *inode)
{
	u32 owner_val, caller_val;

	if (unlikely(!inode)) return false;
	if (likely(inode->i_sb != data_sb)) return false;
	if (likely(!S_ISDIR(inode->i_mode))) return false;

	owner_val = __kuid_val(inode->i_uid);
	if (likely(!is_app_uid_val(owner_val))) return false;

	caller_val = __kuid_val(current_fsuid());
	if (likely(!is_app_uid_val(caller_val))) return false;
	if (likely(caller_val == owner_val)) return false;

	return true;
}

static __always_inline bool should_hide_any(struct inode *inode)
{
	u32 owner_val, caller_val;

	if (unlikely(!inode)) return false;
	if (likely(inode->i_sb != data_sb)) return false;

	owner_val = __kuid_val(inode->i_uid);
	if (likely(!is_app_uid_val(owner_val))) return false;

	caller_val = __kuid_val(current_fsuid());
	if (likely(!is_app_uid_val(caller_val))) return false;
	if (likely(caller_val == owner_val)) return false;

	return true;
}

#define DENY_AND_SKIP(regs) do { \
	regs->regs[0] = (unsigned long)(long)(s32)(-ENOENT); \
	instruction_pointer_set(regs, regs->regs[30]); \
} while (0)

/* ============ inode_permission ============ */
static int perm_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct inode *inode = (struct inode *)regs->regs[1];
	if (should_hide_dir(inode)) {
		DENY_AND_SKIP(regs);
		if (unlikely(debug_verbose))
			pr_info("hide_dd: PERM uid=%u\n", __kuid_val(inode->i_uid));
		return 1;
	}
	return 0;
}
static struct kprobe perm_kp = {
	.symbol_name = "inode_permission",
	.pre_handler = perm_pre_handler,
};

/* ============ security_inode_getattr ============ */
static int sec_getattr_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	const struct path *path = (const struct path *)regs->regs[0];
	struct inode *inode;
	if (unlikely(!path || !path->dentry)) return 0;
	inode = d_inode(path->dentry);
	if (should_hide_dir(inode)) {
		DENY_AND_SKIP(regs);
		if (unlikely(debug_verbose))
			pr_info("hide_dd: GETATTR uid=%u\n", __kuid_val(inode->i_uid));
		return 1;
	}
	return 0;
}
static struct kprobe sec_getattr_kp = {
	.symbol_name = "security_inode_getattr",
	.pre_handler = sec_getattr_pre_handler,
};

/* ============ vfs_open ============ */
static int vfs_open_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	const struct path *path = (const struct path *)regs->regs[0];
	struct inode *inode;
	if (unlikely(!path || !path->dentry)) return 0;
	inode = d_inode(path->dentry);
	if (should_hide_any(inode)) {
		DENY_AND_SKIP(regs);
		if (unlikely(debug_verbose))
			pr_info("hide_dd: OPEN uid=%u\n", __kuid_val(inode->i_uid));
		return 1;
	}
	return 0;
}
static struct kprobe vfs_open_kp = {
	.symbol_name = "vfs_open",
	.pre_handler = vfs_open_pre_handler,
};

/* ============ security_inode_getxattr ============ */
static int sec_getxattr_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct dentry *dentry = (struct dentry *)regs->regs[0];
	struct inode *inode;
	if (unlikely(!dentry)) return 0;
	inode = d_inode(dentry);
	if (should_hide_any(inode)) {
		DENY_AND_SKIP(regs);
		if (unlikely(debug_verbose))
			pr_info("hide_dd: GETXATTR uid=%u\n", __kuid_val(inode->i_uid));
		return 1;
	}
	return 0;
}
static struct kprobe sec_getxattr_kp = {
	.symbol_name = "security_inode_getxattr",
	.pre_handler = sec_getxattr_pre_handler,
};

/* ============ security_inode_listxattr ============ */
static int sec_listxattr_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct dentry *dentry = (struct dentry *)regs->regs[0];
	struct inode *inode;
	if (unlikely(!dentry)) return 0;
	inode = d_inode(dentry);
	if (should_hide_any(inode)) {
		DENY_AND_SKIP(regs);
		if (unlikely(debug_verbose))
			pr_info("hide_dd: LISTXATTR uid=%u\n", __kuid_val(inode->i_uid));
		return 1;
	}
	return 0;
}
static struct kprobe sec_listxattr_kp = {
	.symbol_name = "security_inode_listxattr",
	.pre_handler = sec_listxattr_pre_handler,
};

/* ============ security_inode_setattr (chmod/chown/utimes) ============ */
/*
 * On 5.15:  int security_inode_setattr(struct user_namespace *mnt_userns,
 *                                      struct dentry *dentry,
 *                                      struct iattr *attr)
 * x0 = mnt_userns, x1 = dentry, x2 = attr
 */
static int sec_setattr_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct dentry *dentry = (struct dentry *)regs->regs[1];
	struct inode *inode;
	if (unlikely(!dentry)) return 0;
	inode = d_inode(dentry);
	if (should_hide_any(inode)) {
		DENY_AND_SKIP(regs);
		if (unlikely(debug_verbose))
			pr_info("hide_dd: SETATTR uid=%u\n", __kuid_val(inode->i_uid));
		return 1;
	}
	return 0;
}
static struct kprobe sec_setattr_kp = {
	.symbol_name = "security_inode_setattr",
	.pre_handler = sec_setattr_pre_handler,
};

/* ============ security_path_mkdir ============ */
/*
 * int security_path_mkdir(const struct path *dir, struct dentry *dentry,
 *                         umode_t mode)
 * x0 = dir path, x1 = dentry, x2 = mode
 */
static int sec_mkdir_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct dentry *dentry = (struct dentry *)regs->regs[1];
	struct inode *inode;
	if (unlikely(!dentry)) return 0;
	inode = d_inode(dentry);
	if (should_hide_any(inode)) {
		DENY_AND_SKIP(regs);
		if (unlikely(debug_verbose))
			pr_info("hide_dd: MKDIR uid=%u\n", __kuid_val(inode->i_uid));
		return 1;
	}
	return 0;
}
static struct kprobe sec_mkdir_kp = {
	.symbol_name = "security_path_mkdir",
	.pre_handler = sec_mkdir_pre_handler,
};

/* ============ registration ============ */

static int register_one(struct kprobe *kp)
{
	int ret;
	unsigned long addr;
	const char *name = kp->symbol_name;

	ret = register_kprobe(kp);
	if (ret == 0) {
		pr_info("hide_dd: kprobe on %s\n", name);
		return 0;
	}
	addr = kallsyms_lookup_name(name);
	if (!addr) {
		pr_warn("hide_dd: %s not found\n", name);
		return -ENOENT;
	}
	kp->symbol_name = NULL;
	kp->addr = (kprobe_opcode_t *)addr;
	ret = register_kprobe(kp);
	if (ret == 0) {
		pr_info("hide_dd: kprobe on %s @ 0x%lx\n", name, addr);
		return 0;
	}
	pr_warn("hide_dd: %s addr-based failed: %d\n", name, ret);
	return ret;
}

static int save_data_sb(void)
{
	struct path path;
	int ret = kern_path("/data", LOOKUP_FOLLOW, &path);
	if (ret) return ret;
	data_sb = path.dentry->d_sb;
	path_put(&path);
	pr_info("hide_dd: data_sb=%p\n", data_sb);
	return 0;
}

static int __init hide_dd_init(void)
{
	int ret = save_data_sb();
	if (ret) return ret;

	register_one(&perm_kp);
	register_one(&sec_getattr_kp);
	register_one(&vfs_open_kp);
	register_one(&sec_getxattr_kp);
	register_one(&sec_listxattr_kp);
	register_one(&sec_setattr_kp);
	register_one(&sec_mkdir_kp);

	pr_info("hide_dd: loaded (uid %d..%d)\n", APP_UID_MIN, APP_UID_MAX);
	return 0;
}

static void __exit hide_dd_exit(void)
{
	if (sec_mkdir_kp.addr)        unregister_kprobe(&sec_mkdir_kp);
	if (sec_setattr_kp.addr)      unregister_kprobe(&sec_setattr_kp);
	if (sec_listxattr_kp.addr)    unregister_kprobe(&sec_listxattr_kp);
	if (sec_getxattr_kp.addr)     unregister_kprobe(&sec_getxattr_kp);
	if (vfs_open_kp.addr)         unregister_kprobe(&vfs_open_kp);
	if (sec_getattr_kp.addr)      unregister_kprobe(&sec_getattr_kp);
	if (perm_kp.addr)             unregister_kprobe(&perm_kp);
	pr_info("hide_dd: unloaded\n");
}

module_init(hide_dd_init);
module_exit(hide_dd_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hide app data of other UIDs from app processes");
MODULE_VERSION("14.0");
