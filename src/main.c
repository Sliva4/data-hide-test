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

/*
 * Directory check. On data_sb, any directory owned by an app UID
 * (other than the caller) is a hidden app data dir:
 *   /data/data/<pkg>
 *   /data/user/<N>/<pkg>
 *   /data/user_de/<N>/<pkg>
 */
static __always_inline bool should_hide_dir(struct inode *inode)
{
	u32 owner_val, caller_val;

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

	return true;
}

/* Same as dir check but no S_ISDIR filter — for vfs_open/vfs_getxattr. */
static __always_inline bool should_hide_any(struct inode *inode)
{
	u32 owner_val, caller_val;

	if (unlikely(!inode))
		return false;
	if (likely(inode->i_sb != data_sb))
		return false;

	owner_val = __kuid_val(inode->i_uid);
	if (likely(!is_app_uid_val(owner_val)))
		return false;

	caller_val = __kuid_val(current_fsuid());
	if (likely(!is_app_uid_val(caller_val)))
		return false;
	if (likely(caller_val == owner_val))
		return false;

	return true;
}

/* ============ inode_permission ============ */

static int perm_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct inode *inode = (struct inode *)regs->regs[1];

	if (should_hide_dir(inode)) {
		regs->regs[0] = (unsigned long)(long)(s32)(-ENOENT);
		instruction_pointer_set(regs, regs->regs[30]);
		if (unlikely(debug_verbose))
			pr_info("hide_dd: PERM uid=%u caller=%u comm=%s\n",
				__kuid_val(inode->i_uid),
				__kuid_val(current_fsuid()),
				current->comm);
		return 1;
	}
	return 0;
}

static struct kprobe perm_kp = {
	.symbol_name = "inode_permission",
	.pre_handler = perm_pre_handler,
};

/* ============ security_inode_getattr ============ */

static int sec_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	const struct path *path = (const struct path *)regs->regs[0];
	struct inode *inode;

	if (unlikely(!path || !path->dentry))
		return 0;

	inode = d_inode(path->dentry);
	if (should_hide_dir(inode)) {
		regs->regs[0] = (unsigned long)(long)(s32)(-ENOENT);
		instruction_pointer_set(regs, regs->regs[30]);
		if (unlikely(debug_verbose))
			pr_info("hide_dd: SEC uid=%u caller=%u comm=%s\n",
				__kuid_val(inode->i_uid),
				__kuid_val(current_fsuid()),
				current->comm);
		return 1;
	}
	return 0;
}

static struct kprobe sec_kp = {
	.symbol_name = "security_inode_getattr",
	.pre_handler = sec_pre_handler,
};

/* ============ vfs_open ============ */

static int vfs_open_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	const struct path *path = (const struct path *)regs->regs[0];
	struct inode *inode;

	if (unlikely(!path || !path->dentry))
		return 0;

	inode = d_inode(path->dentry);
	if (should_hide_any(inode)) {
		regs->regs[0] = (unsigned long)(long)(s32)(-ENOENT);
		instruction_pointer_set(regs, regs->regs[30]);
		if (unlikely(debug_verbose))
			pr_info("hide_dd: OPEN uid=%u caller=%u comm=%s\n",
				__kuid_val(inode->i_uid),
				__kuid_val(current_fsuid()),
				current->comm);
		return 1;
	}
	return 0;
}

static struct kprobe vfs_open_kp = {
	.symbol_name = "vfs_open",
	.pre_handler = vfs_open_pre_handler,
};

/* ============ vfs_getxattr ============ */

static int vfs_getxattr_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct dentry *dentry = (struct dentry *)regs->regs[1];
	struct inode *inode;

	if (unlikely(!dentry))
		return 0;

	inode = d_inode(dentry);
	if (should_hide_any(inode)) {
		regs->regs[0] = (unsigned long)(long)(s32)(-ENOENT);
		instruction_pointer_set(regs, regs->regs[30]);
		if (unlikely(debug_verbose))
			pr_info("hide_dd: XATTR uid=%u caller=%u comm=%s\n",
				__kuid_val(inode->i_uid),
				__kuid_val(current_fsuid()),
				current->comm);
		return 1;
	}
	return 0;
}

static struct kprobe vfs_getxattr_kp = {
	.symbol_name = "vfs_getxattr",
	.pre_handler = vfs_getxattr_pre_handler,
};

/* ============ vfs_listxattr ============ */

static int vfs_listxattr_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct dentry *dentry = (struct dentry *)regs->regs[0];
	struct inode *inode;

	if (unlikely(!dentry))
		return 0;

	inode = d_inode(dentry);
	if (should_hide_any(inode)) {
		regs->regs[0] = (unsigned long)(long)(s32)(-ENOENT);
		instruction_pointer_set(regs, regs->regs[30]);
		if (unlikely(debug_verbose))
			pr_info("hide_dd: LISTXATTR uid=%u caller=%u comm=%s\n",
				__kuid_val(inode->i_uid),
				__kuid_val(current_fsuid()),
				current->comm);
		return 1;
	}
	return 0;
}

static struct kprobe vfs_listxattr_kp = {
	.symbol_name = "vfs_listxattr",
	.pre_handler = vfs_listxattr_pre_handler,
};

/* ============ vfs_mkdir (EEXIST leak) ============ */

static int vfs_mkdir_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct dentry *dentry = (struct dentry *)regs->regs[2];
	struct inode *inode;

	if (unlikely(!dentry))
		return 0;

	inode = d_inode(dentry);
	if (should_hide_any(inode)) {
		regs->regs[0] = (unsigned long)(long)(s32)(-ENOENT);
		instruction_pointer_set(regs, regs->regs[30]);
		if (unlikely(debug_verbose))
			pr_info("hide_dd: MKDIR uid=%u caller=%u comm=%s\n",
				__kuid_val(inode->i_uid),
				__kuid_val(current_fsuid()),
				current->comm);
		return 1;
	}
	return 0;
}

static struct kprobe vfs_mkdir_kp = {
	.symbol_name = "vfs_mkdir",
	.pre_handler = vfs_mkdir_pre_handler,
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
		pr_err("hide_dd: %s not found\n", name);
		return -ENOENT;
	}

	kp->symbol_name = NULL;
	kp->addr = (kprobe_opcode_t *)addr;
	ret = register_kprobe(kp);
	if (ret == 0)
		pr_info("hide_dd: kprobe on %s @ 0x%lx\n", name, addr);
	return ret;
}

static int save_sbs(void)
{
	struct path path;
	int ret;

	ret = kern_path("/data", LOOKUP_FOLLOW, &path);
	if (ret) {
		pr_err("hide_dd: kern_path(/data) failed: %d\n", ret);
		return ret;
	}
	data_sb = path.dentry->d_sb;
	path_put(&path);
	pr_info("hide_dd: data_sb=%p\n", data_sb);
	return 0;
}

static bool perm_ok, sec_ok, open_ok, getxattr_ok, listxattr_ok, mkdir_ok;

static int __init hide_dd_init(void)
{
	int ret;

	ret = save_sbs();
	if (ret)
		return ret;

	if (register_one(&perm_kp) == 0) perm_ok = true;
	else return -ENOENT;

	if (register_one(&sec_kp) == 0) sec_ok = true;
	else goto fail;

	if (register_one(&vfs_open_kp) == 0) open_ok = true;
	else goto fail;

	if (register_one(&vfs_getxattr_kp) == 0) getxattr_ok = true;
	else goto fail;

	if (register_one(&vfs_listxattr_kp) == 0) listxattr_ok = true;
	else goto fail;

	if (register_one(&vfs_mkdir_kp) == 0) mkdir_ok = true;
	/* mkdir — не критично, продолжаем даже если не удалось */

	pr_info("hide_dd: loaded (uid %d..%d)\n", APP_UID_MIN, APP_UID_MAX);
	return 0;

fail:
	if (listxattr_ok) unregister_kprobe(&vfs_listxattr_kp);
	if (getxattr_ok)  unregister_kprobe(&vfs_getxattr_kp);
	if (open_ok)      unregister_kprobe(&vfs_open_kp);
	if (sec_ok)       unregister_kprobe(&sec_kp);
	if (perm_ok)      unregister_kprobe(&perm_kp);
	return -ENOENT;
}

static void __exit hide_dd_exit(void)
{
	if (mkdir_ok)     unregister_kprobe(&vfs_mkdir_kp);
	if (listxattr_ok) unregister_kprobe(&vfs_listxattr_kp);
	if (getxattr_ok)  unregister_kprobe(&vfs_getxattr_kp);
	if (open_ok)      unregister_kprobe(&vfs_open_kp);
	if (sec_ok)       unregister_kprobe(&sec_kp);
	if (perm_ok)      unregister_kprobe(&perm_kp);
	pr_info("hide_dd: unloaded\n");
}

module_init(hide_dd_init);
module_exit(hide_dd_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hide app data of other UIDs from app processes (fs-level only)");
MODULE_VERSION("13.0");
