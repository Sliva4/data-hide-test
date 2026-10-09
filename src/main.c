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
#include <linux/version.h>

#if IS_ENABLED(CONFIG_FPROBE)
#include <linux/fprobe.h>
#endif

#ifndef __aarch64__
#error "This module targets arm64 only"
#endif

#define APP_UID_MIN 10000
#define APP_UID_MAX 19999
#define APP_UID_RANGE (APP_UID_MAX - APP_UID_MIN)
#define WALK_MAX_DEPTH 12

static bool debug_verbose = false;
module_param(debug_verbose, bool, 0644);

static bool skip_walk = true;
module_param(skip_walk, bool, 0644);

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

/*
 * Rejection order — most common case first:
 *   1. i_sb != data_sb       (~95% of calls)
 *   2. !S_ISDIR              (files, char devices)
 *   3. owner not app uid
 *   4. caller not app uid
 *   5. caller == owner       (own data, shared uid)
 *   6. [skip_walk] return true
 *      else       dentry chain walk
 */
static __always_inline bool should_hide(struct inode *inode)
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

	if (skip_walk)
		return true;

	{
		struct dentry *d = d_find_alias(inode);
		bool ret;

		if (unlikely(!d))
			return false;
		ret = is_under_data_data(d);
		dput(d);
		return ret;
	}
}

struct hide_data {
	bool hide;
};

/* ============ fprobe handlers (fast path) ============ */

#if IS_ENABLED(CONFIG_FPROBE)

static int fp_perm_entry(struct fprobe *fp, unsigned long entry_ip,
			 unsigned long ret_ip, struct pt_regs *regs,
			 void *data)
{
	struct hide_data *d = data;
	d->hide = should_hide((struct inode *)regs->regs[1]);
	return 0;
}

static void fp_perm_exit(struct fprobe *fp, unsigned long entry_ip,
			 unsigned long ret_ip, struct pt_regs *regs,
			 void *data)
{
	struct hide_data *d = data;
	if (unlikely(d->hide))
		regs->regs[0] = (unsigned long)(long)(s32)(-ENOENT);
}

static int fp_sec_entry(struct fprobe *fp, unsigned long entry_ip,
			unsigned long ret_ip, struct pt_regs *regs,
			void *data)
{
	struct hide_data *d = data;
	const struct path *path = (const struct path *)regs->regs[0];

	if (unlikely(!path || !path->dentry)) {
		d->hide = false;
		return 0;
	}
	d->hide = should_hide(d_inode(path->dentry));
	return 0;
}

static void fp_sec_exit(struct fprobe *fp, unsigned long entry_ip,
			unsigned long ret_ip, struct pt_regs *regs,
			void *data)
{
	struct hide_data *d = data;
	if (unlikely(d->hide))
		regs->regs[0] = (unsigned long)(long)(s32)(-ENOENT);
}

static struct fprobe perm_fp = {
	.entry_handler = fp_perm_entry,
	.exit_handler  = fp_perm_exit,
	.entry_data_size = sizeof(struct hide_data),
};

static struct fprobe sec_fp = {
	.entry_handler = fp_sec_entry,
	.exit_handler  = fp_sec_exit,
	.entry_data_size = sizeof(struct hide_data),
};

static bool perm_fp_ok;
static bool sec_fp_ok;

static const char *perm_syms[] = { "inode_permission", NULL };
static const char *sec_syms[]  = { "security_inode_getattr", NULL };

static int try_fprobe(void)
{
	int ret;

	ret = register_fprobe_syms(&perm_fp, perm_syms, 1);
	if (ret) {
		pr_warn("hide_dd: fprobe inode_permission failed: %d\n", ret);
		return ret;
	}
	perm_fp_ok = true;

	ret = register_fprobe_syms(&sec_fp, sec_syms, 1);
	if (ret) {
		pr_warn("hide_dd: fprobe security_inode_getattr failed: %d\n",
			ret);
		unregister_fprobe(&perm_fp);
		perm_fp_ok = false;
		return ret;
	}
	sec_fp_ok = true;

	pr_info("hide_dd: fprobe registered (fast path)\n");
	return 0;
}

static void unregister_fprobe_all(void)
{
	if (sec_fp_ok) {
		unregister_fprobe(&sec_fp);
		sec_fp_ok = false;
	}
	if (perm_fp_ok) {
		unregister_fprobe(&perm_fp);
		perm_fp_ok = false;
	}
}

#else /* !CONFIG_FPROBE */

static inline int try_fprobe(void) { return -ENOSYS; }
static inline void unregister_fprobe_all(void) {}

#endif /* CONFIG_FPROBE */

/* ============ kretprobe fallback (slow path) ============ */

static int kr_perm_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hide_data *d = (struct hide_data *)ri->data;
	d->hide = should_hide((struct inode *)regs->regs[1]);
	return 0;
}

static int kr_perm_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hide_data *d = (struct hide_data *)ri->data;
	if (unlikely(d->hide))
		regs->regs[0] = (unsigned long)(long)(s32)(-ENOENT);
	return 0;
}

static struct kretprobe perm_krp = {
	.kp.symbol_name = "inode_permission",
	.entry_handler = kr_perm_entry,
	.handler       = kr_perm_ret,
	.data_size     = sizeof(struct hide_data),
	.maxactive     = 4096,
};

static int kr_sec_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hide_data *d = (struct hide_data *)ri->data;
	const struct path *path = (const struct path *)regs->regs[0];

	if (unlikely(!path || !path->dentry)) {
		d->hide = false;
		return 0;
	}
	d->hide = should_hide(d_inode(path->dentry));
	return 0;
}

static int kr_sec_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct hide_data *d = (struct hide_data *)ri->data;
	if (unlikely(d->hide))
		regs->regs[0] = (unsigned long)(long)(s32)(-ENOENT);
	return 0;
}

static struct kretprobe sec_krp = {
	.kp.symbol_name = "security_inode_getattr",
	.entry_handler = kr_sec_entry,
	.handler       = kr_sec_ret,
	.data_size     = sizeof(struct hide_data),
	.maxactive     = 1024,
};

static bool perm_krp_ok;
static bool sec_krp_ok;

static int register_kret_fallback(struct kretprobe *krp, const char *name,
				  bool *ok)
{
	int ret;
	unsigned long addr;

	krp->kp.symbol_name = name;
	krp->kp.addr = NULL;
	ret = register_kretprobe(krp);
	if (ret == 0) {
		pr_info("hide_dd: kretprobe on %s\n", name);
		*ok = true;
		return 0;
	}

	addr = kallsyms_lookup_name(name);
	if (!addr)
		return -ENOENT;

	krp->kp.symbol_name = NULL;
	krp->kp.addr = (kprobe_opcode_t *)addr;
	ret = register_kretprobe(krp);
	if (ret == 0) {
		pr_info("hide_dd: kretprobe on %s @ 0x%lx\n", name, addr);
		*ok = true;
	}
	return ret;
}

static int try_kretprobe(void)
{
	int ret;

	ret = register_kret_fallback(&perm_krp, "inode_permission",
				     &perm_krp_ok);
	if (ret)
		return ret;

	ret = register_kret_fallback(&sec_krp, "security_inode_getattr",
				     &sec_krp_ok);
	if (ret) {
		unregister_kretprobe(&perm_krp);
		perm_krp_ok = false;
		return ret;
	}
	return 0;
}

static void unregister_kretprobe_all(void)
{
	if (sec_krp_ok) {
		unregister_kretprobe(&sec_krp);
		sec_krp_ok = false;
	}
	if (perm_krp_ok) {
		unregister_kretprobe(&perm_krp);
		perm_krp_ok = false;
	}
}

/* ============ init / exit ============ */

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
	if (ret) {
		pr_err("hide_dd: save_data_sb failed: %d\n", ret);
		return ret;
	}

	if (try_fprobe() == 0) {
		pr_info("hide_dd: loaded (fprobe, uid %d..%d, skip_walk=%d)\n",
			APP_UID_MIN, APP_UID_MAX, skip_walk);
		return 0;
	}

	pr_info("hide_dd: falling back to kretprobe\n");
	if (try_kretprobe() == 0) {
		pr_info("hide_dd: loaded (kretprobe, uid %d..%d, skip_walk=%d)\n",
			APP_UID_MIN, APP_UID_MAX, skip_walk);
		return 0;
	}

	pr_err("hide_dd: registration failed\n");
	return -ENOENT;
}

static void __exit hide_dd_exit(void)
{
	unregister_fprobe_all();
	unregister_kretprobe_all();
	pr_info("hide_dd: unloaded\n");
}

module_init(hide_dd_init);
module_exit(hide_dd_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hide /data/data/<other_uid> from app processes");
MODULE_VERSION("7.0-fprobe");
