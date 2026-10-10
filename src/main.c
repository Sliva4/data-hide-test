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
#include <linux/ktime.h>
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

static __always_inline bool parent_looks_like_pkg(struct dentry *d)
{
	struct dentry *p, *pp;

	p = d->d_parent;
	if (unlikely(!p || p == d))
		return false;

	if (p->d_name.len == 4 && memcmp(p->d_name.name, "data", 4) == 0)
		return true;

	if (p->d_name.len == 1 &&
	    p->d_name.name[0] >= '0' && p->d_name.name[0] <= '9') {
		pp = p->d_parent;
		if (pp && pp->d_name.len == 4 &&
		    memcmp(pp->d_name.name, "user", 4) == 0) {
			struct dentry *ppp = pp->d_parent;
			if (ppp && ppp->d_name.len == 4 &&
			    memcmp(ppp->d_name.name, "data", 4) == 0)
				return true;
		}
	}
	return false;
}

static __always_inline bool should_hide(struct inode *inode)
{
	struct dentry *d;
	u32 owner_val, caller_val;
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
	ret = parent_looks_like_pkg(d);
	dput(d);
	return ret;
}

/* ---------- inode_permission ---------- */

static int perm_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct inode *inode = (struct inode *)regs->regs[1];

	if (should_hide(inode)) {
		regs->regs[0] = (unsigned long)(long)(s32)(-ENOENT);
		instruction_pointer_set(regs, regs->regs[30]);
		if (unlikely(debug_verbose))
			pr_info("hide_dd: PERM skip uid=%u comm=%s\n",
				__kuid_val(inode->i_uid), current->comm);
		return 1;
	}
	return 0;
}

static struct kprobe perm_kp = {
	.symbol_name = "inode_permission",
	.pre_handler = perm_pre_handler,
};

/* ---------- security_inode_getattr ---------- */

static int sec_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	const struct path *path = (const struct path *)regs->regs[0];
	struct inode *inode;

	if (unlikely(!path || !path->dentry))
		return 0;

	inode = d_inode(path->dentry);
	if (should_hide(inode)) {
		regs->regs[0] = (unsigned long)(long)(s32)(-ENOENT);
		instruction_pointer_set(regs, regs->regs[30]);
		if (unlikely(debug_verbose))
			pr_info("hide_dd: SEC skip uid=%u comm=%s\n",
				__kuid_val(inode->i_uid), current->comm);
		return 1;
	}
	return 0;
}

static struct kprobe sec_kp = {
	.symbol_name = "security_inode_getattr",
	.pre_handler = sec_pre_handler,
};

/* ---------- syscall 45 timing balancer ---------- */

static int empty_delay_ns = 500;
module_param(empty_delay_ns, int, 0644);

static int max_key_len = 128;
module_param(max_key_len, int, 0644);

static int per_byte_ns = 4;
module_param(per_byte_ns, int, 0644);

static int proportional_delay = 1;
module_param(proportional_delay, int, 0644);

static int supercall_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	u32 uid;
	unsigned long path_ptr;
	long len;
	int delay;
	u64 start;

	if (empty_delay_ns <= 0 && (per_byte_ns <= 0 || !proportional_delay))
		return 0;

	uid = __kuid_val(current_fsuid());
	if (!is_app_uid_val(uid))
		return 0;

	path_ptr = regs->regs[0];
	if (!path_ptr)
		return 0;

	len = strnlen_user((const char __user *)path_ptr, max_key_len);
	if (len <= 0)
		return 0;

	if (proportional_delay) {
		if (len > max_key_len)
			len = max_key_len;
		delay = (max_key_len - (int)len) * per_byte_ns;
	} else {
		if (len != 1)
			return 0;
		delay = empty_delay_ns;
	}

	if (delay <= 0)
		return 0;

	start = ktime_get_ns();
	while ((long)(ktime_get_ns() - start) < delay)
		cpu_relax();

	if (unlikely(debug_verbose))
		pr_info("hide_dd: DELAY uid=%u len=%ld comm=%s +%dns\n",
			uid, len, current->comm, delay);

	return 0;
}

static unsigned long *sys_call_table_p;
static struct kprobe supercall_kp = {
	.pre_handler = supercall_pre_handler,
};

static int register_supercall_hook(void)
{
	int ret;
	unsigned long addr;

	sys_call_table_p =
		(unsigned long *)kallsyms_lookup_name("sys_call_table");
	if (!sys_call_table_p || !sys_call_table_p[45])
		return -ENOENT;

	addr = sys_call_table_p[45];
	supercall_kp.addr = (kprobe_opcode_t *)addr;
	supercall_kp.symbol_name = NULL;
	ret = register_kprobe(&supercall_kp);
	if (ret == 0)
		pr_info("hide_dd: delay hook on sys_call_table[45]@0x%lx "
			"uid %d..%d proportional=%d delay=%dns per_byte=%dns max_len=%d\n",
			addr, APP_UID_MIN, APP_UID_MAX,
			proportional_delay, empty_delay_ns,
			per_byte_ns, max_key_len);
	else
		pr_warn("hide_dd: sys_call_table[45] hook failed: %d\n", ret);
	return ret;
}

static void unregister_supercall_hook(void)
{
	if (supercall_kp.addr) {
		unregister_kprobe(&supercall_kp);
		supercall_kp.addr = NULL;
	}
}

/* ---------- registration ---------- */

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
	if (!addr)
		return -ENOENT;

	kp->symbol_name = NULL;
	kp->addr = (kprobe_opcode_t *)addr;
	ret = register_kprobe(kp);
	if (ret == 0)
		pr_info("hide_dd: kprobe on %s @ 0x%lx\n", name, addr);
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

static bool perm_registered;
static bool sec_registered;

static int __init hide_dd_init(void)
{
	int ret;

	ret = save_data_sb();
	if (ret) {
		pr_err("hide_dd: save_data_sb failed: %d\n", ret);
		return ret;
	}

	if (register_one(&perm_kp) == 0)
		perm_registered = true;
	else
		return -ENOENT;

	if (register_one(&sec_kp) == 0)
		sec_registered = true;
	else {
		unregister_kprobe(&perm_kp);
		perm_registered = false;
		return -ENOENT;
	}

	register_supercall_hook();

	pr_info("hide_dd: loaded (uid %d..%d)\n", APP_UID_MIN, APP_UID_MAX);
	return 0;
}

static void __exit hide_dd_exit(void)
{
	unregister_supercall_hook();
	if (sec_registered) {
		unregister_kprobe(&sec_kp);
		sec_registered = false;
	}
	if (perm_registered) {
		unregister_kprobe(&perm_kp);
		perm_registered = false;
	}
	pr_info("hide_dd: unloaded\n");
}

module_init(hide_dd_init);
module_exit(hide_dd_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hide /data/data/<other_uid> + timing balancer");
MODULE_VERSION("11.0");
