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

static bool debug_verbose = true;
module_param(debug_verbose, bool, 0644);

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

static void dump_dentry_chain(struct dentry *d, char *buf, size_t buflen)
{
	struct dentry *cur = d;
	size_t off = 0;
	int depth = 0;

	if (!buf || buflen == 0)
		return;
	buf[0] = '\0';

	while (cur && depth < DENTRY_WALK_MAX) {
		const char *name = cur->d_name.name;
		size_t len = cur->d_name.len;
		int n;

		if (off + len + 2 >= buflen)
			break;

		n = snprintf(buf + off, buflen - off, "/%.*s",
			     (int)len, name);
		if (n <= 0)
			break;
		off += n;
		cur = cur->d_parent;
		if (!cur || cur == cur->d_parent)
			break;
		depth++;
	}
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
	struct dentry *dentry;
	kuid_t caller;
	char chain[256];

	data->hide = false;

	if (!hide_dd_guard_enter())
		return 0;

	path = (const struct path *)regs->regs[0];
	caller = current_fsuid();

	if (!path || !path->dentry)
		goto out;

	dentry = path->dentry;

	if (debug_verbose) {
		dump_dentry_chain(dentry, chain, sizeof(chain));
		pr_info("hide_dd: entry uid=%u comm=%s path=%s\n",
			__kuid_val(caller),
			current->comm,
			chain);
	}

	data->hide = should_hide(path);

	if (data->hide)
		pr_info("hide_dd: MATCH uid=%u path=%s\n",
			__kuid_val(caller), chain);

out:
	return 0;
}

static int hide_ret_handler(struct kretprobe_instance *ri,
			    struct pt_regs *regs)
{
	struct hide_data *data = (struct hide_data *)ri->data;
	long orig = (long)regs->regs[0];

	if (data->hide) {
		pr_info("hide_dd: ret orig=%ld\n", orig);
		if (orig == -EPERM || orig == -EACCES) {
			regs->regs[0] = (unsigned long)(-ENOENT);
			pr_info("hide_dd: rewrote to -ENOENT\n");
		}
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

static const char *hook_candidates[] = {
	"vfs_getattr",
	"vfs_getattr_nosec",
	"vfs_statx",
	"vfs_fstatat",
	NULL,
};

static int hide_dd_register(void)
{
	int i, ret;
	unsigned long addr;

	for (i = 0; hook_candidates[i] != NULL; i++) {
		hide_krp.kp.symbol_name = hook_candidates[i];
		hide_krp.kp.addr = NULL;

		ret = register_kretprobe(&hide_krp);
		if (ret == 0) {
			pr_info("hide_dd: kretprobe registered on %s\n",
				hook_candidates[i]);
			return 0;
		}

		pr_info("hide_dd: symbol-based %s failed (%d), trying addr\n",
			hook_candidates[i], ret);

		addr = kallsyms_lookup_name(hook_candidates[i]);
		if (!addr) {
			pr_info("hide_dd: kallsyms_lookup_name(%s) = 0\n",
				hook_candidates[i]);
			continue;
		}

		hide_krp.kp.symbol_name = NULL;
		hide_krp.kp.addr = (kprobe_opcode_t *)addr;

		ret = register_kretprobe(&hide_krp);
		if (ret == 0) {
			pr_info("hide_dd: kretprobe registered on %s @ 0x%lx\n",
				hook_candidates[i], addr);
			return 0;
		}

		pr_info("hide_dd: addr-based %s failed (%d)\n",
			hook_candidates[i], ret);
	}

	return -ENOENT;
}

static int __init hide_dd_init(void)
{
	int ret = hide_dd_register();

	if (ret < 0) {
		pr_err("hide_dd: all hook candidates failed: %d\n", ret);
		return ret;
	}

	pr_info("hide_dd: loaded (uid %d..%d)\n", APP_UID_MIN, APP_UID_MAX);
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
MODULE_DESCRIPTION("Hide /data/data/<other_uid> from app processes (RKP-safe)");
MODULE_AUTHOR("Sliva4");
MODULE_VERSION("1.1-debug");