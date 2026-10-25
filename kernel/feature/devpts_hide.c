#include "devpts_hide.h"

#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/namei.h>

#include "klog.h" // IWYU pragma: keep

/*
 * Duck Detector 之类的检测会遍历 /dev/pts，发现 owner uid == 0 的 pty 就判
 * "Found ROOT PTY"。root 进程（su/ksud 起 shell）打开 /dev/ptmx 时，
 * devpts_pty_new() 会把 i_uid 设成 current_fsuid()==0。
 *
 * 做法：kretprobe devpts_pty_new，在返回的 dentry 上把属主改成 2000(shell)，
 * 与 adb shell 创建的 pty 一致；再扫一遍已存在的节点处理模块加载前创建的。
 * 只改 uid==0 的，非 root 创建的 pty 不动。
 */
#define KSU_FAKE_PTY_UID 2000

#ifdef CONFIG_KRETPROBES
static struct kretprobe devpts_pty_new_rp;

static int devpts_pty_new_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct dentry *dentry = (struct dentry *)regs_return_value(regs);
	struct inode *inode;

	if (IS_ERR_OR_NULL(dentry))
		return 0;

	inode = d_inode(dentry);
	if (!inode)
		return 0;

	if (inode->i_uid.val == 0) {
		inode->i_uid = KUIDT_INIT(KSU_FAKE_PTY_UID);
		inode->i_gid = KGIDT_INIT(KSU_FAKE_PTY_UID);
	}
	return 0;
}
#endif

void ksu_devpts_hide_sweep(void)
{
	struct path path;
	struct dentry *root, *child;

	if (kern_path("/dev/pts", LOOKUP_DIRECTORY, &path))
		return;

	root = path.dentry;
	spin_lock(&root->d_lock);
	list_for_each_entry(child, &root->d_subdirs, d_child) {
		struct inode *inode = d_inode(child);
		if (!inode)
			continue;
		if (inode->i_uid.val == 0) {
			inode->i_uid = KUIDT_INIT(KSU_FAKE_PTY_UID);
			inode->i_gid = KGIDT_INIT(KSU_FAKE_PTY_UID);
		}
	}
	spin_unlock(&root->d_lock);
	path_put(&path);
	pr_info("devpts_hide: sweep done\n");
}

void ksu_devpts_hide_init(void)
{
#ifdef CONFIG_KRETPROBES
	int ret;

	devpts_pty_new_rp.kp.symbol_name = "devpts_pty_new";
	devpts_pty_new_rp.handler = devpts_pty_new_ret_handler;
	devpts_pty_new_rp.data_size = 0;
	devpts_pty_new_rp.maxactive = 0;

	ret = register_kretprobe(&devpts_pty_new_rp);
	if (ret)
		pr_warn("devpts_hide: register_kretprobe(devpts_pty_new) failed: %d\n", ret);
	else
		pr_info("devpts_hide: armed on devpts_pty_new\n");
#endif
}

void ksu_devpts_hide_exit(void)
{
#ifdef CONFIG_KRETPROBES
	unregister_kretprobe(&devpts_pty_new_rp);
#endif
}
