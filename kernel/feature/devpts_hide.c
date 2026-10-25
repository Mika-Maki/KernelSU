#include "devpts_hide.h"

#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/magic.h>
#include <linux/stat.h>

#include "klog.h" // IWYU pragma: keep

/*
 * Duck Detector 会遍历 /dev/pts，用 stat 看 owner uid，发现 0 就判
 * "Found ROOT PTY"。root 进程（su/ksud 起的 shell）打开 /dev/ptmx 时
 * devpts_pty_new() 会把 i_uid 设成 current_fsuid()==0。
 *
 * 这里不改真实属主（避免动到 tty 的权限语义），只在“视图”层改：
 * kretprobe generic_fillattr（newfstatat / statx / fstat 最终都走它），
 * 对 non-root 调用者把 devpts 字符设备节点填出去的 uid/gid 伪装成 2000。
 * 真实 inode、权限、SELinux 标签、root shell 行为一律不变。
 */
#define KSU_FAKE_PTY_UID 2000

#ifdef CONFIG_KRETPROBES
struct devpts_fillattr_data {
	struct kstat *stat;
	struct inode *inode;
};

static struct kretprobe devpts_fillattr_rp;

static int devpts_fillattr_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct devpts_fillattr_data *data = (struct devpts_fillattr_data *)ri->data;
	data->inode = (struct inode *)PT_REGS_PARM1(regs);
	data->stat = (struct kstat *)PT_REGS_PARM2(regs);
	return 0;
}

static int devpts_fillattr_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct devpts_fillattr_data *data = (struct devpts_fillattr_data *)ri->data;
	struct inode *inode = data->inode;
	struct kstat *stat = data->stat;

	if (!inode || !stat)
		return 0;
	if (current_uid().val < 10000)
		return 0;
	if (!inode->i_sb || inode->i_sb->s_magic != DEVPTS_SUPER_MAGIC)
		return 0;
	if (inode->i_uid.val != 0)
		return 0;

	stat->uid = KUIDT_INIT(KSU_FAKE_PTY_UID);
	stat->gid = KGIDT_INIT(KSU_FAKE_PTY_UID);
	return 0;
}
#endif

void ksu_devpts_hide_init(void)
{
#ifdef CONFIG_KRETPROBES
	int ret;

	devpts_fillattr_rp.kp.symbol_name = "generic_fillattr";
	devpts_fillattr_rp.entry_handler = devpts_fillattr_entry_handler;
	devpts_fillattr_rp.handler = devpts_fillattr_ret_handler;
	devpts_fillattr_rp.data_size = sizeof(struct devpts_fillattr_data);
	devpts_fillattr_rp.maxactive = 0;

	ret = register_kretprobe(&devpts_fillattr_rp);
	if (ret)
		pr_warn("devpts_hide: register_kretprobe(generic_fillattr) failed: %d\n", ret);
	else
		pr_info("devpts_hide: armed on generic_fillattr\n");
#endif
}

void ksu_devpts_hide_exit(void)
{
#ifdef CONFIG_KRETPROBES
	unregister_kretprobe(&devpts_fillattr_rp);
#endif
}
