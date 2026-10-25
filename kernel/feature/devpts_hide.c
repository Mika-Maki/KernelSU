#include "devpts_hide.h"

#include <asm/unistd.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "arch.h"
#include "klog.h" // IWYU pragma: keep

/*
 * Duck Detector 会 stat /dev/pts 下的 pty 节点看 owner uid，root 创建的 pty
 * owner 是 0 就判 Found ROOT PTY。这里不改真实属主，只在 sys_enter tracepoint
 * 重定向到派发器之后，把回填给用户态的 stat/statx 里的 uid/gid 改成 2000。
 * 路径不是 /dev/pts/ 的调用在 tracepoint 层直接放行，不产生额外时延。
 */
#define KSU_FAKE_PTY_UID 2000

/* struct stat (arm64, asm-generic): st_uid @24, st_gid @28 */
#define STAT_UID_OFF 24
#define STAT_GID_OFF 28
/* struct statx (uapi): stx_uid @20, stx_gid @24 */
#define STATX_UID_OFF 20
#define STATX_GID_OFF 24

bool ksu_devpts_path_match(const struct pt_regs *regs)
{
    const char __user *fn = (const char __user *)PT_REGS_PARM2(regs);
    char path[16];

    if (!fn)
        return false;
    if (strncpy_from_user_nofault(path, fn, sizeof(path) - 1) <= 0)
        return false;
    path[sizeof(path) - 1] = 0;

    if (!strncmp(path, "/dev/pts/", 9)) {
        pr_info_ratelimited("devpts_hide: match pid=%d path=%s\n", current->pid, path);
        return true;
    }

    return false;
}

static void patch_uid_gid(void __user *buf, int uid_off, int gid_off)
{
    u32 uid, gid;

    if (get_user(uid, (u32 __user *)((char __user *)buf + uid_off)))
        return;
    if (uid != 0)
        return;
    uid = KSU_FAKE_PTY_UID;
    gid = KSU_FAKE_PTY_UID;
    put_user(uid, (u32 __user *)((char __user *)buf + uid_off));
    put_user(gid, (u32 __user *)((char __user *)buf + gid_off));
}

void ksu_devpts_fix_stat(int orig_nr, const struct pt_regs *regs)
{
    if (current_uid().val < 10000)
        return;

    pr_info_ratelimited("devpts_hide: fix_stat nr=%d uid=%d pid=%d\n", orig_nr, current_uid().val, current->pid);

    if (orig_nr == __NR_newfstatat) {
        patch_uid_gid((void __user *)PT_REGS_PARM3(regs), STAT_UID_OFF, STAT_GID_OFF);
    }
#ifdef __NR_statx
    else if (orig_nr == __NR_statx) {
        patch_uid_gid((void __user *)PT_REGS_PARM5(regs), STATX_UID_OFF, STATX_GID_OFF);
    }
#endif
}

void ksu_devpts_hide_init(void)
{
}
void ksu_devpts_hide_exit(void)
{
}
