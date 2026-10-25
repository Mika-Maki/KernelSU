#ifndef __KSU_H_DEVPTS_HIDE
#define __KSU_H_DEVPTS_HIDE

#include <asm/ptrace.h>

bool ksu_devpts_path_match(const struct pt_regs *regs);
void ksu_devpts_fix_stat(int orig_nr, const struct pt_regs *regs);

void ksu_devpts_hide_init(void);
void ksu_devpts_hide_exit(void);

#endif
