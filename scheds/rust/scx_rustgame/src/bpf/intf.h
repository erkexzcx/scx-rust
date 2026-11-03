#ifndef __INTF_H
#define __INTF_H

#include <limits.h>

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define CLAMP(val, lo, hi) MIN(MAX(val, lo), hi)

enum consts {
	NSEC_PER_USEC = 1000ULL,
	NSEC_PER_MSEC = (1000ULL * NSEC_PER_USEC),
	NSEC_PER_SEC = (1000ULL * NSEC_PER_MSEC),

	MAX_CPUS = 1024,
	MAX_PROCS = 64,
};

/*
 * What a process is to the scheduler, as found by user space.
 */
enum proc_kind {
	PROC_GAME = 1,
	PROC_HELPER = 2,
};

/*
 * Task classes, ordered by priority. A task may preempt a CPU running a
 * task of a lower class.
 */
enum task_class {
	CLS_NONE = 0,	/* idle CPU, or no class yet */
	CLS_NORMAL,	/* everything outside the game */
	CLS_GAME_BG,	/* game threads off the frame path */
	CLS_JOB,	/* Unity job workers */
	CLS_HELPER,	/* kernel threads, compositor, X server, wineserver, audio */
	CLS_CRIT,	/* game main, render and DXVK submission threads */
	CLS_MAX,
};

#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;

typedef int pid_t;
#endif /* __VMLINUX_H__ */

struct quiet_arg {
	s32 cpu;
	s32 quiet;
};

#endif /* __INTF_H */
