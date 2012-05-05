#include "gdb/callback.h"

/* Check
	   gdb: include/gdb/callback.h
	kernel: arch/nds32/include/asm/unistd.h
	newlib: libgloss/nds32/syscall.h
   for details.  */

#define CB_SYS_BASE		0x1000
#define CB_SYS_link		(CB_SYS_BASE + 9)
#define CB_SYS_times		(CB_SYS_BASE + 43)
#define CB_SYS_brk		(CB_SYS_BASE + 45)
#define CB_SYS_gettimeofday	(CB_SYS_BASE + 78)
#define CB_SYS_uname		(CB_SYS_BASE + 122)
#define CB_SYS_getpagesize	(CB_SYS_BASE + 166)
#define CB_SYS_fstat64		(CB_SYS_BASE + 197)
#define CB_SYS_getuid32		(CB_SYS_BASE + 199)
#define CB_SYS_getgid32		(CB_SYS_BASE + 200)
#define CB_SYS_geteuid32	(CB_SYS_BASE + 201)
#define CB_SYS_getegid32	(CB_SYS_BASE + 202)

#define CB_SYS_LG_fstat		(CB_SYS_BASE + 0x200)
#define CB_SYS_LG_stat		(CB_SYS_BASE + 0x201)
#define CB_SYS_NDS32_isatty	(CB_SYS_BASE + 0x202)
#define CB_SYS_NDS32_errno	(CB_SYS_BASE + 0x203)
#define CB_SYS_NDS32_getcmdline	(CB_SYS_BASE + 0x204)

#if 0
  /* More standard syscalls.  */
  {CB_SYS_lstat,	19},
  {CB_SYS_truncate,	21},
  {CB_SYS_ftruncate,	22},
  {CB_SYS_pipe,		23},
#endif

static CB_TARGET_DEFS_MAP cb_nds32_syscall_map[] =
{
  /*
   * libgloss syscall.
   */

   /* These are used by the ANSI C support of libc.  */
  {CB_SYS_exit,		1},
  {CB_SYS_open,		2},
  {CB_SYS_close,	3},
  {CB_SYS_read,		4},
  {CB_SYS_write,	5},
  {CB_SYS_lseek,	6},
  {CB_SYS_unlink,	7},
  {CB_SYS_getpid,	8},
  {CB_SYS_kill,		9},
  {CB_SYS_LG_fstat,	10},

  /* ARGV support.  */
  {CB_SYS_argvlen,	12},
  {CB_SYS_argv,		13},

  /* These are extras added for one reason or another.  */
  {CB_SYS_chdir,	14},
  {CB_SYS_LG_stat,	15},
  {CB_SYS_chmod,	16},
  {CB_SYS_utime,	17},
  {CB_SYS_time,		18},

  {CB_SYS_gettimeofday,	19},
  {CB_SYS_times,	20},
  {CB_SYS_link,		21},
  /* SYS_argc		= 172, */
  /* SYS_argnlen	= 173, */
  /* SYS_argn		= 174, */
  /* RedBoot. */
  {CB_SYS_rename,	3001},
  {CB_SYS_NDS32_isatty,	3002},
  /* SYS_system		= 3003, */

  /* NDS32 specific */
  {CB_SYS_NDS32_errno,	6001},
  {CB_SYS_NDS32_getcmdline, 6002},

  /*
   * Linux syscall.
   */
  {CB_SYS_exit,		0x5001},
  {CB_SYS_read,		0x5003},
  {CB_SYS_write,	0x5004},
  {CB_SYS_open,		0x5005},
  {CB_SYS_close,	0x5006},
  {CB_SYS_brk,		0x502d},
  {CB_SYS_uname,	0x507a},
  {CB_SYS_getpagesize,	0x50a6},
  {CB_SYS_fstat64,	0x50c5},
  {CB_SYS_getuid32,	0x50c7},
  {CB_SYS_getgid32,	0x50c8},
  {CB_SYS_geteuid32,	0x50c9},
  {CB_SYS_getegid32,	0x50ca},

  {-1, -1}
};
