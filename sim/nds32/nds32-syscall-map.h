#include "gdb/callback.h"

/* Check
	   gdb: include/gdb/callback.h
	kernel: arch/nds32/include/asm/unistd.h
	newlib: libgloss/nds32/syscall.h
   for details.  */

#define CB_SYS_BASE		0x1000
#define CB_SYS_link		(CB_SYS_BASE + 9)
#define CB_SYS_access		(CB_SYS_BASE + 33)
#define CB_SYS_times		(CB_SYS_BASE + 43)
#define CB_SYS_brk		(CB_SYS_BASE + 45)
#define CB_SYS_gettimeofday	(CB_SYS_BASE + 78)
#define CB_SYS_settimeofday	(CB_SYS_BASE + 79)
#define CB_SYS_mmap		(CB_SYS_BASE + 90)
#define CB_SYS_munmap		(CB_SYS_BASE + 91)
#define CB_SYS_uname		(CB_SYS_BASE + 122)
#define CB_SYS_mprotect		(CB_SYS_BASE + 125)
#define CB_SYS_llseek		(CB_SYS_BASE + 140)
#define CB_SYS_readv		(CB_SYS_BASE + 145)
#define CB_SYS_writev		(CB_SYS_BASE + 146)
#define CB_SYS_getpagesize	(CB_SYS_BASE + 166)
#define CB_SYS_sigaction	(CB_SYS_BASE + 174)
#define CB_SYS_mmap2		(CB_SYS_BASE + 192)
#define CB_SYS_stat64		(CB_SYS_BASE + 195)
#define CB_SYS_lstat64		(CB_SYS_BASE + 196)
#define CB_SYS_fstat64		(CB_SYS_BASE + 197)
#define CB_SYS_getuid32		(CB_SYS_BASE + 199)
#define CB_SYS_getgid32		(CB_SYS_BASE + 200)
#define CB_SYS_geteuid32	(CB_SYS_BASE + 201)
#define CB_SYS_getegid32	(CB_SYS_BASE + 202)
#define CB_SYS_setuid32		(CB_SYS_BASE + 213)
#define CB_SYS_setgid32		(CB_SYS_BASE + 214)
#define CB_SYS_exit_group	(CB_SYS_BASE + 248)

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

#define LINUX_SYS_BASE		0x5000

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
  {CB_SYS_fstat,	10},

  /* ARGV support.  */
  {CB_SYS_argvlen,	12},
  {CB_SYS_argv,		13},

  /* These are extras added for one reason or another.  */
  {CB_SYS_chdir,	14},
  {CB_SYS_stat,		15},
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
  {CB_SYS_exit,		LINUX_SYS_BASE + 1},
  {CB_SYS_read,		LINUX_SYS_BASE + 3},
  {CB_SYS_write,	LINUX_SYS_BASE + 4},
  {CB_SYS_open,		LINUX_SYS_BASE + 5},
  {CB_SYS_close,	LINUX_SYS_BASE + 6},
  {CB_SYS_link,		LINUX_SYS_BASE + 9},
  {CB_SYS_unlink,	LINUX_SYS_BASE + 10},
  {CB_SYS_chdir,	LINUX_SYS_BASE + 12},
  {CB_SYS_time,		LINUX_SYS_BASE + 13},
  {CB_SYS_chmod,	LINUX_SYS_BASE + 15},
#define TARGET_LINUX_SYS_lseek	(LINUX_SYS_BASE + 19)
  {CB_SYS_lseek,	LINUX_SYS_BASE + 19},
  {CB_SYS_getpid,	LINUX_SYS_BASE + 20},
  {CB_SYS_utime,	LINUX_SYS_BASE + 30},
  {CB_SYS_access,	LINUX_SYS_BASE + 33},
  {CB_SYS_rename,	LINUX_SYS_BASE + 38},
  {CB_SYS_times,	LINUX_SYS_BASE + 43},
  {CB_SYS_brk,		LINUX_SYS_BASE + 45},
  {CB_SYS_gettimeofday,	LINUX_SYS_BASE + 78},
  /* {CB_SYS_settimeofday,	LINUX_SYS_BASE + 79}, */
  {CB_SYS_mmap,		LINUX_SYS_BASE + 90},
  {CB_SYS_munmap,	LINUX_SYS_BASE + 91},
#define TARGET_LINUX_SYS_stat	(LINUX_SYS_BASE + 106)
#define TARGET_LINUX_SYS_lstat	(LINUX_SYS_BASE + 107)
#define TARGET_LINUX_SYS_fstat	(LINUX_SYS_BASE + 108)
  {CB_SYS_stat,		LINUX_SYS_BASE + 106},
  {CB_SYS_lstat,	LINUX_SYS_BASE + 107},
  {CB_SYS_fstat,	LINUX_SYS_BASE + 108},
  {CB_SYS_uname,	LINUX_SYS_BASE + 122},
  {CB_SYS_mprotect,	LINUX_SYS_BASE + 125},
  {CB_SYS_llseek,	LINUX_SYS_BASE + 140},
  {CB_SYS_readv,	LINUX_SYS_BASE + 145},
  {CB_SYS_writev,	LINUX_SYS_BASE + 146},
  {CB_SYS_getpagesize,	LINUX_SYS_BASE + 166},
  {CB_SYS_mmap2,	LINUX_SYS_BASE + 192},
  {CB_SYS_stat64,	LINUX_SYS_BASE + 195},
  {CB_SYS_lstat64,	LINUX_SYS_BASE + 196},
  {CB_SYS_fstat64,	LINUX_SYS_BASE + 197},
  {CB_SYS_getuid32,	LINUX_SYS_BASE + 199},
  {CB_SYS_getgid32,	LINUX_SYS_BASE + 200},
  {CB_SYS_geteuid32,	LINUX_SYS_BASE + 201},
  {CB_SYS_getegid32,	LINUX_SYS_BASE + 202},
  {CB_SYS_setuid32,	LINUX_SYS_BASE + 213},
  {CB_SYS_setgid32,	LINUX_SYS_BASE + 214},
  {CB_SYS_exit_group,	LINUX_SYS_BASE + 248},

  {-1, -1}
};
