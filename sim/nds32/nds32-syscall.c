/* Simulator for NDS32 processors.

   Copyright (C) 2011-2013 Free Software Foundation, Inc.
   Contributed by Andes Technology Corporation.

   This file is part of simulators.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "config.h"

#include <errno.h>

#include "gdb/callback.h"
#include "targ-vals.h"

#if defined (__linux__) || defined (__CYGWIN__)
#include <sys/time.h>
#include <sys/times.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#elif defined (__WIN32__)
#include "mingw32-hdep.h"
#endif
#include <unistd.h>
#include <fcntl.h>

#include "nds32-sim.h"
#include "nds32-mm.h"
#include "nds32-syscall.h"

#if 0
  /* More standard syscalls.  */
  {CB_SYS_lstat,	19},
  {CB_SYS_truncate,	21},
  {CB_SYS_ftruncate,	22},
  {CB_SYS_pipe,		23},
#endif

CB_TARGET_DEFS_MAP cb_nds32_libgloss_syscall_map[] =
{
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

  {-1, -1}
};

CB_TARGET_DEFS_MAP cb_nds32_linux_syscall_map[] =
{
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
  {CB_SYS_lseek,	LINUX_SYS_BASE + 19},
  {CB_SYS_getpid,	LINUX_SYS_BASE + 20},
  {CB_SYS_utime,	LINUX_SYS_BASE + 30},
  {CB_SYS_access,	LINUX_SYS_BASE + 33},
  {CB_SYS_rename,	LINUX_SYS_BASE + 38},
  {CB_SYS_times,	LINUX_SYS_BASE + 43},
  {CB_SYS_brk,		LINUX_SYS_BASE + 45},
  {CB_SYS_ioctl,	LINUX_SYS_BASE + 54},
  {CB_SYS_gettimeofday,	LINUX_SYS_BASE + 78},
  /* {CB_SYS_settimeofday,	LINUX_SYS_BASE + 79}, */
  {CB_SYS_mmap,		LINUX_SYS_BASE + 90},
  {CB_SYS_munmap,	LINUX_SYS_BASE + 91},
  {CB_SYS_stat,		LINUX_SYS_BASE + 106},
  {CB_SYS_lstat,	LINUX_SYS_BASE + 107},
  {CB_SYS_fstat,	LINUX_SYS_BASE + 108},
  {CB_SYS_uname,	LINUX_SYS_BASE + 122},
  {CB_SYS_mprotect,	LINUX_SYS_BASE + 125},
  {CB_SYS_llseek,	LINUX_SYS_BASE + 140},
  {CB_SYS_readv,	LINUX_SYS_BASE + 145},
  {CB_SYS_writev,	LINUX_SYS_BASE + 146},
  {CB_SYS_getpagesize,	LINUX_SYS_BASE + 166},
  {CB_SYS_ugetrlimit,	LINUX_SYS_BASE + 191},
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
  {CB_SYS_fcntl64,	LINUX_SYS_BASE + 221},

  {-1, -1}
};

/* Check
	linux: arch/nds32/include/asm/stat.h
	newlib: libc/include/sys/stat.h
   for details.  */
static const char cb_linux_stat_map_32[] =
"st_dev,2:space,2:st_ino,4:st_mode,2:st_nlink,2:st_uid,2:st_gid,2:st_rdev,2:space,2:"
"st_size,4:st_blksize,4:st_blocks,4:st_atime,4:st_atimensec,4:"
"st_mtime,4:st_mtimensec,4:st_ctime,4:st_ctimensec,4:space,4:space,4";

static const char cb_linux_stat_map_64[] =
"st_dev,8:space,4:__st_ino,4:st_mode,4:st_nlink,4:st_uid,4:st_gid,4:st_rdev,8:"
"space,8:st_size,8:st_blksize,4:space,4:st_blocks,8:st_atime,4:st_atimensec,4:"
"st_mtime,4:st_mtimensec,4:st_ctime,4:st_ctimensec,4:st_ino,8";

static const char cb_libgloss_stat_map_32[] =
"st_dev,2:st_ino,2:st_mode,4:st_nlink,2:st_uid,2:st_gid,2:st_rdev,2:"
"st_size,4:st_atime,4:space,4:st_mtime,4:space,4:st_ctime,4:space,4:"
"st_blksize,4:st_blocks,4:space,8";

/* Utility of cb_syscall to fetch a path name.
   The buffer is malloc'd and the address is stored in BUFP.
   The result is that of get_string, but prepended with
   simulator_sysroot if the string starts with '/'.
   If an error occurs, no buffer is left malloc'd.  */

/* This code is copied from comm/syscall.c, because it's a static
   function. */

static int
get_path (host_callback *cb, CB_SYSCALL *sc, uint32_t addr, char **bufp)
{
#define MAX_PATH_LEN	1024
  char *buf = xmalloc (MAX_PATH_LEN);
  int result;
  int sysroot_len = strlen (simulator_sysroot);

  result = cb_get_string (cb, sc, buf, MAX_PATH_LEN - sysroot_len, addr);
  if (result == 0)
    {
      /* Prepend absolute paths with simulator_sysroot.  Relative paths
	 are supposed to be relative to a chdir within that path, but at
	 this point unknown where.  */
      if (simulator_sysroot[0] != '\0' && *buf == '/')
	{
	  /* Considering expected rareness of syscalls with absolute
	     file paths (compared to relative file paths and instruction
	     execution), it does not seem worthwhile to rearrange things
	     to get rid of the string moves here; we'd need at least an
	     extra call to check the initial '/' in the path.  */
	  memmove (buf + sysroot_len, buf, sysroot_len);
	  memcpy (buf, simulator_sysroot, sysroot_len);
	}

      *bufp = buf;
    }
  else
    free (buf);
  return result;
}

/* Read/write functions for system call interface.  */

static int
syscall_read_mem (host_callback *cb, struct cb_syscall *sc,
		  unsigned long taddr, char *buf, int bytes)
{
  SIM_DESC sd = (SIM_DESC) sc->p1;
  SIM_CPU *cpu = (SIM_CPU *) sc->p2;

  return sim_core_read_buffer (sd, cpu, read_map, buf, taddr, bytes);
}

static int
syscall_write_mem (host_callback *cb, struct cb_syscall *sc,
		  unsigned long taddr, const char *buf, int bytes)
{
  SIM_DESC sd = (SIM_DESC) sc->p1;
  SIM_CPU *cpu = (SIM_CPU *) sc->p2;

  return sim_core_write_buffer (sd, cpu, write_map, buf, taddr, bytes);
}

void
nds32_syscall (sim_cpu *cpu, int swid, sim_cia cia)
{
  SIM_DESC sd = CPU_STATE (cpu);
  host_callback *cb = STATE_CALLBACK (sd);
  CB_SYSCALL sc;
  int cbid;

  CB_SYSCALL_INIT (&sc);

  sc.func = swid;
  sc.arg1 = CCPU_GPR[0].s;
  sc.arg2 = CCPU_GPR[1].s;
  sc.arg3 = CCPU_GPR[2].s;
  sc.arg4 = CCPU_GPR[3].s;

  sc.p1 = (PTR) sd;
  sc.p2 = (PTR) cpu;
  sc.result = -1;
  sc.errcode = 0;
  sc.read_mem = syscall_read_mem;
  sc.write_mem = syscall_write_mem;

  /* switch (swid) */
  switch (cbid = cb_target_to_host_syscall (cb, sc.func))
    {
    default:
      cb_syscall (cb, &sc);
      if (sc.result == -1 && sc.errcode == TARGET_ENOSYS)
	{
	  nds32_bad_op (cpu, cia, swid, "syscall");
	  return;
	}
      break;

    /*
     * System calls used by libgloss and Linux.
     */

    case CB_SYS_exit_group:
    case CB_SYS_exit:
      sim_engine_halt (CPU_STATE (cpu), cpu, NULL, cia,
		       sim_exited, CCPU_GPR[0].s);
      break;

    case CB_SYS_llseek:
      {
	unsigned int fd = CCPU_GPR[0].u;
	unsigned long offhi = CCPU_GPR[1].u;
	unsigned long offlo = CCPU_GPR[2].u;
	unsigned int whence = CCPU_GPR[4].u;
	loff_t roff;

	sc.func = swid;
	sc.arg1 = fd;
	sc.arg2 = offlo;
	sc.arg3 = whence;

	SIM_ASSERT (offhi == 0);

	sc.func = TARGET_LINUX_SYS_lseek;
	cb_syscall (cb, &sc);
	roff = sc.result;

	/* Copy the result only if user really passes other then NULL.  */
	if (sc.result != -1 && CCPU_GPR[3].u)
	  sim_write (sd, CCPU_GPR[3].u, (const unsigned char *) &roff,
		     sizeof (loff_t));
      }

    case CB_SYS_getpid:
      sc.result = getpid ();
      break;

    case CB_SYS_stat:
    case CB_SYS_lstat:
    case CB_SYS_fstat:
      if (STATE_ENVIRONMENT (sd) == USER_ENVIRONMENT)
	cb->stat_map = cb_linux_stat_map_32;
      else
	cb->stat_map = cb_libgloss_stat_map_32;
      cb_syscall (cb, &sc);
      break;

    case CB_SYS_stat64:
      cb->stat_map = cb_linux_stat_map_64;
      sc.func = TARGET_LINUX_SYS_stat;
      cb_syscall (cb, &sc);
      break;
    case CB_SYS_lstat64:
      cb->stat_map = cb_linux_stat_map_64;
      sc.func = TARGET_LINUX_SYS_lstat;
      cb_syscall (cb, &sc);
      break;
    case CB_SYS_fstat64:
      cb->stat_map = cb_linux_stat_map_64;
      sc.func = TARGET_LINUX_SYS_fstat;
      cb_syscall (cb, &sc);
      break;

    case CB_SYS_gettimeofday:
      {
	struct timeval t;
	struct timezone tz;

	sc.result = gettimeofday (&t, &tz);
	if (CCPU_GPR[0].u)
	  sim_write (sd, CCPU_GPR[0].u, (const unsigned char *) &t,
		     sizeof (t));
	if (CCPU_GPR[1].u)
	  sim_write (sd, CCPU_GPR[1].u, (const unsigned char *) &t,
		     sizeof (tz));
      }
      break;

    /* glibc will try to use this, but we should reject it,
       so getrlimit will be used instread.  */
    case CB_SYS_ugetrlimit:
      sc.result = -1;
      sc.errcode = TARGET_ENOSYS;
      break;

    /*
     * System calls used by Linux only.
     */

    case CB_SYS_brk:
      sc.result = nds32_sys_brk (cpu, CCPU_GPR[0].u);
      break;

    case CB_SYS_ioctl:
      sc.result = ioctl (CCPU_GPR[0].s, CCPU_GPR[1].s, CCPU_GPR[2].s);
      break;

    case CB_SYS_fcntl64:
      sc.result = fcntl (CCPU_GPR[0].s, CCPU_GPR[1].s, CCPU_GPR[2].s);
      break;

    case CB_SYS_times:
      {
	struct tms tms;

	sc.result = times (&tms);
	if (CCPU_GPR[0].u)
	  sim_write (sd, CCPU_GPR[0].u, (const unsigned char *) &tms,
		     sizeof (tms));
      }
      break;

    case CB_SYS_access:
      {
	char *path;

	get_path (cb, &sc, CCPU_GPR[0].u, &path);
	sc.result = access (path, CCPU_GPR[1].u);
	free (path);
      }
      break;

    case CB_SYS_link:
      {
	char *oldpath;
	char *newpath;

	get_path (cb, &sc, CCPU_GPR[0].u, &oldpath);
	get_path (cb, &sc, CCPU_GPR[1].u, &newpath);

	sc.result = link (oldpath, newpath);

	free (oldpath);
	free (newpath);
      }
      break;

    case CB_SYS_uname:
      {
	struct utsname buf;

	if ((sc.result = uname (&buf)) == 0 && CCPU_GPR[0].u)
	  sim_write (sd, CCPU_GPR[0].u, (const unsigned char *) &buf,
		     sizeof (buf));
      }
      break;

    case CB_SYS_getpagesize:
      sc.result = PAGE_SIZE;
      break;

    case CB_SYS_getuid32:
      sc.result = getuid ();
      break;

    case CB_SYS_getgid32:
      sc.result = getgid ();
      break;

    case CB_SYS_geteuid32:
      sc.result = geteuid ();
      break;

    case CB_SYS_getegid32:
      sc.result = getegid ();
      break;

    case CB_SYS_setuid32:
      sc.result = setuid (CCPU_GPR[0].u);
      break;

    case CB_SYS_setgid32:
      sc.result = setgid (CCPU_GPR[0].u);
      break;

    /* case CB_SYS_readv: */
    case CB_SYS_writev:
      {
	/* ssize_t writev(int fd, const struct iovec *iov, int iovcnt); */
	uint32_t iov_base = 0, iov_len = 0;
	int fd = CCPU_GPR[0].u;
	int piov = CCPU_GPR[1].u;
	int iovcnt = CCPU_GPR[2].u;
	int i;
	int ret = 0;

	if (fd < 0 || fd > MAX_CALLBACK_FDS || cb->fd_buddy[fd] < 0)
	  {
	    sc.result = -1;
	    sc.errcode = TARGET_EBADF;
	    break;
	  }
	fd = cb->fdmap[fd];

	/* I'm not sure whether use write () to implement wrivev ()
	   is better or not.  */
	for (i = 0; i < iovcnt; i++)
	  {
	    /* Read the iov struct from target.  */
	    sim_read (sd, piov + i * 8 /* sizeof (struct iovec) */,
		      (unsigned char *) &iov_base, 4);
	    sim_read (sd, piov + i * 8 + 4,
		      (unsigned char *) &iov_len, 4);

	    sc.func = TARGET_LINUX_SYS_write;
	    sc.arg1 = fd;
	    sc.arg2 = iov_base;
	    sc.arg3 = iov_len;
	    cb_syscall (cb, &sc);

	    ret += sc.result;
	    if (sc.result < 0)	/* on error */
	      goto out;
	    else if (sc.result != iov_len) /* fail to write whole buffer */
	      break;
	  }
	sc.result = ret;
      }
      break;

    case CB_SYS_mmap2:
      {
	uint32_t addr = CCPU_GPR[0].u;
	size_t len = CCPU_GPR[1].s;
	int prot = CCPU_GPR[2].s;
	int flags = CCPU_GPR[3].s;
	int fd = CCPU_GPR[4].s;
	off_t pgoffset = CCPU_GPR[5].u;

       /* void *mmap2 (void *addr, size_t length, int prot,
		       int flags, int fd, off_t pgoffset);  */
	sc.result = (long) nds32_mmap (cpu, addr, len, prot, flags, fd,
				       pgoffset * PAGE_SIZE);
      }
      break;
    case CB_SYS_munmap:
      {
	uint32_t addr = CCPU_GPR[0].u;
	size_t len = CCPU_GPR[1].s;

	sc.result = nds32_munmap (cpu, addr, len);
      }
      break;

    case CB_SYS_setrlimit:
      {
	struct rlimit rlim;

	/* int setrlimit(int resource, const struct rlimit *rlim); */
	sim_read (sd, CCPU_GPR[1].u, (unsigned char *) &rlim, sizeof (rlim));
	sc.result = setrlimit (CCPU_GPR[0].s, &rlim);
      }
      break;

    case CB_SYS_getrlimit:
      {
	struct rlimit rlim;

	/* int getrlimit(int resource, struct rlimit *rlim); */
	sc.result = getrlimit (CCPU_GPR[0].s, &rlim);
	if (sc.result >= 0)
	  sim_write (sd, CCPU_GPR[1].u, (const unsigned char *) &rlim,
		     sizeof (rlim));
      }
      break;

    case CB_SYS_mprotect:
      sc.result = 0; /* Just do nothing now. */
      break;

    case CB_SYS_NDS32_isatty:
      sc.result = sim_io_isatty (sd, CCPU_GPR[0].s);
      if (sc.result == -1)
	sc.result = 0; /* -1 is returned if EBADF, but caller wants 0. */
      break;

    case CB_SYS_NDS32_getcmdline:
      sc.result = CCPU_GPR[0].u;
      sim_write (sd, CCPU_GPR[0].u, (unsigned char*)sd->cmdline,
		 strlen (sd->cmdline) + 1);
      break;

    /* This is used by libgloss only.  */
    case CB_SYS_NDS32_errno:
      sc.result = sim_io_get_errno (sd);
      break;
    }

out:
  if (sc.result < 0)
    {
      /* cb_syscall should set this value.
	 Otherwise, the syscall is not handled by it.  */
      if (sc.errcode == 0)
	sc.errcode = errno;
      CCPU_GPR[0].s = -sc.errcode;
    }
  else
    CCPU_GPR[0].s = sc.result;
  return;
}
