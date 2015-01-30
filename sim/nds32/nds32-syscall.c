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

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_TIMES_H
#include <sys/times.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#include <unistd.h>
#include <fcntl.h>

#include "nds32-sim.h"
#include "nds32-syscall.h"

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

/* Check
	newlib: libc/include/sys/stat.h
   for details.  */
static const char cb_libgloss_stat_map_32[] =
"st_dev,2:st_ino,2:st_mode,4:st_nlink,2:st_uid,2:st_gid,2:st_rdev,2:"
"st_size,4:st_atime,4:space,4:st_mtime,4:space,4:st_ctime,4:space,4:"
"st_blksize,4:st_blocks,4:space,8";

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

  /* TODO: Handling big endian.  */

  /* switch (swid) */
  switch (cbid = cb_target_to_host_syscall (cb, sc.func))
    {
    default:
      cb_syscall (cb, &sc);
      if (sc.result == -1 && sc.errcode == ENOSYS)
	{
	  nds32_bad_op (cpu, cia, swid, "syscall");
	  return;
	}
      break;

    /*
     * System calls used by libgloss.
     */

    case CB_SYS_exit:
      sim_engine_halt (CPU_STATE (cpu), cpu, NULL, cia,
		       sim_exited, CCPU_GPR[0].s);
      break;

    case CB_SYS_getpid:
      sc.result = getpid ();
      break;

    case CB_SYS_stat:
    case CB_SYS_fstat:
      cb->stat_map = cb_libgloss_stat_map_32;
      cb_syscall (cb, &sc);
      break;

#ifdef HAVE_GETTIMEOFDAY
    case CB_SYS_gettimeofday:
      {
	struct timeval tv;
	struct timezone tz;
	struct {
	  signed_word tv_sec;
	  signed_word tv_usec;
	} target_tv;
	struct {
	  signed_4 tz_minuteswest;
	  signed_4 tz_dsttime;
	} target_tz;

	sc.result = gettimeofday (&tv, &tz);

	target_tv.tv_sec = H2T_word (tv.tv_sec);
	target_tv.tv_usec = H2T_word (tv.tv_usec);
	target_tz.tz_minuteswest = H2T_4 (tz.tz_minuteswest);
	target_tz.tz_dsttime = H2T_4 (tz.tz_dsttime);

	if (CCPU_GPR[0].u)
	  sim_write (sd, CCPU_GPR[0].u, (const unsigned char *) &target_tv,
		     sizeof (target_tv));
	if (CCPU_GPR[1].u)
	  sim_write (sd, CCPU_GPR[1].u, (const unsigned char *) &target_tz,
		     sizeof (target_tz));
      }
      break;
#endif
    /* This a nds32 libgloss only system calls.  */

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

      /* Our libgloss implementation uses SYS_NDS32_errno for `errno'.
	 Syscalls per se only return -1 when fail.  */
      CCPU_GPR[0].s = -1;
    }
  else
    CCPU_GPR[0].s = sc.result;
  return;
}
