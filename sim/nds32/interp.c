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

#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "bfd.h"
#include "elf-bfd.h"
#include "gdb/callback.h"
#include "gdb/signals.h"
#include "libiberty.h"
#include "gdb/remote-sim.h"
#include "dis-asm.h"
#include "sim-main.h"
#include "nds32-sim.h"
#include "sim-utils.h"
#include "sim-fpu.h"
#include "sim-trace.h"
#include "targ-vals.h"

#include "opcode/nds32.h"
#include "nds32-sim.h"
#include "nds32-mm.h"
#include "nds32-syscall-map.h"

#ifdef __linux__
/* FIXME */
#include <sys/time.h>
#include <sys/times.h>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#elif defined (__WIN32__)
#include "mingw32-hdep.h"
#endif
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>

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

static ulongest_t
extract_unsigned_integer (unsigned char *addr, int len, int byte_order)
{
  ulongest_t retval;
  const unsigned char *p;
  const unsigned char *startaddr = addr;
  const unsigned char *endaddr = startaddr + len;

  retval = 0;
  if (byte_order == BIG_ENDIAN)
    {
      for (p = startaddr; p < endaddr; ++p)
	retval = (retval << 8) | *p;
    }
  else
    {
      for (p = endaddr - 1; p >= startaddr; --p)
	retval = (retval << 8) | *p;
    }
  return retval;
}

static void
store_unsigned_integer (unsigned char *addr, int len,
			int byte_order, ulongest_t val)
{
  unsigned char *p;
  unsigned char *startaddr = addr;
  unsigned char *endaddr = startaddr + len;

  /* Start at the least significant end of the integer,
     and work towards the most significant.  */
  if (byte_order == BIG_ENDIAN)
    {
      for (p = endaddr - 1; p >= startaddr; --p)
	{
	  *p = val & 0xff;
	  val >>= 8;
	}
    }
  else
    {
      for (p = startaddr; p < endaddr; ++p)
	{
	  *p = val & 0xff;
	  val >>= 8;
	}
    }
}

/* Utility of cb_syscall to fetch a path name.
   The buffer is malloc'd and the address is stored in BUFP.
   The result is that of get_string, but prepended with
   simulator_sysroot if the string starts with '/'.
   If an error occurs, no buffer is left malloc'd.

   This code is copied from comm/syscall.c,
   because it's a static function. */

static int
get_path (host_callback *cb, CB_SYSCALL *sc, uint32_t addr, char **bufp)
{
  const int max_path_len = 1024;
  char *buf = xmalloc (max_path_len);
  int result;
  int sysroot_len = strlen (simulator_sysroot);

  result = cb_get_string (cb, sc, buf, max_path_len - sysroot_len, addr);
  if (result == 0)
    {
      /* Prepend absolute paths with simulator_sysroot.  Relative paths
	 are supposed to be relative to a chdir within that path, but at
	 this point unknown where.  */
      if (simulator_sysroot[0] != '\0' && *buf == '/')
	{
	  /* Considering expected rareness of syscalls with absolute
	     file paths (compared to relative file paths and insn
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

enum nds32_exceptions
{
  EXP_RESET = 0,
  EXP_TLB_FILL = 1,
  EXP_NO_PTE = 2,
  EXP_TLB_MISC = 3,
  EXP_TLB_VLPT_MISS = 4,
  EXP_MACHINE_ERROR = 5,
  EXP_DEBUG = 6,
  EXP_GENERAL = 7,
  EXP_SYSCALL = 8,

  EXP_BADOP,
};

void
nds32_bad_op (sim_cpu *cpu, uint32_t cia, uint32_t insn, char *tag)
{
  if (tag == NULL)
    tag = "";

  sim_io_error (CPU_STATE (cpu),
		"Unhandled %s instruction at 0x%x, code=0x%08x\n",
		tag, cia, insn);

  sim_engine_halt (CPU_STATE (cpu), cpu, NULL, cia, sim_stopped, SIM_SIGILL);
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

static sim_cia
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
	  return cia;
	}
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

    case CB_SYS_exit_group:
    case CB_SYS_exit:
      sim_engine_halt (CPU_STATE (cpu), cpu, NULL, cia, sim_exited, CCPU_GPR[0].s);
      break;

    case CB_SYS_brk:
      sc.result = nds32_sys_brk (cpu, CCPU_GPR[0].u);
      break;

    case CB_SYS_ioctl:
      sc.result = ioctl (CCPU_GPR[0].s, CCPU_GPR[1].s, CCPU_GPR[2].s);
      break;

    case CB_SYS_getpid:
      sc.result = getpid ();
      break;

    case CB_SYS_fcntl64:
      sc.result = fcntl (CCPU_GPR[0].s, CCPU_GPR[1].s, CCPU_GPR[2].s);
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
	    sc.result = EBADF;
	    break;
	  }
	fd = cb->fdmap[fd];

	/* I'm not sure whether use write () to implement wrivev () is better or not.  */
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
       /* void *mmap2 (void *addr, size_t length, int prot,
		       int flags, int fd, off_t pgoffset);  */
      {
	uint32_t addr = CCPU_GPR[0].u;
	size_t len = CCPU_GPR[1].s;
	int prot = CCPU_GPR[2].s;
	int flags = CCPU_GPR[3].s;
	int fd = CCPU_GPR[4].s;
	off_t pgoffset = CCPU_GPR[5].u;

	sc.result = (long) nds32_mmap (cpu, addr, len, prot, flags,
				       fd, pgoffset * PAGE_SIZE);
      }
      break;
    case CB_SYS_munmap:
      {
	uint32_t addr = CCPU_GPR[0].u;
	size_t len = CCPU_GPR[1].s;

	sc.result = nds32_munmap (cpu, addr, len);
      }
      break;

    case CB_SYS_mprotect:
      sc.result = 0; /* Just do nothing now. */
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
	  sim_write (sd, CCPU_GPR[3].u, (const unsigned char *) &roff, sizeof (loff_t));
      }

    case CB_SYS_NDS32_isatty:
      sc.result = sim_io_isatty (sd, CCPU_GPR[0].s);
      if (sc.result == -1)
	sc.result = 0; /* -1 is returned if EBADF, but caller wants 0. */
      break;

    case CB_SYS_NDS32_getcmdline:
      sc.result = CCPU_GPR[0].u;
      sim_write (sd, CCPU_GPR[0].u, (unsigned char*)sd->cmdline, strlen (sd->cmdline) + 1);
      break;

    case CB_SYS_NDS32_errno:
      sc.result = sim_io_get_errno (sd);
      break;
    }

out:
  CCPU_GPR[0].s = sc.result;
  return cia + 4;
}

ulongest_t
__nds32_ld (sim_cpu *cpu, SIM_ADDR addr, int size, int aligned_p)
{
  int r;
  ulongest_t val = 0;
  int order;
  SIM_DESC sd = CPU_STATE (cpu);
  uint32_t cia = CCPU_USR[NC_PC].u;

  SIM_ASSERT (size <= sizeof (ulongest_t));

  if (aligned_p && (addr & (size - 1)) != 0)
    {
      sim_io_eprintf (sd, "Unaligned access at 0x%08x. "
			  "Read of address 0x%08x", cia, addr);
      sim_engine_halt (CPU_STATE (cpu), cpu, NULL, cia, sim_stopped, SIM_SIGSEGV);
    }

  r = sim_read (sd, addr, (unsigned char *) &val, size);
  order = CCPU_SR_TEST (PSW, PSW_BE) ? BIG_ENDIAN : LITTLE_ENDIAN;
  val = extract_unsigned_integer ((unsigned char *) &val, size, order);

  if (r == size)
    return val;

  sim_io_eprintf (sd, "Access violation at 0x%08x. Read of address 0x%08x\n",
		  cia, addr);
  sim_engine_halt (CPU_STATE (cpu), cpu, NULL, cia, sim_stopped, SIM_SIGSEGV);

  return val;
}

void
__nds32_st (sim_cpu *cpu, SIM_ADDR addr, int size, ulongest_t val,
	    int aligned_p)
{
  int r;
  int order;
  SIM_DESC sd = CPU_STATE (cpu);
  uint32_t cia = CCPU_USR[NC_PC].u;

  SIM_ASSERT (size <= sizeof (ulongest_t));

  if (aligned_p && (addr & (size - 1)) != 0)
    {
      sim_io_eprintf (sd, "Unaligned access at 0x%08x. "
			  "Read of address 0x%08x", cia, addr);
      sim_engine_halt (CPU_STATE (cpu), cpu, NULL, cia, sim_stopped, SIM_SIGSEGV);
    }

  order = CCPU_SR_TEST (PSW, PSW_BE) ? BIG_ENDIAN : LITTLE_ENDIAN;
  store_unsigned_integer ((unsigned char *) &val, size, order, val);
  r = sim_write (sd, addr, (unsigned char *) &val, size);

  if (r == size)
    return;

  sim_io_eprintf (sd, "Access violation at 0x%08x. "
		      "Write of address 0x%08x\n", cia, addr);
  sim_engine_halt (CPU_STATE (cpu), cpu, NULL, cia, sim_stopped, SIM_SIGSEGV);

  return;
}

static void
nds32_free_state (SIM_DESC sd)
{
  if (STATE_MODULES (sd) != NULL)
    sim_module_uninstall (sd);
  sim_cpu_free_all (sd);
  sim_state_free (sd);
}

void
sim_size (int s)
{
}

static sim_cia
nds32_decode32_mem (sim_cpu *cpu, const uint32_t insn, sim_cia cia)
{
  const int rt = N32_RT5 (insn);
  const int ra = N32_RA5 (insn);
  const int rb = N32_RB5 (insn);
  const int sv = __GF (insn, 8, 2);
  const int op = insn & 0xFF;
  uint32_t addr;
  uint32_t shift;

  switch (op)
    {
    case 0x0:			/* lb */
    case 0x1:			/* lh */
    case 0x2:			/* lw */
    case 0x3:			/* ld */
      addr = CCPU_GPR[ra].u + (CCPU_GPR[rb].u << sv);
      CCPU_GPR[rt].u = nds32_ld_aligned (cpu, addr, (1 << (op)));
      break;
    case 0x4:			/* lb.bi */
    case 0x5:			/* lh.bi */
    case 0x6:			/* lw.bi */
    case 0x7:			/* ld.bi */
      addr = CCPU_GPR[ra].u + (CCPU_GPR[rb].u << sv);
      CCPU_GPR[rt].u = nds32_ld_aligned (cpu, CCPU_GPR[ra].u, (1 << (op & 0x3)));
      CCPU_GPR[ra].u = addr;
      break;
    case 0x8:			/* sb */
    case 0x9:			/* sh */
    case 0xa:			/* sw */
    case 0xb:			/* sd */
      addr = CCPU_GPR[ra].u + (CCPU_GPR[rb].u << sv);
      nds32_st_aligned (cpu, addr, (1 << (op & 0x3)), CCPU_GPR[rt].u);
      break;
    case 0xc:			/* sb.bi */
    case 0xd:			/* sh.bi */
    case 0xe:			/* sw.bi */
    case 0xf:			/* sd.bi */
      nds32_st_aligned (cpu, CCPU_GPR[ra].u, (1 << (op & 0x3)),
			CCPU_GPR[rt].u);
      CCPU_GPR[ra].u += (CCPU_GPR[rb].u << sv);
      break;
    case 0x10:			/* lbs */
    case 0x11:			/* lhs */
    case 0x12:			/* lws */
      addr = CCPU_GPR[ra].u + (CCPU_GPR[rb].u << sv);
      CCPU_GPR[rt].u =
	nds32_ld_aligned (cpu, addr, (1 << (op & 0x3)));
      CCPU_GPR[rt].u = __SEXT (CCPU_GPR[rt].u, (1 << (op & 0x3)) * 8);
      break;
    case 0x13:			/* dpref */
      /* do nothing */
      break;
    case 0x14:			/* lbs.bi */
    case 0x15:			/* lhs.bi */
    case 0x16:			/* lws.bi */
      CCPU_GPR[rt].u = nds32_ld_aligned (cpu, CCPU_GPR[ra].u,
					 (1 << (op & 0x3)));
      CCPU_GPR[rt].u = __SEXT (CCPU_GPR[rt].u, (1 << (op & 0x3)) * 8);
      CCPU_GPR[ra].u += (CCPU_GPR[rb].u << sv);
      break;
    case 0x18:			/* llw */
    case 0x19:			/* scw */
    case 0x20:			/* lbup */
    case 0x22:			/* lwup */
    case 0x28:			/* sbup */
    case 0x2a:			/* swup */
    default:
      nds32_bad_op (cpu, cia, insn, "MEM");
      return cia;
    }

  return cia + 4;
}

static sim_cia
nds32_decode32_lsmw (sim_cpu *cpu, const uint32_t insn, sim_cia cia)
{
  /* smwa?.(a|b)(d|i)m? rb,[ra],re,enable4 */
  SIM_DESC sd = CPU_STATE (cpu);
  int rb, re, ra, enable4, i;
  int aligned;
  int m = 0;
  int di;			/* dec=-1 or inc=1 */
  unsigned char reg[4];
  char enb4map[2][4] = { /*smw */ {0, 1, 2, 3}, /*smwa */ {3, 1, 2, 0} };
  ulongest_t base = ~1 + 1;

  rb = N32_RT5 (insn);
  ra = N32_RA5 (insn);
  re = N32_RB5 (insn);
  enable4 = (insn >> 6) & 0x0F;
  aligned = (insn & 3) ? 1 : 0;
  di = (insn & (1 << 3)) ? -1 : 1;

  /* m = TNReg * 4; */
  m += (enable4 & 0x1) ? 1 : 0;
  m += (enable4 & 0x2) ? 1 : 0;
  m += (enable4 & 0x4) ? 1 : 0;
  m += (enable4 & 0x8) ? 1 : 0;
  if (rb < NG_FP && re < NG_FP)
    {
      /* Reg-list should not include fp, gp, lp and sp,
	 i.e., the rb == re == sp case, anyway... */
      m += (re - rb) + 1;
    }
  m *= 4;			/* 4*TNReg */

  base = CCPU_GPR[ra].u;

  if (insn & (1 << 0x4))	/* a:b, a for +-4 */
    base += 4 * di;

  if (di == 1)
    base += (m - 4);

  switch (insn & 0x23)
    {
    case 33:			/* smwa */
      if (base & 3)
	{
	  sim_io_eprintf (sd, "SMWA: unaligned access at 0x%x. "
			      "Write of address 0x%llx.\n",
			  cia, base);
	  return cia;
	}
    case 32:			/* smw */
      /* TODO: alignment exception check for SMWA */
      for (i = 0; i < 4; i++)
	{
	  if (enable4 & (1 << enb4map[aligned][i]))
	    {
	      sim_write (sd, base, reg, 4);
	      nds32_st_unaligned (cpu, base, 4,
				  CCPU_GPR[NG_SP - (enb4map[aligned][i])].u);
	      base -= 4;
	    }
	}

      /* Skip if re == rb == sp > fp.  */
      for (i = re; i >= rb && rb < NG_FP; i--)
	{
	  nds32_st_unaligned (cpu, base, 4, CCPU_GPR[i].u);
	  base -= 4;
	}

      if (insn & (1 << 2))
	CCPU_GPR[ra].u += m * di;
      break;
    case 1:			/* lmwa */
      if (base & 3)
	{
	  sim_io_eprintf (sd, "LMWA: unaligned access at 0x%x. "
			      "Read of address 0x%llx.\n",
			  cia, base);
	  sim_engine_halt (CPU_STATE (cpu), cpu, NULL, cia, sim_stopped, SIM_SIGSEGV);
	  return cia;
	}
    case 0:			/* lmw */
      /* TODO: alignment exception check for SMWA */
      for (i = 0; i < 4; i++)
	{
	  if (enable4 & (1 << enb4map[aligned][i]))
	    {
	      uint32_t u;

	      u = nds32_ld_unaligned (cpu, base, 4);
	      CCPU_GPR[NG_SP - (enb4map[aligned][i])].u = u;
	      base -= 4;
	    }
	}

      /* Skip if re == rb == sp > fp.  */
      for (i = re; i >= rb && rb < NG_FP; i--)
	{
	  CCPU_GPR[i].u = nds32_ld_unaligned (cpu, base, 4);
	  base -= 4;
	}

      if (insn & (1 << 2))
	CCPU_GPR[ra].u += m * di;
      break;
    case 2:			/* lmwzb */
    case 34:			/* smwzb */
    default:
      nds32_bad_op (cpu, cia, insn, "LSMW");
      return cia;
    }

  return cia + 4;
}

static sim_cia
nds32_decode32_alu1 (sim_cpu *cpu, const uint32_t insn, sim_cia cia)
{
  int rt = N32_RT5 (insn);
  int ra = N32_RA5 (insn);
  int rb = N32_RB5 (insn);
  const int rd = N32_RD5 (insn);
  const int imm5u = rb;
  const int sh5 = N32_SH5 (insn);

  switch (insn & 0x1f)
    {
    case 0x0:			/* add, add_slli */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u + (CCPU_GPR[rb].u << sh5);
      break;
    case 0x1:			/* sub, sub_slli */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u - (CCPU_GPR[rb].u << sh5);
      break;
    case 0x2:			/* and, add_slli */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u & (CCPU_GPR[rb].u << sh5);
      break;
    case 0x3:			/* xor, xor_slli */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u ^ (CCPU_GPR[rb].u << sh5);
      break;
    case 0x4:			/* or, or_slli */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u | (CCPU_GPR[rb].u << sh5);
      break;
    case 0x5:			/* nor */
      CCPU_GPR[rt].u = ~(CCPU_GPR[ra].u | CCPU_GPR[rb].u);
      break;
    case 0x6:			/* slt */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u < CCPU_GPR[rb].u ? 1 : 0;
      break;
    case 0x7:			/* slts */
      CCPU_GPR[rt].u = CCPU_GPR[ra].s < CCPU_GPR[rb].s ? 1 : 0;
      break;

    case 0x8:			/* slli */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u << imm5u;
      break;
    case 0x9:			/* srli */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u >> imm5u;
      break;
    case 0xa:			/* srai */
      CCPU_GPR[rt].s = CCPU_GPR[ra].s >> imm5u;
      break;
    case 0xc:			/* sll */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u << (CCPU_GPR[rb].u & 0x1f);
      break;
    case 0xd:			/* srl */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u >> CCPU_GPR[rb].u;
      break;
    case 0xe:			/* sra */
      CCPU_GPR[rt].s = CCPU_GPR[ra].s >> CCPU_GPR[rb].u;
      break;
    case 0xb:			/* rotri */
    case 0xf:			/* rotr */
      {
	uint32_t shift = ((insn & 0x1f) == 0xb) ? imm5u : CCPU_GPR[rb].u;
	uint32_t m = CCPU_GPR[ra].u & ((1 << shift) - 1);
	CCPU_GPR[rt].u = CCPU_GPR[ra].u >> shift;
	CCPU_GPR[rt].u |= m << (32 - shift);
      }
      break;

    case 0x10:			/* seb */
      CCPU_GPR[rt].s = __SEXT (CCPU_GPR[ra].s, 8);
      break;
    case 0x11:			/* seh */
      CCPU_GPR[rt].s = __SEXT (CCPU_GPR[ra].s, 16);
      break;
    case 0x12:			/* bitc */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u & ~(CCPU_GPR[rb].u);
      break;
    case 0x13:			/* zeh */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u & 0xffff;
      break;
    case 0x14:			/* wsbh */
      CCPU_GPR[rt].u = ((CCPU_GPR[ra].u & 0xFF00FF00) >> 8)
		       | ((CCPU_GPR[ra].u & 0x00FF00FF) << 8);
      break;
    case 0x15:			/* or_srli */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u | (CCPU_GPR[rb].u >> sh5);
      break;
    case 0x16:			/* divsr */
      {
	/* FIXME: Positive qoutient exception.  */
	int64_t q;
	int64_t r;

	q = CCPU_GPR[ra].s / CCPU_GPR[rb].s;
	r = CCPU_GPR[ra].s % CCPU_GPR[rb].s;
	CCPU_GPR[rt].s = q;
	if (rt != rd)
	  CCPU_GPR[rd].s = r;
      }
      break;
    case 0x17:			/* divr */
      {
	uint64_t q;
	uint64_t r;

	q = CCPU_GPR[ra].u / CCPU_GPR[rb].u;
	r = CCPU_GPR[ra].u % CCPU_GPR[rb].u;
	CCPU_GPR[rt].u = q;
	if (rt != rd)
	  CCPU_GPR[rd].u = r;
      }
      break;
    case 0x18:			/* sva */
      {
	uint64_t s = (uint64_t) CCPU_GPR[ra].u + (uint64_t) CCPU_GPR[rb].u;
	s = (s >> 31) & 0x3;
	CCPU_GPR[rt].u = (s == 0 || s == 3);
      }
      break;
    case 0x19:			/* svs */
      break;
    case 0x1a:			/* comvz */
      if (CCPU_GPR[rb].u == 0)
	CCPU_GPR[rt].u = CCPU_GPR[ra].u;
      break;
    case 0x1b:			/* comvn */
      if (CCPU_GPR[rb].u != 0)
	CCPU_GPR[rt].u = CCPU_GPR[ra].u;
      break;
    case 0x1c:			/* add_srli */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u + (CCPU_GPR[rb].u >> sh5);
      break;
    case 0x1d:			/* sub_srli */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u - (CCPU_GPR[rb].u >> sh5);
      break;
    case 0x1e:			/* and_srli */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u & (CCPU_GPR[rb].u >> sh5);
      break;
    case 0x1f:			/* xor_srli */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u ^ (CCPU_GPR[rb].u >> sh5);
      break;
    default:
      nds32_bad_op (cpu, cia, insn, "ALU1");
      return cia;
    }

  return cia + 4;
}

static sim_cia
nds32_decode32_alu2 (sim_cpu *cpu, const uint32_t insn, sim_cia cia)
{
  int rt = N32_RT5 (insn);
  int ra = N32_RA5 (insn);
  int rb = N32_RB5 (insn);
  const int imm5u = rb;
  const int dt = (insn & (1 << 21)) ? NC_D1LO : NC_D0LO;

  switch (insn & 0x3ff)
    {
    case 0x0:			/* max */
      CCPU_GPR[rt].s = (CCPU_GPR[ra].s > CCPU_GPR[rb].s)
		       ? CCPU_GPR[ra].s : CCPU_GPR[rb].s;
      break;
    case 0x1:			/* min */
      CCPU_GPR[rt].s = (CCPU_GPR[ra].s < CCPU_GPR[rb].s)
		       ? CCPU_GPR[ra].s : CCPU_GPR[rb].s;
      break;
    case 0x2:			/* ave */
      {
	int64_t r = ((int64_t) CCPU_GPR[ra].s << 1)
		    + ((int64_t) CCPU_GPR[rb].s << 1) + 1;
	CCPU_GPR[rt].u = (r >> 1) & 0xFFFFFFFF;
      }
      break;
    case 0x3:			/* abs */
      if (CCPU_GPR[ra].s >= 0)
	CCPU_GPR[rt].s = CCPU_GPR[ra].s;
      else if (CCPU_GPR[ra].u == 0x80000000)
	CCPU_GPR[rt].u = 0x7fffffff;
      else
	CCPU_GPR[rt].s = -CCPU_GPR[ra].s;
      break;
    case 0x4:			/* clips */
      if (CCPU_GPR[ra].s > ((1 << imm5u) - 1))
	CCPU_GPR[rt].s = ((1 << imm5u) - 1);
      else if (CCPU_GPR[ra].s < -(1 << imm5u))
	CCPU_GPR[rt].s = -(1 << imm5u);
      else
	CCPU_GPR[rt].s = CCPU_GPR[ra].s;
      break;
    case 0x5:			/* clip */
      if (CCPU_GPR[ra].s > ((1 << imm5u) - 1))
	CCPU_GPR[rt].s = ((1 << imm5u) - 1);
      else if (CCPU_GPR[ra].s < 0)
	CCPU_GPR[rt].s = 0;
      else
	CCPU_GPR[rt].s = CCPU_GPR[ra].s;
      break;
    case 0x6:			/* clo */
      {
	int i, cnt = 0;

	for (i = 31; i >= 0; i--)
	  {
	    if (CCPU_GPR[ra].u & (1 << i))
	      cnt++;
	    else
	      break;
	  }
	CCPU_GPR[rt].u = cnt;
      }
      break;
    case 0x7:			/* clz */
      {
	int i, cnt = 0;

	for (i = 31; i >= 0; i--)
	  {
	    if ((CCPU_GPR[ra].u & (1 << i)) == 0)
	      cnt++;
	    else
	      break;
	  }
	CCPU_GPR[rt].u = cnt;
      }
      break;
    case 0x8:			/* bset */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u | (1 << imm5u);
      break;
    case 0x9:			/* bclr */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u & ~(1 << imm5u);
      break;
    case 0xa:			/* btgl */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u ^ (1 << imm5u);
      break;
    case 0xb:			/* btst */
      CCPU_GPR[rt].u = (CCPU_GPR[ra].u & (1 << imm5u)) != 0;
      break;
    case 0x24:			/* mul */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u * CCPU_GPR[rb].u;
      break;
    case 0x20:			/* mfusr */
      CCPU_GPR[rt].u = CCPU_USR[rb << 5 | ra].u;
      if (((rb << 5) | ra) == 31)	/* PC */
	CCPU_GPR[rt].u = cia;
      break;
    case 0x21:			/* mtusr */
      CCPU_USR[(rb << 5) | ra].u = CCPU_GPR[rt].u;
      break;
    case 0x28:			/* mults64 */
      {
	int64_t d = (int64_t) CCPU_GPR[ra].s * (int64_t) CCPU_GPR[rb].s;

	CCPU_USR[dt].s = d & 0xFFFFFFFF;
	CCPU_USR[dt + 1].s = (d >> 32) & 0xFFFFFFFF;
      }
      break;
    case 0x29:			/* mult64 */
      {
	uint64_t d = (uint64_t) CCPU_GPR[ra].u * (uint64_t) CCPU_GPR[rb].u;

	CCPU_USR[dt].u = d & 0xFFFFFFFF;
	CCPU_USR[dt + 1].u = (d >> 32) & 0xFFFFFFFF;
      }
      break;
    case 0x2a:			/* madds64 */
      {
	int64_t mr = (int64_t) CCPU_GPR[ra].s * (int64_t) CCPU_GPR[rb].s;
	int64_t d = ((int64_t) CCPU_USR[dt + 1].s << 32)
		    | ((int64_t) CCPU_USR[dt].  s & 0xFFFFFFFF);

	d += mr;
	CCPU_USR[dt].u = d & 0xFFFFFFFF;
	CCPU_USR[dt + 1].u = (d >> 32) & 0xFFFFFFFF;
      }
      break;
    case 0x2b:			/* madd64 */
      {
	uint64_t mr = (uint64_t) CCPU_GPR[ra].u * (uint64_t) CCPU_GPR[rb].u;
	uint64_t d = ((uint64_t) CCPU_USR[dt + 1].u << 32)
		     | ((uint64_t) CCPU_USR[dt].u & 0xFFFFFFFF);

	d += mr;
	CCPU_USR[dt].u = d & 0xFFFFFFFF;
	CCPU_USR[dt + 1].u = (d >> 32) & 0xFFFFFFFF;
      }
      break;
    case 0x2c:			/* msubs64 */
      {
	int64_t mr = (int64_t) CCPU_GPR[ra].s * (int64_t) CCPU_GPR[rb].s;
	int64_t d = ((int64_t) CCPU_USR[dt + 1].s << 32)
		    | ((int64_t) CCPU_USR[dt].s & 0xFFFFFFFF);

	d -= mr;
	CCPU_USR[dt].u = d & 0xFFFFFFFF;
	CCPU_USR[dt + 1].u = (d >> 32) & 0xFFFFFFFF;
      }
      break;
    case 0x2d:			/* msub64 */
      {
	uint64_t mr = (uint64_t) CCPU_GPR[ra].u * (uint64_t) CCPU_GPR[rb].u;
	uint64_t d = ((uint64_t) CCPU_USR[dt + 1].u << 32)
		     | ((uint64_t) CCPU_USR[dt].u & 0xFFFFFFFF);

	d -= mr;
	CCPU_USR[dt].u = d & 0xFFFFFFFF;
	CCPU_USR[dt + 1].u = (d >> 32) & 0xFFFFFFFF;
      }
      break;
    case 0x2e:			/* divs */
      {
	int32_t q;
	int32_t r;

	q = CCPU_GPR[ra].s / CCPU_GPR[rb].s;
	r = CCPU_GPR[ra].s % CCPU_GPR[rb].s;
	CCPU_USR[dt].s = q;
	CCPU_USR[dt + 1].s = r;
      }
      break;
    case 0x2f:			/* div */
      {
	uint32_t q;
	uint32_t r;

	q = CCPU_GPR[ra].u / CCPU_GPR[rb].u;
	r = CCPU_GPR[ra].u % CCPU_GPR[rb].u;
	CCPU_USR[dt].u = q;
	CCPU_USR[dt + 1].u = r;
      }
      break;
    case 0x31:			/* mult32 */
      CCPU_USR[dt].s = CCPU_GPR[ra].s * CCPU_GPR[rb].s;
      break;
    case 0x33:			/* madd32 */
      CCPU_USR[dt].s += CCPU_GPR[ra].s * CCPU_GPR[rb].s;
      break;
    case 0x35:			/* msub32 */
      CCPU_USR[dt].s -= CCPU_GPR[ra].s * CCPU_GPR[rb].s;
      break;
    case 0x68:			/* mulsr64 */
      {
	int64_t r = (int64_t) CCPU_GPR[ra].s * (int64_t) CCPU_GPR[rb].s;
	int d = rt & ~1;

	if (CCPU_SR_TEST (PSW, PSW_BE))
	  {
	    CCPU_GPR[d].u = (r >> 32) & 0xFFFFFFFF;
	    CCPU_GPR[d + 1].u = r & 0xFFFFFFFF;
	  }
	else
	  {
	    CCPU_GPR[d + 1].u = (r >> 32) & 0xFFFFFFFF;
	    CCPU_GPR[d].u = r & 0xFFFFFFFF;
	  }
      }
      break;
    case 0x69:			/* mulr64 */
      {
	uint64_t r = (uint64_t) CCPU_GPR[ra].u * (uint64_t) CCPU_GPR[rb].u;
	int d = rt & ~1;

	if (CCPU_SR_TEST (PSW, PSW_BE))
	  {
	    CCPU_GPR[d].u = (r >> 32) & 0xFFFFFFFF;
	    CCPU_GPR[d + 1].u = r & 0xFFFFFFFF;
	  }
	else
	  {
	    CCPU_GPR[d + 1].u = (r >> 32) & 0xFFFFFFFF;
	    CCPU_GPR[d].u = r & 0xFFFFFFFF;
	  }
      }
      break;
    case 0x73:			/* maddr32 */
      CCPU_GPR[rt].u += (CCPU_GPR[ra].u * CCPU_GPR[rb].u) & 0xFFFFFFFF;
      break;
    case 0x75:			/* msubr32 */
      CCPU_GPR[rt].u -= (CCPU_GPR[ra].u * CCPU_GPR[rb].u) & 0xFFFFFFFF;
      break;
    default:
      nds32_bad_op (cpu, cia, insn, "ALU2");
      return cia;
    }

  return cia + 4;
}

static sim_cia
nds32_decode32_jreg (sim_cpu *cpu, const uint32_t insn, sim_cia cia)
{
  SIM_DESC sd = CPU_STATE (cpu);
  int rt = N32_RT5 (insn);
  int ra = N32_RA5 (insn);
  int rb = N32_RB5 (insn);

  if (ra != 0)
    sim_io_error (sd, "JREG RA == %d at pc=0x%x, code=0x%08x\n",
		  ra, cia, insn);

  if (__GF (insn, 8, 2) != 0)
    sim_io_error (sd, "JREG DT/IT not supported at pc=0x%x, code=0x%08x\n",
		  cia, insn);

  switch (insn & 0x1f)
    {
    case 0:			/* jr, ifret, ret */
      if (__GF (insn, 5, 2) == 0x3)
	{
	  /* ifret. IFC + RET */
	  if (CCPU_SR_TEST (PSW, PSW_IFCON))
	    cia = CCPU_USR[NC_IFCLP].u;
	  else
	    cia += 4;	/* Do nothing */
	}
      else
	/* jr or ret */
	cia = CCPU_GPR[rb].u;

      CCPU_SR_CLEAR (PSW, PSW_IFCON);
      /* SIM_IO_DPRINTF (sd, "set $pc to 0x%x\n", CCPU_USR[NC_PC].u); */
      cpu->iflags &= ~NIF_EX9;	/* Check ex9.it for details. */
      return cia;

    case 1:			/* jral */
      if (cpu->iflags & NIF_EX9)
	CCPU_GPR[rt].u = cia + 2;
      else
	CCPU_GPR[rt].u = cia + 4;

      cia = CCPU_GPR[rb].u;
      /* SIM_IO_DPRINTF (sd, "set $pc to 0x%x, save ra to $r%d\n", CCPU_USR[NC_PC].u, rb); */
      if (CCPU_SR_TEST (PSW, PSW_IFCON))
	{
	  CCPU_GPR[rt] = CCPU_USR[NC_IFCLP];
	  CCPU_SR_CLEAR (PSW, PSW_IFCON);
	}

      cpu->iflags &= ~NIF_EX9;	/* Check ex9.it for details. */
      return cia;

    case 2:			/* jrnez */
      if (CCPU_GPR[rb].u != 0)	/* taken */
	{
	  CCPU_SR_CLEAR (PSW, PSW_IFCON);
	  cpu->iflags &= ~NIF_EX9;	/* Check ex9.it for details. */
	  return CCPU_GPR[rb].u;
	}

      break; /* NOT taken */

    case 3:			/* jralnez */
      if (cpu->iflags & NIF_EX9)
	CCPU_GPR[rt].u = cia + 2;
      else
	CCPU_GPR[rt].u = cia + 4;

      if (CCPU_GPR[rb].u != 0)	/* taken */
	{
	  if (CCPU_SR_TEST (PSW, PSW_IFCON))
	    {
	      CCPU_GPR[rt] = CCPU_USR[NC_IFCLP];
	      CCPU_SR_CLEAR (PSW, PSW_IFCON);
	    }
	  cpu->iflags &= ~NIF_EX9;	/* Check ex9.it for details. */
	  return CCPU_GPR[rb].u;
	}

      break; /* NOT taken */

    default:
      nds32_bad_op (cpu, cia, insn, "JREG");
      return cia;
    }

  return cia + 4;
}

static sim_cia
nds32_decode32_br1 (sim_cpu *cpu, const uint32_t insn, sim_cia cia)
{
  int rt = N32_RT5 (insn);
  int ra = N32_RA5 (insn);
  int imm14s = N32_IMM14S (insn);

  switch ((insn >> 14) & 1)
    {
    case 0:			/* beq */
      if (CCPU_GPR[rt].u == CCPU_GPR[ra].u)
	{
	  cpu->iflags &= ~NIF_EX9;	/* Check ex9.it for details. */
	  return cia + (imm14s << 1);
	}
      break;
    case 1:			/* bne */
      if (CCPU_GPR[rt].u != CCPU_GPR[ra].u)
	{
	  cpu->iflags &= ~NIF_EX9;	/* Check ex9.it for details. */
	  return cia + (imm14s << 1);
	}
      break;
    }

  return cia + 4;
}

static sim_cia
nds32_decode32_br2 (sim_cpu *cpu, const uint32_t insn, sim_cia cia)
{
  int rt = N32_RT5 (insn);
  int imm16s = N32_IMM16S (insn);

  switch (__GF (insn, 16, 4))
    {
    case 0x0:			/* ifcall */
      if (!CCPU_SR_TEST (PSW, PSW_IFCON))
	{
	  if (cpu->iflags & NIF_EX9)
	    CCPU_USR[NC_IFCLP].u = cia + 2;
	  else
	    CCPU_USR[NC_IFCLP].u = cia + 4;

	  CCPU_SR_SET (PSW, PSW_IFCON);
	  cpu->iflags &= ~NIF_EX9;	/* Check ex9.it for details. */
	  return cia + (N32_IMMS (insn, 16) << 1);
	}
      else
	{
	  sim_io_error (CPU_STATE (cpu), "Nested IFCALL.\n");
	  sim_engine_halt (CPU_STATE (cpu), cpu, NULL, cia, sim_stopped, SIM_SIGABRT);
	}
      break;
    case 0x2:			/* beqz */
      if (CCPU_GPR[rt].s == 0)
	{
	  cpu->iflags &= ~NIF_EX9;	/* Check ex9.it for details. */
	  return cia + (imm16s << 1);
	}
      break;
    case 0x3:			/* bnez */
      if (CCPU_GPR[rt].s != 0)
	{
	  cpu->iflags &= ~NIF_EX9;	/* Check ex9.it for details. */
	  return cia + (imm16s << 1);
	}
      break;
    case 0x4:			/* bgez */
      if (CCPU_GPR[rt].s >= 0)
	{
	  cpu->iflags &= ~NIF_EX9;	/* Check ex9.it for details. */
	  return cia + (imm16s << 1);
	}
      break;
    case 0x5:			/* bltz */
      if (CCPU_GPR[rt].s < 0)
	{
	  cpu->iflags &= ~NIF_EX9;	/* Check ex9.it for details. */
	  return cia + (imm16s << 1);
	}
      break;
    case 0x6:			/* bgtz */
      if (CCPU_GPR[rt].s > 0)
	{
	  cpu->iflags &= ~NIF_EX9;	/* Check ex9.it for details. */
	  return cia + (imm16s << 1);
	}
      break;
    case 0x7:			/* blez */
      if (CCPU_GPR[rt].s <= 0)
	{
	  cpu->iflags &= ~NIF_EX9;	/* Check ex9.it for details. */
	  return cia + (imm16s << 1);
	}
      break;
    case 0x1c:			/* bgezal */
      if (CCPU_GPR[rt].s >= 0)
	{
	  CCPU_GPR[NG_LP].u = cia + 4;
	  cpu->iflags &= ~NIF_EX9;	/* Check ex9.it for details. */
	  return cia + (imm16s << 1);
	}
      break;
    case 0x1d:			/* bltzal */
      if (CCPU_GPR[rt].s < 0)
	{
	  if (cpu->iflags & NIF_EX9)
	    CCPU_USR[NC_IFCLP].u = cia + 2;
	  else
	    CCPU_USR[NC_IFCLP].u = cia + 4;

	  cpu->iflags &= ~NIF_EX9;	/* Check ex9.it for details. */
	  return cia + (imm16s << 1);
	}
      break;
    default:
      goto bad_op;
    }

  return cia + 4;

bad_op:
  nds32_bad_op (cpu, cia, insn, "BR2");
  return cia;
}

static sim_cia
nds32_decode32_misc (sim_cpu *cpu, const uint32_t insn, sim_cia cia)
{
  int rt = N32_RT5 (insn);

  switch (insn & 0x1F)
    {
    case 0x0:			/* standby */
    case 0x1:			/* cctl */
    case 0x8:			/* dsb */
    case 0x9:			/* isb */
    case 0xd:			/* isync */
    case 0xc:			/* msync */
      break;
    case 0x5:			/* trap */
    case 0xa:			/* break */
      sim_engine_halt (CPU_STATE (cpu), cpu, NULL, cia, sim_stopped, SIM_SIGTRAP);
      return cia; /* FIXME dispatch exception? */
    case 0x2:			/* mfsr */
      CCPU_GPR[rt] = CCPU_SR[__GF (insn, 10, 10)];
      break;
    case 0x3:			/* mtsr */
      CCPU_SR[__GF (insn, 10, 10)] = CCPU_GPR[rt];
      break;
    case 0xb:			/* syscall */
      return nds32_syscall (cpu, __GF (insn, 5, 15), cia);
    case 0x4:			/* iret */
      nds32_bad_op (cpu, cia, insn, "iret (MISC)");
      return cia;
    case 0x6:			/* teqz */
      nds32_bad_op (cpu, cia, insn, "teqz (MISC)");
      return cia;
    case 0x7:			/* tnez */
      nds32_bad_op (cpu, cia, insn, "tnez (MISC)");
      return cia;
    case 0xe:			/* tlbop */
      nds32_bad_op (cpu, cia, insn, "tlbop (MISC)");
      return cia;
    default:
      nds32_bad_op (cpu, cia, insn, "MISC");
      return cia;
    }

  return cia + 4;
}

static sim_cia
nds32_decode32 (sim_cpu *cpu, const uint32_t insn, sim_cia cia)
{
  int op = N32_OP6 (insn);
  int rt = N32_RT5 (insn);
  int ra = N32_RA5 (insn);
  int rb = N32_RB5 (insn);
  int imm15s = N32_IMM15S (insn);
  int imm15u = N32_IMM15U (insn);
  uint32_t shift;
  uint32_t addr;

  switch (op)
    {
    case 0x0:			/* lbi */
    case 0x1:			/* lhi */
    case 0x2:			/* lwi */
    case 0x3:			/* ldi */
      {
	shift = (op - 0x0);
	addr = CCPU_GPR[ra].u + (imm15s << shift);
	CCPU_GPR[rt].u = nds32_ld_aligned (cpu, addr, 1 << shift);
      }
      break;

    case 0x4:			/* lbi.bi */
    case 0x5:			/* lhi.bi */
    case 0x6:			/* lwi.bi */
    case 0x7:			/* ldi.bi */
      {
	shift = (op - 0x4);
	CCPU_GPR[rt].u = nds32_ld_aligned (cpu, CCPU_GPR[ra].u, 1 << shift);
	CCPU_GPR[ra].u += (imm15s << shift);
      }
      break;

    case 0x8:			/* sbi */
    case 0x9:			/* shi */
    case 0xa:			/* swi */
    case 0xb:			/* sdi */
      {
	shift = (op - 0x8);
	addr = CCPU_GPR[ra].u + (imm15s << shift);
	nds32_st_aligned (cpu, addr, 1 << shift, CCPU_GPR[rt].u);
      }
      break;

    case 0xc:			/* sbi.bi */
    case 0xd:			/* shi.bi */
    case 0xe:			/* swi.bi */
    case 0xf:			/* sdi.bi */
      {
	shift = (op - 0xc);
	nds32_st_aligned (cpu, CCPU_GPR[ra].u, 1 << shift, CCPU_GPR[rt].u);
	CCPU_GPR[ra].u += (imm15s << shift);
      }
      break;

    case 0x10:			/* lbsi */
    case 0x11:			/* lhsi */
    case 0x12:			/* lwsi */
      {
	shift = (op - 0x10);
	addr = CCPU_GPR[ra].u + (imm15s << shift);
	CCPU_GPR[rt].u = nds32_ld_aligned (cpu, addr, 1 << shift);
	CCPU_GPR[rt].u = __SEXT (CCPU_GPR[rt].u, (1 << shift) * 8);
      }
      break;
    case 0x13:			/* dprefi */
      /* do nothing */
      break;
    case 0x14:			/* lbsi.bi */
    case 0x15:			/* lhsi.bi */
    case 0x16:			/* lwsi.bi */
      {
	shift = (op - 0x14);
	CCPU_GPR[rt].u = nds32_ld_aligned (cpu, CCPU_GPR[ra].u, 1 << shift);
	CCPU_GPR[rt].u = __SEXT (CCPU_GPR[rt].u, (1 << shift) * 8);
	CCPU_GPR[ra].u += (imm15s << shift);
      }
      break;
    case 0x17:			/* LBGP */
      if (insn & (1 << 19))	/* lbsi.gp */
	{
	  addr = CCPU_GPR[NG_GP].u + N32_IMMS (insn, 19);
	  CCPU_GPR[rt].u = nds32_ld_aligned (cpu, addr, 1);
	  CCPU_GPR[rt].u = __SEXT (CCPU_GPR[rt].u, 1 * 8);
	}
      else			/* lbi.gp */
	CCPU_GPR[rt].u =
	  nds32_ld_aligned (cpu, CCPU_GPR[NG_GP].u + N32_IMMS (insn, 19), 1);
      break;
    case 0x18:			/* LWC */
      return nds32_decode32_lwc (cpu, insn, cia);
    case 0x19:			/* SWC */
      return nds32_decode32_swc (cpu, insn, cia);
    case 0x1a:			/* LDC */
      return nds32_decode32_ldc (cpu, insn, cia);
    case 0x1b:			/* SDC */
      return nds32_decode32_sdc (cpu, insn, cia);
    case 0x1c:			/* MEM */
      return nds32_decode32_mem (cpu, insn, cia);
    case 0x1d:			/* LSMW */
      return nds32_decode32_lsmw (cpu, insn, cia);
    case 0x1e:			/* HWGP */
      switch (__GF (insn, 17, 3))
	{
	case 0: case 1:		/* lhi.gp */
	  addr = CCPU_GPR[NG_GP].u + (N32_IMMS (insn, 18) << 1);
	  CCPU_GPR[rt].u = nds32_ld_aligned (cpu, addr, 2);
	  break;
	case 2: case 3:		/* lhsi.gp */
	  addr = CCPU_GPR[NG_GP].u + (N32_IMMS (insn, 18) << 1);
	  CCPU_GPR[rt].u = nds32_ld_aligned (cpu, addr, 2);
	  CCPU_GPR[rt].u = __SEXT (CCPU_GPR[rt].u, 2 * 8);
	  break;
	case 4: case 5:		/* shi.gp */
	  nds32_st_aligned (cpu, CCPU_GPR[NG_GP].u + (N32_IMMS (insn, 18) << 1), 2,
			    CCPU_GPR[rt].u);
	  break;
	case 6:			/* lwi.gp */
	  addr= CCPU_GPR[NG_GP].u + (N32_IMMS (insn, 17) << 2);
	  CCPU_GPR[rt].u = nds32_ld_aligned (cpu, addr, 4);
	  break;
	case 7:			/* swi.gp */
	  nds32_st_aligned (cpu, CCPU_GPR[NG_GP].u + (N32_IMMS (insn, 17) << 2),
			    4, CCPU_GPR[rt].u);
	  break;
	}
      break;
    case 0x1f:			/* SBGP */
      if (insn & (1 << 19))	/* addi.gp */
	CCPU_GPR[rt].s = CCPU_GPR[NG_GP].u + N32_IMMS (insn, 19);
      else			/* sbi.gp */
	nds32_st_aligned (cpu, CCPU_GPR[NG_GP].u + N32_IMMS (insn, 19), 1,
			  CCPU_GPR[rt].u & 0xFF);
      break;
    case 0x20:			/* ALU_1 */
      return nds32_decode32_alu1 (cpu, insn, cia);
    case 0x21:			/* ALU_2 */
      return nds32_decode32_alu2 (cpu, insn, cia);
    case 0x22:			/* movi */
      CCPU_GPR[rt].s = N32_IMM20S (insn);
      break;
    case 0x23:			/* sethi */
      CCPU_GPR[rt].u = N32_IMM20U (insn) << 12;
      break;
    case 0x24:			/* ji, jal */
      if (cpu->iflags & NIF_EX9)
	{
	  if (insn & (1 << 24))	/* jal in ex9 */
	    CCPU_GPR[NG_LP].u = cia + 2;
	  cia = (cia & 0xff000000) | (N32_IMMU (insn, 24) << 1);
	}
      else
	{
	  if (insn & (1 << 24))	/* jal */
	    CCPU_GPR[NG_LP].u = cia + 4;
	  cia = cia + (N32_IMMS (insn, 24) << 1);
	}

      if (CCPU_SR_TEST (PSW, PSW_IFCON))
	{
	  CCPU_GPR[NG_LP] = CCPU_USR[NC_IFCLP];
	  CCPU_SR_CLEAR (PSW, PSW_IFCON);
	}

      cpu->iflags &= ~NIF_EX9;
      return cia;
    case 0x25:			/* jreg */
      cia = nds32_decode32_jreg (cpu, insn, cia);
      return cia;
    case 0x26:			/* br1 */
      cia = nds32_decode32_br1 (cpu, insn, cia);
      return cia;
    case 0x27:			/* br2 */
      cia = nds32_decode32_br2 (cpu, insn, cia);
      return cia;
    case 0x28:			/* addi rt, ra, imm15s */
      CCPU_GPR[rt].s = CCPU_GPR[ra].s + imm15s;
      break;
    case 0x29:			/* subri */
      CCPU_GPR[rt].s = imm15s - CCPU_GPR[ra].s;
      break;
    case 0x2a:			/* andi */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u & imm15u;
      break;
    case 0x2b:			/* xori */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u ^ imm15u;
      break;
    case 0x2c:			/* ori */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u | imm15u;
      break;
    case 0x2d:			/* br3, beqc, bnec */
      {
	int imm11s = __SEXT (__GF (insn, 8, 11), 11);

	if (((insn & (1 << 19)) == 0) ^ (CCPU_GPR[rt].s != imm11s))
	  {
	    cpu->iflags &= ~NIF_EX9;
	    return cia + (N32_IMMS (insn, 8) << 1);
	  }
      }
      break;
    case 0x2e:			/* slti */
      CCPU_GPR[rt].u = (CCPU_GPR[ra].u < (uint32_t) imm15s) ? 1 : 0;
      break;
    case 0x2f:			/* sltsi */
      CCPU_GPR[rt].u = (CCPU_GPR[ra].s < imm15s) ? 1 : 0;
      break;
    case 0x32:			/* misc */
      return nds32_decode32_misc (cpu, insn, cia);
    case 0x33:			/* bitci */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u & ~imm15u;
      break;
    case 0x35:			/* COP */
      return nds32_decode32_cop (cpu, insn, cia);
    default:
      goto bad_op;
    }

  return cia + 4;

bad_op:
  nds32_bad_op (cpu, cia, insn, "32-bit");
  return cia;
}

static sim_cia
nds32_decode16_ex9 (sim_cpu *cpu, uint32_t insn, sim_cia cia)
{
  sim_cia ex9_cia;

  /* For jump and taken branch, it should clear the NIF_EX9 bit
     to indicate the ex9_cia should be used; otherwsie,
     the next cia, cia + 2, should be used.  */

  cpu->iflags |= NIF_EX9;
  ex9_cia = nds32_decode32 (cpu, insn, cia);

  if ((cpu->iflags & NIF_EX9) == 0)
    return ex9_cia;

  cpu->iflags &= ~NIF_EX9;
  return cia + 2;
}

static sim_cia
nds32_decode16 (sim_cpu *cpu, uint32_t insn, sim_cia cia)
{
  SIM_DESC sd = CPU_STATE (cpu);
  const int rt5 = N16_RT5 (insn);
  const int ra5 = N16_RA5 (insn);
  const int rt4 = N16_RT4 (insn);
  const int imm5u = N16_IMM5U (insn);
  const int imm5s = N16_IMM5S (insn);
  const int imm9u = N16_IMM9U (insn);
  const int rt3 = N16_RT3 (insn);
  const int ra3 = N16_RA3 (insn);
  const int rb3 = N16_RB3 (insn);
  const int rt38 = N16_RT38 (insn);
  const int imm3u = rb3;
  uint32_t shift;
  uint32_t addr;

  switch (__GF (insn, 7, 8))
    {
    case 0xf8:			/* push25 */
      {
	uint32_t smw_adm = 0x3A6F83BC;
	uint32_t res[] = { 6, 8, 10, 14 };
	uint32_t re = __GF (insn, 5, 2);

	smw_adm |= res[re] << 10;
	nds32_decode32_lsmw (cpu, smw_adm, cia);
	CCPU_GPR[NG_SP].u -= (imm5u << 3);
	if (re >= 1)
	  CCPU_GPR[8].u = cia & 0xFFFFFFFC;
      }
      goto done;
    case 0xf9:			/* pop25 */
      {
	uint32_t lmw_bim = 0x3A6F8384;
	uint32_t res[] = { 6, 8, 10, 14 };
	uint32_t re = __GF (insn, 5, 2);

	lmw_bim |= res[re] << 10;
	CCPU_GPR[NG_SP].u += (imm5u << 3);
	nds32_decode32_lsmw (cpu, lmw_bim, cia);
	cia = CCPU_GPR[NG_LP].u;
	CCPU_SR_CLEAR (PSW, PSW_IFCON);
	return cia;
      }
    }

  if (__GF (insn, 8, 7) == 0x7d)
    {
      int rt5e = __GF (insn, 4, 4) << 1;
      int ra5e = __GF (insn, 0, 4) << 1;

      CCPU_GPR[rt5e] = CCPU_GPR[ra5e];
      CCPU_GPR[rt5e + 1] = CCPU_GPR[ra5e + 1];
      goto done;
    }

  switch (__GF (insn, 9, 6))
    {
    case 0x4:			/* add45 */
      CCPU_GPR[rt4].u += CCPU_GPR[ra5].u;
      goto done;
    case 0x5:			/* sub45 */
      CCPU_GPR[rt4].u -= CCPU_GPR[ra5].u;
      goto done;
    case 0x6:			/* addi45 */
      CCPU_GPR[rt4].u += imm5u;
      goto done;
    case 0x7:			/* subi45 */
      CCPU_GPR[rt4].u -= imm5u;
      goto done;
    case 0x8:			/* srai45 */
      CCPU_GPR[rt4].u = CCPU_GPR[rt4].s >> imm5u;
      goto done;
    case 0x9:			/* srli45 */
      CCPU_GPR[rt4].u = CCPU_GPR[rt4].u >> imm5u;
      goto done;
    case 0xa:			/* slli333 */
      CCPU_GPR[rt3].u = CCPU_GPR[ra3].u << imm3u;
      goto done;
    case 0xc:			/* add333 */
      CCPU_GPR[rt3].u = CCPU_GPR[ra3].u + CCPU_GPR[rb3].u;
      goto done;
    case 0xd:			/* sub333 */
      CCPU_GPR[rt3].u = CCPU_GPR[ra3].u - CCPU_GPR[rb3].u;
      goto done;
    case 0xe:			/* addi333 */
      CCPU_GPR[rt3].u = CCPU_GPR[ra3].u + imm3u;
      goto done;
    case 0xf:			/* subi333 */
      CCPU_GPR[rt3].u = CCPU_GPR[ra3].u - imm3u;
      goto done;
    case 0x10:			/* lwi333 */
    case 0x12:			/* lhi333 */
    case 0x13:			/* lbi333 */
      {
	int shtbl[] = { 2, -1, 1, 0 };

	shift = shtbl[(__GF (insn, 9, 6) - 0x10)];
	addr = CCPU_GPR[ra3].u + (imm3u << shift);
	CCPU_GPR[rt3].u = nds32_ld_aligned (cpu, addr, 1 << shift);
      }
      goto done;
    case 0x11:			/* lwi333.bi */
      CCPU_GPR[rt3].u = nds32_ld_aligned (cpu, CCPU_GPR[ra3].u, 4);
      CCPU_GPR[ra3].u += imm3u << 2;
      goto done;
    case 0x14:			/* swi333 */
    case 0x16:			/* shi333 */
    case 0x17:			/* sbi333 */
      {
	int shtbl[] = { 2, -1, 1, 0 };

	shift = shtbl[(__GF (insn, 9, 6) - 0x14)];
	nds32_st_aligned (cpu, CCPU_GPR[ra3].u + (imm3u << shift),
			  1 << shift, CCPU_GPR[rt3].u);
      }
      goto done;
    case 0x15:			/* swi333.bi */
      nds32_st_aligned (cpu, CCPU_GPR[ra3].u, 4, CCPU_GPR[rt3].u);
      CCPU_GPR[ra3].u += imm3u << 2;
      goto done;
    case 0x18:			/* addri36.sp */
      CCPU_GPR[rt3].u = CCPU_GPR[NG_SP].u + (N16_IMM6U (insn) << 2);
      goto done;
    case 0x19:			/* lwi45.fe */
      {
	/* Not tested yet */
	int imm7n = -((32 - imm5u) << 2);

	CCPU_GPR[rt4].u = nds32_ld_aligned (cpu, CCPU_GPR[8].u + imm7n, 4);
      }
      goto done;
    case 0x1a:			/* lwi450 */
      CCPU_GPR[rt4].u = nds32_ld_aligned (cpu, CCPU_GPR[ra5].u, 4);
      goto done;
    case 0x1b:			/* swi450 */
      nds32_st_aligned (cpu, CCPU_GPR[ra5].u, 4, CCPU_GPR[rt4].u);
      goto done;
    case 0x30:			/* slts45 */
      CCPU_GPR[NG_TA].u = (CCPU_GPR[rt4].s < CCPU_GPR[ra5].s) ? 1 : 0;
      goto done;
    case 0x31:			/* slt45 */
      CCPU_GPR[NG_TA].u = (CCPU_GPR[rt4].u < CCPU_GPR[ra5].u) ? 1 : 0;
      goto done;
    case 0x32:			/* sltsi45 */
      CCPU_GPR[NG_TA].u = (CCPU_GPR[rt4].s < imm5u) ? 1 : 0;
      goto done;
    case 0x33:			/* slti45 */
      CCPU_GPR[NG_TA].u = (CCPU_GPR[rt4].u < imm5u) ? 1 : 0;
      goto done;

    case 0x34:			/* beqzs8, bnezs8 */
      if (((insn & (1 << 8)) == 0) ^ (CCPU_GPR[NG_TA].u != 0))
	return cia + (N16_IMM8S (insn) << 1);
      goto done;
    case 0x35:			/* break16, ex9.it */
      if (imm9u < 32)		/* break16 */
	{
	  sim_engine_halt (CPU_STATE (cpu), cpu, NULL, cia, sim_stopped, SIM_SIGTRAP);
	  return cia;
	}

      /* ex9.it */
      sim_read (sd, (CCPU_USR[NC_ITB].u & 0xfffffffc) + (imm9u << 2),
		(unsigned char *) &insn, 4);
      insn = extract_unsigned_integer ((unsigned char *) &insn, 4, BIG_ENDIAN);
      return nds32_decode16_ex9 (cpu, insn, cia);
    case 0x3c:			/* ifcall9 */
      if (!CCPU_SR_TEST (PSW, PSW_IFCON))
	{
	  CCPU_USR[NC_IFCLP].u = cia + 2;
	  CCPU_SR_SET (PSW, PSW_IFCON);
	  return cia + (N16_IMM9U (insn) << 1);
	}
      else
	{
	  /* FIXME: Raise Exception */
	}
      goto done;
    case 0x3d:			/* movpi45 */
      CCPU_GPR[rt4].u = imm5u + 16;
      goto done;
    case 0x3f:			/* MISC33 */
      switch (insn & 0x7)
	{
	case 2:			/* neg33 */
	  CCPU_GPR[rt3].s = -CCPU_GPR[ra3].u;
	  goto done;
	case 3:			/* not33 */
	  CCPU_GPR[rt3].u = ~CCPU_GPR[ra3].u;
	  goto done;
	case 4:			/* mul33 */
	  CCPU_GPR[rt3].u = CCPU_GPR[rt3].u * CCPU_GPR[ra3].u;
	  goto done;
	case 5:			/* xor33 */
	  CCPU_GPR[rt3].u = CCPU_GPR[rt3].u ^ CCPU_GPR[ra3].u;
	  goto done;
	case 6:			/* and33 */
	  CCPU_GPR[rt3].u = CCPU_GPR[rt3].u & CCPU_GPR[ra3].u;
	  goto done;
	case 7:			/* or33 */
	  CCPU_GPR[rt3].u = CCPU_GPR[rt3].u | CCPU_GPR[ra3].u;
	  goto done;
	default:
	  goto bad_op;
	}
      goto done;
    case 0xb:			/* ... */
      switch (insn & 0x7)
	{
	case 0:			/* zeb33 */
	  CCPU_GPR[rt3].u = CCPU_GPR[ra3].u & 0xff;
	  break;
	case 1:			/* zeh33 */
	  CCPU_GPR[rt3].u = CCPU_GPR[ra3].u & 0xffff;
	  break;
	case 2:			/* seb33 */
	  CCPU_GPR[rt3].s = __SEXT (CCPU_GPR[ra3].s, 8);
	  break;
	case 3:			/* seh33 */
	  CCPU_GPR[rt3].s = __SEXT (CCPU_GPR[ra3].s, 16);
	  break;
	case 4:			/* xlsb33 */
	  CCPU_GPR[rt3].u = CCPU_GPR[ra3].u & 0x1;
	  break;
	case 5:			/* x11b33 */
	  CCPU_GPR[rt3].u = CCPU_GPR[ra3].u & 0x7FF;
	  break;
	case 6:			/* bmski33 */
	  CCPU_GPR[rt3].u = CCPU_GPR[rt3].u & (1 << __GF (insn, 3, 3));
	  break;
	case 7:			/* fexti33 */
	  CCPU_GPR[rt3].u = CCPU_GPR[rt3].u & ((1 << (__GF (insn, 3, 3) + 1)) - 1);
	  break;
	}
      goto done;
    }

  switch (__GF (insn, 10, 5))
    {
    case 0x0:			/* mov55 or ifret16 */
      if (CCPU_SR_TEST (PSW, PSW_IFCON) && rt5 == ra5 && rt5 == 31)
	{
	  CCPU_SR_CLEAR (PSW, PSW_IFCON);
	  return CCPU_USR[NC_IFCLP].u;
	}
      else
	CCPU_GPR[rt5].u = CCPU_GPR[ra5].u;
      goto done;
    case 0x1:			/* movi55 */
      CCPU_GPR[rt5].s = imm5s;
      goto done;
    case 0x1b:			/* addi10s (V2) */
      CCPU_GPR[NG_SP].u += N16_IMM10S (insn);
      goto done;
    }

  switch (__GF (insn, 11, 4))
    {
    case 0x7:			/* lwi37.fp/swi37.fp */
      addr = CCPU_GPR[NG_FP].u + (N16_IMM7U (insn) << 2);
      if (insn & (1 << 7))	/* swi37.fp */
	nds32_st_aligned (cpu, addr, 4, CCPU_GPR[rt38].u);
      else			/* lwi37.fp */
	CCPU_GPR[rt38].u = nds32_ld_aligned (cpu, addr, 4);
      goto done;
    case 0x8:			/* beqz38 */
      if (CCPU_GPR[rt38].u == 0)
	return cia + (N16_IMM8S (insn) << 1);
      goto done;
    case 0x9:			/* bnez38 */
      if (CCPU_GPR[rt38].u != 0)
	return cia + (N16_IMM8S (insn) << 1);
      goto done;
    case 0xa:			/* beqs38/j8, implied r5 */
      if (CCPU_GPR[rt38].u == CCPU_GPR[5].u)	/* rt38 == 5 means j8 */
	{
	  CCPU_SR_CLEAR (PSW, PSW_IFCON);
	  return cia + (N16_IMM8S (insn) << 1);
	}
      goto done;
    case 0xb:			/* bnes38 and others */
      if (rt38 == 5)
	{
	  switch (__GF (insn, 5, 3))
	    {
	    case 0:		/* jr5 */
	    case 4:		/* ret5 */
	      CCPU_SR_CLEAR (PSW, PSW_IFCON);
	      return CCPU_GPR[ra5].u;
	    case 1:		/* jral5 */
	      CCPU_GPR[NG_LP].u = cia + 2;
	      if (CCPU_SR_TEST (PSW, PSW_IFCON))
		{
		  CCPU_GPR[NG_LP] = CCPU_USR[NC_IFCLP];
		  CCPU_SR_CLEAR (PSW, PSW_IFCON);
		}
	      return CCPU_GPR[ra5].u;
	    case 2:		/* ex9.it imm5 */
	      sim_read (sd, (CCPU_USR[NC_ITB].u & 0xfffffffc) + (imm5u << 2),
			(unsigned char *) &insn, 4);
	      insn = extract_unsigned_integer ((unsigned char *) &insn, 4,
					       BIG_ENDIAN);
	      return nds32_decode16_ex9 (cpu, insn, cia);
	    case 5:		/* add5.pc */
	      CCPU_GPR[ra5].u += cia;
	      break;
	    default:
	      goto bad_op;
	    }
	  goto done;
	}
      else if (CCPU_GPR[rt38].u != CCPU_GPR[5].u)
	return cia + (N16_IMM8S (insn) << 1);
      goto done;
    case 0xe:			/* lwi37/swi37 */
      addr = CCPU_GPR[NG_SP].u + (N16_IMM7U (insn) << 2);
      if (insn & (1 << 7))	/* swi37.sp */
	nds32_st_aligned (cpu, addr, 4, CCPU_GPR[rt38].u);
      else			/* lwi37.sp */
	CCPU_GPR[rt38].u = nds32_ld_aligned (cpu, addr, 4);
      goto done;
    }

bad_op:
  nds32_bad_op (cpu, cia, insn, "16-bit");
  return cia;

done:
  return cia + 2;
}

void
sim_engine_run (SIM_DESC sd, int next_cpu_nr, int nr_cpus, int siggnal)
{
  int r;
  sim_cia cia;
  sim_cpu *cpu;
  SIM_ASSERT (STATE_MAGIC (sd) == SIM_MAGIC_NUMBER);
  cpu = STATE_CPU (sd, 0);
  cia = CIA_GET (cpu);

  if (siggnal != 0)
    {
      /* FIXME: Study kernel to make sure this.  */
      sim_engine_halt (CPU_STATE (cpu), cpu, NULL, cia, sim_exited,
		       128 + siggnal);
      return;
    }

  while (1)
    {
      uint32_t insn;

      r = sim_read (sd, cia, (unsigned char *) &insn, 4);
      insn = extract_unsigned_integer ((unsigned char *) &insn, 4,
				       BIG_ENDIAN);

      SIM_ASSERT (r == 4);

      if (TRACE_LINENUM_P (cpu))
	{
	  trace_prefix (sd, cpu, NULL_CIA, cia, TRACE_LINENUM_P (cpu),
			NULL, 0, " "); /* Use a space for gcc warnings.  */
	}

      if ((insn & 0x80000000) == 0)
	cia = nds32_decode32 (cpu, insn, cia);
      else
	cia = nds32_decode16 (cpu, insn >> 16, cia);

      if (TRACE_LINENUM_P (cpu))
	{
	  trace_result_addr1 (sd, cpu, TRACE_INSN_IDX, cia);
	}
      /* Sync registers. TODO: Sync PSW with current_target_endian.  */
      CIA_SET (cpu, cia);

      /* process any events */
      if (sim_events_tick (sd))
	{
	  CIA_SET (cpu, cia);
	  sim_events_process (sd);
	}
    }
}

/* This function is mainly used for fetch general purpose registers.
   GDB remote-sim calls this too, so it will be used for fetch some
   USR (PC, D0, D1), FLOAT, SR (PSW).  */

static int
nds32_fetch_register (sim_cpu *cpu, int rn, unsigned char *memory, int length)
{
  ulongest_t val = 0;

  /* General purpose registers.  */
  if (rn < 32)
    {
      val = cpu->reg_gpr[rn].u;
      goto do_fetch;
    }

  /* Special user registers.  */
  switch (rn)
    {
    case NG_PC:
      val = cpu->reg_usr[NC_PC].u;
      goto do_fetch;
    case NG_D0LO:
      val = cpu->reg_usr[NC_D0LO].u;
      goto do_fetch;
    case NG_D0HI:
      val = cpu->reg_usr[NC_D0HI].u;
      goto do_fetch;
    case NG_D1LO:
      val = cpu->reg_usr[NC_D1LO].u;
      goto do_fetch;
    case NG_D1HI:
      val = cpu->reg_usr[NC_D1HI].u;
      goto do_fetch;
    case NG_ITB:
      val = cpu->reg_usr[NC_ITB].u;
      goto do_fetch;
    case NG_IFCLP:
      val = cpu->reg_usr[NC_IFCLP].u;
      goto do_fetch;
    }

  if (rn >= NG_FS0 && rn < NG_FS0 + 64)
    {
      int fr = rn - NG_FS0;
      if (fr < 32)
	val = cpu->reg_fpr[fr].u;
      else
	{
	  fr = (fr - 32) << 1;
	  val = ((uint64_t) cpu->reg_fpr[fr].u << 32)
		| (uint64_t) cpu->reg_fpr[fr + 1].u;
	}
      goto do_fetch;
    }

  /* System registers.  */
  switch (rn)
    {
    case NG_PSW:
      val = cpu->reg_sr[SRIDX (1, 0, 0)].u;
      goto do_fetch;
    }
  return 0;

do_fetch:
  store_unsigned_integer (memory, length,
			  CCPU_SR_TEST (PSW, PSW_BE)
			  ? BIG_ENDIAN : LITTLE_ENDIAN,
			  val);
  return 4;
}

static int
nds32_store_register (sim_cpu *cpu, int rn, unsigned char *memory, int length)
{
  ulongest_t val;

  val = extract_unsigned_integer (memory, length,
				  CCPU_SR_TEST (PSW, PSW_BE)
				  ? BIG_ENDIAN : LITTLE_ENDIAN);

  /* General purpose registers.  */
  if (rn < 32)
    {
      cpu->reg_gpr[rn].u = val;
      return 4;
    }

  /* Special user registers.  */
  switch (rn)
    {
    case NG_PC:
      cpu->reg_usr[NC_PC].u = val;
      return 4;
    case NG_D0LO:
      cpu->reg_usr[NC_D0LO].u = val;
      return 4;
    case NG_D0HI:
      cpu->reg_usr[NC_D0HI].u = val;
      return 4;
    case NG_D1LO:
      cpu->reg_usr[NC_D1LO].u = val;
      return 4;
    case NG_D1HI:
      cpu->reg_usr[NC_D1HI].u = val;
      return 4;
    case NG_ITB:
      cpu->reg_usr[NC_ITB].u = val;
      return 4;
    case NG_IFCLP:
      cpu->reg_usr[NC_IFCLP].u = val;
      return 4;
    }

  /* System registers.  */
  switch (rn)
    {
    case NG_PSW:
      cpu->reg_sr[SRIDX (1, 0, 0)].u = val;
      return 4;
    }
  return 0;
}

static sim_cia
nds32_pc_get (sim_cpu *cpu)
{
  return cpu->reg_usr[NC_PC].u;
}

static void
nds32_pc_set (sim_cpu *cpu, sim_cia cia)
{
  cpu->reg_usr[NC_PC].u = cia;
}

static void
nds32_initialize_cpu (SIM_DESC sd, sim_cpu *cpu, struct bfd *abfd)
{
  /* Common operations defined in sim-cpu.h */
  CPU_REG_FETCH (cpu) = nds32_fetch_register;
  CPU_REG_STORE (cpu) = nds32_store_register;
  CPU_PC_FETCH (cpu) = nds32_pc_get;
  CPU_PC_STORE (cpu) = nds32_pc_set;

  /* CPU_VER: N12 + COP/FPU */
  CCPU_SR[SRIDX (0, 0, 0)].u = (0xc << 24) | 3;

  /* MSC_CFG */
  /* User code may need this for specialized code. e.g., set $ITB.  */
  CCPU_SR_SET (MSC_CFG, MSC_CFG_PFM);
  CCPU_SR_SET (MSC_CFG, MSC_CFG_DIV);
  CCPU_SR_SET (MSC_CFG, MSC_CFG_MAC);
  CCPU_SR_SET (MSC_CFG, MSC_CFG_IFC);
  CCPU_SR_SET (MSC_CFG, MSC_CFG_EIT);
}

SIM_DESC
sim_open (SIM_OPEN_KIND kind, host_callback * callback,
	  struct bfd *abfd, char **argv)
{
  int i;
  SIM_DESC sd = sim_state_alloc (kind, callback);

  /* The cpu data is kept in a separately allocated chunk of memory.  */
  if (sim_cpu_alloc_all (sd, 1, 0) != SIM_RC_OK)
    {
      nds32_free_state (sd);
      return 0;
    }

  if (sim_pre_argv_init (sd, argv[0]) != SIM_RC_OK)
    {
      nds32_free_state (sd);
      return 0;
    }

  /* Handle target sim arguments. */
  if (sim_parse_args (sd, argv) != SIM_RC_OK)
    {
      nds32_free_state (sd);
      return 0;
    }

  /* Check for/establish the a reference program image.  */
  if (sim_analyze_program (sd,
			   (STATE_PROG_ARGV (sd) != NULL
			    ? *STATE_PROG_ARGV (sd)
			    : NULL), abfd) != SIM_RC_OK)
    {
      nds32_free_state (sd);
      return 0;
    }

#if 0
  /* COLE: Not sure whether this is necessary. */

  /* Establish any remaining configuration options.  */
  if (sim_config (sd) != SIM_RC_OK)
    {
      nds32_free_state (sd);
      return 0;
    }
#endif

  if (sim_post_argv_init (sd) != SIM_RC_OK)
    {
      nds32_free_state (sd);
      return 0;
    }

  /* CPU specific initialization.  */
  for (i = 0; i < MAX_NR_PROCESSORS; ++i)
    {
      sim_cpu *cpu = STATE_CPU (sd, i);
      nds32_initialize_cpu (sd, cpu, abfd);
    }

  callback->syscall_map = cb_nds32_syscall_map;

  return sd;
}

void
sim_close (SIM_DESC sd, int quitting)
{
  /* Nothing to do.  */
}

SIM_RC
sim_create_inferior (SIM_DESC sd, struct bfd *prog_bfd, char **argv,
		     char **env)
{
  SIM_CPU *cpu = STATE_CPU (sd, 0);

  /* Set the initial register set.  */
  if (prog_bfd == NULL)
    return SIM_RC_OK;

  /* Set PC to entry point address.  */
  (*CPU_PC_STORE (cpu)) (cpu, bfd_get_start_address (prog_bfd));

  /* Set default endian.  */
  if (bfd_big_endian (prog_bfd))
    CCPU_SR_SET (PSW, PSW_BE);
  else
    CCPU_SR_CLEAR (PSW, PSW_BE);

  if (STATE_ENVIRONMENT (sd) == USER_ENVIRONMENT)
    nds32_init_linux (sd, prog_bfd, argv, env);
  else
    nds32_init_libgloss (sd, prog_bfd, argv, env);

  return SIM_RC_OK;
}

void
sim_kill (SIM_DESC sd)
{
  /* Nothing to do.  */
}

void
sim_set_callbacks (host_callback * ptr)
{
  /* callback = ptr; */
}