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
#include "gdb/callback.h"
#include "gdb/signals.h"
#include "libiberty.h"
#include "gdb/remote-sim.h"
#include "dis-asm.h"
#include "sim-main.h"
#include "sim-utils.h"
#include "sim-fpu.h"

#include "opcode/nds32.h"
#include "nds32-libc.h"

/* Debug flag to display instructions and registers.  */
static int tracing = 0;
static int lock_step = 0;
static int verbose;

/* The only real register.  */
static unsigned int pc;

/* We update a cycle counter.  */
static unsigned int cycles = 0;

static struct bfd *cur_bfd;

static enum sim_stop cpu_exception;
static int cpu_signal;

static SIM_OPEN_KIND sim_kind;
static char *myname;
static host_callback *callback;

reg_t nds32_gpr[32];		/* 32 GPR */
reg_t nds32_usr[32 * 32];	/* Group, Usr */
reg_t nds32_sr[8 * 16 * 8];	/* Major, Minor, Ext */
reg_t nds32_fpr[64];

uint32_t *nds32_pc = (uint32_t *) (nds32_usr + UXIDX (0, 31));

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

static ulongest_t
extract_unsigned_integer_by_psw (unsigned char *addr, int len)
{
  int order = nds32_psw_be ()? BIG_ENDIAN : LITTLE_ENDIAN;

  return extract_unsigned_integer (addr, len, order);
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

static void
store_unsigned_integer_by_psw (unsigned char *addr, int len, ulongest_t val)
{
  int order = nds32_psw_be () ? BIG_ENDIAN : LITTLE_ENDIAN;

  store_unsigned_integer (addr, len, order, val);
}

/* Read a null terminated string from memory, return in a buffer */

static char *
fetch_str (SIM_DESC sd, address_word addr)
{
  char *buf;
  int nr = 0;
  char null;

  while (sim_read (sd, addr + nr, &null, 1) == 1 && null != 0)
    nr++;
  buf = NZALLOC (char, nr + 1);
  sim_read (sd, addr, buf, nr);

  return buf;
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
nds32_bad_op (SIM_DESC sd, uint32_t pc, uint32_t insn, char *tag)
{
  if (tag == NULL)
    tag = "";

  *nds32_pc = pc;
  cpu_exception = sim_stopped;
  sim_io_printf (sd,
		 "Unhandled %s instruction at pc=0x%x, code=0x%08x\n",
		 tag, pc, insn);
}

static void
nds32_syscall (SIM_DESC sd, int swid)
{
  int r = -1;

  switch (swid)
    {
    case SYS_exit:
      cpu_exception = sim_exited;
      cpu_signal = nds32_gpr[0].s;
      break;
    case SYS_open:
      {
	char *path = fetch_str (sd, nds32_gpr[0].u);

	r = sim_io_open (sd, path, nds32_gpr[1].u);
	free (path);
      }
      break;
    case SYS_close:
      r = sim_io_close (sd, nds32_gpr[0].u);
      break;
    case SYS_read:
      {
	int fd = nds32_gpr[0].s;
	SIM_ADDR addr = nds32_gpr[1].s;
	int nr = nds32_gpr[2].s;
	char *buf = zalloc (nr);

	r = sim_io_read (sd, fd, buf, nr);
	if (r > 0)
	  sim_write (sd, addr, buf, r);
	/* SIM_IO_DPRINTF (sd, "sys_read () = %s\n", buf); */
      }
      break;
    case SYS_write:
      {
	int fd = nds32_gpr[0].s;
	SIM_ADDR addr = nds32_gpr[1].s;
	int nr = nds32_gpr[2].s;
	char *buf = zalloc (nr);

	sim_read (sd, addr, buf, nr);
#if 0
	if (fd == 1)
	  r = sim_io_write_stdout (sd, buf, nr);
	else if (fd == 2)
	  r = sim_io_write_stderr (sd, buf, nr);
	else
#endif
	/* SIM_IO_DPRINTF (sd, "sys_write (%s)\n", buf); */
	  r = sim_io_write (sd, fd, buf, nr);

	break;
      }
    case SYS_lseek:
      r = sim_io_lseek (sd, nds32_gpr[0].s, nds32_gpr[1].s, nds32_gpr[2].s);
      break;
    case SYS_fstat:
      {
	SIM_ADDR addr = nds32_gpr[1].s;
	struct stat stat;
	struct nds32_stat nstat;

	SIM_ASSERT (sizeof (struct nds32_stat) == 60);
	r = sim_io_fstat (sd, nds32_gpr[0].s, &stat);
	if (r >= 0)
	  {
	    memset (&nstat, 0, sizeof (nstat));
	    nstat.st_dev = stat.st_dev;
	    nstat.st_ino = stat.st_ino;
	    nstat.st_mode = stat.st_mode;
	    nstat.st_nlink = stat.st_nlink;
	    nstat.st_uid = stat.st_uid;
	    nstat.st_gid = stat.st_gid;
	    nstat.st_rdev = stat.st_rdev;
	    nstat.st_size = stat.st_size;
	    nstat.st_atime_ = stat.st_atime;
	    nstat.st_mtime_ = stat.st_mtime;
	    nstat.st_ctime_ = stat.st_ctime;
	    sim_write (sd, addr, (unsigned char *) &nstat,
		       sizeof (struct nds32_stat));
	  }
      }
      break;
    case SYS_isatty:
      r = sim_io_isatty (sd, nds32_gpr[0].s);
      break;
    case SYS_getcmdline:
      r = nds32_gpr[0].u;
      sim_write (sd, nds32_gpr[0].u, sd->cmdline, strlen (sd->cmdline) + 1);
      break;
    case SYS_errno:
      break;
    case SYS_time:
      break;
    case SYS_gettimeofday:
      break;
    case SYS_times:
      break;
    default:
      nds32_bad_op (sd, *nds32_pc - 4, swid, "syscall");
      break;
    }

  nds32_gpr[0].s = r;
}


longest_t
nds32_ld_sext (SIM_DESC sd, SIM_ADDR addr, int size)
{
  int r;
  longest_t val = 0;
  int order;
  SIM_ASSERT (size <= sizeof (longest_t));

  r = sim_read (sd, addr, (unsigned char *) &val, size);
  order = nds32_psw_be () ? BIG_ENDIAN : LITTLE_ENDIAN;
  val = extract_unsigned_integer ((unsigned char *) &val, size, order);
  val = __SEXT (val, size * 8);

  if (r != size)
    {
      sim_io_eprintf (sd, "access violation at 0x%x. pc=0x%x\n", addr, *nds32_pc);
      cpu_exception = sim_stopped;
    }

  return val;
}

ulongest_t
nds32_ld (SIM_DESC sd, SIM_ADDR addr, int size)
{
  int r;
  ulongest_t val = 0;
  int order;
  SIM_ASSERT (size <= sizeof (ulongest_t));

  r = sim_read (sd, addr, (unsigned char *) &val, size);
  order = nds32_psw_be () ? BIG_ENDIAN : LITTLE_ENDIAN;
  val = extract_unsigned_integer ((unsigned char *) &val, size, order);

  if (r != size)
    {
      sim_io_eprintf (sd, "access violation at 0x%x. pc=0x%x\n", addr, *nds32_pc);
      cpu_exception = sim_stopped;
    }

  return val;
}

void
nds32_st (SIM_DESC sd, SIM_ADDR addr, int size, ulongest_t val)
{
  int r;
  int order;
  SIM_ASSERT (size <= sizeof (ulongest_t));

  order = nds32_psw_be () ? BIG_ENDIAN : LITTLE_ENDIAN;
  store_unsigned_integer ((unsigned char *) &val, size, order, val);
  r = sim_write (sd, addr, (unsigned char *) &val, size);

  if (r != size)
    {
      sim_io_eprintf (sd, "access violation at 0x%x. pc=0x%x\n", addr, *nds32_pc);
      cpu_exception = sim_stopped;
    }

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

static void
nds32_decode32_mem (SIM_DESC sd, const uint32_t insn)
{
  const int rt = N32_RT5 (insn);
  const int ra = N32_RA5 (insn);
  const int rb = N32_RB5 (insn);
  const int sv = __GF (insn, 8, 2);
  const int op = insn & 0xFF;

  switch (op)
    {
    case 0x0:			/* lb */
    case 0x1:			/* lh */
    case 0x2:			/* lw */
    case 0x3:			/* ld */
      nds32_gpr[rt].u =
	nds32_ld (sd, nds32_gpr[ra].u + (nds32_gpr[rb].u << sv), (1 << (op)));
      return;
    case 0x4:			/* lb.bi */
    case 0x5:			/* lh.bi */
    case 0x6:			/* lw.bi */
    case 0x7:			/* ld.bi */
      nds32_gpr[rt].u = nds32_ld (sd, nds32_gpr[ra].u, (1 << (op & 0x3)));
      nds32_gpr[ra].u += (nds32_gpr[rb].u << sv);
      return;
    case 0x8:			/* sb */
    case 0x9:			/* sh */
    case 0xa:			/* sw */
    case 0xb:			/* sd */
      nds32_st (sd, nds32_gpr[ra].u + (nds32_gpr[rb].u << sv), (1 << (op & 0x3)),
		nds32_gpr[rt].u);
      return;
    case 0xc:			/* sb.bi */
    case 0xd:			/* sh.bi */
    case 0xe:			/* sw.bi */
    case 0xf:			/* sd.bi */
      nds32_st (sd, nds32_gpr[ra].u, (1 << (op & 0x3)), nds32_gpr[rt].u);
      nds32_gpr[ra].u += (nds32_gpr[rb].u << sv);
      return;
    case 0x10:			/* lbs */
    case 0x11:			/* lhs */
    case 0x12:			/* lws */
      nds32_gpr[rt].u =
	nds32_ld_sext (sd, nds32_gpr[ra].u + (nds32_gpr[rb].u << sv), (1 << (op & 0x3)));
      return;
    case 0x13:			/* dpref */
      /* do nothing */
      return;
    case 0x14:			/* lbs.bi */
    case 0x15:			/* lhs.bi */
    case 0x16:			/* lws.bi */
      nds32_gpr[rt].u = nds32_ld_sext (sd, nds32_gpr[ra].u, (1 << (op & 0x3)));
      nds32_gpr[ra].u += (nds32_gpr[rb].u << sv);
      return;
    case 0x18:			/* llw */
    case 0x19:			/* scw */
    case 0x20:			/* lbup */
    case 0x22:			/* lwup */
    case 0x28:			/* sbup */
    case 0x2a:			/* swup */
	goto bad_op;
    }

bad_op:
  nds32_bad_op (sd, *nds32_pc - 4, insn, "MEM");
}

static void
nds32_decode32_lsmw (SIM_DESC sd, const uint32_t insn)
{
  /* smwa?.(a|b)(d|i)m? rb,[ra],re,enable4 */
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

  base = nds32_gpr[ra].u;

  if (insn & (1 << 0x4))	/* a:b, a for +-4 */
    base += 4 * di;

  if (di == 1)
    base += (m - 4);

  switch (insn & 0x23)
    {
    case 33:			/* smwa */
      sim_io_error (sd, "SMWA aligment is not checked at 0x%x\n", *nds32_pc);
    case 32:			/* smw */
      /* TODO: alignment exception check for SMWA */
      for (i = 0; i < 4; i++)
	{
	  if (enable4 & (1 << enb4map[aligned][i]))
	    {
	      sim_write (sd, base, reg, 4);
	      nds32_st (sd, base, 4,
			nds32_gpr[NG_SP - (enb4map[aligned][i])].u);
	      base -= 4;
	    }
	}

      /* Skip if re == rb == sp > fp.  */
      for (i = re; i >= rb && rb < NG_FP; i--)
	{
	  nds32_st (sd, base, 4, nds32_gpr[i].u);
	  base -= 4;
	}

      if (insn & (1 << 2))
	nds32_gpr[ra].u += m * di;
      return;
    case 1:			/* lmwa */
      sim_io_error (sd, "LMWA aligment is not checked.\n");
    case 0:			/* lmw */
      /* TODO: alignment exception check for SMWA */
      for (i = 0; i < 4; i++)
	{
	  if (enable4 & (1 << enb4map[aligned][i]))
	    {
	      nds32_gpr[NG_SP - (enb4map[aligned][i])].u
		= nds32_ld (sd, base, 4);
	      base -= 4;
	    }
	}

      /* Skip if re == rb == sp > fp.  */
      for (i = re; i >= rb && rb < NG_FP; i--)
	{
	  nds32_gpr[i].u = nds32_ld (sd, base, 4);
	  base -= 4;
	}

      if (insn & (1 << 2))
	nds32_gpr[ra].u += m * di;
      return;
    case 2:			/* lmwzb */
    case 34:			/* smwzb */
    default:
      nds32_bad_op (sd, *nds32_pc - 4, insn, "LSMW");
    }
}

static void
nds32_decode32_alu1 (SIM_DESC sd, const uint32_t insn)
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
      nds32_gpr[rt].u = nds32_gpr[ra].u + (nds32_gpr[rb].u << sh5);
      return;
    case 0x1:			/* sub, sub_slli */
      nds32_gpr[rt].u = nds32_gpr[ra].u - (nds32_gpr[rb].u << sh5);
      return;
    case 0x2:			/* and, add_slli */
      nds32_gpr[rt].u = nds32_gpr[ra].u & (nds32_gpr[rb].u << sh5);
      return;
    case 0x3:			/* xor, xor_slli */
      nds32_gpr[rt].u = nds32_gpr[ra].u ^ (nds32_gpr[rb].u << sh5);
      return;
    case 0x4:			/* or, or_slli */
      nds32_gpr[rt].u = nds32_gpr[ra].u | (nds32_gpr[rb].u << sh5);
      return;
    case 0x5:			/* nor */
      nds32_gpr[rt].u = ~(nds32_gpr[ra].u | nds32_gpr[rb].u);
      return;
    case 0x6:			/* slt */
      nds32_gpr[rt].u = nds32_gpr[ra].u < nds32_gpr[rb].u ? 1 : 0;
      return;
    case 0x7:			/* slts */
      nds32_gpr[rt].u = nds32_gpr[ra].s < nds32_gpr[rb].s ? 1 : 0;
      return;

    case 0x8:			/* slli */
      nds32_gpr[rt].u = nds32_gpr[ra].u << imm5u;
      return;
    case 0x9:			/* srli */
      nds32_gpr[rt].u = nds32_gpr[ra].u >> imm5u;
      return;
    case 0xa:			/* srai */
      nds32_gpr[rt].s = nds32_gpr[ra].s >> imm5u;
      return;
    case 0xc:			/* sll */
      nds32_gpr[rt].u = nds32_gpr[ra].u << (nds32_gpr[rb].u & 0x1f);
      return;
    case 0xd:			/* srl */
      nds32_gpr[rt].u = nds32_gpr[ra].u >> nds32_gpr[rb].u;
      return;
    case 0xe:			/* sra */
      nds32_gpr[rt].s = nds32_gpr[ra].s >> nds32_gpr[rb].u;
      return;
    case 0xb:			/* rotri */
    case 0xf:			/* rotr */
      {
	uint32_t shift = ((insn & 0x1f) == 0xb) ? imm5u : nds32_gpr[rb].u;
	uint32_t m = nds32_gpr[ra].u & ((1 << shift) - 1);
	nds32_gpr[rt].u = nds32_gpr[ra].u >> shift;
	nds32_gpr[rt].u |= m << (32 - shift);
      }
      return;

    case 0x10:			/* seb */
      nds32_gpr[rt].s = __SEXT (nds32_gpr[ra].s, 8);
      return;
    case 0x11:			/* seh */
      nds32_gpr[rt].s = __SEXT (nds32_gpr[ra].s, 16);
      return;
    case 0x12:			/* bitc */
      nds32_gpr[rt].u = nds32_gpr[ra].u & ~(nds32_gpr[rb].u);
      return;
    case 0x13:			/* zeh */
      nds32_gpr[rt].u = nds32_gpr[ra].u & 0xffff;
      return;
    case 0x14:			/* wsbh */
      nds32_gpr[rt].u = ((nds32_gpr[ra].u & 0xFF00FF00) >> 8)
			| ((nds32_gpr[ra].u & 0x00FF00FF) << 8);
      return;
    case 0x15:			/* or_srli */
      nds32_gpr[rt].u = nds32_gpr[ra].u | (nds32_gpr[rb].u >> sh5);
      return;
    case 0x16:			/* divsr */
      {
	/* FIXME: Positive qoutient exception.  */
	int64_t q;
	int64_t r;

	q = nds32_gpr[ra].s / nds32_gpr[rb].s;
	r = nds32_gpr[ra].s % nds32_gpr[rb].s;
	nds32_gpr[rt].s = q;
	if (rt != rd)
	  nds32_gpr[rd].s = r;
      }
      return;
    case 0x17:			/* divr */
      {
	uint64_t q;
	uint64_t r;

	q = nds32_gpr[ra].u / nds32_gpr[rb].u;
	r = nds32_gpr[ra].u % nds32_gpr[rb].u;
	nds32_gpr[rt].u = q;
	if (rt != rd)
	  nds32_gpr[rd].u = r;
      }
      return;
    case 0x18:			/* sva */
      {
	uint64_t s = (uint64_t)nds32_gpr[ra].u + (uint64_t)nds32_gpr[rb].u;
	s = (s >> 31) & 0x3;
	nds32_gpr[rt].u = (s == 0 || s == 3);
      }
      return;
    case 0x19:			/* svs */
      return;
    case 0x1a:			/* comvz */
      if (nds32_gpr[rb].u == 0)
	nds32_gpr[rt].u = nds32_gpr[ra].u;
      return;
    case 0x1b:			/* comvn */
      if (nds32_gpr[rb].u != 0)
	nds32_gpr[rt].u = nds32_gpr[ra].u;
      return;
    case 0x1c:			/* add_srli */
      nds32_gpr[rt].u = nds32_gpr[ra].u + (nds32_gpr[rb].u >> sh5);
      return;
    case 0x1d:			/* sub_srli */
      nds32_gpr[rt].u = nds32_gpr[ra].u - (nds32_gpr[rb].u >> sh5);
      return;
    case 0x1e:			/* and_srli */
      nds32_gpr[rt].u = nds32_gpr[ra].u & (nds32_gpr[rb].u >> sh5);
      return;
    case 0x1f:			/* xor_srli */
      nds32_gpr[rt].u = nds32_gpr[ra].u ^ (nds32_gpr[rb].u >> sh5);
      return;
    }

bad_op:
  nds32_bad_op (sd, *nds32_pc - 4, insn, "ALU1");
}

static void
nds32_decode32_alu2 (SIM_DESC sd, const uint32_t insn)
{
  int rt = N32_RT5 (insn);
  int ra = N32_RA5 (insn);
  int rb = N32_RB5 (insn);
  const int imm5u = rb;
  const int dt = (insn & (1 << 21)) ? NC_D1LO : NC_D0LO;

  switch (insn & 0x3ff)
    {
    case 0x0:			/* max */
      nds32_gpr[rt].s = (nds32_gpr[ra].s > nds32_gpr[rb].s) ? nds32_gpr[ra].s: nds32_gpr[rb].s;
      return;
    case 0x1:			/* min */
      nds32_gpr[rt].s = (nds32_gpr[ra].s < nds32_gpr[rb].s) ? nds32_gpr[ra].s: nds32_gpr[rb].s;
      return;
    case 0x2:			/* ave */
      {
        int64_t r = ((int64_t)nds32_gpr[ra].s << 1) + ((int64_t)nds32_gpr[rb].s << 1) + 1;
	nds32_gpr[rt].u = (r >> 1) & 0xFFFFFFFF;
      }
      return;
    case 0x3:			/* abs */
      if (nds32_gpr[ra].s >= 0)
	nds32_gpr[rt].s = nds32_gpr[ra].s;
      else if (nds32_gpr[ra].u == 0x80000000)
	nds32_gpr[rt].u = 0x7fffffff;
      else
	nds32_gpr[rt].s = -nds32_gpr[ra].s;
      return;
    case 0x6:			/* clo */
      {
	int i, cnt = 0;

	for (i = 31; i >= 0; i--)
	  {
	    if (nds32_gpr[ra].u & (1 << i))
	      cnt++;
	    else
	      break;
	  }
	nds32_gpr[rt].u = cnt;
      }
      return;
    case 0x7:			/* clz */
      {
	int i, cnt = 0;

	for (i = 31; i >= 0; i--)
	  {
	    if ((nds32_gpr[ra].u & (1 << i)) == 0)
	      cnt++;
	    else
	      break;
	  }
	nds32_gpr[rt].u = cnt;
      }
      return;
    case 0x8:			/* bset */
      nds32_gpr[rt].u = nds32_gpr[ra].u | (1 << imm5u);
      return;
    case 0x9:			/* bclr */
      nds32_gpr[rt].u = nds32_gpr[ra].u & ~(1 << imm5u);
      return;
    case 0xa:			/* btgl */
      nds32_gpr[rt].u = nds32_gpr[ra].u ^ (1 << imm5u);
      return;
    case 0xb:			/* btst */
      nds32_gpr[rt].u = (nds32_gpr[ra].u & (1 << imm5u)) != 0;
      return;
    case 0x24:			/* mul */
      nds32_gpr[rt].u = nds32_gpr[ra].u * nds32_gpr[rb].u;
      return;
    case 0x20:			/* mfusr */
      nds32_gpr[rt].u = nds32_usr[rb << 5 | ra].u;
      return;
    case 0x21:			/* mtusr */
      nds32_usr[rb << 5 | ra].u = nds32_gpr[rt].u;
      return;
    case 0x28:			/* mults64 */
      {
	int64_t d = (int64_t) nds32_gpr[ra].s * (int64_t) nds32_gpr[rb].s;

	nds32_usr[dt].s = d & 0xFFFFFFFF;
	nds32_usr[dt + 1].s = (d >> 32) & 0xFFFFFFFF;
      }
      return;
    case 0x29:			/* mult64 */
      {
	uint64_t d = (uint64_t) nds32_gpr[ra].u * (uint64_t) nds32_gpr[rb].u;

	nds32_usr[dt].u = d & 0xFFFFFFFF;
	nds32_usr[dt + 1].u = (d >> 32) & 0xFFFFFFFF;
      }
      return;
    case 0x2a:			/* madds64 */
      {
	int64_t mr = (int64_t) nds32_gpr[ra].s * (int64_t) nds32_gpr[rb].s;
	int64_t d = ((int64_t) nds32_usr[dt + 1].s << 32)
		    | ((int64_t) nds32_usr[dt].  s & 0xFFFFFFFF);

	d += mr;
	nds32_usr[dt].u = d & 0xFFFFFFFF;
	nds32_usr[dt + 1].u = (d >> 32) & 0xFFFFFFFF;
      }
      return;
    case 0x2b:			/* madd64 */
      {
	uint64_t mr = (uint64_t) nds32_gpr[ra].u * (uint64_t) nds32_gpr[rb].u;
	uint64_t d = ((uint64_t) nds32_usr[dt + 1].u << 32)
		     | ((uint64_t) nds32_usr[dt].u & 0xFFFFFFFF);

	d += mr;
	nds32_usr[dt].u = d & 0xFFFFFFFF;
	nds32_usr[dt + 1].u = (d >> 32) & 0xFFFFFFFF;
      }
      return;
    case 0x2c:			/* msubs64 */
      {
	int64_t mr = (int64_t) nds32_gpr[ra].s * (int64_t) nds32_gpr[rb].s;
	int64_t d = ((int64_t) nds32_usr[dt + 1].s << 32)
		    | ((int64_t) nds32_usr[dt].s & 0xFFFFFFFF);

	d -= mr;
	nds32_usr[dt].u = d & 0xFFFFFFFF;
	nds32_usr[dt + 1].u = (d >> 32) & 0xFFFFFFFF;
      }
      return;
    case 0x2d:			/* msub64 */
      {
	uint64_t mr = (uint64_t) nds32_gpr[ra].u * (uint64_t) nds32_gpr[rb].u;
	uint64_t d = ((uint64_t) nds32_usr[dt + 1].u << 32)
		     | ((uint64_t) nds32_usr[dt].u & 0xFFFFFFFF);

	d -= mr;
	nds32_usr[dt].u = d & 0xFFFFFFFF;
	nds32_usr[dt + 1].u = (d >> 32) & 0xFFFFFFFF;
      }
      return;
    case 0x2e:			/* divs */
      {
	int32_t q;
	int32_t r;

	q = nds32_gpr[ra].s / nds32_gpr[rb].s;
	r = nds32_gpr[ra].s % nds32_gpr[rb].s;
	nds32_usr[dt].s = q;
	nds32_usr[dt + 1].s = r;
      }
      return;
    case 0x2f:			/* div */
      {
	uint32_t q;
	uint32_t r;

	q = nds32_gpr[ra].u / nds32_gpr[rb].u;
	r = nds32_gpr[ra].u % nds32_gpr[rb].u;
	nds32_usr[dt].u = q;
	nds32_usr[dt + 1].u = r;
      }
      return;
    case 0x31:			/* mult32 */
      nds32_usr[dt].s = nds32_gpr[ra].s * nds32_gpr[rb].s;
      return;
    case 0x33:			/* madd32 */
      nds32_usr[dt].s += nds32_gpr[ra].s * nds32_gpr[rb].s;
      return;
    case 0x35:			/* msub32 */
      nds32_usr[dt].s -= nds32_gpr[ra].s * nds32_gpr[rb].s;
      return;
    case 0x68:			/* mulsr64 */
      {
	int64_t r = (int64_t) nds32_gpr[ra].s * (int64_t) nds32_gpr[rb].s;
	int d = rt & ~1;

	if (nds32_psw_be ())
	  {
	    nds32_gpr[d].u = (r >> 32) & 0xFFFFFFFF;
	    nds32_gpr[d + 1].u = r & 0xFFFFFFFF;
	  }
	else
	  {
	    nds32_gpr[d + 1].u = (r >> 32) & 0xFFFFFFFF;
	    nds32_gpr[d].u = r & 0xFFFFFFFF;
	  }
      }
      return;
    case 0x69:			/* mulr64 */
      {
	uint64_t r = (uint64_t) nds32_gpr[ra].u * (uint64_t) nds32_gpr[rb].u;
	int d = rt & ~1;

	if (nds32_psw_be ())
	  {
	    nds32_gpr[d].u = (r >> 32) & 0xFFFFFFFF;
	    nds32_gpr[d + 1].u = r & 0xFFFFFFFF;
	  }
	else
	  {
	    nds32_gpr[d + 1].u = (r >> 32) & 0xFFFFFFFF;
	    nds32_gpr[d].u = r & 0xFFFFFFFF;
	  }
      }
      return;
    case 0x73:			/* maddr32 */
      nds32_gpr[rt].u += (nds32_gpr[ra].u * nds32_gpr[rb].u) & 0xFFFFFFFF;
      return;
    case 0x75:			/* msubr32 */
      nds32_gpr[rt].u -= (nds32_gpr[ra].u * nds32_gpr[rb].u) & 0xFFFFFFFF;
      return;
    }

bad_op:
  nds32_bad_op (sd, *nds32_pc - 4, insn, "ALU2");
}

static void
nds32_decode32_jreg (SIM_DESC sd, const uint32_t insn)
{
  int rt = N32_RT5 (insn);
  int ra = N32_RA5 (insn);
  int rb = N32_RB5 (insn);

  if (ra != 0)
    sim_io_error (sd, "JREG RA == %d at pc=0x%x, code=0x%08x\n",
		  ra, *nds32_pc, insn);

  if (__GF (insn, 8, 2) != 0)
    sim_io_error (sd, "JREG DT/IT not supported at pc=0x%x, code=0x%08x\n",
		  *nds32_pc, insn);

  switch (insn & 0x1f)
    {
    case 0:			/* jr */
      *nds32_pc = nds32_gpr[rb].u;
      /* SIM_IO_DPRINTF (sd, "set $pc to 0x%x\n", *nds32_pc); */
      return;
    case 1:			/* jral */
      nds32_gpr[rt].u = *nds32_pc;
      *nds32_pc = nds32_gpr[rb].u;
      /* SIM_IO_DPRINTF (sd, "set $pc to 0x%x, save ra to $r%d\n", *nds32_pc, rb); */
      return;
    case 2:			/* jrnez */
      if (nds32_gpr[rb].u != 0)
	*nds32_pc = nds32_gpr[rb].u;
      return;
    case 3:			/* jralnez */
      nds32_gpr[rt].u = *nds32_pc;
      if (nds32_gpr[rb].u != 0)
	*nds32_pc = nds32_gpr[rb].u;
      return;
    }
  nds32_bad_op (sd, *nds32_pc - 4, insn, "JREG");
}

static void
nds32_decode32_br1 (SIM_DESC sd, const uint32_t insn)
{
  int rt = N32_RT5 (insn);
  int ra = N32_RA5 (insn);
  int imm14s = N32_IMM14S (insn);

  switch ((insn >> 14) & 1)
    {
    case 0:			/* beq */
      if (nds32_gpr[rt].u == nds32_gpr[ra].u)
	*nds32_pc += -4 + (imm14s << 1);
      return;
    case 1:			/* bne */
      if (nds32_gpr[rt].u != nds32_gpr[ra].u)
	*nds32_pc += -4 + (imm14s << 1);
      return;
    }
  nds32_bad_op (sd, *nds32_pc - 4, insn, "BR1");
}

static void
nds32_decode32_br2 (SIM_DESC sd, const uint32_t insn)
{
  int rt = N32_RT5 (insn);
  int imm16s = N32_IMM16S (insn);

  switch (__GF (insn, 16, 4))
    {
    case 0x2:			/* beqz */
      if (nds32_gpr[rt].s == 0)
	*nds32_pc += -4 + (imm16s << 1);
      return;
    case 0x3:			/* bnez */
      if (nds32_gpr[rt].s != 0)
	*nds32_pc += -4 + (imm16s << 1);
      return;
    case 0x4:			/* bgez */
      if (nds32_gpr[rt].s >= 0)
	*nds32_pc += -4 + (imm16s << 1);
      return;
    case 0x5:			/* bltz */
      if (nds32_gpr[rt].s < 0)
	*nds32_pc += -4 + (imm16s << 1);
      return;
    case 0x6:			/* bgtz */
      if (nds32_gpr[rt].s > 0)
	*nds32_pc += -4 + (imm16s << 1);
      return;
    case 0x7:			/* blez */
      if (nds32_gpr[rt].s <= 0)
	*nds32_pc += -4 + (imm16s << 1);
      return;
    case 0x1c:			/* bgezal */
      if (nds32_gpr[rt].s >= 0)
	{
	  nds32_gpr[NG_LP].u = *nds32_pc;
	  *nds32_pc += -4 + (imm16s << 1);
	}
      return;
    case 0x1d:			/* bltzal */
	if (nds32_gpr[rt].s < 0)
	{
	  nds32_gpr[NG_LP].u = *nds32_pc;
	  *nds32_pc += -4 + (imm16s << 1);
	}
      return;
    }
  nds32_bad_op (sd, *nds32_pc - 4, insn, "BR2");
}

static void
nds32_decode32_misc (SIM_DESC sd, const uint32_t insn)
{
  int rt = N32_RT5 (insn);

  switch (insn & 0x1F)
    {
    case 0x0:			/* standby */
    case 0x1:			/* cctl */
    case 0x4:			/* iret */
    case 0x6:			/* teqz */
    case 0x7:			/* tnez */
    case 0x8:			/* dsb */
    case 0x9:			/* isb */
    case 0xc:			/* msync */
    case 0xd:			/* isync */
    case 0xe:			/* tlbop */
	goto bad_op;
    case 0x5:			/* trap */
    case 0xa:			/* break */
      *nds32_pc -= 4;
      cpu_exception = sim_stopped;
      return;
    case 0x2:			/* mfsr */
      nds32_gpr[rt] = nds32_sr[__GF (insn, 10, 10)];
      return;
    case 0x3:			/* mtsr */
      nds32_sr[__GF (insn, 10, 10)] = nds32_gpr[rt];
      return;
    case 0xb:			/* syscall */
      nds32_syscall (sd, __GF (insn, 5, 15));
      return;
    }

bad_op:
  nds32_bad_op (sd, *nds32_pc - 4, insn, "MISC");
}

static void
nds32_decode32 (SIM_DESC sd, const uint32_t insn)
{
  int op = N32_OP6 (insn);
  int rt = N32_RT5 (insn);
  int ra = N32_RA5 (insn);
  int rb = N32_RB5 (insn);
  int imm15s = N32_IMM15S (insn);
  int imm15u = N32_IMM15U (insn);

  *nds32_pc += 4;

  switch (op)
    {
    case 0x0:			/* lbi */
    case 0x1:			/* lhi */
    case 0x2:			/* lwi */
    case 0x3:			/* ldi */
      {
	int shift = (op - 0x0);

	nds32_gpr[rt].u =
	  nds32_ld (sd, nds32_gpr[ra].u + (imm15s << shift), 1 << shift);
      }
      return;

    case 0x4:			/* lbi.bi */
    case 0x5:			/* lhi.bi */
    case 0x6:			/* lwi.bi */
    case 0x7:			/* ldi.bi */
      {
	int shift = (op - 0x4);

	nds32_gpr[rt].u = nds32_ld (sd, nds32_gpr[ra].u, 1 << shift);
	nds32_gpr[ra].u += (imm15s << shift);
      }
      return;

    case 0x8:			/* sbi */
    case 0x9:			/* shi */
    case 0xa:			/* swi */
    case 0xb:			/* sdi */
      {
	int shift = (op - 0x8);

	nds32_st (sd, nds32_gpr[ra].u + (imm15s << shift), 1 << shift,
		  nds32_gpr[rt].u);
      }
      return;

    case 0xc:			/* sbi.bi */
    case 0xd:			/* shi.bi */
    case 0xe:			/* swi.bi */
    case 0xf:			/* sdi.bi */
      {
	int shift = (op - 0xc);

	nds32_st (sd, nds32_gpr[ra].u, 1 << shift, nds32_gpr[rt].u);
	nds32_gpr[ra].u += (imm15s << shift);
      }
      return;

    case 0x10:			/* lbsi */
    case 0x11:			/* lhsi */
    case 0x12:			/* lwsi */
      {
	int shift = (op - 0x10);

	nds32_gpr[rt].s =
	  nds32_ld_sext (sd, nds32_gpr[ra].u + (imm15s << shift), 1 << shift);
      }
      return;
    case 0x13:			/* dprefi */
      /* do nothing */
      return;
    case 0x14:			/* lbsi.bi */
    case 0x15:			/* lhsi.bi */
    case 0x16:			/* lwsi.bi */
      {
	int shift = (op - 0x14);

	nds32_gpr[rt].s = nds32_ld_sext (sd, nds32_gpr[ra].u, 1 << shift);
	nds32_gpr[ra].u += (imm15s << shift);
      }
      return;
    case 0x17:			/* LBGP */
      if(insn & (1 << 19))	/* lbsi.gp */
	nds32_gpr[rt].s = nds32_ld_sext (sd, nds32_gpr[NG_GP].u + N32_IMMS (insn, 19), 1);
      else			/* lbi.gp */
	nds32_gpr[rt].u = nds32_ld (sd, nds32_gpr[NG_GP].u + N32_IMMS (insn, 19), 1);
      return;
    case 0x18:			/* LWC */
      nds32_decode32_lwc (sd, insn);
      return;
    case 0x19:			/* SWC */
      nds32_decode32_swc (sd, insn);
      return;
    case 0x1a:			/* LDC */
      nds32_decode32_ldc (sd, insn);
      return;
    case 0x1b:			/* SDC */
      nds32_decode32_sdc (sd, insn);
      return;
    case 0x1c:			/* MEM */
      nds32_decode32_mem (sd, insn);
      return;
    case 0x1d:			/* LSMW */
      nds32_decode32_lsmw (sd, insn);
      return;
    case 0x1e:			/* HWGP */
      switch (__GF (insn, 17, 3))
	{
	case 0: case 1:		/* lhi.gp */
	  nds32_gpr[rt].u =
	    nds32_ld (sd, nds32_gpr[NG_GP].u + (N32_IMMS (insn, 18) << 1), 2);
	  break;
	case 2: case 3:		/* lhsi.gp */
	  nds32_gpr[rt].u =
	    nds32_ld_sext (sd, nds32_gpr[NG_GP].u + (N32_IMMS (insn, 18) << 1), 2);
	  break;
	case 4: case 5:		/* shi.gp */
	  nds32_st (sd, nds32_gpr[NG_GP].u + (N32_IMMS (insn, 18) << 1), 2, nds32_gpr[rt].u);
	  break;
	case 6:			/* lwi.gp */
	  nds32_gpr[rt].u =
	    nds32_ld (sd, nds32_gpr[NG_GP].u + (N32_IMMS (insn, 17) << 2), 4);
	  break;
	case 7:			/* swi.gp */
	  nds32_st (sd, nds32_gpr[NG_GP].u + (N32_IMMS (insn, 17) << 2), 4, nds32_gpr[rt].u);
	  break;
	}
      return;
    case 0x1f:			/* SBGP */
      if(insn & (1 << 19))	/* addi.gp */
	nds32_gpr[rt].s = nds32_gpr[NG_GP].u + N32_IMMS (insn, 19);
      else			/* sbi.gp */
	nds32_st (sd, nds32_gpr[NG_GP].u + N32_IMMS (insn, 19), 1, nds32_gpr[rt].u & 0xFF);
      return;
    case 0x20:			/* ALU_1 */
      nds32_decode32_alu1 (sd, insn);
      return;
    case 0x21:			/* ALU_2 */
      nds32_decode32_alu2 (sd, insn);
      return;
    case 0x22:			/* movi */
      nds32_gpr[rt].s = N32_IMM20S (insn);
      return;
    case 0x23:			/* sethi */
      nds32_gpr[rt].u = N32_IMM20U (insn) << 12;
      return;
    case 0x24:			/* ji, jal */
      if (insn & (1 << 24))	/* jal */
	nds32_gpr[NG_LP].u = *nds32_pc;
      *nds32_pc = *nds32_pc - 4 + (N32_IMM24S (insn) << 1);
      return;
    case 0x25:			/* jreg */
      nds32_decode32_jreg (sd, insn);
      return;
    case 0x26:			/* br1 */
      nds32_decode32_br1 (sd, insn);
      return;
    case 0x27:			/* br2 */
      nds32_decode32_br2 (sd, insn);
      return;
    case 0x28:			/* addi rt, ra, imm15s */
      nds32_gpr[rt].s = nds32_gpr[ra].s + imm15s;
      return;
    case 0x29:			/* subri */
      nds32_gpr[rt].s = imm15s - nds32_gpr[ra].s;
      return;
    case 0x2a:			/* andi */
      nds32_gpr[rt].u = nds32_gpr[ra].u & imm15u;
      return;
    case 0x2b:			/* xori */
      nds32_gpr[rt].u = nds32_gpr[ra].u ^ imm15u;
      return;
    case 0x2c:			/* ori */
      nds32_gpr[rt].u = nds32_gpr[ra].u | imm15u;
      return;
    case 0x2d:			/* br3, beqc, bnec */
      {
	int imm11s = __SEXT (__GF (insn, 8, 11), 11);

	if (((insn & (1 << 19)) == 0) ^ (nds32_gpr[rt].s != imm11s))
	  *nds32_pc += -4 + (N32_IMMS (insn, 8) << 1);
      }
      return;
    case 0x2e:			/* slti */
      nds32_gpr[rt].u = (nds32_gpr[ra].u < imm15u) ? 1 : 0;
      return;
    case 0x2f:			/* sltsi */
      nds32_gpr[rt].u = (nds32_gpr[ra].s < imm15s) ? 1 : 0;
      return;
    case 0x32:			/* misc */
      nds32_decode32_misc (sd, insn);
      return;
    case 0x33:			/* bitci */
      nds32_gpr[rt].u = nds32_gpr[ra].u & ~imm15u;
      return;
    case 0x35:			/* COP */
      nds32_decode32_cop (sd, insn);
      return;
    }

bad_op:
  nds32_bad_op (sd, *nds32_pc - 4, insn, "32-bit");
}

static void
nds32_decode16 (SIM_DESC sd, uint32_t insn)
{
  const int rt5 = N16_RT5 (insn);
  const int ra5 = N16_RA5 (insn);
  const int rt4 = N16_RT4 (insn);
  const int imm5u = N16_IMM5U (insn);
  const int imm5s = N16_IMM5S (insn);
  const int rt3 = N16_RT3 (insn);
  const int ra3 = N16_RA3 (insn);
  const int rb3 = N16_RB3 (insn);
  const int rt38 = N16_RT38 (insn);
  const int imm3u = rb3;

  *nds32_pc += 2;

  switch (__GF (insn, 7, 8))
    {
    case 0xf8:			/* push25 */
      {
	uint32_t smw_adm = 0x3A6F83BC;
	uint32_t res[] = { 6, 8, 10, 14 };
	uint32_t re = __GF (insn, 5, 2);

	smw_adm |= res[re] << 10;
	nds32_decode32_lsmw (sd, smw_adm);
	nds32_gpr[NG_SP].u -= (imm5u << 3);
	if (re >= 1)
	  nds32_gpr[8].u = (*nds32_pc - 2) & 0xFFFFFFFC;
      }
      return;
    case 0xf9:			/* pop25 */
      {
	uint32_t lmw_bim = 0x3A6F8384;
	uint32_t res[] = { 6, 8, 10, 14 };
	uint32_t re = __GF (insn, 5, 2);

	lmw_bim |= res[re] << 10;
	nds32_gpr[NG_SP].u += (imm5u << 3);
	nds32_decode32_lsmw (sd, lmw_bim);
	nds32_usr[NC_PC] = nds32_gpr[NG_LP];
      }
      return;
    }

  if (__GF (insn, 8, 7) == 0x7d)
    {
      int rt5e = __GF (insn, 4, 4) << 1;
      int ra5e = __GF (insn, 0, 4) << 1;

      nds32_gpr[rt5e] = nds32_gpr[ra5e];
      nds32_gpr[rt5e + 1] = nds32_gpr[ra5e + 1];
      return;
    }

  switch (__GF (insn, 9, 6))
    {
    case 0x4:			/* add45 */
      nds32_gpr[rt4].u += nds32_gpr[ra5].u;
      return;
    case 0x5:			/* sub45 */
      nds32_gpr[rt4].u -= nds32_gpr[ra5].u;
      return;
    case 0x6:			/* addi45 */
      nds32_gpr[rt4].u += imm5u;
      return;
    case 0x7:			/* subi45 */
      nds32_gpr[rt4].u -= imm5u;
      return;
    case 0x8:			/* srai45 */
      nds32_gpr[rt4].u = nds32_gpr[rt4].s >> imm5u;
      return;
    case 0x9:			/* srli45 */
      nds32_gpr[rt4].u = nds32_gpr[rt4].u >> imm5u;
      return;
    case 0xa:			/* slli333 */
      nds32_gpr[rt3].u = nds32_gpr[ra3].u << imm3u;
      return;
    case 0xc:			/* add333 */
      nds32_gpr[rt3].u = nds32_gpr[ra3].u + nds32_gpr[rb3].u;
      return;
    case 0xd:			/* sub333 */
      nds32_gpr[rt3].u = nds32_gpr[ra3].u - nds32_gpr[rb3].u;
      return;
    case 0xe:			/* addi333 */
      nds32_gpr[rt3].u = nds32_gpr[ra3].u + imm3u;
      return;
    case 0xf:			/* subi333 */
      nds32_gpr[rt3].u = nds32_gpr[ra3].u - imm3u;
      return;
    case 0x10:			/* lwi333 */
    case 0x12:			/* lhi333 */
    case 0x13:			/* lbi333 */
      {
	int shtbl[] = { 2, -1, 1, 0 };
	int shift = shtbl[(__GF (insn, 9, 6) - 0x10)];

	nds32_gpr[rt3].u =
	  nds32_ld (sd, nds32_gpr[ra3].u + (imm3u << shift), 1 << shift);
      }
      return;
    case 0x11:			/* lwi333.bi */
      nds32_gpr[rt3].u = nds32_ld (sd, nds32_gpr[ra3].u, 4);
      nds32_gpr[ra3].u += imm3u << 2;
      return;
    case 0x14:			/* swi333 */
    case 0x16:			/* shi333 */
    case 0x17:			/* sbi333 */
      {
	int shtbl[] = { 2, -1, 1, 0 };
	int shift = shtbl[(__GF (insn, 9, 6) - 0x14)];

	nds32_st (sd, nds32_gpr[ra3].u + (imm3u << shift), 1 << shift,
		  nds32_gpr[rt3].u);
      }
      return;
    case 0x15:			/* swi333.bi */
      nds32_st (sd, nds32_gpr[ra3].u, 4, nds32_gpr[rt3].u);
      nds32_gpr[ra3].u += imm3u << 2;
      return;
    case 0x19:			/* lwi45.fe */
      {
	/* Not tested yet */
	int imm7n = -((32 - imm5u) << 2);

	nds32_gpr[rt4].u = nds32_ld (sd, nds32_gpr[8].u + imm7n, 4);
      }
      return;
    case 0x1a:			/* lwi450 */
      nds32_gpr[rt4].u = nds32_ld (sd, nds32_gpr[ra5].u, 4);
      return;
    case 0x1b:			/* swi450 */
      nds32_st (sd, nds32_gpr[ra5].u, 4, nds32_gpr[rt4].u);
      return;
    case 0x30:			/* slts45 */
      nds32_gpr[NG_TA].u =
	(nds32_gpr[rt4].s < nds32_gpr[ra5].s) ? 1 : 0;
      return;
    case 0x31:			/* slt45 */
      nds32_gpr[NG_TA].u =
	(nds32_gpr[rt4].u < nds32_gpr[ra5].u) ? 1 : 0;
      return;
    case 0x32:			/* sltsi45 */
      nds32_gpr[NG_TA].u = (nds32_gpr[rt4].s < imm5u) ? 1 : 0;
      return;
    case 0x33:			/* slti45 */
      nds32_gpr[NG_TA].u = (nds32_gpr[rt4].u < imm5u) ? 1 : 0;
      return;

    case 0x34:			/* beqzs8, bnezs8 */
      if (((insn & (1 << 8)) == 0) ^ (nds32_gpr[NG_TA].u != 0))
	*nds32_pc += -2 + (N16_IMM8S (insn) << 1);
      return;
    case 0x35:			/* break16 */
      *nds32_pc -= 2;
      cpu_exception = sim_stopped;
      return;
    case 0x3d:			/* movpi45 */
      nds32_gpr[rt4].u = imm5u + 16;
      return;
    case 0x3f:			/* MISC33 */
      switch (insn & 0x7)
	{
	case 2:			/* neg33 */
	  nds32_gpr[rt3].s = -nds32_gpr[ra3].u;
	  return;
	case 3:			/* not33 */
	  nds32_gpr[rt3].u = ~nds32_gpr[ra3].u;
	  return;
	case 4:			/* mul33 */
	  nds32_gpr[rt3].u = nds32_gpr[rt3].u * nds32_gpr[ra3].u;
	  return;
	case 5:			/* xor33 */
	  nds32_gpr[rt3].u = nds32_gpr[rt3].u ^ nds32_gpr[ra3].u;
	  return;
	case 6:			/* and33 */
	  nds32_gpr[rt3].u = nds32_gpr[rt3].u & nds32_gpr[ra3].u;
	  return;
	case 7:			/* or33 */
	  nds32_gpr[rt3].u = nds32_gpr[rt3].u | nds32_gpr[ra3].u;
	  return;
	default:
	  goto bad_op;
	}
      return;
    case 0xb:			/* ... */
      switch (insn & 0x7)
	{
	case 0:			/* zeb33 */
	  nds32_gpr[rt3].u = nds32_gpr[ra3].u & 0xff;
	  break;
	case 1:			/* zeh33 */
	  nds32_gpr[rt3].u = nds32_gpr[ra3].u & 0xffff;
	  break;
	case 2:			/* seb33 */
	  nds32_gpr[rt3].s = __SEXT (nds32_gpr[ra3].s, 8);
	  break;
	case 3:			/* seh33 */
	  nds32_gpr[rt3].s = __SEXT (nds32_gpr[ra3].s, 16);
	  break;
	case 4:			/* xlsb33 */
	  nds32_gpr[rt3].u = nds32_gpr[ra3].u & 0x1;
	  break;
	case 5:			/* x11b33 */
	  nds32_gpr[rt3].u = nds32_gpr[ra3].u & 0x7FF;
	  break;
	case 6:
	case 7:
	  goto bad_op;
	}
      return;
    }

  switch (__GF (insn, 10, 5))
    {
    case 0x0:			/* mov55 */
      nds32_gpr[rt5].u = nds32_gpr[ra5].u;
      return;
    case 0x1:			/* movi55 */
      nds32_gpr[rt5].s = imm5s;
      return;
    case 0x1b:			/* addi10s (V2) */
      nds32_gpr[NG_SP].u += N16_IMM10S (insn);
      return;
    }

  switch (__GF (insn, 11, 4))
    {
    case 0x7:			/* lwi37.fp/swi37.fp */
      if (insn & (1 << 7))	/* swi37.fp */
	nds32_st (sd, nds32_gpr[NG_FP].u + (N16_IMM7U (insn) << 2), 4, nds32_gpr[rt38].u);
      else			/* lwi37.fp */
	nds32_gpr[rt38].u = nds32_ld (sd, nds32_gpr[NG_FP].u + (N16_IMM7U (insn) << 2), 4);
      return;
    case 0x8:			/* beqz38 */
      if (nds32_gpr[rt38].u == 0)
	*nds32_pc += -2 + (N16_IMM8S (insn) << 1);
      return;
    case 0x9:			/* bnez38 */
      if (nds32_gpr[rt38].u != 0)
	*nds32_pc += -2 + (N16_IMM8S (insn) << 1);
      return;
    case 0xa:			/* beqs38/j8, implied r5 */
      if (nds32_gpr[rt38].u == nds32_gpr[5].u)
	*nds32_pc += -2 + (N16_IMM8S (insn) << 1);
      return;
    case 0xb:			/* bnes38 and others */
      if (rt38 == 5)
	{
	  switch (__GF (insn, 5, 3))
	    {
	    case 0:		/* jr5 */
	    case 4:		/* ret5 */
	      *nds32_pc = nds32_gpr[ra5].u;
	      return;
	    case 1:		/* jral5 */
	      nds32_gpr[NG_LP].u = *nds32_pc;
	      *nds32_pc = nds32_gpr[ra5].u;
	      return;
	    default:
	      goto bad_op;
	    }
	}
      else if (nds32_gpr[rt38].u != nds32_gpr[5].u)
	*nds32_pc += -2 + (N16_IMM8S (insn) << 1);
      return;
    case 0xe:			/* lwi37/swi37 */
      if (insn & (1 << 7))	/* swi37.sp */
	nds32_st (sd, nds32_gpr[NG_SP].u + (N16_IMM7U (insn) << 2), 4, nds32_gpr[rt38].u);
      else			/* lwi37.sp */
	nds32_gpr[rt38].u = nds32_ld (sd, nds32_gpr[NG_SP].u + (N16_IMM7U (insn) << 2), 4);
      return;
    }

bad_op:
  nds32_bad_op (sd, *nds32_pc - 2, insn, "16-bit");
}

void
sim_resume (SIM_DESC sd, int step, int signal)
{
  if (step)
    {
      cpu_exception = sim_stopped;
      cpu_signal = GDB_SIGNAL_TRAP;
    }
  else
    cpu_exception = sim_running;

  do
    {
      uint32_t insn;
      cycles++;

      sim_read (sd, *nds32_pc, (unsigned char *) &insn, 4);
      insn = extract_unsigned_integer ((unsigned char *) &insn, 4,
				       BIG_ENDIAN);

      if ((insn & 0x80000000) == 0)
	{
	  nds32_decode32 (sd, insn);
	}
      else
	{
	  nds32_decode16 (sd, insn >> 16);
	}
    }
  while (cpu_exception == sim_running);
}


int
sim_trace (SIM_DESC sd)
{
  tracing = 1;

  sim_resume (sd, 0, 0);

  tracing = 0;

  return 1;
}

int
sim_store_register (SIM_DESC sd, int rn, unsigned char *memory, int length)
{
  /* General purpose registers.  */
  if (rn < 32)
    {
      nds32_gpr[rn].u = extract_unsigned_integer_by_psw (memory, length);
      return 4;
    }

  /* Special user registers.  */
  switch (rn)
    {
    case NG_PC:
      *nds32_pc = extract_unsigned_integer_by_psw (memory, length);
      return 4;
    case NG_D0LO:
      nds32_usr[NC_D0LO].u = extract_unsigned_integer_by_psw (memory, length);
      return 4;
    case NG_D0HI:
      nds32_usr[NC_D0HI].u = extract_unsigned_integer_by_psw (memory, length);
      return 4;
    case NG_D1LO:
      nds32_usr[NC_D1LO].u = extract_unsigned_integer_by_psw (memory, length);
      return 4;
    case NG_D1HI:
      nds32_usr[NC_D1HI].u = extract_unsigned_integer_by_psw (memory, length);
      return 4;
    }

  /* System registers.  */
  return 0;
}

int
sim_fetch_register (SIM_DESC sd, int rn, unsigned char *memory, int length)
{
  /* General purpose registers.  */
  if (rn < 32)
    {
      store_unsigned_integer_by_psw (memory, length, nds32_gpr[rn].u);
      return 4;
    }

  /* Special user registers.  */
  switch (rn)
    {
    case NG_PC:
      store_unsigned_integer_by_psw (memory, length, *nds32_pc);
      return 4;
    case NG_D0LO:
      store_unsigned_integer_by_psw (memory, length, nds32_usr[NC_D0LO].u);
      return 4;
    case NG_D0HI:
      store_unsigned_integer_by_psw (memory, length, nds32_usr[NC_D0HI].u);
      return 4;
    case NG_D1LO:
      store_unsigned_integer_by_psw (memory, length, nds32_usr[NC_D1LO].u);
      return 4;
    case NG_D1HI:
      store_unsigned_integer_by_psw (memory, length, nds32_usr[NC_D1HI].u);
      return 4;
    }

  if (rn >= NG_FS0 && rn < NG_FS0 + 64)
    {
      int fr = rn - NG_FS0;
      if (fr < 32)
	{
          store_unsigned_integer_by_psw (memory, length, nds32_fpr[fr].u);
	}
      else
	{
	  uint64_t d;
	  fr = (fr - 32) << 1;
	  d = ((uint64_t)nds32_fpr[fr].u << 32) | (uint64_t)nds32_fpr[fr + 1].u;
	  store_unsigned_integer_by_psw (memory, length, d);
	}
    }

  /* System registers.  */
  return 0;
}

void
sim_stop_reason (SIM_DESC sd, enum sim_stop *reason, int *sigrc)
{
  *reason = cpu_exception;
  if (cpu_exception == sim_stopped)
    *sigrc = 5;
  /* *reason = sim_stopped; */
}

int
sim_stop (SIM_DESC sd)
{
  cpu_exception = sim_stopped;
  cpu_signal = GDB_SIGNAL_INT;
  return 1;
}

static void
nds32_initialize_cpu (SIM_DESC sd, SIM_CPU * cpu)
{
  /* CPU_VER */
  nds32_sr[SRIDX (0, 0, 0)].u = (0xc << 24) | 3;
}

SIM_DESC
sim_open (SIM_OPEN_KIND kind, host_callback * callback,
	  struct bfd *abfd, char **argv)
{
  char c;
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

  /* getopt will print the error message so we just have to exit if this fails.
     FIXME: Hmmm...  in the case of gdb we need getopt to call
     print_filtered.  */
  if (sim_parse_args (sd, argv) != SIM_RC_OK)
    {
      nds32_free_state (sd);
      return 0;
    }

  sim_do_command (sd, "memory region 0,0x04000000");

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
      SIM_CPU *cpu = STATE_CPU (sd, i);
      nds32_initialize_cpu (sd, cpu);
    }

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
  int len;
  int mlen;
  int i;
  /* Set the initial register set.  */
  if (prog_bfd != NULL)
    *nds32_pc = bfd_get_start_address (prog_bfd);
  else
    *nds32_pc = 0;

  memset (sd->cmdline, 0, sizeof (sd->cmdline));
  mlen = sizeof (sd->cmdline) - 1;
  len = 0;
  for (i = 0; argv && argv[i]; i++)
    {
      int l = strlen (argv[i]) + 1;
      if (l + len >= mlen)
	break;

      len += sprintf (sd->cmdline + len, "%s ",
		argv[i]);
    }
  if (len > 0)
    sd->cmdline[len - 1] = '\0'; /* Eat the last space. */

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
  callback = ptr;
}
