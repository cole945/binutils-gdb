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

#include "opcode/nds32.h"

#if 1
#define SIM_IO_DPRINTF(sd, fmt, args...)   sim_io_printf (sd, fmt, ## args)
#else
#define SIM_IO_DPRINTF(...)            do { } while (0)
#endif

typedef unsigned long long ulongest_t;
typedef signed long long longest_t;

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

enum nds32_regnum
{
  NDS32_TA_REGNUM = 15,
  NDS32_FP_REGNUM = 28,
  NDS32_GP_REGNUM = 29,
  NDS32_LP_REGNUM = 30,
  NDS32_SP_REGNUM = 31,
  NDS32_PC_REGNUM = 32,
  NDS32_D0LO_REGNUM = 33,
  NDS32_D0HI_REGNUM = 34,
  NDS32_D1LO_REGNUM = 35,
  NDS32_D1HI_REGNUM = 36,
};

/* Define some frequently used registers.  */
#define SRIDX(M,m,e)  ((M << 7) | (m << 3) | e)
#define UXIDX(g,u)    ((g << 5) | u)

reg_t nds32_gpr[32];		/* 32 GPR */
reg_t nds32_usr[32 * 32];	/* Group, Usr */
reg_t nds32_sr[8 * 16 * 8];	/* Major, Minor, Ext */

reg_t *nds32_pc = nds32_usr + UXIDX (0, 31);
reg_t *nds32_d0lo = nds32_usr + UXIDX (0, 0);
reg_t *nds32_d0hi = nds32_usr + UXIDX (0, 1);
reg_t *nds32_d1lo = nds32_usr + UXIDX (0, 2);
reg_t *nds32_d1hi = nds32_usr + UXIDX (0, 3);
reg_t *nds32_psw = nds32_sr + SRIDX (1, 0, 0);

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
  int order = (*nds32_psw & (1 << 5)) ? BIG_ENDIAN : LITTLE_ENDIAN;

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
  int order = (*nds32_psw & (1 << 5)) ? BIG_ENDIAN : LITTLE_ENDIAN;

  store_unsigned_integer (addr, len, order, val);
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

static longest_t
nds32_ld_sext (SIM_DESC sd, SIM_ADDR addr, int size)
{
  longest_t r;
  int order;
  SIM_ASSERT (size <= sizeof (longest_t));

  sim_read (sd, addr, (unsigned char *) &r, size);
  order = (*nds32_psw & (1 << 5)) ? BIG_ENDIAN : LITTLE_ENDIAN;
  r = extract_unsigned_integer ((unsigned char *) &r, size, order);
  r = __SEXT (r, size * 8);

  return r;
}

static ulongest_t
nds32_ld (SIM_DESC sd, SIM_ADDR addr, int size)
{
  ulongest_t r;
  int order;
  SIM_ASSERT (size <= sizeof (ulongest_t));

  sim_read (sd, addr, (unsigned char *) &r, size);
  order = (*nds32_psw & (1 << 5)) ? BIG_ENDIAN : LITTLE_ENDIAN;
  r = extract_unsigned_integer ((unsigned char *) &r, size, order);

  return r;
}

static void
nds32_st (SIM_DESC sd, SIM_ADDR addr, int size, ulongest_t r)
{
  int order;
  SIM_ASSERT (size <= sizeof (ulongest_t));

  order = (*nds32_psw & (1 << 5)) ? BIG_ENDIAN : LITTLE_ENDIAN;
  store_unsigned_integer ((unsigned char *) &r, size, order, r);
  sim_write (sd, addr, (unsigned char *) &r, size);
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
  if (rb < NDS32_FP_REGNUM && re < NDS32_FP_REGNUM)
    {
      /* Reg-list should not include fp, gp, lp and sp,
	 i.e., the rb == re == sp case, anyway... */
      m += (re - rb) + 1;
    }
  m *= 4;			/* 4*TNReg */

  base = nds32_gpr[ra];

  if (insn & (1 << 0x4))	/* a:b, a for +-4 */
    base += 4 * di;

  if (di == 1)
    base += (m - 4);

  switch (insn & 0x23)
    {
    case 33:			/* smwa */
      sim_io_error (sd, "SMWA aligment is not checked.\n");
    case 32:			/* smw */
      /* TODO: alignment exception check for SMWA */
      for (i = 0; i < 4; i++)
	{
	  if (enable4 & (1 << enb4map[aligned][i]))
	    {
	      sim_write (sd, base, reg, 4);
	      nds32_st (sd, base, 4,
			nds32_gpr[NDS32_SP_REGNUM - (enb4map[aligned][i])]);
	      base -= 4;
	    }
	}

      /* Skip if re == rb == sp > fp.  */
      for (i = re; i >= rb && rb < NDS32_FP_REGNUM; i--)
	{
	  nds32_st (sd, base, 4, nds32_gpr[i]);
	  base -= 4;
	}

      if (insn & (1 << 2))
	nds32_gpr[ra] += m * di;
      return;
    case 1:			/* lmwa */
      sim_io_error (sd, "LMWA aligment is not checked.\n");
    case 0:			/* lmw */
      /* TODO: alignment exception check for SMWA */
      for (i = 0; i < 4; i++)
	{
	  if (enable4 & (1 << enb4map[aligned][i]))
	    {
	      nds32_gpr[NDS32_SP_REGNUM - (enb4map[aligned][i])]
		= nds32_ld (sd, base, 4);
	      base -= 4;
	    }
	}

      /* Skip if re == rb == sp > fp.  */
      for (i = re; i >= rb && rb < NDS32_FP_REGNUM; i--)
	{
	  nds32_gpr[i] = nds32_ld (sd, base, 4);
	  base -= 4;
	}

      if (insn & (1 << 2))
	nds32_gpr[ra] += m * di;
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

  switch (insn & 0x1f)
    {
    case 0x0:			/* add */
      nds32_gpr[rt] = nds32_gpr[ra] + nds32_gpr[rb];
      return;
    case 0x1:			/* sub */
      nds32_gpr[rt] = nds32_gpr[ra] - nds32_gpr[rb];
      return;
    case 0x2:			/* and */
      nds32_gpr[rt] = nds32_gpr[ra] & nds32_gpr[rb];
      return;
    case 0x3:			/* xor */
      nds32_gpr[rt] = nds32_gpr[ra] ^ nds32_gpr[rb];
      return;
    case 0x4:			/* or */
      nds32_gpr[rt] = nds32_gpr[ra] | nds32_gpr[rb];
      return;
    case 0x5:			/* nor */
      nds32_gpr[rt] = ~(nds32_gpr[ra] | nds32_gpr[rb]);
      return;
    case 0x6:			/* slt */
      nds32_gpr[rt] =
	((ureg_t) nds32_gpr[ra] < (ureg_t) nds32_gpr[rb]) ? 1 : 0;
      return;
    case 0x7:			/* slts */
      nds32_gpr[rt] =
	((reg_t) nds32_gpr[ra] < (reg_t) nds32_gpr[rb]) ? 1 : 0;
      return;

#if 0
    case 0x8:			/* slli */
      return;
    case 0x9:			/* srli */
      return;
    case 0xa:			/* srai */
      return;
    case 0xb:			/* rotri */
      return;
    case 0xc:			/* sll */
      return;
    case 0xd:			/* srl */
      return;
    case 0xe:			/* sra */
      return;
    case 0xf:			/* rotr */
      return;

    case 0x10:			/* seb */
      return;
    case 0x11:			/* seh */
      return;

    case 0x13:			/* zeh */
      return;
    case 0x14:			/* wsbh */
      return;

    case 0x16:			/* divsr */
      return;
    case 0x17:			/* divr */
      return;

    case 0x18:			/* sva */
      return;
    case 0x19:			/* svs */
      return;
    case 0x1a:			/* comvz */
      return;
    case 0x1b:			/* vomvn */
      return;
#endif
    default:
      nds32_bad_op (sd, *nds32_pc - 4, insn, "ALU1");
    }
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
    case 0:
      *nds32_pc = nds32_gpr[rb];
      SIM_IO_DPRINTF (sd, "set $pc to 0x%x\n", *nds32_pc);
      return;
    case 1:
      nds32_gpr[rt] = *nds32_pc;
      *nds32_pc = nds32_gpr[rb];
      SIM_IO_DPRINTF (sd, "set $pc to 0x%x, save ra to $r%d\n", *nds32_pc,
		      rb);
      return;
    default:
      nds32_bad_op (sd, *nds32_pc - 4, insn, "JREG");
    }
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
      if (nds32_gpr[rt] == nds32_gpr[ra])
	*nds32_pc += -4 + (imm14s << 1);
      return;
    case 1:			/* bne */
      if (nds32_gpr[rt] == nds32_gpr[ra])
	*nds32_pc += -4 + (imm14s << 1);
      return;
    default:
      nds32_bad_op (sd, *nds32_pc - 4, insn, "BR1");
    }
}

static void
nds32_decode32_br2 (SIM_DESC sd, const uint32_t insn)
{
  int rt = N32_RT5 (insn);
  int imm16s = N32_IMM16S (insn);

  switch (__GF (insn, 16, 4))
    {
    case 0x2:			/* beqz */
      if (nds32_gpr[rt] == 0)
	*nds32_pc += -4 + (imm16s << 1);
      return;
    case 0x3:			/* bnez */
      if (nds32_gpr[rt] != 0)
	*nds32_pc += -4 + (imm16s << 1);
      return;
    case 0x4:			/* bgez */
      if (nds32_gpr[rt] >= 0)
	*nds32_pc += -4 + (imm16s << 1);
      return;
    case 0x5:			/* bltz */
      if (nds32_gpr[rt] < 0)
	*nds32_pc += -4 + (imm16s << 1);
      return;
    case 0x6:			/* bgtz */
      if (nds32_gpr[rt] > 0)
	*nds32_pc += -4 + (imm16s << 1);
      return;
    case 0x7:			/* blez */
      if (nds32_gpr[rt] <= 0)
	*nds32_pc += -4 + (imm16s << 1);
      return;
    case 0x1c:			/* bgezal */
      nds32_gpr[NDS32_LP_REGNUM] = *nds32_pc;
      if (nds32_gpr[rt] >= 0)
	*nds32_pc += -4 + (imm16s << 1);
      return;
    case 0x1d:			/* bltzal */
      nds32_gpr[NDS32_LP_REGNUM] = *nds32_pc;
      if (nds32_gpr[rt] < 0)
	*nds32_pc += -4 + (imm16s << 1);
      return;
    default:
      nds32_bad_op (sd, *nds32_pc - 4, insn, "BR2");
    }
}

static void
nds32_decode32_misc (SIM_DESC sd, const uint32_t insn)
{
  int rt = N32_RT5 (insn);

  switch (insn & 0x1F)
    {
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
    case 0x4:			/* iret */
    case 0xb:			/* syscall */
    default:
      nds32_bad_op (sd, *nds32_pc - 4, insn, "MISC");
    }
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

	nds32_gpr[rt] =
	  nds32_ld (sd, nds32_gpr[ra] + (imm15s << shift), 1 << shift);
      }
      return;

    case 0x4:			/* lbi.bi */
    case 0x5:			/* lhi.bi */
    case 0x6:			/* lwi.bi */
    case 0x7:			/* ldi.bi */
      {
	int shift = (op - 0x4);

	nds32_gpr[rt] = nds32_ld (sd, nds32_gpr[ra], 1 << shift);
	nds32_gpr[ra] += (imm15s << shift);
      }
      return;

    case 0x8:			/* sbi */
    case 0x9:			/* shi */
    case 0xa:			/* swi */
    case 0xb:			/* sdi */
      {
	int shift = (op - 0x8);

	nds32_st (sd, nds32_gpr[ra] + (imm15s << shift), 1 << shift,
		  nds32_gpr[rt]);
      }
      return;

    case 0xc:			/* sbi.bi */
    case 0xd:			/* shi.bi */
    case 0xe:			/* swi.bi */
    case 0xf:			/* sdi.bi */
      {
	int shift = (op - 0xc);

	nds32_st (sd, nds32_gpr[ra], 1 << shift, nds32_gpr[rt]);
	nds32_gpr[ra] += (imm15s << shift);
      }
      return;

    case 0x10:			/* lbsi */
    case 0x11:			/* lhsi */
    case 0x12:			/* lwsi */
      {
	int shift = (op - 0x10);

	nds32_gpr[rt] =
	  nds32_ld_sext (sd, nds32_gpr[ra] + (imm15s << shift), 1 << shift);
      }
      return;

    case 0x14:			/* lbsi.bi */
    case 0x15:			/* lhsi.bi */
    case 0x16:			/* lwsi.bi */
      {
	int shift = (op - 0x14);

	nds32_gpr[rt] = nds32_ld_sext (sd, nds32_gpr[ra], 1 << shift);
	nds32_gpr[ra] += (imm15s << shift);
      }
      return;

    case 0x1d:			/* lsmw */
      nds32_decode32_lsmw (sd, insn);
      return;
    case 0x20:			/* alu_1 */
      nds32_decode32_alu1 (sd, insn);
      return;
#if 0
    case 0x21:			/* alu_2 */
      nds32_decode32_alu2 (sd, insn);
      return;
#endif
    case 0x22:			/* movi */
      nds32_gpr[rt] = N32_IMM20S (insn);
      return;
    case 0x23:			/* sethi */
      nds32_gpr[rt] = N32_IMM20U (insn) << 12;
      return;
    case 0x24:			/* ji */
      if (insn & (1 << 24))
	nds32_gpr[NDS32_LP_REGNUM] = *nds32_pc;
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
      nds32_gpr[rt] = nds32_gpr[ra] + imm15s;
      return;
    case 0x29:			/* subri */
    case 0x2a:			/* andi */
    case 0x2b:			/* xori */
      nds32_gpr[rt] = nds32_gpr[ra] ^ imm15u;
      return;
    case 0x2c:			/* ori */
      nds32_gpr[rt] = nds32_gpr[rt] | imm15u;
      return;
    case 0x2e:			/* slti */
      nds32_gpr[rt] = ((ureg_t) nds32_gpr[ra] < imm15s) ? 1 : 0;
      return;
    case 0x2f:			/* sltsi */
      nds32_gpr[rt] = ((reg_t) nds32_gpr[ra] < imm15s) ? 1 : 0;
      return;
    case 0x32:			/* misc */
      nds32_decode32_misc (sd, insn);
      return;
    default:
    bad_op:
      nds32_bad_op (sd, *nds32_pc - 4, insn, "32-bit");
    }
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

  switch (__GF (insn, 10, 5))
    {
    case 0x0:			/* mov55 */
      nds32_gpr[rt5] = nds32_gpr[ra5];
      return;
    case 0x1:			/* movi55 */
      nds32_gpr[rt5] = imm5s;
      return;
    case 0x1b:			/* addi10s (V2) */
      nds32_gpr[NDS32_SP_REGNUM] += N16_IMM10S (insn);
      return;
    }

  switch (__GF (insn, 9, 6))
    {
    case 0x4:			/* add45 */
      nds32_gpr[rt4] += nds32_gpr[ra5];
      return;
    case 0x5:			/* sub45 */
      nds32_gpr[rt4] -= nds32_gpr[ra5];
      return;
    case 0x6:			/* addi45 */
      nds32_gpr[rt4] += imm5u;
      return;
    case 0x7:			/* subi45 */
      nds32_gpr[rt4] -= imm5u;
      return;
    case 0x8:			/* srai45 */
      nds32_gpr[rt4] >>= imm5u;
      return;
    case 0x9:			/* srli45 */
      nds32_gpr[rt4] <<= imm5u;
      return;
    case 0x1a:			/* lwi450 */
      nds32_gpr[rt4] = nds32_ld (sd, nds32_gpr[ra5], 4);
      return;
    case 0x1b:			/* swi450 */
      nds32_st (sd, nds32_gpr[ra5], 4, nds32_gpr[rt4]);
      return;
    case 0x30:			/* slts45 */
      nds32_gpr[NDS32_TA_REGNUM] =
	((reg_t) nds32_gpr[rt4] < (reg_t) nds32_gpr[ra5]) ? 1 : 0;
      return;
    case 0x31:			/* slt45 */
      nds32_gpr[NDS32_TA_REGNUM] =
	((ureg_t) nds32_gpr[rt4] < (ureg_t) nds32_gpr[ra5]) ? 1 : 0;
      return;
    case 0x32:			/* sltsi45 */
      nds32_gpr[NDS32_TA_REGNUM] =
	((reg_t) nds32_gpr[rt4] < imm5s) ? 1 : 0;
      return;
    case 0x33:			/* slti45 */
      nds32_gpr[NDS32_TA_REGNUM] =
	((reg_t) nds32_gpr[rt4] < imm5u) ? 1 : 0;
      return;

    case 0xa:			/* slli333 */
      nds32_gpr[rt3] = nds32_gpr[ra3] << imm3u;
      return;
    case 0xc:			/* add333 */
      nds32_gpr[rt3] = nds32_gpr[ra3] + nds32_gpr[rb3];
      return;
    case 0xd:			/* sub333 */
      nds32_gpr[rt3] = nds32_gpr[ra3] - nds32_gpr[rb3];
      return;
    case 0xe:			/* addi333 */
      nds32_gpr[rt3] = nds32_gpr[ra3] +imm3u;
      return;
    case 0xf:			/* subi333 */
      nds32_gpr[rt3] = nds32_gpr[ra3] - imm3u;
      return;
    case 0x10:			/* lwi333 */
    case 0x12:			/* lhi333 */
    case 0x13:			/* lbi333 */
      {
	int shtbl[] = { 2, -1, 1, 0 };
	int shift = shtbl[(__GF (insn, 9, 6) - 0x10)];

	nds32_gpr[rt3] =
	  nds32_ld (sd, nds32_gpr[ra3] + (imm3u << shift), 1 << shift);
      }
      return;
    case 0x11:			/* lwi333.bi */
      nds32_gpr[rt3] = nds32_ld (sd, nds32_gpr[ra3], 4);
      nds32_gpr[ra3] += imm3u << 2;
      return;
    case 0x14:			/* swi333 */
    case 0x16:			/* shi333 */
    case 0x17:			/* sbi333 */
      {
	int shtbl[] = { 2, -1, 1, 0 };
	int shift = shtbl[(__GF (insn, 9, 6) - 0x14)];

	nds32_st (sd, nds32_gpr[ra3] + (imm3u << shift), 1 << shift,
		  nds32_gpr[rt3]);
      }
      return;
    case 0x15:			/* swi333.bi */
      nds32_st (sd, nds32_gpr[ra3], 4, nds32_gpr[rt3]);
      nds32_gpr[ra3] += imm3u << 2;
      return;
    case 0x34:			/* beqzs8, bnezs8 */
      if (((insn & (1 << 8)) == 0) ^ (nds32_gpr[NDS32_TA_REGNUM] != 0))
	*nds32_pc += -2 + (N16_IMM8S (insn) << 1);
      return;
    case 0x35:			/* break16 */
      *nds32_pc -= 2;
      cpu_exception = sim_stopped;
      return;
    case 0xb:			/* ... */
      return;
    }

  switch (__GF (insn, 11, 4))
    {
    case 0x8:			/* beqz38 */
      if (nds32_gpr[rt38] == 0)
	*nds32_pc += -2 + (N16_IMM8S (insn) << 1);
      return;
    case 0x9:			/* bnez38 */
      if (nds32_gpr[rt38] != 0)
	*nds32_pc += -2 + (N16_IMM8S (insn) << 1);
      return;
    case 0xa:			/* beqs38/j8, implied r5 */
      if (nds32_gpr[rt38] == nds32_gpr[5])
	*nds32_pc += -2 + (N16_IMM8S (insn) << 1);
      return;
    case 0xb:			/* bnes38 and others */
      if (rt38 == 5)
	{
	  switch (__GF (insn, 5, 3))
	    {
	    case 0:		/* jr5 */
	    case 4:		/* ret5 */
	      *nds32_pc = nds32_gpr[ra5];
	      return;
	    case 1:		/* jral5 */
	      nds32_gpr[NDS32_LP_REGNUM] = *nds32_pc;
	      *nds32_pc = nds32_gpr[ra5];
	      return;
	    default:
	      goto bad_op;
	    }
	}
      else if (nds32_gpr[rt38] != nds32_gpr[5])
	*nds32_pc += -2 + (N16_IMM8S (insn) << 1);
      return;
    case 0xe:			/* lwi37/swi37 */
    case 0x32:			/* lwi37sp/swi37sp */
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
      nds32_gpr[rn] = extract_unsigned_integer_by_psw (memory, length);
      return 4;
    }

  /* Special user registers.  */
  switch (rn)
    {
    case NDS32_PC_REGNUM:
      *nds32_pc = extract_unsigned_integer_by_psw (memory, length);
      return 4;
    case NDS32_D0LO_REGNUM:
      return 4;
    case NDS32_D0HI_REGNUM:
      return 4;
    case NDS32_D1LO_REGNUM:
      return 4;
    case NDS32_D1HI_REGNUM:
      return 4;
    default:
      return 0;
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
      store_unsigned_integer_by_psw (memory, length, nds32_gpr[rn]);
      return 4;
    }

  /* Special user registers.  */
  switch (rn)
    {
    case NDS32_PC_REGNUM:
      store_unsigned_integer_by_psw (memory, length, *nds32_pc);
      return 4;
    case NDS32_D0LO_REGNUM:
      return 4;
    case NDS32_D0HI_REGNUM:
      return 4;
    case NDS32_D1LO_REGNUM:
      return 4;
    case NDS32_D1HI_REGNUM:
      return 4;
    default:
      return 0;
    }

  /* System registers.  */
  return 0;
}

void
sim_stop_reason (SIM_DESC sd, enum sim_stop *reason, int *sigrc)
{
  *reason = cpu_exception;
  *sigrc = cpu_signal;
  *reason = sim_stopped;
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
  nds32_sr[SRIDX (0, 0, 0)] = (0xc << 24) | 3;
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
  /* Set the initial register set.  */
  if (prog_bfd != NULL)
    *nds32_pc = bfd_get_start_address (prog_bfd);
  else
    *nds32_pc = 0;

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
