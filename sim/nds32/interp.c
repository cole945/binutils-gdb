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

#include <stdlib.h>
#include "bfd.h"
#include "elf-bfd.h"
#include "gdb/callback.h"
#include "gdb/signals.h"
#include "libiberty.h"
#include "gdb/remote-sim.h"
#include "gdb/sim-nds32.h"
#include "dis-asm.h"
#include "sim-main.h"
#include "nds32-sim.h"
#include "sim-utils.h"
#include "sim-fpu.h"
#include "sim-trace.h"
#include "sim-options.h"

#include "opcode/nds32.h"
#include "nds32-sim.h"
#include "nds32-syscall.h"

#include <sys/types.h>
#include <unistd.h>
#include <time.h>

struct disassemble_info dis_info; /* For print insn.  */

static void nds32_set_nia (sim_cpu *cpu, sim_cia nia);

/* Recent $pc, for debugging.  */
#define RECENT_CIA_MASK	0xf
static sim_cia recent_cia[RECENT_CIA_MASK + 1];
static int recent_cia_idx = 0;

static uint64_t
extract_unsigned_integer (unsigned char *addr, int len, int byte_order)
{
  uint64_t retval;
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
			int byte_order, uint64_t val)
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
nds32_dump_registers (SIM_DESC sd)
{
  static char *reg2names[] = {
	"r0", "r1", "r2", "r3", "r4", "r5",
	"r6", "r7", "r8", "r9", "10", "11",
	"12", "13", "14", "ta", "16", "17",
	"18", "19", "20", "21", "22", "23",
	"24", "25", "p0", "p1", "fp", "gp",
	"lp", "sp"
	};
  int i;
  int j;

  for (i = 0; i < MAX_NR_PROCESSORS; ++i)
    {
      sim_cpu *cpu = STATE_CPU (sd, i);
      sim_io_eprintf (sd, "pc  %08x\n", CCPU_USR[USR0_PC].u);

      for (j = 0; j < 32; j++)
	{
	  sim_io_eprintf (sd, "%s  %08x  ", reg2names[j], CCPU_GPR[j].u);
	  if (j % 6 == 5)
	    sim_io_eprintf (sd, "\n");
	}
      sim_io_eprintf (sd, "\n");

      sim_io_eprintf (sd, "itb %08x  ", CCPU_USR[USR0_ITB].u);
      sim_io_eprintf (sd, "ifc %08x  ", CCPU_USR[USR0_IFCLP].u);
      sim_io_eprintf (sd, "d0  %08x  ", CCPU_USR[USR0_D0LO].u);
      sim_io_eprintf (sd, "hi  %08x  ", CCPU_USR[USR0_D0HI].u);
      sim_io_eprintf (sd, "d1  %08x  ", CCPU_USR[USR0_D1LO].u);
      sim_io_eprintf (sd, "hi  %08x  ", CCPU_USR[USR0_D1HI].u);
      sim_io_eprintf (sd, "\n");

      sim_io_eprintf (sd, "psw %08x  ", CCPU_SR[SRIDX_PSW].u);
      sim_io_eprintf (sd, "\n");
    }

  sim_io_eprintf (sd, "Recent $pc:\n");
  for (i = 0; i <= RECENT_CIA_MASK; i++)
    {
      sim_io_eprintf (sd, "  0x%x",
		      recent_cia[(i + recent_cia_idx) & RECENT_CIA_MASK]);
      if (i % 6 == 5)
	sim_io_eprintf (sd, "\n");
    }

  sim_io_eprintf (sd, "\n");
}

uint32_t
nds32_raise_exception (sim_cpu *cpu, enum nds32_exceptions e, int sig,
		       char *msg, ...)
{
  SIM_DESC sd = CPU_STATE (cpu);
  uint32_t cia = CCPU_USR[USR0_PC].u;
  int i;

  if (msg)
    {
      va_list va;
      va_start (va, msg);
      sim_io_evprintf (sd, msg, va);
      va_end (va);
    }

  /* Dump registers before halt.  */
  if (STATE_OPEN_KIND (sd) != SIM_OPEN_DEBUG)
    {
      fprintf (stderr, "  ");
      print_insn_nds32 (cia, &dis_info);
      fprintf (stderr, "\n");
      nds32_dump_registers (sd);
    }

  sim_engine_halt (CPU_STATE (cpu), cpu, NULL, cia, sim_stopped, sig);

  return cia;
}

void
nds32_bad_op (sim_cpu *cpu, uint32_t cia, uint32_t insn, char *tag)
{
  if (tag == NULL)
    tag = "";

  nds32_raise_exception (cpu, EXP_GENERAL, SIM_SIGILL,
			 "Illegal/Unhandled %s instruction (%08x)\n", tag, insn);
}

/* Load an integer in endian specified in PSW.BE flag.  */

uint64_t
__nds32_ld (sim_cpu *cpu, SIM_ADDR addr, int size, int aligned_p)
{
  int r, order;
  uint64_t val = 0;
  SIM_DESC sd = CPU_STATE (cpu);

  SIM_ASSERT (size <= sizeof (uint64_t));

  if (aligned_p && (addr & (size - 1)) != 0)
    nds32_raise_exception (cpu, EXP_GENERAL, SIM_SIGSEGV,
			   "Alignment check exception. "
			   "Read of address 0x%08x in size of %d.\n",
			   addr, size);

  r = sim_read (sd, addr, (unsigned char *) &val, size);
  order = CCPU_SR_TEST (PSW, PSW_BE) ? BIG_ENDIAN : LITTLE_ENDIAN;
  val = extract_unsigned_integer ((unsigned char *) &val, size, order);

  if (r == size)
    return val;

  nds32_raise_exception (cpu, EXP_GENERAL, SIM_SIGSEGV,
			 "Access violation. Read of address 0x%08x.\n", addr);

  return val;
}

/* Store an integer in endian specified in PSW.BE flag.  */

void
__nds32_st (sim_cpu *cpu, SIM_ADDR addr, int size, uint64_t val,
	    int aligned_p)
{
  int r, order;
  SIM_DESC sd = CPU_STATE (cpu);

  SIM_ASSERT (size <= sizeof (uint64_t));

  if (aligned_p && (addr & (size - 1)) != 0)
    nds32_raise_exception (cpu, EXP_GENERAL, SIM_SIGSEGV,
			   "Alignment check exception. "
			   "Write of address 0x%08x in size of %d.\n",
			   addr, size);

  order = CCPU_SR_TEST (PSW, PSW_BE) ? BIG_ENDIAN : LITTLE_ENDIAN;
  store_unsigned_integer ((unsigned char *) &val, size, order, val);
  r = sim_write (sd, addr, (unsigned char *) &val, size);

  if (r == size)
    return;

  nds32_raise_exception (cpu, EXP_GENERAL, SIM_SIGSEGV,
			 "Access violation. Write of address 0x%08x\n", addr);

  return;
}

/* Set next-instructoin-address, so sim_engine_run () fetches `nia'
   instead of ($pc + 4) or ($pc + 2) for next instruction base on
   currenly instruction size. */

static void
nds32_set_nia (sim_cpu *cpu, sim_cia nia)
{
  cpu->iflags |= NIF_BRANCH;
  cpu->baddr = nia;
}

/* Find first zero byte or mis-match in sequential memory address.
   If no such byte is found, return 0.  */

static uint32_t
find_null_mism (unsigned char *b1, unsigned char *b2)
{
  int i;

  for (i = 0; i < 4; i++)
    {
      if ((b1[i] == '\0') || (b1[i] != b2[i]))
	return -4 + i;
    }
  return 0;
}

/* Find first mis-match in sequential memory address.
   The 3rd argument inc: 1 means incremental memory address.
			-1 means decremental memory address.
   If no such byte is found, return 0.  */

static uint32_t
find_mism (unsigned char *b1, unsigned char *b2, int inc)
{
  int i, end;

  i = (inc == 1) ? 0 : 3;
  end = (inc == 1) ? 3 : 0;

  while (1)
    {
      if ((b1[i] != b2[i]))
	return -4 + i;
      if (i == end)
	return 0;
      i += inc;
    }
}

static void
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
    /* case 0x7: */		/* ld.bi */
      /* UNPREDICTABLE if rt is equal to ra.
	 Compute address before load, because rb could be rt.  */
      addr = CCPU_GPR[ra].u + (CCPU_GPR[rb].u << sv);
      CCPU_GPR[rt].u = nds32_ld_aligned (cpu, CCPU_GPR[ra].u, (1 << (op & 0x3)));
      CCPU_GPR[ra].u = addr;
      break;
    case 0x8:			/* sb */
    case 0x9:			/* sh */
    case 0xa:			/* sw */
    /* case 0xb: */		/* sd */
      addr = CCPU_GPR[ra].u + (CCPU_GPR[rb].u << sv);
      nds32_st_aligned (cpu, addr, (1 << (op & 0x3)), CCPU_GPR[rt].u);
      break;
    case 0xc:			/* sb.bi */
    case 0xd:			/* sh.bi */
    case 0xe:			/* sw.bi */
    /* case 0xf: */		/* sd.bi */
      nds32_st_aligned (cpu, CCPU_GPR[ra].u, (1 << (op & 0x3)),
			CCPU_GPR[rt].u);
      CCPU_GPR[ra].u += (CCPU_GPR[rb].u << sv);
      break;
    case 0x10:			/* lbs */
    case 0x11:			/* lhs */
    /* case 0x12: */		/* lws */
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
    /* case 0x16: */		/* lws.bi */
      /* UNPREDICTABLE if rt is equal to ra.
	Compute address before load, because rb could be rt.  */
      addr = CCPU_GPR[ra].u + (CCPU_GPR[rb].u << sv);
      CCPU_GPR[rt].u = nds32_ld_aligned (cpu, CCPU_GPR[ra].u, (1 << (op & 0x3)));
      CCPU_GPR[rt].u = __SEXT (CCPU_GPR[rt].u, (1 << (op & 0x3)) * 8);
      CCPU_GPR[ra].u = addr;
      break;
    case 0x18:			/* llw */
      CCPU_GPR[rt].u =
	nds32_ld_aligned (cpu, CCPU_GPR[ra].u + (CCPU_GPR[rb].u << sv), 4);
      break;
    case 0x19:			/* scw */
      /* SCW always successes.  */
      nds32_st_aligned (cpu, CCPU_GPR[ra].u + (CCPU_GPR[rb].u << sv), 4,
			CCPU_GPR[rt].u);
      CCPU_GPR[rt].u = 1;
      break;
    case 0x20:			/* lbup */
    case 0x22:			/* lwup */
    case 0x28:			/* sbup */
    case 0x2a:			/* swup */
    default:
      nds32_bad_op (cpu, cia, insn, "MEM");
      return;
    }
}

static void
nds32_decode32_lsmw (sim_cpu *cpu, const uint32_t insn, sim_cia cia)
{
  SIM_DESC sd = CPU_STATE (cpu);
  int rb, re, ra, enable4, i, ret;
  char buf[4];
  int wac;			/* With alignment-check?  */
  int reg_cnt = 0;		/* Total number of registers count.  */
  int di;			/* dec=-1 or inc=1  */
  int size = 4;			/* The load/store bytes.  */
  int len = 4;			/* The length of a fixed-size string.  */
  int order = CCPU_SR_TEST (PSW, PSW_BE) ? BIG_ENDIAN : LITTLE_ENDIAN;
  char enb4map[2][4] = { {3, 2, 1, 0}, {0, 1, 2, 3} };
  uint32_t val = 0;
  SIM_ADDR base = -1;

  /* Filter out undefined opcode.  */
  if ((insn & 0x3) == 0x3)
    {
      nds32_bad_op (cpu, cia, insn, "LSMW");
      return;
    }

  /* Filter out invalid opcode.  */
  if ((insn & 0xB) == 0xA)
    {
      nds32_bad_op (cpu, cia, insn, "LSMW");
      return;
    }

  /* Decode instruction.  */
  rb = N32_RT5 (insn);
  ra = N32_RA5 (insn);
  re = N32_RB5 (insn);
  enable4 = (insn >> 6) & 0x0F;
  wac = (insn & 1) ? 1 : 0;
  di = __TEST (insn, 3) ? -1 : 1;

  /* Get the first memory address  */
  base = CCPU_GPR[ra].u;

  /* Do the alignment check. */
  if (wac && (base & 0x3))
    {
      nds32_raise_exception (cpu, EXP_GENERAL, SIM_SIGSEGV,
			     (insn & 0x20)
			     ? "Alignment check exception (SMWA). "
			       "Write of address 0x%08x.\n"
			     : "Alignment check exception (LMWA). "
			       "Read of address 0x%08x.\n",
			     base);
      return;
    }

  /* Sum up the registers count.  */
  reg_cnt += (enable4 & 0x1) ? 1 : 0;
  reg_cnt += (enable4 & 0x2) ? 1 : 0;
  reg_cnt += (enable4 & 0x4) ? 1 : 0;
  reg_cnt += (enable4 & 0x8) ? 1 : 0;
  if (rb < GPR_FP && re < GPR_FP)
    {
      reg_cnt += (re - rb) + 1;
    }

  /* Generate the first memory address.  */
  if (__TEST (insn, 4))
    base += 4 * di;
  /* Set base to the lowest memory address we are going to access.
     Because we may load/store in increasing or decreasing order,
     always access the memory from the lowest address simplify the
     opertions.  */
  if (__TEST (insn, 3))
    base -= (reg_cnt - 1) * 4;

  for (i = rb; i <= re && rb < GPR_FP; i++)
    {
      if (insn & 0x20)
	{
	  /* SMW */

	  val = CCPU_GPR[i].u;
	  store_unsigned_integer ((unsigned char *) buf, 4, order, val);
	  if ((insn & 0x3) == 0x2)
	    {
	      /* Until zero byte case.  */
	      len = strnlen (buf, 4);
	      size = (len == 4) ? 4 : len + 1;	/* Include zero byte.  */
	    }
	  ret = sim_write (sd, base, (unsigned char *) buf, size);
	  if (ret != size)
	    {
	      nds32_raise_exception (cpu, EXP_GENERAL, SIM_SIGSEGV,
				     "Access violation. Write of address %#x\n",
				     base);
	    }
	  if (len < 4)
	    goto zero_byte_exist;
	}
      else
	{
	  /* LMW */

	  ret = sim_read (sd, base, (unsigned char *) buf, 4);
	  if (ret != 4)
	    {
	      nds32_raise_exception (cpu, EXP_GENERAL, SIM_SIGSEGV,
				     "Access violation. Write of address %#x\n",
				     base);
	    }
	  val = extract_unsigned_integer ((unsigned char *) buf, 4, order);
	  CCPU_GPR[i].u = val;
	  if ((insn & 0x3) == 0x2)
	    {
	      /* Until zero byte case.  */
	      len = strnlen (buf, 4);
	      if (len < 4)
		goto zero_byte_exist;
	    }
	}
      base += 4;
    }

  /* Load/store the 4 individual registers from low address memory
     to high address memory. */
  for (i = 0; i < 4; i++)
    {
      if (__TEST (enable4, enb4map[wac][i]))
	{
	  if (insn & 0x20)
	    {
	      /* SMW */

	      val = CCPU_GPR[GPR_SP - (enb4map[wac][i])].u;
	      store_unsigned_integer ((unsigned char *) buf, 4, order, val);
	      if ((insn & 0x3) == 0x2)	/* Until zero byte case.  */
		{
		  len = strnlen (buf, 4);
		  size = (len == 4) ? 4 : len + 1;	/* Include zero byte.  */
		}
	      ret = sim_write (sd, base, (unsigned char *) buf, size);
	      if (ret != size)
		{
		  nds32_raise_exception (cpu, EXP_GENERAL, SIM_SIGSEGV,
					 "Access violation. Write of address %#x\n",
					 base);
		}
	      if (len < 4)
		goto zero_byte_exist;
	    }
	  else
	    {
	      /* LMW */

	      ret = sim_read (sd, base, (unsigned char *) buf, 4);
	      if (ret != 4)
		{
		  nds32_raise_exception (cpu, EXP_GENERAL, SIM_SIGSEGV,
					 "Access violation. Write of address %#x\n",
					 base);
		}
	      val =
		extract_unsigned_integer ((unsigned char *) buf, 4, order);
	      CCPU_GPR[GPR_SP - (enb4map[wac][i])].u = val;
	      if ((insn & 0x3) == 0x2)	/* until zero byte ? */
		{
		  len = strnlen (buf, 4);
		  if (len < 4)
		    goto zero_byte_exist;
		}
	    }
	  base += 4;
	}
    }

zero_byte_exist:
  /* Update the base address register.  */
  if (__TEST (insn, 2))
    CCPU_GPR[ra].u += reg_cnt * 4 * di;

  return;
}

static void
nds32_decode32_alu1 (sim_cpu *cpu, const uint32_t insn, sim_cia cia)
{
  const int rt = N32_RT5 (insn);
  const int ra = N32_RA5 (insn);
  const int rb = N32_RB5 (insn);
  const int rd = N32_RD5 (insn);
  const int imm5u = rb;
  const int sh5 = N32_SH5 (insn);

  switch (N32_SUB5 (insn))
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
	uint32_t shift = (N32_SUB5 (insn) == 0xb) ? imm5u : CCPU_GPR[rb].u;
	uint32_t m = CCPU_GPR[ra].u & __MASK (shift);
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
	/* TODO: Generate positive qoutient exception.  */
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
    case 0x19:			/* svs */
      {
	int c1, c2;
	unsigned int ua, ub;
	int sub;

	ua = CCPU_GPR[ra].u;
	ub = CCPU_GPR[rb].u;
	sub = N32_SUB5 (insn) == 0x19 ? 1 : 0;

	if (sub)
	  ub = ~ub;

	c1 = ((ua & 0x7fffffff) + (ub & 0x7fffffff) + sub) >> 31;
	c2 = ((ua >> 31) + (ub >> 31) + c1) >> 1;

	CCPU_GPR[rt].u = c1 ^ c2;
      }
      break;
    case 0x1a:			/* cmovz */
      if (CCPU_GPR[rb].u == 0)
	CCPU_GPR[rt].u = CCPU_GPR[ra].u;
      break;
    case 0x1b:			/* cmovn */
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
      return;
    }

  return;
}

static void
nds32_decode32_alu2 (sim_cpu *cpu, const uint32_t insn, sim_cia cia)
{
  const int rt = N32_RT5 (insn);
  const int ra = N32_RA5 (insn);
  const int rb = N32_RB5 (insn);
  const int imm5u = rb;
  const int dt = __TEST (insn, 21) ? USR0_D1LO : USR0_D0LO;

  if ((insn & 0x7f) == 0x4e)	/* ffbi */
    {
      unsigned char buff[4];
      int order = CCPU_SR_TEST (PSW, PSW_BE) ? BIG_ENDIAN : LITTLE_ENDIAN;
      int imm8 = ((insn >> 7) & 0xff);
      unsigned char *ret;

      store_unsigned_integer (buff, 4, order, CCPU_GPR[ra].u);
      ret = memchr (buff, imm8, 4);
      if (NULL == ret)
	CCPU_GPR[rt].u = 0;
      else
	CCPU_GPR[rt].u = ret - buff - 4;
      return;
    }

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
	CCPU_GPR[rt].u = (r >> 1);
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
	    if (__TEST (CCPU_GPR[ra].u, i))
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
	    if (__TEST (CCPU_GPR[ra].u, i) == 0)
	      cnt++;
	    else
	      break;
	  }
	CCPU_GPR[rt].u = cnt;
      }
      break;
    case 0x8:			/* bset */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u | __BIT (imm5u);
      break;
    case 0x9:			/* bclr */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u & ~__BIT (imm5u);
      break;
    case 0xa:			/* btgl */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u ^ __BIT (imm5u);
      break;
    case 0xb:			/* btst */
      CCPU_GPR[rt].u = __TEST (CCPU_GPR[ra].u, imm5u) ? 1 : 0;
      break;
    case 0xc:			/* bse */
      {
	int n = __GF (CCPU_GPR[rb].u, 0, 5);
	int m = __GF (CCPU_GPR[rb].u, 8, 5);
	int underflow = __TEST (CCPU_GPR[rb].u, 30);
	int refill = __TEST (CCPU_GPR[rb].u, 31);
	int len = m + 1;
	int dist = 32 - len - n;	/* From LSB.  */
	int val;
	int d = n + m;
	uint32_t ora = CCPU_GPR[ra].u;

	/* Clear non-occupied.  */
	if (!underflow)
	  CCPU_GPR[rt].u = __GF (CCPU_GPR[rt].u, 0, len);

	/* Normal condition.  */
	if (31 > d)
	  {
	    __put_field (&CCPU_GPR[rb].u, 0, 5, d + 1);
	    val = __GF (ora, dist, len);

	    __put_field (&CCPU_GPR[rt].u, 0, len, val);

	    if (underflow)
	      {
		/* Restore old length.  */
		__put_field (&CCPU_GPR[rb].u, 8, 5, __GF (CCPU_GPR[rb].u, 16, 5));
		/* Why?  */
		__put_field (&CCPU_GPR[rb].u, 13, 3, 0);
	      }

	    CCPU_GPR[rb].u &= ~__BIT (30);
	    CCPU_GPR[rb].u &= ~__BIT (31);
	  }
	/* Empty condition.  */
	else if (31 == d)
	  {
	    CCPU_GPR[rb].u &= ~0x1f;
	    val = __GF (ora, dist, len);

	    __put_field (&CCPU_GPR[rt].u, 0, len, val);

	    CCPU_GPR[rb].u &= ~__BIT (30);
	    CCPU_GPR[rb].u |= __BIT (31);
	  }
	/* Undeflow condition.  */
	else /* 31 < d */
	  {
	    __put_field (&CCPU_GPR[rb].u, 16, 5, m);
	    __put_field (&CCPU_GPR[rb].u, 8, 5, d - 32);
	    CCPU_GPR[rb].u &= ~0x1f;
	    CCPU_GPR[rb].u |= __BIT (30);
	    CCPU_GPR[rb].u |= __BIT (31);
	    val = __GF (ora, 0, 32 - n);
	    __put_field (&CCPU_GPR[rt].u, 0, len, val << (d - 31));
	  }
      }
      break;
    case 0xd:			/* bsp */
      {
	int n = __GF (CCPU_GPR[rb].u, 0, 5);
	int m = __GF (CCPU_GPR[rb].u, 8, 5);
	int underflow = __TEST (CCPU_GPR[rb].u, 30);
	int refill = __TEST (CCPU_GPR[rb].u, 31);
	int len = m + 1;
	int dist = 32 - len - n;	/* From LSB.  */
	int val;
	int d = n + m;
	uint32_t ora = CCPU_GPR[ra].u;

	/* Normal condition.  */
	if (31 > d)
	  {
	    __put_field (&CCPU_GPR[rb].u, 0, 5, d + 1);
	    val = __GF (ora, 0, len);

	    __put_field (&CCPU_GPR[rt].u, dist, len, val);

	    if (underflow)
	      {
		/* Restore old length.  */
		__put_field (&CCPU_GPR[rb].u, 8, 5, __GF (CCPU_GPR[rb].u, 16, 5));
		/* Why?  */
		__put_field (&CCPU_GPR[rb].u, 13, 3, 0);
	      }

	    CCPU_GPR[rb].u &= ~__BIT (30);
	    CCPU_GPR[rb].u &= ~__BIT (31);
	  }
	/* Empty condition.  */
	else if (31 == d)
	  {
	    CCPU_GPR[rb].u &= ~0x1f;
	    val = __GF (ora, 0, len);

	    __put_field (&CCPU_GPR[rt].u, dist, len, val);

	    CCPU_GPR[rb].u &= ~__BIT (30);
	    CCPU_GPR[rb].u |= __BIT (31);
	  }
	/* Undeflow condition.  */
	else /* 31 < d */
	  {
	    __put_field (&CCPU_GPR[rb].u, 16, 5, m);
	    __put_field (&CCPU_GPR[rb].u, 8, 5, d - 32);
	    CCPU_GPR[rb].u &= ~0x1f;
	    CCPU_GPR[rb].u |= __BIT (30);
	    CCPU_GPR[rb].u |= __BIT (31);
	    val = __GF (ora, 0, len) >> (d - 31);
	    __put_field (&CCPU_GPR[rt].u, 0, 32 - n, val);
	  }
      }
      break;
    case 0xe:			/* ffb */
      {
	char buff[4];
	int order = CCPU_SR_TEST (PSW, PSW_BE) ? BIG_ENDIAN : LITTLE_ENDIAN;
	void *ret;

	store_unsigned_integer ((unsigned char *) &buff, 4, order, CCPU_GPR[ra].u);
	ret = memchr (buff, CCPU_GPR[rb].u, 4);
	if (NULL == ret)
	  CCPU_GPR[rt].u = 0;
	else
	  CCPU_GPR[rt].u = (char *) ret - (char *) buff - 4;
      }
      break;
    case 0xf:			/* ffmism */
      {
	char a[4];
	char b[4];
	int order = CCPU_SR_TEST (PSW, PSW_BE) ? BIG_ENDIAN : LITTLE_ENDIAN;
	int ret;

	store_unsigned_integer ((unsigned char *) &a, 4, order, CCPU_GPR[ra].u);
	store_unsigned_integer ((unsigned char *) &b, 4, order, CCPU_GPR[rb].u);
	ret = find_mism ((unsigned char *) &a, (unsigned char *) &b, 1);
	CCPU_GPR[rt].u = ret;
      }
      break;
    case 0x17:			/* ffzmism */
      {
	char a[4];
	char b[4];
	int order = CCPU_SR_TEST (PSW, PSW_BE) ? BIG_ENDIAN : LITTLE_ENDIAN;
	int ret;

	store_unsigned_integer ((unsigned char *) &a, 4, order, CCPU_GPR[ra].u);
	store_unsigned_integer ((unsigned char *) &b, 4, order, CCPU_GPR[rb].u);
	ret = find_null_mism ((unsigned char *) &a, (unsigned char *) &b);
	CCPU_GPR[rt].u = ret;
      }
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

	CCPU_USR[dt].s = d;
	CCPU_USR[dt + 1].s = (d >> 32);
      }
      break;
    case 0x29:			/* mult64 */
      {
	uint64_t d = (uint64_t) CCPU_GPR[ra].u * (uint64_t) CCPU_GPR[rb].u;

	CCPU_USR[dt].u = d;
	CCPU_USR[dt + 1].u = (d >> 32);
      }
      break;
    case 0x2a:			/* madds64 */
      {
	int64_t mr = (int64_t) CCPU_GPR[ra].s * (int64_t) CCPU_GPR[rb].s;
	int64_t d = ((int64_t) CCPU_USR[dt + 1].s << 32)
		    | ((int64_t) CCPU_USR[dt].s & 0xFFFFFFFF);

	d += mr;
	CCPU_USR[dt].u = d;
	CCPU_USR[dt + 1].u = (d >> 32);
      }
      break;
    case 0x2b:			/* madd64 */
      {
	uint64_t mr = (uint64_t) CCPU_GPR[ra].u * (uint64_t) CCPU_GPR[rb].u;
	uint64_t d = ((uint64_t) CCPU_USR[dt + 1].u << 32)
		     | ((uint64_t) CCPU_USR[dt].u & 0xFFFFFFFF);

	d += mr;
	CCPU_USR[dt].u = d;
	CCPU_USR[dt + 1].u = (d >> 32);
      }
      break;
    case 0x2c:			/* msubs64 */
      {
	int64_t mr = (int64_t) CCPU_GPR[ra].s * (int64_t) CCPU_GPR[rb].s;
	int64_t d = ((int64_t) CCPU_USR[dt + 1].s << 32)
		    | ((int64_t) CCPU_USR[dt].s & 0xFFFFFFFF);

	d -= mr;
	CCPU_USR[dt].u = d;
	CCPU_USR[dt + 1].u = (d >> 32);
      }
      break;
    case 0x2d:			/* msub64 */
      {
	uint64_t mr = (uint64_t) CCPU_GPR[ra].u * (uint64_t) CCPU_GPR[rb].u;
	uint64_t d = ((uint64_t) CCPU_USR[dt + 1].u << 32)
		     | ((uint64_t) CCPU_USR[dt].u & 0xFFFFFFFF);

	d -= mr;
	CCPU_USR[dt].u = d;
	CCPU_USR[dt + 1].u = (d >> 32);
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
    case 0x4f:			/* flmism */
      {
	char a[4];
	char b[4];
	int order = CCPU_SR_TEST (PSW, PSW_BE) ? BIG_ENDIAN : LITTLE_ENDIAN;
	int ret;

	store_unsigned_integer ((unsigned char *) &a, 4, order, CCPU_GPR[ra].u);
	store_unsigned_integer ((unsigned char *) &b, 4, order, CCPU_GPR[rb].u);
	ret = find_mism ((unsigned char *) &a, (unsigned char *) &b, -1);
	CCPU_GPR[rt].u = ret;
      }
      break;
    case 0x68:			/* mulsr64 */
      {
	int64_t r = (int64_t) CCPU_GPR[ra].s * (int64_t) CCPU_GPR[rb].s;
	int d = rt & ~1;

	if (CCPU_SR_TEST (PSW, PSW_BE))
	  {
	    CCPU_GPR[d].u = (r >> 32);
	    CCPU_GPR[d + 1].u = r;
	  }
	else
	  {
	    CCPU_GPR[d + 1].u = (r >> 32);
	    CCPU_GPR[d].u = r;
	  }
      }
      break;
    case 0x69:			/* mulr64 */
      {
	uint64_t r = (uint64_t) CCPU_GPR[ra].u * (uint64_t) CCPU_GPR[rb].u;
	int d = rt & ~1;

	if (CCPU_SR_TEST (PSW, PSW_BE))
	  {
	    CCPU_GPR[d].u = (r >> 32);
	    CCPU_GPR[d + 1].u = r;
	  }
	else
	  {
	    CCPU_GPR[d + 1].u = (r >> 32);
	    CCPU_GPR[d].u = r;
	  }
      }
      break;
    case 0x73:			/* maddr32 */
      CCPU_GPR[rt].u += (CCPU_GPR[ra].u * CCPU_GPR[rb].u);
      break;
    case 0x75:			/* msubr32 */
      CCPU_GPR[rt].u -= (CCPU_GPR[ra].u * CCPU_GPR[rb].u);
      break;
    default:
      nds32_bad_op (cpu, cia, insn, "ALU2");
      return;
    }

  return;
}

static void
nds32_decode32_jreg (sim_cpu *cpu, const uint32_t insn, sim_cia cia)
{
  const SIM_DESC sd = CPU_STATE (cpu);
  const int rt = N32_RT5 (insn);
  const int ra = N32_RA5 (insn);
  const int rb = N32_RB5 (insn);
  sim_cia nia;

  if (ra != 0)
    sim_io_error (sd, "JREG RA == %d at pc=0x%x, code=0x%08x\n",
		  ra, cia, insn);

  if (__GF (insn, 8, 2) != 0)
    sim_io_error (sd, "JREG DT/IT not supported at pc=0x%x, code=0x%08x\n",
		  cia, insn);

  switch (N32_SUB5 (insn))
    {
    case 0:			/* jr, ifret, ret */
      if (__GF (insn, 5, 2) == 0x3)
	{
	  /* ifret. IFC + RET */
	  if (CCPU_SR_TEST (PSW, PSW_IFCON))
	    cia = CCPU_USR[USR0_IFCLP].u;
	  else
	    return;		/* Do nothing. (ifret) */
	}
      else
	/* jr or ret */
	cia = CCPU_GPR[rb].u;

      CCPU_SR_CLEAR (PSW, PSW_IFCON);
      nds32_set_nia (cpu, cia);
      return;

    case 1:			/* jral */
      if (cpu->iflags & NIF_EX9)
	CCPU_GPR[rt].u = cia + 2;
      else
	CCPU_GPR[rt].u = cia + 4;

      cia = CCPU_GPR[rb].u;
      /* If PSW.IFCON, it returns to $ifclp instead.  */
      if (CCPU_SR_TEST (PSW, PSW_IFCON))
	CCPU_GPR[rt] = CCPU_USR[USR0_IFCLP];

      CCPU_SR_CLEAR (PSW, PSW_IFCON);
      nds32_set_nia (cpu, cia);
      return;

    case 2:			/* jrnez */
      if (CCPU_GPR[rb].u == 0)
	return;			/* NOT taken */

      /* PSW.IFCON is only cleared when taken.  */
      CCPU_SR_CLEAR (PSW, PSW_IFCON);
      nds32_set_nia (cpu, CCPU_GPR[rb].u);
      return;

    case 3:			/* jralnez */
      /* Prevent early clobbing of rb (rt == rb).  */
      nia = CCPU_GPR[rb].u;

      /* Rt is always set according to spec.  */
      if (cpu->iflags & NIF_EX9)
	CCPU_GPR[rt].u = cia + 2;
      else
	CCPU_GPR[rt].u = cia + 4;

      /* By spec, PSW.IFCON is always cleared no matter it takes or not.  */
      if (CCPU_SR_TEST (PSW, PSW_IFCON))
	CCPU_GPR[rt] = CCPU_USR[USR0_IFCLP];
      CCPU_SR_CLEAR (PSW, PSW_IFCON);

      if (nia != 0)		/* taken branch */
	nds32_set_nia (cpu, nia);

      return;

    default:
      nds32_bad_op (cpu, cia, insn, "JREG");
      return;
    }

  return;
}

static void
nds32_decode32_br1 (sim_cpu *cpu, const uint32_t insn, sim_cia cia)
{
  const int rt = N32_RT5 (insn);
  const int ra = N32_RA5 (insn);
  const int imm14s = N32_IMM14S (insn);

  switch ((insn >> 14) & 1)
    {
    case 0:			/* beq */
      if (CCPU_GPR[rt].u == CCPU_GPR[ra].u)
	{
	  CCPU_SR_CLEAR (PSW, PSW_IFCON);
	  nds32_set_nia (cpu, cia + (imm14s << 1));
	}
      break;
    case 1:			/* bne */
      if (CCPU_GPR[rt].u != CCPU_GPR[ra].u)
	{
	  CCPU_SR_CLEAR (PSW, PSW_IFCON);
	  nds32_set_nia (cpu, cia + (imm14s << 1));
	}
      break;
    }
}

static void
nds32_decode32_br2 (sim_cpu *cpu, const uint32_t insn, sim_cia cia)
{
  const SIM_DESC sd = CPU_STATE (cpu);
  const int rt = N32_RT5 (insn);
  const int imm16s1 = N32_IMM16S (insn) << 1;

  switch (__GF (insn, 16, 4))
    {
    case 0x0:			/* ifcall */
      /* Do not set $ifclp when chaining ifcall.  */
      if (!CCPU_SR_TEST (PSW, PSW_IFCON))
	{
	  if (cpu->iflags & NIF_EX9)
	    CCPU_USR[USR0_IFCLP].u = cia + 2;
	  else
	    CCPU_USR[USR0_IFCLP].u = cia + 4;
	}
      nds32_set_nia (cpu, cia + imm16s1);
      CCPU_SR_SET (PSW, PSW_IFCON);
      break;
    case 0x2:			/* beqz */
      if (CCPU_GPR[rt].s == 0)
	{
	  CCPU_SR_CLEAR (PSW, PSW_IFCON);
	  nds32_set_nia (cpu, cia + imm16s1);
	}
      break;
    case 0x3:			/* bnez */
      if (CCPU_GPR[rt].s != 0)
	{
	  CCPU_SR_CLEAR (PSW, PSW_IFCON);
	  nds32_set_nia (cpu, cia + imm16s1);
	}
      break;
    case 0x4:			/* bgez */
      if (CCPU_GPR[rt].s >= 0)
	{
	  CCPU_SR_CLEAR (PSW, PSW_IFCON);
	  nds32_set_nia (cpu, cia + imm16s1);
	}
      break;
    case 0x5:			/* bltz */
      if (CCPU_GPR[rt].s < 0)
	{
	  CCPU_SR_CLEAR (PSW, PSW_IFCON);
	  nds32_set_nia (cpu, cia + imm16s1);
	}
      break;
    case 0x6:			/* bgtz */
      if (CCPU_GPR[rt].s > 0)
	{
	  CCPU_SR_CLEAR (PSW, PSW_IFCON);
	  nds32_set_nia (cpu, cia + imm16s1);
	}
      break;
    case 0x7:			/* blez */
      if (CCPU_GPR[rt].s <= 0)
	{
	  CCPU_SR_CLEAR (PSW, PSW_IFCON);
	  nds32_set_nia (cpu, cia + imm16s1);
	}
      break;
    case 0xc:			/* bgezal */
      /* Always clob $lp.  */
      if (cpu->iflags & NIF_EX9)
	CCPU_GPR[GPR_LP].u = cia + 2;
      else
	CCPU_GPR[GPR_LP].u = cia + 4;

      /* Always set $lp = $ifc_lp no matter it takes no not.  */
      if (CCPU_SR_TEST (PSW, PSW_IFCON))
	CCPU_GPR[GPR_LP].u = CCPU_USR[USR0_IFCLP].u;

      /* PSW.IFCON is only cleared when the branch is taken.  */
      if (!(CCPU_GPR[rt].s >= 0))
	return;

      CCPU_SR_CLEAR (PSW, PSW_IFCON);
      nds32_set_nia (cpu, cia + imm16s1);
      return;
    case 0xd:			/* bltzal */
      /* Always clob $lp.  */
      if (cpu->iflags & NIF_EX9)
	CCPU_GPR[GPR_LP].u = cia + 2;
      else
	CCPU_GPR[GPR_LP].u = cia + 4;

      /* Always set $lp = $ifc_lp no matter it takes no not.  */
      if (CCPU_SR_TEST (PSW, PSW_IFCON))
	CCPU_GPR[GPR_LP].u = CCPU_USR[USR0_IFCLP].u;

      /* PSW.IFCON is only cleared when the branch is taken.  */
      if (!(CCPU_GPR[rt].s < 0))
	return;

      CCPU_SR_CLEAR (PSW, PSW_IFCON);
      nds32_set_nia (cpu, cia + imm16s1);
      break;
    default:
      nds32_bad_op (cpu, cia, insn, "BR2");
      break;
    }
}

static void
nds32_pfm_ctl (sim_cpu *cpu)
{
  int en, ie, ovf, ks, ku;
  int sel0, sel1, sel2;

  en = CCPU_SR_GET (PFM_CTL, PFM_CTL_EN);
  ie = CCPU_SR_GET (PFM_CTL, PFM_CTL_IE);
  ovf = CCPU_SR_GET (PFM_CTL, PFM_CTL_OVF);
  ks = CCPU_SR_GET (PFM_CTL, PFM_CTL_KS);
  ku = CCPU_SR_GET (PFM_CTL, PFM_CTL_KU);
  sel0 = CCPU_SR_GET (PFM_CTL, PFM_CTL_SEL0);
  sel1 = CCPU_SR_GET (PFM_CTL, PFM_CTL_SEL1);
  sel2 = CCPU_SR_GET (PFM_CTL, PFM_CTL_SEL2);
}

static void
nds32_pfm_event (sim_cpu *cpu, int pfm_event)
{
  int sel[3];
  int en, ovf;
  int i;

  en = CCPU_SR_GET (PFM_CTL, PFM_CTL_EN);
  ovf = CCPU_SR_GET (PFM_CTL, PFM_CTL_OVF);

  sel[0] = CCPU_SR_GET (PFM_CTL, PFM_CTL_SEL0);
  sel[1] = CCPU_SR_GET (PFM_CTL, PFM_CTL_SEL1);
  sel[2] = CCPU_SR_GET (PFM_CTL, PFM_CTL_SEL2);

  switch (pfm_event)
    {
    case PFM_CYCLE:
    case PFM_INST:
      for (i = 0; i < 3; i++)
	{
	  if (sel[i] == pfm_event && __TEST (en, i))
	    {
	      CCPU_SR[SRIDX_PFMC0 + i].u++;
	      if (CCPU_SR[SRIDX_PFMC0 + i].u == 0)
		ovf |= (1 << i);
	    }
	}
      break;
    }

  CCPU_SR_PUT (PFM_CTL, PFM_CTL_OVF, ovf);
}

static void
nds32_decode32_misc (sim_cpu *cpu, const uint32_t insn, sim_cia cia)
{
  const int rt = N32_RT5 (insn);

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
      nds32_raise_exception (cpu, EXP_DEBUG, SIM_SIGTRAP, NULL);
      return;
    case 0x2:			/* mfsr */
      CCPU_GPR[rt] = CCPU_SR[__GF (insn, 10, 10)];
      break;
    case 0x3:			/* mtsr */
      {
	int sridx = __GF (insn, 10, 10);

	switch (__GF (insn, 5, 5))
	  {
	  case 0:		/* mtsr */
	    CCPU_SR[sridx] = CCPU_GPR[rt];
	    switch (sridx)
	      {
	      case SRIDX_PFM_CTL:
		nds32_pfm_ctl (cpu);
		break;
	      }
	    break;
	  case 1:		/* setend */
	    if (sridx != 0x80)
	      nds32_bad_op (cpu, cia, insn, "SETEND (sridx)");

	    if (rt == 1)
	      CCPU_SR_SET (PSW, PSW_BE);
	    else if (rt == 0)
	      CCPU_SR_CLEAR (PSW, PSW_BE);
	    else
	      nds32_bad_op (cpu, cia, insn, "SETEND (BE/LE)");
	    break;
	  case 2:		/* setgie */
	    if (sridx != 0x80)
	      nds32_bad_op (cpu, cia, insn, "SETGIE (sridx)");

	    if (rt == 1)
	      CCPU_SR_SET (PSW, PSW_GIE);
	    else if (rt == 0)
	      CCPU_SR_CLEAR (PSW, PSW_GIE);
	    else
	      nds32_bad_op (cpu, cia, insn, "SETEND (BE/LE)");
	    break;
	  }
      }
      break;
    case 0xb:			/* syscall */
      nds32_syscall (cpu, __GF (insn, 5, 15), cia);
      break;
    case 0x4:			/* iret */
      nds32_bad_op (cpu, cia, insn, "iret (MISC)");
      break;
    case 0x6:			/* teqz */
      nds32_bad_op (cpu, cia, insn, "teqz (MISC)");
      break;
    case 0x7:			/* tnez */
      nds32_bad_op (cpu, cia, insn, "tnez (MISC)");
      break;
    case 0xe:			/* tlbop */
      nds32_bad_op (cpu, cia, insn, "tlbop (MISC)");
      break;
    default:
      nds32_bad_op (cpu, cia, insn, "MISC");
      break;
    }
}

static void
nds32_decode32 (sim_cpu *cpu, const uint32_t insn, sim_cia cia)
{
  const SIM_DESC sd = CPU_STATE (cpu);
  const int op = N32_OP6 (insn);
  const int rt = N32_RT5 (insn);
  const int ra = N32_RA5 (insn);
  const int imm15s = N32_IMM15S (insn);
  const int imm15u = N32_IMM15U (insn);
  uint32_t shift;
  uint32_t addr;
  sim_cia next_cia;

  switch (op)
    {
    case 0x0:			/* lbi */
    case 0x1:			/* lhi */
    case 0x2:			/* lwi */
    /* case 0x3: */		/* ldi */
      {
	shift = (op - 0x0);
	addr = CCPU_GPR[ra].u + (imm15s << shift);
	CCPU_GPR[rt].u = nds32_ld_aligned (cpu, addr, 1 << shift);
      }
      break;

    case 0x4:			/* lbi.bi */
    case 0x5:			/* lhi.bi */
    case 0x6:			/* lwi.bi */
    /* case 0x7: */		/* ldi.bi */
      {
	shift = (op - 0x4);
	CCPU_GPR[rt].u = nds32_ld_aligned (cpu, CCPU_GPR[ra].u, 1 << shift);
	CCPU_GPR[ra].u += (imm15s << shift);
      }
      break;

    case 0x8:			/* sbi */
    case 0x9:			/* shi */
    case 0xa:			/* swi */
    /* case 0xb: */		/* sdi */
      {
	shift = (op - 0x8);
	addr = CCPU_GPR[ra].u + (imm15s << shift);
	nds32_st_aligned (cpu, addr, 1 << shift, CCPU_GPR[rt].u);
      }
      break;

    case 0xc:			/* sbi.bi */
    case 0xd:			/* shi.bi */
    case 0xe:			/* swi.bi */
    /* case 0xf: */		/* sdi.bi */
      {
	shift = (op - 0xc);
	nds32_st_aligned (cpu, CCPU_GPR[ra].u, 1 << shift, CCPU_GPR[rt].u);
	CCPU_GPR[ra].u += (imm15s << shift);
      }
      break;

    case 0x10:			/* lbsi */
    case 0x11:			/* lhsi */
    /* case 0x12: */		/* lwsi */
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
    /* case 0x16: */		/* lwsi.bi */
      {
	shift = (op - 0x14);
	CCPU_GPR[rt].u = nds32_ld_aligned (cpu, CCPU_GPR[ra].u, 1 << shift);
	CCPU_GPR[rt].u = __SEXT (CCPU_GPR[rt].u, (1 << shift) * 8);
	CCPU_GPR[ra].u += (imm15s << shift);
      }
      break;
    case 0x17:			/* LBGP */
      if (__TEST (insn, 19))	/* lbsi.gp */
	{
	  addr = CCPU_GPR[GPR_GP].u + N32_IMMS (insn, 19);
	  CCPU_GPR[rt].u = nds32_ld_aligned (cpu, addr, 1);
	  CCPU_GPR[rt].u = __SEXT (CCPU_GPR[rt].u, 1 * 8);
	}
      else			/* lbi.gp */
	CCPU_GPR[rt].u =
	  nds32_ld_aligned (cpu, CCPU_GPR[GPR_GP].u + N32_IMMS (insn, 19), 1);
      break;
    case 0x18:			/* LWC */
      nds32_decode32_lwc (cpu, insn, cia);
      return;
    case 0x19:			/* SWC */
      nds32_decode32_swc (cpu, insn, cia);
      return;
    case 0x1a:			/* LDC */
      nds32_decode32_ldc (cpu, insn, cia);
      return;
    case 0x1b:			/* SDC */
      nds32_decode32_sdc (cpu, insn, cia);
      return;
    case 0x1c:			/* MEM */
      nds32_decode32_mem (cpu, insn, cia);
      return;
    case 0x1d:			/* LSMW */
      nds32_decode32_lsmw (cpu, insn, cia);
      return;
    case 0x1e:			/* HWGP */
      switch (__GF (insn, 17, 3))
	{
	case 0: case 1:		/* lhi.gp */
	  addr = CCPU_GPR[GPR_GP].u + (N32_IMMS (insn, 18) << 1);
	  CCPU_GPR[rt].u = nds32_ld_aligned (cpu, addr, 2);
	  break;
	case 2: case 3:		/* lhsi.gp */
	  addr = CCPU_GPR[GPR_GP].u + (N32_IMMS (insn, 18) << 1);
	  CCPU_GPR[rt].u = nds32_ld_aligned (cpu, addr, 2);
	  CCPU_GPR[rt].u = __SEXT (CCPU_GPR[rt].u, 2 * 8);
	  break;
	case 4: case 5:		/* shi.gp */
	  nds32_st_aligned (cpu, CCPU_GPR[GPR_GP].u + (N32_IMMS (insn, 18) << 1), 2,
			    CCPU_GPR[rt].u);
	  break;
	case 6:			/* lwi.gp */
	  addr= CCPU_GPR[GPR_GP].u + (N32_IMMS (insn, 17) << 2);
	  CCPU_GPR[rt].u = nds32_ld_aligned (cpu, addr, 4);
	  break;
	case 7:			/* swi.gp */
	  nds32_st_aligned (cpu, CCPU_GPR[GPR_GP].u + (N32_IMMS (insn, 17) << 2),
			    4, CCPU_GPR[rt].u);
	  break;
	}
      break;
    case 0x1f:			/* SBGP */
      if (__TEST (insn, 19))	/* addi.gp */
	CCPU_GPR[rt].s = CCPU_GPR[GPR_GP].u + N32_IMMS (insn, 19);
      else			/* sbi.gp */
	nds32_st_aligned (cpu, CCPU_GPR[GPR_GP].u + N32_IMMS (insn, 19), 1,
			  CCPU_GPR[rt].u & 0xFF);
      break;
    case 0x20:			/* ALU_1 */
      nds32_decode32_alu1 (cpu, insn, cia);
      return;
    case 0x21:			/* ALU_2 */
      nds32_decode32_alu2 (cpu, insn, cia);
      return;
    case 0x22:			/* movi */
      CCPU_GPR[rt].s = N32_IMM20S (insn);
      break;
    case 0x23:			/* sethi */
      CCPU_GPR[rt].u = N32_IMM20U (insn) << 12;
      break;
    case 0x24:			/* ji, jal */
      if (cpu->iflags & NIF_EX9)
	{
	  /* Address in ji/jal is treated as absolute address in ex9.  */
	  if (__TEST (insn, 24))	/* jal in ex9 */
	    CCPU_GPR[GPR_LP].u = cia + 2;
	  next_cia = (cia & 0xff000000) | (N32_IMMU (insn, 24) << 1);
	}
      else
	{
	  if (__TEST (insn, 24))	/* jal */
	    CCPU_GPR[GPR_LP].u = cia + 4;
	  next_cia = cia + (N32_IMMS (insn, 24) << 1);
	}

      if (CCPU_SR_TEST (PSW, PSW_IFCON))
	{
	  if (__TEST (insn, 24))	/* jal */
	    CCPU_GPR[GPR_LP] = CCPU_USR[USR0_IFCLP];
	}

      CCPU_SR_CLEAR (PSW, PSW_IFCON);
      nds32_set_nia (cpu, next_cia);
      return;
    case 0x25:			/* jreg */
      nds32_decode32_jreg (cpu, insn, cia);
      return;
    case 0x26:			/* br1 */
      nds32_decode32_br1 (cpu, insn, cia);
      return;
    case 0x27:			/* br2 */
      nds32_decode32_br2 (cpu, insn, cia);
      return;
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

	if ((__TEST (insn, 19) == 0) ^ (CCPU_GPR[rt].s != imm11s))
	  {
	    CCPU_SR_CLEAR (PSW, PSW_IFCON);
	    nds32_set_nia (cpu, cia + (N32_IMMS (insn, 8) << 1));
	  }
	return;
      }
      break;
    case 0x2e:			/* slti */
      CCPU_GPR[rt].u = (CCPU_GPR[ra].u < (uint32_t) imm15s) ? 1 : 0;
      break;
    case 0x2f:			/* sltsi */
      CCPU_GPR[rt].u = (CCPU_GPR[ra].s < imm15s) ? 1 : 0;
      break;
    case 0x32:			/* misc */
      nds32_decode32_misc (cpu, insn, cia);
      return;
    case 0x33:			/* bitci */
      CCPU_GPR[rt].u = CCPU_GPR[ra].u & ~imm15u;
      break;
    case 0x35:			/* COP */
      nds32_decode32_cop (cpu, insn, cia);
      return;
    default:
      nds32_bad_op (cpu, cia, insn, "32-bit");
    }
}

static void
nds32_decode16_ex9 (sim_cpu *cpu, uint32_t insn, sim_cia cia)
{
  /* Set NIF_EX9 so to change how JI/JAL interpreting address.  */

  cpu->iflags |= NIF_EX9;
  nds32_decode32 (cpu, insn, cia);
  cpu->iflags &= ~NIF_EX9;
}

static void
nds32_decode16 (sim_cpu *cpu, uint32_t insn, sim_cia cia)
{
  const SIM_DESC sd = CPU_STATE (cpu);
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
  int tmp;

  switch (__GF (insn, 7, 8))
    {
    case 0xf8:			/* push25 */
      {
	uint32_t smw_adm = 0x3A6F83BC;
	uint32_t res[] = { 6, 8, 10, 14 };
	uint32_t re = __GF (insn, 5, 2);

	smw_adm |= res[re] << 10;
	nds32_decode32_lsmw (cpu, smw_adm, cia);
	CCPU_GPR[GPR_SP].u -= (imm5u << 3);
	if (re >= 1)
	  CCPU_GPR[8].u = cia & 0xFFFFFFFC;
      }
      return;
    case 0xf9:			/* pop25 */
      {
	uint32_t lmw_bim = 0x3A6F8384;
	uint32_t res[] = { 6, 8, 10, 14 };
	uint32_t re = __GF (insn, 5, 2);

	lmw_bim |= res[re] << 10;
	CCPU_GPR[GPR_SP].u += (imm5u << 3);
	nds32_decode32_lsmw (cpu, lmw_bim, cia);
	CCPU_SR_CLEAR (PSW, PSW_IFCON);
	nds32_set_nia (cpu, CCPU_GPR[GPR_LP].u);
      }
      return;
    }

  if (__GF (insn, 8, 7) == 0x7d)	/* movd44 */
    {
      int rt5e = __GF (insn, 4, 4) << 1;
      int ra5e = __GF (insn, 0, 4) << 1;

      CCPU_GPR[rt5e] = CCPU_GPR[ra5e];
      CCPU_GPR[rt5e + 1] = CCPU_GPR[ra5e + 1];
      return;
    }

  switch (__GF (insn, 9, 6))
    {
    case 0x4:			/* add45 */
      CCPU_GPR[rt4].u += CCPU_GPR[ra5].u;
      return;
    case 0x5:			/* sub45 */
      CCPU_GPR[rt4].u -= CCPU_GPR[ra5].u;
      return;
    case 0x6:			/* addi45 */
      CCPU_GPR[rt4].u += imm5u;
      return;
    case 0x7:			/* subi45 */
      CCPU_GPR[rt4].u -= imm5u;
      return;
    case 0x8:			/* srai45 */
      CCPU_GPR[rt4].u = CCPU_GPR[rt4].s >> imm5u;
      return;
    case 0x9:			/* srli45 */
      CCPU_GPR[rt4].u = CCPU_GPR[rt4].u >> imm5u;
      return;
    case 0xa:			/* slli333 */
      CCPU_GPR[rt3].u = CCPU_GPR[ra3].u << imm3u;
      return;
    case 0xc:			/* add333 */
      CCPU_GPR[rt3].u = CCPU_GPR[ra3].u + CCPU_GPR[rb3].u;
      return;
    case 0xd:			/* sub333 */
      CCPU_GPR[rt3].u = CCPU_GPR[ra3].u - CCPU_GPR[rb3].u;
      return;
    case 0xe:			/* addi333 */
      CCPU_GPR[rt3].u = CCPU_GPR[ra3].u + imm3u;
      return;
    case 0xf:			/* subi333 */
      CCPU_GPR[rt3].u = CCPU_GPR[ra3].u - imm3u;
      return;
    case 0x10:			/* lwi333 */
    case 0x12:			/* lhi333 */
    case 0x13:			/* lbi333 */
      {
	int shtbl[] = { 2, -1, 1, 0 };

	shift = shtbl[(__GF (insn, 9, 6) - 0x10)];
	addr = CCPU_GPR[ra3].u + (imm3u << shift);
	CCPU_GPR[rt3].u = nds32_ld_aligned (cpu, addr, 1 << shift);
      }
      return;
    case 0x11:			/* lwi333.bi */
      CCPU_GPR[rt3].u = nds32_ld_aligned (cpu, CCPU_GPR[ra3].u, 4);
      CCPU_GPR[ra3].u += imm3u << 2;
      return;
    case 0x14:			/* swi333 */
    case 0x16:			/* shi333 */
    case 0x17:			/* sbi333 */
      {
	int shtbl[] = { 2, -1, 1, 0 };

	shift = shtbl[(__GF (insn, 9, 6) - 0x14)];
	nds32_st_aligned (cpu, CCPU_GPR[ra3].u + (imm3u << shift),
			  1 << shift, CCPU_GPR[rt3].u);
      }
      return;
    case 0x15:			/* swi333.bi */
      nds32_st_aligned (cpu, CCPU_GPR[ra3].u, 4, CCPU_GPR[rt3].u);
      CCPU_GPR[ra3].u += imm3u << 2;
      return;
    case 0x18:			/* addri36.sp */
      CCPU_GPR[rt3].u = CCPU_GPR[GPR_SP].u + (N16_IMM6U (insn) << 2);
      return;
    case 0x19:			/* lwi45.fe */
      tmp = -((32 - imm5u) << 2); /* imm7n */
      CCPU_GPR[rt4].u = nds32_ld_aligned (cpu, CCPU_GPR[8].u + tmp, 4);
      return;
    case 0x1a:			/* lwi450 */
      CCPU_GPR[rt4].u = nds32_ld_aligned (cpu, CCPU_GPR[ra5].u, 4);
      return;
    case 0x1b:			/* swi450 */
      nds32_st_aligned (cpu, CCPU_GPR[ra5].u, 4, CCPU_GPR[rt4].u);
      return;
    case 0x30:			/* slts45 */
      CCPU_GPR[GPR_TA].u = (CCPU_GPR[rt4].s < CCPU_GPR[ra5].s) ? 1 : 0;
      return;
    case 0x31:			/* slt45 */
      CCPU_GPR[GPR_TA].u = (CCPU_GPR[rt4].u < CCPU_GPR[ra5].u) ? 1 : 0;
      return;
    case 0x32:			/* sltsi45 */
      CCPU_GPR[GPR_TA].u = (CCPU_GPR[rt4].s < imm5u) ? 1 : 0;
      return;
    case 0x33:			/* slti45 */
      CCPU_GPR[GPR_TA].u = (CCPU_GPR[rt4].u < imm5u) ? 1 : 0;
      return;

    case 0x34:			/* beqzs8, bnezs8 */
      if ((__TEST (insn, 8) == 0) ^ (CCPU_GPR[GPR_TA].u != 0))
	{
	  CCPU_SR_CLEAR (PSW, PSW_IFCON);
	  nds32_set_nia (cpu, cia + (N16_IMM8S (insn) << 1));
	}
      return;
    case 0x35:			/* break16, ex9.it */
      if (imm9u < 32)		/* break16 */
	{
	  nds32_raise_exception (cpu, EXP_DEBUG, SIM_SIGTRAP, NULL);
	  return;
	}

      /* ex9.it */
      sim_read (sd, (CCPU_USR[USR0_ITB].u & ~3U) + (imm9u << 2),
		(unsigned char *) &insn, 4);
      insn = extract_unsigned_integer ((unsigned char *) &insn, 4, BIG_ENDIAN);
      nds32_decode16_ex9 (cpu, insn, cia);
      return;
    case 0x3c:			/* ifcall9 */
      if (!CCPU_SR_TEST (PSW, PSW_IFCON))
	CCPU_USR[USR0_IFCLP].u = cia + 2;

      nds32_set_nia (cpu, cia + (N16_IMM9U (insn) << 1));
      CCPU_SR_SET (PSW, PSW_IFCON);
      return;
    case 0x3d:			/* movpi45 */
      CCPU_GPR[rt4].u = imm5u + 16;
      return;
    case 0x3f:			/* MISC33 */
      switch (insn & 0x7)
	{
	case 2:			/* neg33 */
	  CCPU_GPR[rt3].s = -CCPU_GPR[ra3].u;
	  return;
	case 3:			/* not33 */
	  CCPU_GPR[rt3].u = ~CCPU_GPR[ra3].u;
	  return;
	case 4:			/* mul33 */
	  CCPU_GPR[rt3].u = CCPU_GPR[rt3].u * CCPU_GPR[ra3].u;
	  return;
	case 5:			/* xor33 */
	  CCPU_GPR[rt3].u = CCPU_GPR[rt3].u ^ CCPU_GPR[ra3].u;
	  return;
	case 6:			/* and33 */
	  CCPU_GPR[rt3].u = CCPU_GPR[rt3].u & CCPU_GPR[ra3].u;
	  return;
	case 7:			/* or33 */
	  CCPU_GPR[rt3].u = CCPU_GPR[rt3].u | CCPU_GPR[ra3].u;
	  return;
	default:
	  goto bad_op;
	}
      return;
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
      return;
    }

  switch (__GF (insn, 10, 5))
    {
    case 0x0:			/* mov55 or ifret16 */
      /* It's ok to do assignment even if it's ifret16.  */
      CCPU_GPR[rt5].u = CCPU_GPR[ra5].u;

      if (rt5 == ra5 && rt5 == 31 && CCPU_SR_TEST (PSW, PSW_IFCON))
	{
	  /* ifret */
	  CCPU_SR_CLEAR (PSW, PSW_IFCON);
	  nds32_set_nia (cpu, CCPU_USR[USR0_IFCLP].u);
	}
      return;
    case 0x1:			/* movi55 */
      CCPU_GPR[rt5].s = imm5s;
      return;
    case 0x1b:			/* addi10s (V2) */
      CCPU_GPR[GPR_SP].u += N16_IMM10S (insn);
      return;
    }

  switch (__GF (insn, 11, 4))
    {
    case 0x7:			/* lwi37.fp/swi37.fp */
      addr = CCPU_GPR[GPR_FP].u + (N16_IMM7U (insn) << 2);
      if (__TEST (insn, 7))	/* swi37.fp */
	nds32_st_aligned (cpu, addr, 4, CCPU_GPR[rt38].u);
      else			/* lwi37.fp */
	CCPU_GPR[rt38].u = nds32_ld_aligned (cpu, addr, 4);
      return;
    case 0x8:			/* beqz38 */
      if (CCPU_GPR[rt38].u == 0)
	{
	  CCPU_SR_CLEAR (PSW, PSW_IFCON);
	  nds32_set_nia (cpu, cia + (N16_IMM8S (insn) << 1));
	}
      return;
    case 0x9:			/* bnez38 */
      if (CCPU_GPR[rt38].u != 0)
	{
	  CCPU_SR_CLEAR (PSW, PSW_IFCON);
	  nds32_set_nia (cpu, cia + (N16_IMM8S (insn) << 1));
	}
      return;
    case 0xa:			/* beqs38/j8, implied r5 */
      if (CCPU_GPR[rt38].u == CCPU_GPR[5].u)	/* rt38 == 5 means j8 */
	{
	  CCPU_SR_CLEAR (PSW, PSW_IFCON);
	  nds32_set_nia (cpu, cia + (N16_IMM8S (insn) << 1));
	}
      return;
    case 0xb:			/* bnes38 and others */
      if (rt38 == 5)
	{
	  switch (__GF (insn, 5, 3))
	    {
	    case 0:		/* jr5 */
	    case 4:		/* ret5 */
	      CCPU_SR_CLEAR (PSW, PSW_IFCON);
	      nds32_set_nia (cpu, CCPU_GPR[ra5].u);
	      return;
	    case 1:		/* jral5 */
	      CCPU_GPR[GPR_LP].u = cia + 2;
	      if (CCPU_SR_TEST (PSW, PSW_IFCON))
		CCPU_GPR[GPR_LP] = CCPU_USR[USR0_IFCLP];
	      CCPU_SR_CLEAR (PSW, PSW_IFCON);
	      nds32_set_nia (cpu, CCPU_GPR[ra5].u);
	      return;
	    case 2:		/* ex9.it imm5 */
	      sim_read (sd, (CCPU_USR[USR0_ITB].u & ~3U) + (imm5u << 2),
			(unsigned char *) &insn, 4);
	      insn = extract_unsigned_integer ((unsigned char *) &insn, 4,
					       BIG_ENDIAN);
	      nds32_decode16_ex9 (cpu, insn, cia);
	      return;
	    case 5:		/* add5.pc */
	      CCPU_GPR[ra5].u += cia;
	      return;
	    default:
	      goto bad_op;
	    }
	  return;
	}
      else if (CCPU_GPR[rt38].u != CCPU_GPR[5].u)
	{
	  /* bnes38 */
	  CCPU_SR_CLEAR (PSW, PSW_IFCON);
	  nds32_set_nia (cpu, cia + (N16_IMM8S (insn) << 1));
	  return;
	}
      return;
    case 0xe:			/* lwi37/swi37 */
      addr = CCPU_GPR[GPR_SP].u + (N16_IMM7U (insn) << 2);
      if (__TEST (insn, 7))	/* swi37.sp */
	nds32_st_aligned (cpu, addr, 4, CCPU_GPR[rt38].u);
      else			/* lwi37.sp */
	CCPU_GPR[rt38].u = nds32_ld_aligned (cpu, addr, 4);
      return;
    }

bad_op:
  nds32_bad_op (cpu, cia, insn, "16-bit");
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
      sim_engine_halt (CPU_STATE (cpu), cpu, NULL, cia, sim_exited,
		       128 + siggnal);
      return;
    }

  while (1)
    {
      uint32_t insn;

      recent_cia[recent_cia_idx] = cia;
      recent_cia_idx = (recent_cia_idx + 1) & RECENT_CIA_MASK;

      nds32_pfm_event (cpu, PFM_CYCLE);
      nds32_pfm_event (cpu, PFM_INST);

      r = sim_read (sd, cia, (unsigned char *) &insn, 4);
      insn = extract_unsigned_integer ((unsigned char *) &insn, 4,
				       BIG_ENDIAN);

      if (r != 4)
	nds32_dump_registers (sd);
      SIM_ASSERT (r == 4);

      if (TRACE_LINENUM_P (cpu))
	{
	  trace_prefix (sd, cpu, NULL_CIA, cia, TRACE_LINENUM_P (cpu),
			NULL, 0, " "); /* Use a space for gcc warnings.  */
	}

      cpu->iflags &= ~NIF_BRANCH;
      if ((insn & 0x80000000) == 0)
	{
	  nds32_decode32 (cpu, insn, cia);
	  cia += 4;
	}
      else
	{
	  nds32_decode16 (cpu, insn >> 16, cia);
	  cia += 2;
	}

      if (cpu->iflags & NIF_BRANCH)
	{
	  if (cpu->baddr & 1)
	    nds32_raise_exception (cpu, EXP_GENERAL, SIM_SIGSEGV,
				   "Alignment check exception. "
				   "Unaligned instruction address 0x%08x\n",
				   cia);
	  cia = cpu->baddr;
	}

      if (TRACE_LINENUM_P (cpu))
	{
	  trace_result_addr1 (sd, cpu, TRACE_INSN_IDX, cia);
	}

      /* Sync registers.  */
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
  uint64_t val = 0;

  /* General purpose registers.  */
  if (rn < 32)
    {
      val = cpu->reg_gpr[rn].u;
      goto do_fetch;
    }

  /* Special user registers.  */
  switch (rn)
    {
    case SIM_NDS32_PC_REGNUM:
      val = cpu->reg_usr[USR0_PC].u;
      goto do_fetch;
    case SIM_NDS32_D0LO_REGNUM:
      val = cpu->reg_usr[USR0_D0LO].u;
      goto do_fetch;
    case SIM_NDS32_D0HI_REGNUM:
      val = cpu->reg_usr[USR0_D0HI].u;
      goto do_fetch;
    case SIM_NDS32_D1LO_REGNUM:
      val = cpu->reg_usr[USR0_D1LO].u;
      goto do_fetch;
    case SIM_NDS32_D1HI_REGNUM:
      val = cpu->reg_usr[USR0_D1HI].u;
      goto do_fetch;
    case SIM_NDS32_ITB_REGNUM:
      val = cpu->reg_usr[USR0_ITB].u;
      goto do_fetch;
    case SIM_NDS32_IFCLP_REGNUM:
      val = cpu->reg_usr[USR0_IFCLP].u;
      goto do_fetch;
    }

  if (rn >= SIM_NDS32_FD0_REGNUM && rn < SIM_NDS32_FD0_REGNUM + 32)
    {
      int fr = (rn - SIM_NDS32_FD0_REGNUM) << 1;

      val = ((uint64_t) cpu->reg_fpr[fr].u << 32)
	    | (uint64_t) cpu->reg_fpr[fr + 1].u;
      goto do_fetch;
    }

  /* System registers.  */
  switch (rn)
    {
    case SIM_NDS32_PSW_REGNUM:
      val = cpu->reg_sr[SRIDX (1, 0, 0)].u;
      goto do_fetch;
    }

  return 0;

do_fetch:
  store_unsigned_integer (memory, length,
			  CCPU_SR_TEST (PSW, PSW_BE)
			  ? BIG_ENDIAN : LITTLE_ENDIAN,
			  val);
  return length;
}

static int
nds32_store_register (sim_cpu *cpu, int rn, unsigned char *memory, int length)
{
  uint64_t val;

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
    case SIM_NDS32_PC_REGNUM:
      cpu->reg_usr[USR0_PC].u = val;
      return 4;
    case SIM_NDS32_D0LO_REGNUM:
      cpu->reg_usr[USR0_D0LO].u = val;
      return 4;
    case SIM_NDS32_D0HI_REGNUM:
      cpu->reg_usr[USR0_D0HI].u = val;
      return 4;
    case SIM_NDS32_D1LO_REGNUM:
      cpu->reg_usr[USR0_D1LO].u = val;
      return 4;
    case SIM_NDS32_D1HI_REGNUM:
      cpu->reg_usr[USR0_D1HI].u = val;
      return 4;
    case SIM_NDS32_ITB_REGNUM:
      cpu->reg_usr[USR0_ITB].u = val;
      return 4;
    case SIM_NDS32_IFCLP_REGNUM:
      cpu->reg_usr[USR0_IFCLP].u = val;
      return 4;
    }

  if (rn >= SIM_NDS32_FD0_REGNUM && rn < SIM_NDS32_FD0_REGNUM + 32)
    {
      int fr = (rn - SIM_NDS32_FD0_REGNUM) << 1;

      cpu->reg_fpr[fr + 1].u = val & 0xffffffff;
      cpu->reg_fpr[fr].u = (val >> 32) & 0xffffffff;
      return 8;
    }

  /* System registers.  */
  switch (rn)
    {
    case SIM_NDS32_PSW_REGNUM:
      cpu->reg_sr[SRIDX (1, 0, 0)].u = val;
      return 4;
    }

  return 0;
}

static sim_cia
nds32_pc_get (sim_cpu *cpu)
{
  return cpu->reg_usr[USR0_PC].u;
}

static void
nds32_pc_set (sim_cpu *cpu, sim_cia cia)
{
  cpu->reg_usr[USR0_PC].u = cia;
}

static void
nds32_initialize_cpu (SIM_DESC sd, sim_cpu *cpu, struct bfd *abfd)
{
  memset (cpu->reg_gpr, 0, sizeof (cpu->reg_gpr));
  memset (cpu->reg_usr, 0, sizeof (cpu->reg_usr));
  memset (cpu->reg_sr, 0, sizeof (cpu->reg_sr));
  memset (cpu->reg_fpr, 0, sizeof (cpu->reg_fpr));

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

  CCPU_SR_CLEAR (IVB, IVB_EVIC);	/* (IM) */
  CCPU_SR_PUT (IVB, IVB_ESZ, 1);	/* 16-byte */
  CCPU_SR_PUT (IVB, IVB_IVBASE, 0);	/* (IM) */

  /* Floating-Point Configuration Register.  */
  CCPU_FPCFG_SET (SP);
  CCPU_FPCFG_SET (DP);
  CCPU_FPCFG_SET (FMA);
  CCPU_FPCFG_PUT (FREG, 3);
  /* Floating-Point Control Status Register.  */
  CCPU_FPCSR.u = 0;
}

static void
nds32_free_state (SIM_DESC sd)
{
  if (STATE_MODULES (sd) != NULL)
    sim_module_uninstall (sd);
  sim_cpu_free_all (sd);
  sim_state_free (sd);
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

  /* Establish any remaining configuration options.  */
  if (sim_config (sd) != SIM_RC_OK)
    {
      nds32_free_state (sd);
      return 0;
    }

  if (sim_post_argv_init (sd) != SIM_RC_OK)
    {
      nds32_free_state (sd);
      return 0;
    }

  /* Allocate 64MB memory if none is set up by user.  */
  if (STATE_MEMOPT (sd) == NULL)
    sim_do_command (sd, "memory region 0,0x4000000");	/* 64 MB */

  /* CPU specific initialization.  */
  for (i = 0; i < MAX_NR_PROCESSORS; ++i)
    {
      sim_cpu *cpu = STATE_CPU (sd, i);
      nds32_initialize_cpu (sd, cpu, abfd);
    }

  return sd;
}

void
sim_close (SIM_DESC sd, int quitting)
{
  sim_module_uninstall (sd);
}

static int
sim_dis_read (bfd_vma memaddr, bfd_byte *myaddr, unsigned int length,
	      struct disassemble_info *dinfo)
{
  SIM_DESC sd = (SIM_DESC) dinfo->application_data;

  return sim_read (sd, memaddr, (unsigned char *) myaddr, length)
	 != length;
}

void
nds32_init_libgloss (SIM_DESC sd, struct bfd *abfd, char **argv, char **env)
{
  int len, mlen, i;

  STATE_CALLBACK (sd)->syscall_map = cb_nds32_libgloss_syscall_map;

  /* Save argv for -mcrt-arg hacking.  */
  memset (sd->cmdline, 0, sizeof (sd->cmdline));
  mlen = sizeof (sd->cmdline) - 1;
  len = 0;
  for (i = 0; argv && argv[i]; i++)
    {
      int l = strlen (argv[i]) + 1;

      if (l + len >= mlen)
	break;

      len += sprintf (sd->cmdline + len, "%s ", argv[i]);
    }

  if (len > 0)
    sd->cmdline[len - 1] = '\0';	/* Trim the last space. */

  return;
}

SIM_RC
sim_create_inferior (SIM_DESC sd, struct bfd *prog_bfd, char **argv,
		     char **env)
{
  SIM_CPU *cpu = STATE_CPU (sd, 0);

  /* Set the initial register set.  */
  if (prog_bfd == NULL)
    return SIM_RC_OK;

  memset (&dis_info, 0, sizeof (dis_info));
  /* See opcode/dis-init.c and dis-asm.h for details.  */
  INIT_DISASSEMBLE_INFO (dis_info, stderr, fprintf);
  dis_info.application_data = (void *) sd;
  dis_info.read_memory_func = sim_dis_read;
  dis_info.arch = bfd_get_arch (prog_bfd);
  dis_info.mach = bfd_get_mach (prog_bfd);
  disassemble_init_for_target (&dis_info);

  /* Set PC to entry point address.  */
  (*CPU_PC_STORE (cpu)) (cpu, bfd_get_start_address (prog_bfd));

  /* Set default endian.  */
  if (bfd_big_endian (prog_bfd))
    CCPU_SR_SET (PSW, PSW_BE);
  else
    CCPU_SR_CLEAR (PSW, PSW_BE);

  STATE_CALLBACK (sd)->syscall_map = cb_nds32_libgloss_syscall_map;
  nds32_init_libgloss (sd, prog_bfd, argv, env);

  return SIM_RC_OK;
}

void
sim_set_callbacks (host_callback * ptr)
{
  /* callback = ptr; */
}
