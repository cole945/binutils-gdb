/* Simulator for NDS32 COP0/FPU.

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

void
nds32_decode32_lwc (SIM_DESC sd, const uint32_t insn)
{
  const int cop = __GF (insn, 13, 2);
  const int fst = N32_RT5 (insn);
  const int ra = N32_RA5 (insn);
  const int imm12s = N32_IMM12S (insn);
  sim_fpu sf;

  if (insn & (1 << 12))
    {
      nds32_fpr[fst].u = nds32_ld (sd, nds32_gpr[ra].u, 4);
      nds32_gpr[ra].u += (imm12s << 2);
    }
  else
    {
      nds32_fpr[fst].u = nds32_ld (sd, nds32_gpr[ra].u + (imm12s << 2), 4);
    }
}

void
nds32_decode32_swc (SIM_DESC sd, const uint32_t insn)
{
  const int cop = __GF (insn, 13, 2);
  const int fst = N32_RT5 (insn);
  const int ra = N32_RA5 (insn);
  const int imm12s = N32_IMM12S (insn);

  if (insn & (1 << 12))		/* fssi.bi */
    {
      nds32_st (sd, nds32_gpr[ra].u, 4, nds32_fpr[fst].u);
      nds32_gpr[ra].u += (imm12s << 2);
    }
  else				/* fssi */
    {
      nds32_st (sd, nds32_gpr[ra].u + (imm12s << 2), 4, nds32_fpr[fst].u);
    }
}

void
nds32_decode32_ldc (SIM_DESC sd, const uint32_t insn)
{
  const int cop = __GF (insn, 13, 2);
  const int fdt = N32_RT5 (insn) << 1;
  const int ra = N32_RA5 (insn);
  const int imm12s = N32_IMM12S (insn);
  uint64_t d;

  if (insn & (1 << 12))		/* fldi.bi */
    {
      d = nds32_ld (sd, nds32_gpr[ra].u, 8);
      nds32_gpr[ra].u += (imm12s << 2);
    }
  else				/* fldi */
    {
      d = nds32_ld (sd, nds32_gpr[ra].u + (imm12s << 2), 8);
    }

  nds32_fpr[fdt + 1].u = d & 0xFFFFFFFF;
  nds32_fpr[fdt].u = (d >> 32) & 0xFFFFFFFF;
}

void
nds32_decode32_sdc (SIM_DESC sd, const uint32_t insn)
{
  const int cop = __GF (insn, 13, 2);
  const int fdt = N32_RT5 (insn) << 1;
  const int ra = N32_RA5 (insn);
  const int imm12s = N32_IMM12S (insn);
  uint64_t d;

  d = ((uint64_t) nds32_fpr[fdt].u << 32) | (uint64_t) nds32_fpr[fdt + 1].u;

  if (insn & (1 << 12))
    {
      nds32_st (sd, nds32_gpr[ra].u, 8, d);
      nds32_gpr[ra].u += (imm12s << 2);
    }
  else
    {
      nds32_st (sd, nds32_gpr[ra].u + (imm12s << 2), 8, d);
    }
}

void
nds32_decode32_cop (SIM_DESC sd, const uint32_t insn)
{
  const int cop = __GF (insn, 4, 2);
  const int fst = N32_RT5 (insn);
  const int fsa = N32_RA5 (insn);
  const int fsb = N32_RB5 (insn);
  int rt = N32_RT5 (insn);
  const int ra = N32_RA5 (insn);
  const int rb = N32_RB5 (insn);
  const int fdt = N32_RT5 (insn) << 1;
  const int fda = N32_RA5 (insn) << 1;
  const int fdb = N32_RB5 (insn) << 1;
  int fcmp;
  uint64_t d;
  sim_fpu sfst;
  sim_fpu sfsa;
  sim_fpu sfsb;

  sim_fpu_32to (&sfsa, nds32_fpr[fsa].u);
  sim_fpu_32to (&sfsb, nds32_fpr[fsb].u);
  fcmp = sim_fpu_cmp (&sfsa, &sfsb);

  switch (insn & 0x3ff)
    {
    case 0x1:		/* fmfsr */
      nds32_gpr[rt].u = nds32_fpr[fsa].u;
      return;
    case 0x9:		/* fmtsr */
      nds32_fpr[fst].u = nds32_gpr[ra].u;
      return;
    case 0x41:		/* fmfdr */
      rt &= ~1;
      if (nds32_psw_be ())
	{
	  nds32_gpr[rt] = nds32_fpr[fda];
	  nds32_gpr[rt + 1] = nds32_fpr[fda + 1];
	}
      else
	{
	  nds32_gpr[rt + 1] = nds32_fpr[fda];
	  nds32_gpr[rt] = nds32_fpr[fda + 1];
	}
      return;
    case 0x49:		/* fmtdr */
      rt &= ~1;
      if (nds32_psw_be ())
	{
	  nds32_fpr[fdt] = nds32_gpr[ra];
	  nds32_fpr[fdt + 1] = nds32_gpr[ra + 1];
	}
      else
	{
	  nds32_fpr[fdt + 1] = nds32_gpr[ra];
	  nds32_fpr[fdt] = nds32_gpr[ra + 1];
	}
      return;
    case 0xc8:		/* fcpysd */
      nds32_fpr[fdt].u = nds32_fpr[fda].u & 0x7fffffff;
      nds32_fpr[fdt].u |= nds32_fpr[fdb].u & 0x80000000;
      return;
    case 0x300:		/* fmuls */
      sim_fpu_mul (&sfst, &sfsa, &sfsb);
      sim_fpu_to32 ((unsigned32*)(nds32_fpr + fst), &sfst);
      return;
    case 0x3c0:		/* fs2d */
      sim_fpu_32to (&sfst, nds32_fpr[fsa].u);
      sim_fpu_to64 (&d, &sfst);
      nds32_fpr[fdt].u = (d >> 32) & 0xFFFFFFFF;
      nds32_fpr[fdt + 1].u = d & 0xFFFFFFFF;
      return;
    case 0x3c8:		/* fsi2d */
    case 0x0c:		/* fcmpeqd */
#if 0
      if (fcmp == SIM_FPU_IS_NZERO || fcmp == SIM_FPU_IS_NZERO)
	sim_fpu_to64 (&d, &sim_fpu_one);
      else
	sim_fpu_to64 (&d, &sim_fpu_zero);
      nds32_fpr[fdt].u = (d >> 32) & 0xFFFFFFFF;
      nds32_fpr[fdt + 1].u = d & 0xFFFFFFFF;
      return;
#endif
    case 0x8c:		/* fcmpltd */
    case 0x10c:		/* fcmpled */
    case 0x18c:		/* fcmpund */
	goto bad_op;
    }

bad_op:
  nds32_bad_op (sd, nds32_usr[NC_PC].u - 4, insn, "COP");
}
