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
#include "nds32-sim.h"
#include "sim-utils.h"
#include "sim-fpu.h"

#include "opcode/nds32.h"
#include "nds32-sim.h"
#include "nds32-libc.h"

static inline uint64_t
nds32_fd_to_64 (sim_cpu *cpu, int fd)
{
  fd <<= 1;
  return ((uint64_t) CCPU_FPR[fd].u << 32) | (uint64_t) CCPU_FPR[fd + 1].u;
}

static inline void
nds32_fd_from_64 (sim_cpu *cpu, int fd, uint64_t u64)
{
  fd <<= 1;
  CCPU_FPR[fd + 1].u = u64 & 0xFFFFFFFF;
  CCPU_FPR[fd].u = (u64 >> 32) & 0xFFFFFFFF;
}

sim_cia
nds32_decode32_lwc (sim_cpu *cpu, const uint32_t insn, sim_cia cia)
{
  const int cop = __GF (insn, 13, 2);
  const int fst = N32_RT5 (insn);
  const int ra = N32_RA5 (insn);
  const int imm12s = N32_IMM12S (insn);
  sim_fpu sf;

  if (insn & (1 << 12))
    {
      CCPU_FPR[fst].u = nds32_ld_aligned (cpu, CCPU_GPR[ra].u, 4);
      CCPU_GPR[ra].u += (imm12s << 2);
    }
  else
    {
      CCPU_FPR[fst].u = nds32_ld_aligned (cpu, CCPU_GPR[ra].u + (imm12s << 2), 4);
    }

  return cia + 4;
}

sim_cia
nds32_decode32_swc (sim_cpu *cpu, const uint32_t insn, sim_cia cia)
{
  const int cop = __GF (insn, 13, 2);
  const int fst = N32_RT5 (insn);
  const int ra = N32_RA5 (insn);
  const int imm12s = N32_IMM12S (insn);

  if (insn & (1 << 12))		/* fssi.bi */
    {
      nds32_st_aligned (cpu, CCPU_GPR[ra].u, 4, CCPU_FPR[fst].u);
      CCPU_GPR[ra].u += (imm12s << 2);
    }
  else				/* fssi */
    {
      nds32_st_aligned (cpu, CCPU_GPR[ra].u + (imm12s << 2), 4, CCPU_FPR[fst].u);
    }

  return cia + 4;
}

sim_cia
nds32_decode32_ldc (sim_cpu *cpu, const uint32_t insn, sim_cia cia)
{
  const int cop = __GF (insn, 13, 2);
  const int fdt = N32_RT5 (insn);
  const int ra = N32_RA5 (insn);
  const int imm12s = N32_IMM12S (insn);
  uint64_t u64;

  if (insn & (1 << 12))		/* fldi.bi */
    {
      u64 = nds32_ld_aligned (cpu, CCPU_GPR[ra].u, 8);
      CCPU_GPR[ra].u += (imm12s << 2);
    }
  else				/* fldi */
    {
      u64 = nds32_ld_aligned (cpu, CCPU_GPR[ra].u + (imm12s << 2), 8);
    }

  nds32_fd_from_64 (cpu, fdt, u64);

  return cia + 4;
}

sim_cia
nds32_decode32_sdc (sim_cpu *cpu, const uint32_t insn, sim_cia cia)
{
  const int cop = __GF (insn, 13, 2);
  const int fdt = N32_RT5 (insn);
  const int ra = N32_RA5 (insn);
  const int imm12s = N32_IMM12S (insn);
  uint64_t u64;

  u64 = nds32_fd_to_64 (cpu, fdt);

  if (insn & (1 << 12))
    {
      nds32_st_aligned (cpu, CCPU_GPR[ra].u, 8, u64);
      CCPU_GPR[ra].u += (imm12s << 2);
    }
  else
    {
      nds32_st_aligned (cpu, CCPU_GPR[ra].u + (imm12s << 2), 8, u64);
    }

  return cia + 4;
}

/* Returns 0 for false
	   1 for equal
	   2 for less
	   3 for qnan
	   4 for snan */

static int
nds32_decode32_fcmp (sim_fpu *sfa, sim_fpu *sfb)
{
  int op0is = sim_fpu_is (sfa);
  int op1is = sim_fpu_is (sfb);
  int fcmp; /* lazy init. sim_fpu_cmp (&sfa, &sfb); */
  int r;
  static int s2i[12] = {
    [SIM_FPU_IS_NINF] = 0,
    [SIM_FPU_IS_PINF] = 7,
    [SIM_FPU_IS_NNUMBER] = 1,
    [SIM_FPU_IS_PNUMBER] = 6,
    [SIM_FPU_IS_NDENORM] = 2,
    [SIM_FPU_IS_PDENORM] = 5,
    [SIM_FPU_IS_NZERO] = 3,
    [SIM_FPU_IS_PZERO] = 4,
    [SIM_FPU_IS_QNAN] = 8,
    [SIM_FPU_IS_SNAN] = 9,
  };
  /* -i -n -dn -0 +0 +dn +n +i qn sn*/
  static char ctab[100] = {
    1, 0, 0, 0, 0, 0, 0, 0, 3, 4,
    2, 9, 0, 0, 0, 0, 0, 0, 3, 4,
    2, 2, 9, 0, 0, 0, 0, 0, 3, 4,
    2, 2, 2, 1, 1, 0, 0, 0, 3, 4,
    2, 2, 2, 1, 1, 0, 0, 0, 3, 4,
    2, 2, 2, 2, 2, 9, 0, 0, 3, 4,
    2, 2, 2, 2, 2, 2, 9, 0, 3, 4,
    2, 2, 2, 2, 2, 2, 2, 1, 3, 4,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
  };

  r = ctab [s2i[op0is] + s2i[op1is] * 10];
  if (r != 9)
    return r;

  fcmp = sim_fpu_cmp (sfa, sfb);

  if (LSBIT32 (fcmp)
      & (LSBIT32 (SIM_FPU_IS_NZERO) | LSBIT32 (SIM_FPU_IS_PZERO)))
    return 1;
  else if (LSBIT32 (fcmp)
	   & (LSBIT32 (SIM_FPU_IS_NINF) | LSBIT32 (SIM_FPU_IS_NNUMBER)
	      | LSBIT32 (SIM_FPU_IS_NDENORM) | LSBIT32 (SIM_FPU_IS_NZERO)))
    return 2;
  return 0;
}

sim_cia
nds32_decode32_cop (sim_cpu *cpu, const uint32_t insn, sim_cia cia)
{
  const int sv = __GF (insn, 8, 2);
  const int cop = __GF (insn, 4, 2);
  const int fst = N32_RT5 (insn);
  const int fsa = N32_RA5 (insn);
  const int fsb = N32_RB5 (insn);
  const int rt = N32_RT5 (insn);
  const int ra = N32_RA5 (insn);
  const int rb = N32_RB5 (insn);
  const int fdt_ = N32_RT5 (insn) << 1;	/* I use fdX_ as shifted fdX. */
  const int fda_ = N32_RA5 (insn) << 1;
  const int fdb_ = N32_RB5 (insn) << 1;
  int fcmp = SIM_FPU_IS_SNAN;
  uint64_t u64;
  uint32_t u32;
  uint32_t i32;
  sim_fpu sft;
  sim_fpu sfa;
  sim_fpu sfb;

  /* Prepare operand for F[SD][12]. */
  if ((insn & 0xb) == 0)
    {
      /* FS1,  FS2 */
      sim_fpu_32to (&sfa, CCPU_FPR[fsa].u);
      sim_fpu_32to (&sfb, CCPU_FPR[fsb].u);
    }
  else if ((insn & 0xb) == 8)
    {
      /* FD1, FD2 */
      u64 = nds32_fd_to_64 (cpu, fda_ >> 1);
      sim_fpu_64to (&sfa, u64);
      u64 = nds32_fd_to_64 (cpu, fdb_ >> 1);
      sim_fpu_64to (&sfb, u64);
    }

  if ((insn & 0x7) == 0)
    {
      int dp = (insn & 0x8) > 0;
      int sft_to_dp = dp;

      switch (__GF (insn, 6, 4))
	{
	case 0x0:		/* fadds */
	  sim_fpu_add (&sft, &sfa, &sfb);
	  break;
	case 0x1:		/* fsubs */
	  sim_fpu_sub (&sft, &sfa, &sfb);
	  break;
	case 0x3:
	  if (!dp)
	    {
	      /* fcpyss */
	      u32 = CCPU_FPR[fsa].u & 0x7fffffff;
	      u32 |= CCPU_FPR[fsb].u & 0x80000000;
	      CCPU_FPR[fst].u = u32;
	    }
	  else
	    {
	      /* fcpysd */
	      u32 = CCPU_FPR[fda_].u & 0x7fffffff;
	      u32 |= CCPU_FPR[fdb_].u & 0x80000000;
	      CCPU_FPR[fdt_].u = u32;
	      CCPU_FPR[fdt_ + 1].u = CCPU_FPR[fda_ + 1].u;
	    }
	  goto done; /* Just return.  */
	case 0x6:		/* fcmovnX */
	case 0x7:		/* fcmovzX */
	  if (!dp)
	    {
	      /* fcmovzs */
	      if ((CCPU_FPR[fsb].u != 0) ^ ((insn & 1 << 6) != 0))
		CCPU_FPR[fst] = CCPU_FPR[fsa];
	    }
	  else
	    {
	      /* fcmovzd */
	      if ((CCPU_FPR[fsb].u != 0) ^ ((insn & 1 << 6) != 0))
		{
		  CCPU_FPR[fdt_] = CCPU_FPR[fda_];
		  CCPU_FPR[fdt_ + 1] = CCPU_FPR[fda_ + 1];
		}
	    }
	  goto done;
	case 0xc:		/* fmuls */
	  sim_fpu_mul (&sft, &sfa, &sfb);
	  break;
	case 0xd:		/* fdivs */
	  sim_fpu_div (&sft, &sfa, &sfb);
	  break;
#if 0
	case 0x2:		/* fcpynsd */
	case 0x4:		/* fmaddd */
	case 0x5:		/* fmsubd */
	case 0x6:		/* fcmovnd */
	case 0x7:		/* fcmovzd */
	case 0x8:		/* fnmaddd */
	case 0x9:		/* fnmsubd */
	case 0xa:
	case 0xb:		/* reserved */
#endif
	case 0xf:		/* F2OP */
#define	DP (1 << 8)
	  switch (__GF (insn, 10, 5) | (dp ? DP : 0))
	    {
	    case 0x0:		/* fs2d */
	    case 0x0 | DP:	/* fd2s */
	      sft = sfa;
	      sft_to_dp = !dp;
	      break;
	    case 0x1:		/* sqrts */
	    case 0x1 | DP:	/* sqrtd */
	      sim_fpu_sqrt (&sft, &sfa);
	      break;
	    case 0x5:		/* fabss */
	      CCPU_FPR[fst].u = CCPU_FPR[fsa].u & 0x7fffffff;
	      goto done; /* Just return.  */
	    case 0x5 | DP:	/* fabsd */
	      CCPU_FPR[fdt_].u = CCPU_FPR[fda_].u & 0x7fffffff;
	      CCPU_FPR[fdt_ + 1].u = CCPU_FPR[fda_ + 1].u;
	      goto done; /* Just return.  */
	    case 0xc:		/* fsi2s */
	    case 0xc | DP:	/* fsi2d */
	      sim_fpu_i32to (&sft, CCPU_FPR[fsa].u, sim_fpu_round_near);
	      break;
	    case 0x10:		/* fs2ui */
	    case 0x14:		/* fs2ui.z */
	    case 0x10 | DP:	/* fd2ui */
	    case 0x14 | DP:	/* fd2ui.z */
	      sim_fpu_to32u (&u32, &sfa, (insn & (1 << 12))
					 ? sim_fpu_round_zero
					 : sim_fpu_round_near);
	      CCPU_FPR[fst].u = u32;
	      goto done; /* Just return.  */
	    case 0x18:		/* fs2si */
	    case 0x1c:		/* fs2si.z */
	    case 0x18 | DP:	/* fd2si */
	    case 0x1c | DP:	/* fd2si.z */
	      sim_fpu_to32i (&i32, &sfa, (insn & (1 << 12))
					 ? sim_fpu_round_zero
					 : sim_fpu_round_near);
	      CCPU_FPR[fst].s = i32;
	      goto done; /* Just return.  */
	    default:
	      goto bad_op;
	    }
	  break;
	default:
	  goto bad_op;
	}

      if (!sft_to_dp)
	{
	  /* General epilogue for saving result to fst.  */
	  sim_fpu_to32 ((unsigned32 *) (CCPU_FPR + fst), &sft);
	}
      else
	{
	  /* General epilogue for saving result to fdt.  */
	  sim_fpu_to64 (&u64, &sft);
	  nds32_fd_from_64 (cpu, fdt_ >> 1, u64);
	}
      goto done;
    }

  /* fcmpxxd and fcmpxxs share this function. */
  if ((insn & 0x7) == 4)
    {
      fcmp = nds32_decode32_fcmp (&sfa, &sfb);
      switch (__GF (insn, 7, 3))
	{
	case 0x0:		/* fcmpeq[sd] */
	  CCPU_FPR[fst].u = fcmp == 1;
	  goto done;
	case 0x1:		/* fcmplt[sd] */
	  CCPU_FPR[fst].u = fcmp == 2;
	  goto done;
	case 0x2:		/* fcmple[sd] */
	  CCPU_FPR[fst].u = fcmp == 1 || fcmp == 2;
	  goto done;
	case 0x3:
	  CCPU_FPR[fst].u = fcmp == 3 || fcmp == 4;
	  goto done;
	}
      goto done;
    }

  switch (insn & 0x3ff)
    {
    case 0x1:			/* fmfsr */
      CCPU_GPR[rt].u = CCPU_FPR[fsa].u;
      goto done;
    case 0x9:			/* fmtsr */
      CCPU_FPR[fsa].u = CCPU_GPR[rt].u;
      goto done;
    case 0x41:			/* fmfdr */
      {
	int rt_ = rt & ~1;
	if (CCPU_SR_TEST (PSW, PSW_BE))
	  {
	    CCPU_GPR[rt_] = CCPU_FPR[fda_];
	    CCPU_GPR[rt_ + 1] = CCPU_FPR[fda_ + 1];
	  }
	else
	  {
	    CCPU_GPR[rt_] = CCPU_FPR[fda_ + 1];
	    CCPU_GPR[rt_ + 1] = CCPU_FPR[fda_];
	  }
      }
      goto done;
    case 0x49:			/* fmtdr */
      {
	int rt_ = rt & ~1;
	if (CCPU_SR_TEST (PSW, PSW_BE))
	  {
	    CCPU_FPR[fda_ + 1] = CCPU_GPR[rt_ + 1];
	    CCPU_FPR[fda_] = CCPU_GPR[rt_];
	  }
	else
	  {
	    CCPU_FPR[fda_ + 1] = CCPU_GPR[rt_];
	    CCPU_FPR[fda_] = CCPU_GPR[rt_ + 1];
	  }
      }
      goto done;
    }

  switch (insn & 0xFF)
    {
    case 0x2:			/* fls */
      u32 = nds32_ld_aligned (cpu, CCPU_GPR[ra].u + (CCPU_GPR[rb].s << sv), 4);
      CCPU_FPR[fst].u = u32;
      goto done;
    case 0x3:			/* fld */
      u64 = nds32_ld_aligned (cpu, CCPU_GPR[ra].u + (CCPU_GPR[rb].s << sv), 8);
      nds32_fd_from_64 (cpu, fdt_ >> 1, u64);
      goto done;
    case 0xa:			/* fss */
      nds32_st_aligned (cpu, CCPU_GPR[ra].u + (CCPU_GPR[rb].s << sv), 4, CCPU_FPR[fst].u);
      goto done;
    case 0xb:			/* fsd */
      u64 = nds32_fd_to_64 (cpu, fdt_ >> 1);
      nds32_st_aligned (cpu, CCPU_GPR[ra].u + (CCPU_GPR[rb].s << sv), 8, u64);
      goto done;
    case 0x82:			/* fls.bi */
      u32 = nds32_ld_aligned (cpu, CCPU_GPR[ra].u, 4);
      CCPU_GPR[ra].u += (CCPU_GPR[rb].s << sv);
      CCPU_FPR[fst].u = u32;
      goto done;
    case 0x83:			/* fld.bi */
      u64 = nds32_ld_aligned (cpu, CCPU_GPR[ra].u, 8);
      CCPU_GPR[ra].u += (CCPU_GPR[rb].s << sv);
      nds32_fd_from_64 (cpu, fdt_ >> 1, u64);
      goto done;
    case 0x8a:			/* fss.bi */
      nds32_st_aligned (cpu, CCPU_GPR[ra].u, 4, CCPU_FPR[fst].u);
      CCPU_GPR[ra].u += (CCPU_GPR[rb].s << sv);
      goto done;
    case 0x8b:			/* fsd.bi */
      u64 = nds32_fd_to_64 (cpu, fdt_ >> 1);
      nds32_st_aligned (cpu, CCPU_GPR[ra].u, 8, u64);
      CCPU_GPR[ra].u += (CCPU_GPR[rb].s << sv);
      goto done;
    }


done:
  return cia + 4;

bad_op:
  nds32_bad_op (cpu, cia, insn, "COP");
  return cia;
}
