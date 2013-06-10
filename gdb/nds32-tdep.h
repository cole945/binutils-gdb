/* Common target dependent code for GDB on nds32 systems.

   Copyright (C) 2006-2013 Free Software Foundation, Inc.
   Contributed by Andes Technology Corporation.

   This file is part of GDB.

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

#include "nds32-utils.h"

#ifndef __NDS32_TDEP_H__
#define __NDS32_TDEP_H__

/* Define numbers of registers we have in NDS32 arch.  */

#define NDS32_NUM_GR	32	/* general registers. */
#define NDS32_NUM_SPR	5	/* special registers. (PC, D0, D1) */
#define NDS32_NUM_CR	7	/* ctrl registers. */
#define NDS32_NUM_IR	18	/* interruption registers. */
#define NDS32_NUM_MR	11	/* MMU registers. */
#define NDS32_NUM_DR	49	/* debug registers. */
#define NDS32_NUM_PFR	4	/* performance monitoring registers. */
#define NDS32_NUM_DMAR	11	/* local memory DMA registers. */
#define NDS32_NUM_RACR	1	/* resource access control registers. */
#define NDS32_NUM_IDR	2	/* implementation dependent registers. */
#define NDS32_NUM_AUMR	32	/* audio user mode registers. */
#define NDS32_NUM_FPR	66	/* floating point registers */
#define NDS32_NUM_SR	(NDS32_NUM_CR + NDS32_NUM_IR + NDS32_NUM_MR + \
			 NDS32_NUM_DR + NDS32_NUM_PFR + 1 + NDS32_NUM_DMAR + \
			 NDS32_NUM_RACR + NDS32_NUM_IDR + NDS32_NUM_AUMR )

#define NDS32_NUM_REGS	(NDS32_NUM_GR + NDS32_NUM_SPR + NDS32_NUM_SR)
#define NDS32_NUM_PSEUDO_REGS	(NDS32_NUM_FPR)

/* NDS32 virtual registers layout for GDB.  */
enum nds32_regnum
{
  /* Use [NDS32_xxx0_REGNUM, NDS32_END_REGNUM) */
  NDS32_R0_REGNUM = 0,
  NDS32_R5_REGNUM = 5,
  NDS32_R15_REGNUM = 15,
  NDS32_R17_REGNUM = 17,
  NDS32_TA_REGNUM = NDS32_R15_REGNUM,   /* Temp for assembler.  */
  NDS32_FP_REGNUM = 28,			/* Frame register.  */
  NDS32_GP_REGNUM = 29,			/* Global register.  */
  NDS32_LP_REGNUM = 30,			/* Link pointer.  */
  NDS32_SP_REGNUM = 31,			/* Address of stack top.  */

  NDS32_PC_REGNUM = 32,
  NDS32_D0LO_REGNUM = 33,
  NDS32_D0HI_REGNUM = 34,
  NDS32_D1LO_REGNUM = 35,
  NDS32_D1HI_REGNUM = 36,

  /* for linux */
  NDS32_LINUX_ORIG_R0_REGNUM = 37,
  NDS32_LINUX_FUCPR_REGNUM = 38,

  /* FPR registers may be pesudo or not */
  NDS32_FPCFG_REGNUM = 0x100,
  NDS32_FPCSR_REGNUM,
  NDS32_FS0_REGNUM,			/* FS0-FS31. */
  NDS32_FD0_REGNUM = NDS32_FS0_REGNUM + 32,	/* FD0-FD31.  */

  NDS32_FPU_REGNUM = NDS32_FPCFG_REGNUM,
  NDS32_FPU_END_REGNUM = NDS32_FPU_REGNUM + 2 + 32 + 32,
};

/* All the possible NDS32 ABIs.  They must be consistent with elf/nds32.h.  */
enum nds32_abi
{
  NDS32_ABI_V0 = 0,
  NDS32_ABI_V1,
  NDS32_ABI_V2,
  NDS32_ABI_V2FP,
  NDS32_ABI_AABI,
  NDS32_ABI_END,
  NDS32_ABI_BEGIN = NDS32_ABI_V0,
  /* ABI flag is only 4-bits long.  */
  NDS32_ABI_AUTO = 0xFFFFFFFF
};

enum nds32_fpu
{
  NDS32_FPU_8SP_4DP = 0x0,
  NDS32_FPU_16SP_8DP = 0x1,
  NDS32_FPU_32SP_16DP = 0x2,
  NDS32_FPU_32SP_32DP = 0x3,
  NDS32_FPU_END,
  NDS32_FPU_BEGIN = NDS32_FPU_8SP_4DP,
  /* FPU flag is only 2-bits long */
  NDS32_FPU_NONE = 0x4
};

/* ----------------------------------------------
   31   28 27                 8 7   4 3       0
   ----------------------------------------------
   | ARCH | CONFUGURAION FIELD | ABI | VERSION  |
   ---------------------------------------------- */
struct gdbarch_tdep
{
  /* ABI version */
  enum nds32_abi nds32_abi;
  int nds32_fpu_sp_num;
  int nds32_fpu_dp_num;
  int nds32_fpu_pseudo;		/* Whether FPU is implemented using Rcmd.  */
  int use_fpr;			/* Set if sp_num + dp_num > 0.  */
  int use_spill;		/* V2/FP do not allow arg spilling out of stack.  */

  unsigned int eflags;

  /* Detect sigtramp.  */
  int (*sigtramp_p) (struct frame_info *);

  /* Get address of sigcontext for sigtramp.  */
    CORE_ADDR (*sigcontext_addr) (struct frame_info *);

  /* Offset of saved PC in jmp_buf.  */
  /* TODO: int jb_pc_offset; */

  /* Offset of saved PC and SP in `struct sigcontext'. */
  int sc_pc_offset;
  int sc_lp_offset;
  int sc_sp_offset;
  int sc_fp_offset;

  int *sc_reg_offset;
  int sc_num_regs;

  const struct target_desc *tdesc;

  struct nds32_list nds32_types;
};

/* Hidden options.  */
struct nds32_gdb_config
{
  int use_cfi;			/* default false */
  int use_fp;			/* default true  */
  int use_abi;			/* default AUTO  */
  int use_stop_zfp;		/* default false */
  int use_fpreg;		/* default auto */
};

extern struct cmd_list_element *nds32_cmdlist;
#endif
