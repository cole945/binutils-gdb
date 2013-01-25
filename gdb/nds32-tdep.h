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

#define NDS32_NUM_PSEUDO_REGS     (NDS32_NUM_FPR)

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
  NDS32_IFCLP_REGNUM = 37,
  NDS32_PSW_REGNUM = 38,

  /* for linux */
  NDS32_LINUX_ORIG_R0_REGNUM = 39,
  NDS32_LINUX_FUCPR_REGNUM = 40,

  NDS32_LEGACY_NUM_REGS,
  /* Old ICEman/SID sends 169 registers in g-packet.  */
  NDS32_LEGACY_G_NUM_REGS = 169,
  /*
     FPU registers may be pesudo registers or not.
     For target supporting tdesc, FPRs are no different from GPRs.
     For legacy target (e.g., SID), FPRs are pseudo registers and accessed
     by qRcmd.

     Either case, in order to simplify the implementation of GDB.
     we should make register numbering the same,
     so we don't have to handle them differently in these functions,

       # nds32_pseudo_register*
       # nds32_push_dummy_call
       # nds32_return_value
   */
  NDS32_PSEUDO_BASE_REGNUM = 0x100,

  NDS32_FPCFG_REGNUM = NDS32_PSEUDO_BASE_REGNUM,
  NDS32_FPCSR_REGNUM,
  NDS32_FS0_REGNUM,			/* FS0-FS31. */
  NDS32_FD0_REGNUM = NDS32_FS0_REGNUM + 32,	/* FD0-FD31.  */
  NDS32_FPU_REGNUM = NDS32_FPCFG_REGNUM,
  NDS32_FPU_END_REGNUM = NDS32_FPU_REGNUM + 2 + 32 + 32,

  /* Register numbers for target which does'not support tdesc.

       * These are sent by g-packet.
       r0   - r32        0 -  31
       pc               32
       d0lo - d1hi      33 -  36
       cr0  - cr6       37 -  43
       ir0  - ir15      44 -  59
       mr0  - mr10      60 -  70
       dr0  - dr47      71 - 118
       pfr0 - pfr3     119 - 122
       fucpr           123
       dmar0-dmar10    124 - 134
       racr0           135
       idr0 - idr1     136 - 137
       AUDIO*          138 - 169

       * These are sent by p-packet.
       ir16 - ir17     170 - 171
       dr48            172
       ir18 - ir19     173 - 174
       ir20 - ir25     176 - 181
       mr11            182
       secur0          183
       irb             184
       ir26 - ir29     185 - 188
   */


  /* This must be bigger enough to cover all _numbered_ registers,
     (i.e., GPRs, FPRs, et al.) Otherwise, it fails the assertion
     in tdesc_use_registers (). */
  NDS32_NUM_REGS,
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
struct htab;
struct gdbarch_tdep
{
  /* ABI version */
  enum nds32_abi nds32_abi;
  int nds32_fpu_sp_num;
  int nds32_fpu_dp_num;
  int nds32_fpu_pseudo;		/* Whether fpu is implemented using Rcmd.  */
  int nds32_ifc;		/* Whether ifc_lp exists?  */
  int nds32_psw;		/* Whether PSW.IFCON is on?  */
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

  /* Type table for registers.  */
  struct htab *type_tab;
};

/* Hidden options.  */
struct nds32_gdb_config
{
  /* Use DWARF/CFI for stack frame unwinding.
     This is much reliable than manual prologue analysis.
     Default true.  */
  int use_cfi;

  /* Backtrace for IFC frame by checking PSW.IFCON.
     Default true, so monmon is happy about it.  */
  int use_ifcret;		/* default true */

  /* Prefer $fp as framebase instead of analyzing $sp adjustion,
     for dynamic stack, e.g., calling alloca (), this should be reliable.
     Default true.  */
  int use_fp;

  /* ABI for Inferior Call Setup.
     Default AUTO by reading ABI in ELF header.  */
  int use_abi;

  /* Stop backtrace when $fp is 0. If the code does not use $fp
     for frame setup, backtrace might be broken.
     Default false.  */
  int use_stop_zfp;

  /* Whether there exists floating-point registers.
     This should be auto configured by target-desciption,
     but SID does not implement it.
     Default AUTO by checking SP/DP bit is set in ELF header.  */
  int use_fpreg;
};

extern struct cmd_list_element *nds32_cmdlist;
#endif
