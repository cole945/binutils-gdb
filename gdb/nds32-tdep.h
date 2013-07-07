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

/* NDS32 virtual registers layout for GDB.  */
enum nds32_regnum
{
  /* General purpose registers.  */
  NDS32_R0_REGNUM = 0,
  NDS32_R5_REGNUM = 5,
  NDS32_TA_REGNUM = 15,		/* Temp for assembler.  */
  NDS32_FP_REGNUM = 28,		/* Frame register.  */
  NDS32_GP_REGNUM = 29,		/* Global register.  */
  NDS32_LP_REGNUM = 30,		/* Link pointer.  */
  NDS32_SP_REGNUM = 31,		/* Address of stack top.  */

  /* Pseudo PC.  */
  NDS32_PC_REGNUM = 32,

  /* D0/D1 User Registers.  */
  NDS32_D0LO_REGNUM = 33,
  NDS32_D0HI_REGNUM = 34,
  NDS32_D1LO_REGNUM = 35,
  NDS32_D1HI_REGNUM = 36,

  /* If target-description is not supported, only assume above
     registers are supported.  */
  NDS32_NUM_REGS,

  /* These are only used by simulator.  */
  NDS32_SIM_FD0_REGNUM = NDS32_NUM_REGS,
  NDS32_SIM_IFCLP_REGNUM = NDS32_SIM_FD0_REGNUM + 32,
  NDS32_SIM_ITB_REGNUM,
  NDS32_SIM_PSW_REGNUM,

  NDS32_SIM_NUM_REGS,
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
  /* The configuration of FPU FREG.  */
  int fpu_freg;

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

  /* ABI for Inferior Call Setup.
     Default AUTO by reading ABI in ELF header.  */
  int use_abi;
};

extern struct cmd_list_element *nds32_cmdlist;
#endif
