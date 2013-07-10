/* Target-dependent header for NDS32 architecture, for GDB.

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

struct htab;
struct gdbarch_tdep
{
  /* The configuration of FPU FREG.  */
  int fpu_freg;

  /* Large arguments are split between registers and stack.  */
  int abi_split;
  /* Set if fs0-fs5 are used to pass arguments.  */
  int abi_use_fpr;

  /* Type table for registers.  */
  struct htab *type_tab;
};

extern struct cmd_list_element *nds32_cmdlist;
#endif
