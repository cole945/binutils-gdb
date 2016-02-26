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

#ifndef NDS32_TDEP_H
#define NDS32_TDEP_H

enum nds32_regnum
{
  /* General purpose registers.  */
  NDS32_R0_REGNUM = 0,
  NDS32_R5_REGNUM = 5,
  NDS32_TA_REGNUM = 15,		/* Temporary register.  */
  NDS32_FP_REGNUM = 28,		/* Frame pointer.  */
  NDS32_GP_REGNUM = 29,		/* Global pointer.  */
  NDS32_LP_REGNUM = 30,		/* Link pointer.  */
  NDS32_SP_REGNUM = 31,		/* Stack pointer.  */

  NDS32_PC_REGNUM = 32,		/* Program counter.  */

  /* D0/D1 User Registers.  */
  NDS32_D0LO_REGNUM = 33,
  NDS32_D0HI_REGNUM = 34,
  NDS32_D1LO_REGNUM = 35,
  NDS32_D1HI_REGNUM = 36,

  NDS32_NUM_REGS,

  /* Double precision floating-point registers.  */
  NDS32_FD0_REGNUM = NDS32_NUM_REGS,

  /* Single precision floating-point registers.  */
  NDS32_FS0_REGNUM = NDS32_FD0_REGNUM + 32,
};

struct gdbarch_tdep
{
  /* The guessed FPU configuration.  */
  int fpu_freg;
  /* FSRs are defined as pseudo registers.  */
  int use_pseudo_fsrs;
  int fs0_regnum;
  int fd0_regnum;
  /* The guessed number of FDRs implemented.  */
  int num_fdr_regs;
  /* The guessed number of FSRs implemented.  */
  int num_fsr_regs;

  int abi;
};
#endif /* NDS32_TDEP_H */
