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

#ifndef _NDS32_SIM_H_
#define _NDS32_SIM_H_

#include <stdbool.h>
#include <stdint.h>

typedef union {
  uint32_t u;
  int32_t s;
} reg_t;


struct nds32_cpu_state
{
  int dummy;
};

void nds32_bad_op (SIM_DESC sd, uint32_t pc, uint32_t insn, char *tag);

#endif
