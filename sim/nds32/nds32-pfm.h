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

#ifndef NDS32_PFM_CTL_H
#define NDS32_PFM_CTL_H

#include "sim-main.h"
#include <stdint.h>

void nds32_pfm_ctl (sim_cpu *cpu);
void nds32_pfm_event (sim_cpu *cpu, int pfm_event);

enum PERFM_EVENT_ENUM
{
  PFM_CYCLE = 0,
  PFM_INST,

  PFM_COND_BRANCH = 64 + 2,
  PFM_TAKEN_COND,
  PFM_PREFETCH,
  PFM_RET,
  PFM_JR,
  PFM_JAL,
  PFM_NOP,
  PFM_SCW,
  PFM_IDSB,
  PFM_CCTL,
  PFM_TAKEN_INT,
  PFM_LOADS,

  PFM_COND_BRANCH_MISPREDICT = 128 + 2,
};

#endif
