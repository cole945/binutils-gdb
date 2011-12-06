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

#ifndef _NDS32_MAIN_SIM_H_
#define _NDS32_MAIN_SIM_H_

#include <stdint.h>

#include "sim-basics.h"
#include "sim-signal.h"
#include "nds32-sim.h"

typedef unsigned32 sim_cia;

#define CIA_GET(cpu)     CPU_PC_GET (cpu)
#define CIA_SET(cpu,val) CPU_PC_SET ((cpu), (val))

typedef struct _sim_cpu SIM_CPU;

#include "sim-base.h"

struct _sim_cpu {
  /* ... simulator specific members ... */
  struct nds32_cpu_state state;
  sim_cpu_base base;
};

struct sim_state {
  sim_cpu *cpu[MAX_NR_PROCESSORS];
#if (WITH_SMP)
#define STATE_CPU(sd,n) ((sd)->cpu[n])
#else
#define STATE_CPU(sd,n) ((sd)->cpu[0])
#endif
#define STATE_BOARD_DATA(sd) (&(sd)->board)

  char cmdline[256];	/* cmdline buffer */

  sim_state_base base;
};

#include "sim-engine.h"
#include "sim-options.h"
#include "run-sim.h"

#endif
