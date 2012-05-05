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

#include "sim-main.h"

typedef unsigned long long ulongest_t;
typedef signed long long longest_t;

enum nds32_gdb_regnum
{
  NG_TA = 15,
  NG_FP = 28,
  NG_GP = 29,
  NG_LP = 30,
  NG_SP = 31,
  NG_PC = 32,

  NG_D0LO = 33,
  NG_D0HI = 34,
  NG_D1LO = 35,
  NG_D1HI = 36,
  NG_ITB = 184,
  NG_IFCLP = 175,

  NG_PSW = 44,

  NG_FS0 = 0x100 + 2,
  NG_FD0 = NG_FS0 + 32,
};

enum nds32_cpu_regnum
{
  NC_D0LO = 0,
  NC_D0HI = 1,
  NC_D1LO = 2,
  NC_D1HI = 3,
  NC_ITB = 28,
  NC_IFCLP = 29,
  NC_PC = 31,
};

#define STACK_TOP	0xbf000000

#define SRIDX(M,m,e)  ((M << 7) | (m << 3) | e)
#define UXIDX(g,u)    ((g << 5) | u)

/* Do not use thsi directly. */
ulongest_t __nds32_ld (sim_cpu *cpu, SIM_ADDR addr, int size, int aligned_p);
void __nds32_st (sim_cpu *cpu, SIM_ADDR addr, int size, ulongest_t val, int aligned_p);
/* Use these wrappers. */
#define nds32_ld_aligned(CPU, ADDR, SIZE)		__nds32_ld (CPU, ADDR, SIZE, 1)
#define nds32_st_aligned(CPU, ADDR, SIZE, VAL)		__nds32_st (CPU, ADDR, SIZE, VAL, 1)
#define nds32_ld_unaligned(CPU, ADDR, SIZE)		__nds32_ld (CPU, ADDR, SIZE, 0)
#define nds32_st_unaligned(CPU, ADDR, SIZE, VAL)	__nds32_st (CPU, ADDR, SIZE, VAL, 0)

sim_cia nds32_decode32_lwc (sim_cpu *cpu, const uint32_t insn, sim_cia cia);
sim_cia nds32_decode32_swc (sim_cpu *cpu, const uint32_t insn, sim_cia cia);
sim_cia nds32_decode32_ldc (sim_cpu *cpu, const uint32_t insn, sim_cia cia);
sim_cia nds32_decode32_sdc (sim_cpu *cpu, const uint32_t insn, sim_cia cia);
sim_cia nds32_decode32_cop (sim_cpu *cpu, const uint32_t insn, sim_cia cia);
void nds32_bad_op (sim_cpu *cpu, uint32_t cia, uint32_t insn, char *tag);

void nds32_bad_op (sim_cpu *cpu, uint32_t cia, uint32_t insn, char *tag);

#if 1
#define SIM_IO_DPRINTF(sd, fmt, args...)   sim_io_printf (sd, fmt, ## args)
#else
#define SIM_IO_DPRINTF(...)	do { } while (0)
#endif

static inline int
nds32_psw_be ()
{
  /* return nds32_sr[SRIDX (1, 0, 0)].u & (1 << 5); */
  return 0;
}

static inline int
nds32_psw_ifc ()
{
  return 0;
  /* return nds32_sr[SRIDX (1, 0, 0)].u & (1 << 15); */
}

static inline void
nds32_psw_ifc_on ()
{
  /* nds32_sr[SRIDX (1, 0, 0)].u |= (1 << 15); */
}

static inline void
nds32_psw_ifc_off ()
{
  /* nds32_sr[SRIDX (1, 0, 0)].u &= ~(1 << 15); */
}

enum
{
  SRIDX_PSW	= SRIDX (1, 0, 0),
  PSW_BE	= 5,
  PSW_IFCON	= 15,

  SRIDX_MSC_CFG	= SRIDX (0, 4, 0),
  MSC_CFG_PFM	= 2,
  MSC_CFG_DIV	= 5,
  MSC_CFG_MAC	= 6,
  MSC_CFG_IFC	= 19,
  MSC_CFG_EIT	= 24,
};

#define CCPU_SR_TEST(SREG,BIT)	(cpu->reg_sr[SRIDX_##SREG].u & (1 << BIT))
#define CCPU_SR_SET(SREG,BIT)	do { cpu->reg_sr[SRIDX_##SREG].u |= (1 << BIT); } while (0)
#define CCPU_SR_CLEAR(SREG,BIT)	do { cpu->reg_sr[SRIDX_##SREG].u &= ~(1 << BIT); } while (0)

#endif
