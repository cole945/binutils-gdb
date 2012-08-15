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

#define SRIDX(M,m,e)  ((M << 7) | (m << 3) | e)
#define UXIDX(g,u)    ((g << 5) | u)

enum nds32_exceptions
{
  EXP_RESET = 0,
  EXP_TLB_FILL = 1,
  EXP_NO_PTE = 2,
  EXP_TLB_MISC = 3,
  EXP_TLB_VLPT_MISS = 4,
  EXP_MACHINE_ERROR = 5,
  EXP_DEBUG = 6,
  EXP_GENERAL = 7,
  EXP_SYSCALL = 8,
  EXP_HW0 = 9,	/* HW0-5: 9-14 */
  EXP_VEP0 = 9,	/* VEP0-64: 9-72 */
  EXP_SW0 = 15,

  EXP_BADOP,
};

uint32_t nds32_raise_exception (sim_cpu *cpu, enum nds32_exceptions e, int sig, char *msg, ...);

/* Do not use thsi directly. */
ulongest_t __nds32_ld (sim_cpu *cpu, SIM_ADDR addr, int size, int aligned_p);
void __nds32_st (sim_cpu *cpu, SIM_ADDR addr, int size, ulongest_t val, int aligned_p);
/* Use these wrappers. */
#define nds32_ld_aligned(CPU, ADDR, SIZE)		__nds32_ld (CPU, ADDR, SIZE, 1)
#define nds32_st_aligned(CPU, ADDR, SIZE, VAL)		__nds32_st (CPU, ADDR, SIZE, VAL, 1)
#define nds32_ld_unaligned(CPU, ADDR, SIZE)		__nds32_ld (CPU, ADDR, SIZE, 0)
#define nds32_st_unaligned(CPU, ADDR, SIZE, VAL)	__nds32_st (CPU, ADDR, SIZE, VAL, 0)

void nds32_init_libgloss (SIM_DESC sd, struct bfd *abfd, char **argv, char **env);
void nds32_init_linux (SIM_DESC sd, struct bfd *abfd, char **argv, char **env);

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
  SRIDX_IPSW	= SRIDX (1, 0, 1),
  SRIDX_P_IPSW	= SRIDX (1, 0, 2),
  PSW_GIE	= 0,
  PSW_BE	= 5,
  PSW_IFCON	= 15,

  SRIDX_IVB	= SRIDX (1, 1, 1),
  IVB_EVIC	= 13,
  IVB_ESZ	= 14,
  IVB_ESZ_N	= 2,
  IVB_IVBASE	= 16,
  IVB_IVBASE_N	= 16,

  SRIDX_EVA	= SRIDX (1, 2, 1),
  SRIDX_P_EVA	= SRIDX (1, 2, 2),
  SRIDX_ITYPE	= SRIDX (1, 3, 1),
  SRIDX_P_ITYPE	= SRIDX (1, 3, 2),
  ITYPE_ETYPE	= 0,
  ITYPE_ETYPE_N	= 4,
  ITYPE_INST	= 4,
  ITYPE_SWID	= 16,
  ITYPE_SWID_N	= 15,

  SRIDX_MERR	= SRIDX (1, 4, 1),
  SRIDX_IPC	= SRIDX (1, 5, 1),
  SRIDX_P_IPC	= SRIDX (1, 5, 2),
  SRIDX_OIPC	= SRIDX (1, 5, 3),
  SRIDX_P_P0	= SRIDX (1, 6, 2),
  SRIDX_P_P1	= SRIDX (1, 7, 2),
  SRIDX_INT_MASK	= SRIDX (1, 8, 0),
  SRIDX_INT_PEND	= SRIDX (1, 9, 0),

  SRIDX_MSC_CFG	= SRIDX (0, 4, 0),
  MSC_CFG_PFM	= 2,
  MSC_CFG_DIV	= 5,
  MSC_CFG_MAC	= 6,
  MSC_CFG_IFC	= 19,
  MSC_CFG_EIT	= 24,
};

ATTRIBUTE_UNUSED static void
__put_field (uint32_t *src, int shift, int bs, uint32_t val)
{
  uint32_t mask = (1 << bs) - 1;

  val &= mask;
  *src = (*src & ~(mask << shift)) | (val << shift);
}

#define CCPU_SR_TEST(SREG,BIT)	(cpu->reg_sr[SRIDX_##SREG].u & (1 << BIT))
#define CCPU_SR_SET(SREG,BIT)	do { cpu->reg_sr[SRIDX_##SREG].u |= (1 << BIT); } while (0)
#define CCPU_SR_CLEAR(SREG,BIT)	do { cpu->reg_sr[SRIDX_##SREG].u &= ~(1 << BIT); } while (0)
#define CCPU_SR_GET(SREG,BIT)	((cpu->reg_sr[SRIDX_##SREG].u >> BIT) & ((1 << BIT##_N) - 1))
#define CCPU_SR_PUT(SREG,BIT,V)	do { __put_field (&cpu->reg_sr[SRIDX_##SREG].u, BIT, BIT##_N, V); } while (0)

#endif
