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

enum nds32_syscall_num
{
  SYS_exit = 1,
  SYS_open = 2,
  SYS_close = 3,
  SYS_read = 4,
  SYS_write = 5,
  SYS_lseek = 6,
  SYS_unlink = 7,
  SYS_getpid = 8,
  SYS_kill = 9,
  SYS_fstat = 10,
/* ARGV support. */
  SYS_argvlen = 12,
  SYS_argv = 13,
  SYS_chdir = 14,
  SYS_stat = 15,
  SYS_chmod = 16,
  SYS_utime = 17,
  SYS_time = 18,
  SYS_gettimeofday = 19,
  SYS_times = 20,
  SYS_argc = 172,
  SYS_argnlen = 173,
  SYS_argn = 174,
/* RedBoot. */
  SYS_rename = 3001,
  SYS_isatty = 3002,
  SYS_system = 3003,
/* NDS32 specific */
  SYS_errno = 6001,
  SYS_getcmdline = 6002
};

#define SRIDX(M,m,e)  ((M << 7) | (m << 3) | e)
#define UXIDX(g,u)    ((g << 5) | u)

longest_t nds32_ld_sext (sim_cpu *cpu, SIM_ADDR addr, int size);
ulongest_t nds32_ld (sim_cpu *cpu, SIM_ADDR addr, int size);
void nds32_st (sim_cpu *cpu, SIM_ADDR addr, int size, ulongest_t val);

sim_cia nds32_decode32_lwc (sim_cpu *cpu, const uint32_t insn, sim_cia cia);
sim_cia nds32_decode32_swc (sim_cpu *cpu, const uint32_t insn, sim_cia cia);
sim_cia nds32_decode32_ldc (sim_cpu *cpu, const uint32_t insn, sim_cia cia);
sim_cia nds32_decode32_sdc (sim_cpu *cpu, const uint32_t insn, sim_cia cia);
sim_cia nds32_decode32_cop (sim_cpu *cpu, const uint32_t insn, sim_cia cia);
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
  PSW_BE = 5,
  PSW_IFCON = 15,
};

#define CCPU_PSW_TEST(BIT)	(cpu->reg_sr[SRIDX (1, 0, 0)].u & (1 << BIT))
#define CCPU_PSW_SET(BIT)	do { cpu->reg_sr[SRIDX (1, 0, 0)].u |= (1 << BIT); } while (0)
#define CCPU_PSW_CLEAR(BIT)	do { cpu->reg_sr[SRIDX (1, 0, 0)].u &= ~(1 << 15); } while (0)

#endif
