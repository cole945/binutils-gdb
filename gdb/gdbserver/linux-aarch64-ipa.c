/* GNU/Linux/AArch64 specific low level interface, for the in-process
   agent library for GDB.

   Copyright (C) 2010-2015 Free Software Foundation, Inc.

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

#include "server.h"
#include "tracepoint.h"

void init_registers_aarch64 (void);
extern const struct target_desc *tdesc_aarch64;

/* These macros define the position of registers in the buffer collected
   by the fast tracepoint jump pad.  */
#define FT_CR_PC	33
#define FT_CR_R0	0
#define FT_CR_SP	32
#define FT_CR_GPR(n)	(FT_CR_R0 + (n))
#define REGSZ		8

static const int aarch64_ft_collect_regmap[] = {
  /* GPRs */
  FT_CR_GPR (0), FT_CR_GPR (1), FT_CR_GPR (2),
  FT_CR_GPR (3), FT_CR_GPR (4), FT_CR_GPR (5),
  FT_CR_GPR (6), FT_CR_GPR (7), FT_CR_GPR (8),
  FT_CR_GPR (9), FT_CR_GPR (10), FT_CR_GPR (11),
  FT_CR_GPR (12), FT_CR_GPR (13), FT_CR_GPR (14),
  FT_CR_GPR (15), FT_CR_GPR (16), FT_CR_GPR (17),
  FT_CR_GPR (18), FT_CR_GPR (19), FT_CR_GPR (20),
  FT_CR_GPR (21), FT_CR_GPR (22), FT_CR_GPR (23),
  FT_CR_GPR (24), FT_CR_GPR (25), FT_CR_GPR (26),
  FT_CR_GPR (27), FT_CR_GPR (28), FT_CR_GPR (29),
  FT_CR_GPR (30), FT_CR_SP,
  FT_CR_PC
};

#define PPC_NUM_FT_COLLECT_GREGS \
  (sizeof (aarch64_ft_collect_regmap) / sizeof(aarch64_ft_collect_regmap[0]))

/* Supply registers collected by the fast tracepoint jump pad.
   BUF is the second argument we pass to gdb_collect in jump pad.  */

void
supply_fast_tracepoint_registers (struct regcache *regcache,
				  const unsigned char *buf)
{
  int i;

  for (i = 0; i < PPC_NUM_FT_COLLECT_GREGS; i++)
    {
      if (aarch64_ft_collect_regmap[i] == -1)
	continue;
      supply_register (regcache, i,
		       ((char *) buf)
			+ aarch64_ft_collect_regmap[i] * REGSZ);
    }
}

/* Return the value of register REGNUM.  RAW_REGS is collected buffer
   by jump pad.  This function is called by emit_reg.  */

ULONGEST __attribute__ ((visibility("default"), used))
gdb_agent_get_raw_reg (const unsigned char *raw_regs, int regnum)
{
  if (regnum >= PPC_NUM_FT_COLLECT_GREGS)
    return 0;
  if (aarch64_ft_collect_regmap[regnum] == -1)
    return 0;

  return *(ULONGEST *) (raw_regs
			+ aarch64_ft_collect_regmap[regnum] * REGSZ);
}

/* Return the address for where to allocate buffer for jump pad.
   The buffer should be close enough for tracepoints.  */

uintptr_t
jump_pad_area_hint (void)
{
  return 0x10000;
}

/* Initialize ipa_tdesc and others.  */

void
initialize_low_tracepoint (void)
{
  init_registers_aarch64 ();
  ipa_tdesc = tdesc_aarch64;
}
