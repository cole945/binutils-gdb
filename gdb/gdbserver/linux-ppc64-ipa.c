/* GNU/Linux/x86-64 specific low level interface, for the in-process
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

/* Defined in auto-generated file amd64-linux.c.  */
void init_registers_powerpc_64l (void);
extern const struct target_desc *tdesc_powerpc_64l;

/* fast tracepoints collect registers.  */
#define FT_CR_R0	0
#define FT_CR_CR	32
#define FT_CR_LR	34
#define FT_CR_CTR	35
#define FT_CR_XER	33

static const int ppc64_ft_collect_regmap[] = {
  /* GPRs */
  FT_CR_R0 * 8, (FT_CR_R0 + 1) * 8, (FT_CR_R0 + 2) * 8,
  (FT_CR_R0 + 3) * 8, (FT_CR_R0 + 4) * 8, (FT_CR_R0 + 5) * 8,
  (FT_CR_R0 + 6) * 8, (FT_CR_R0 + 7) * 8, (FT_CR_R0 + 8) * 8,
  (FT_CR_R0 + 9) * 8, (FT_CR_R0 + 10) * 8, (FT_CR_R0 + 11) * 8,
  (FT_CR_R0 + 12) * 8, (FT_CR_R0 + 13) * 8, (FT_CR_R0 + 14) * 8,
  (FT_CR_R0 + 15) * 8, (FT_CR_R0 + 16) * 8, (FT_CR_R0 + 17) * 8,
  (FT_CR_R0 + 18) * 8, (FT_CR_R0 + 19) * 8, (FT_CR_R0 + 20) * 8,
  (FT_CR_R0 + 21) * 8, (FT_CR_R0 + 22) * 8, (FT_CR_R0 + 23) * 8,
  (FT_CR_R0 + 24) * 8, (FT_CR_R0 + 25) * 8, (FT_CR_R0 + 26) * 8,
  (FT_CR_R0 + 27) * 8, (FT_CR_R0 + 28) * 8, (FT_CR_R0 + 29) * 8,
  (FT_CR_R0 + 30) * 8, (FT_CR_R0 + 31) * 8,
  /* FPRs - not collected.  */
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, /* PC */
  -1, /* MSR */
  FT_CR_CR, /* CR */
  FT_CR_LR, /* LR */
  FT_CR_CTR, /* CTR */
  FT_CR_XER, /* XER */
  -1, /* FPSCR */

};

#define PPC64_NUM_FT_COLLECT_GREGS \
  (sizeof (ppc64_ft_collect_regmap) / sizeof(ppc64_ft_collect_regmap[0]))

void
supply_fast_tracepoint_registers (struct regcache *regcache,
				  const unsigned char *buf)
{
  int i;

  for (i = 0; i < PPC64_NUM_FT_COLLECT_GREGS; i++)
    {
      if (ppc64_ft_collect_regmap[i] == -1)
	continue;
      supply_register (regcache, i,
		       ((char *) buf) + ppc64_ft_collect_regmap[i]);
    }
}

ULONGEST __attribute__ ((visibility("default"), used))
gdb_agent_get_raw_reg (const unsigned char *raw_regs, int regnum)
{
  if (regnum >= PPC64_NUM_FT_COLLECT_GREGS)
    return 0;
  if (ppc64_ft_collect_regmap[regnum] == -1)
    return 0;

  return *(ULONGEST *) (raw_regs + ppc64_ft_collect_regmap[regnum]);
}

void
initialize_low_tracepoint (void)
{
  init_registers_powerpc_64l ();
  ipa_tdesc = tdesc_powerpc_64l;
}
