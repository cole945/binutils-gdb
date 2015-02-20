/* GNU/Linux/PowerPC specific low level interface, for the in-process
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

#include <sys/auxv.h>

#ifdef __powerpc64__
void init_registers_powerpc_64l (void);
extern const struct target_desc *tdesc_powerpc_64l;
#define REGSZ		8
#else
void init_registers_powerpc_32l (void);
extern const struct target_desc *tdesc_powerpc_32l;
#define REGSZ		4
#endif

/* These macros define the position of registers in the buffer collected
   by the fast tracepoint jump pad.  */
#define FT_CR_R0	0
#define FT_CR_CR	32
#define FT_CR_XER	33
#define FT_CR_LR	34
#define FT_CR_CTR	35
#define FT_CR_PC	36
#define FT_CR_GPR(n)	(FT_CR_R0 + (n))

static const int ppc_ft_collect_regmap[] = {
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
  FT_CR_GPR (30), FT_CR_GPR (31),
  /* FPRs - not collected.  */
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  FT_CR_PC, /* PC */
  -1, /* MSR */
  FT_CR_CR, /* CR */
  FT_CR_LR, /* LR */
  FT_CR_CTR, /* CTR */
  FT_CR_XER, /* XER */
  -1, /* FPSCR */
};

#define PPC_NUM_FT_COLLECT_GREGS \
  (sizeof (ppc_ft_collect_regmap) / sizeof(ppc_ft_collect_regmap[0]))

/* Supply registers collected by the fast tracepoint jump pad.
   BUF is the second argument we pass to gdb_collect in jump pad.  */

void
supply_fast_tracepoint_registers (struct regcache *regcache,
				  const unsigned char *buf)
{
  int i;

  for (i = 0; i < PPC_NUM_FT_COLLECT_GREGS; i++)
    {
      if (ppc_ft_collect_regmap[i] == -1)
	continue;
      supply_register (regcache, i,
		       ((char *) buf)
			+ ppc_ft_collect_regmap[i] * REGSZ);
    }
}

/* Return the value of register REGNUM.  RAW_REGS is collected buffer
   by jump pad.  This function is called by emit_reg.  */

IP_AGENT_EXPORT_FUNC ULONGEST
gdb_agent_get_raw_reg (const unsigned char *raw_regs, int regnum)
{
  if (regnum >= PPC_NUM_FT_COLLECT_GREGS)
    return 0;
  if (ppc_ft_collect_regmap[regnum] == -1)
    return 0;

  return *(ULONGEST *) (raw_regs
			+ ppc_ft_collect_regmap[regnum] * REGSZ);
}

#ifndef HAVE_GETAUXVAL
/* Retrieve the value of TYPE from the auxiliary vector.  If TYPE is not
   found, 0 is returned.  This function is provided if glibc is too old.  */

static unsigned long
getauxval (unsigned long type)
{
  unsigned long data[2];
  FILE *f = fopen ("/proc/self/auxv", "r");
  unsigned long value = 0;

  if (f == NULL)
    return 0;

  while (fread (data, sizeof (data), 1, f) > 0)
    {
      if (data[0] == AT_HWCAP)
	{
	  value = data[1];
	  break;
	}
    }

  fclose (f);
  return value;
}
#endif

/* See tracepoint.h.  */

uintptr_t
jump_pad_area_hint (void)
{
  /* Use AT_PHDR address to guess where the main executable is mapped,
     and try to map the jump pad before it.  The jump pad should be
     closed enough to the executable for unconditional branch (+/- 32MB). */

  const int SCRATCH_BUFFER_NPAGES = 20;
  uintptr_t base = getauxval (AT_PHDR);
  uintptr_t pagesz = sysconf (_SC_PAGE_SIZE);
  uintptr_t hint = (base & ~(pagesz - 1)) - SCRATCH_BUFFER_NPAGES * pagesz;

  /* Return the lowest possible value if wrap-around.  */
  if (hint > base)
    hint = pagesz;

  return hint;
}

/* Initialize ipa_tdesc and others.  */

void
initialize_low_tracepoint (void)
{
#ifdef __powerpc64__
  init_registers_powerpc_64l ();
  ipa_tdesc = tdesc_powerpc_64l;
#else
  init_registers_powerpc_32l ();
  ipa_tdesc = tdesc_powerpc_32l;
#endif
}
