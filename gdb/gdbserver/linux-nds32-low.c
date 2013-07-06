/* GNU/Linux/NDS32 specific low level interface, for the remote server for
   GDB.

   Copyright (C) 2009-2013 Free Software Foundation, Inc.
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

#include "server.h"
#include "linux-low.h"

#include <sys/ptrace.h>
#include <elf.h>

static int nds32_fpu_freg = -1;

/* Defined in auto-generated files.  */
void init_registers_nds32_linux (void);
extern const struct target_desc *tdesc_nds32_linux;
void init_registers_nds32_freg0_linux (void);
extern const struct target_desc *tdesc_nds32_freg0_linux;
void init_registers_nds32_freg1_linux (void);
extern const struct target_desc *tdesc_nds32_freg1_linux;
void init_registers_nds32_freg2_linux (void);
extern const struct target_desc *tdesc_nds32_freg2_linux;
void init_registers_nds32_freg3_linux (void);
extern const struct target_desc *tdesc_nds32_freg3_linux;

static int nds32_regmap[] = {

  /* r0 - h1hi should match nds32.core.xml
     in order to be compatible with nds32-elf */

  /* r0 - r31 */
  52, 56, 60, 64, 68, 72, 76, 80,
  84, 88, 92, 96, 100, 104, 108, 112,
  116, 120, 124, 128, 132, 136, 140, 144,
  148, 152, -1, -1, 156, 160, 164, 12,

  /* ipc(pc), d0lo, d0hi, d1lo, d1hi */
  8, 40, 36, 48, 44,

  /* nds32-linux only in nds32.linux */
  /* orig_r0, fucop */
  16, 168
};
#define nds32_num_regs (sizeof (nds32_regmap) / sizeof (nds32_regmap[0]))

static const unsigned char NDS32_BREAK[] = { 0x64, 0x00, 0x00, 0x0A };
static const unsigned char NDS32_BREAK16[] = { 0xEA, 0x00 };

static int
nds32_cannot_store_register (int regno)
{
  return (regno >= nds32_num_regs);
}

static int
nds32_cannot_fetch_register (int regno)
{
  return (regno >= nds32_num_regs);
}

static void
nds32_fill_gregset (struct regcache *regcache, void *buf)
{
  int i;

  for (i = 0; i < nds32_num_regs; i++)
    if (nds32_regmap[i] != -1)
      collect_register (regcache, i, ((char *) buf) + nds32_regmap[i]);
}

static void
nds32_store_gregset (struct regcache *regcache, const void *buf)
{
  int i;
  char zerobuf[8];

  memset (zerobuf, 0, 8);
  for (i = 0; i < nds32_num_regs; i++)
    if (nds32_regmap[i] != -1)
      supply_register (regcache, i, ((char *) buf) + nds32_regmap[i]);
    else
      supply_register (regcache, i, zerobuf);
}

static void
nds32_fill_fpregset (struct regcache *regcache, void *buf)
{
  int i, num, base;

  num = 4 << nds32_fpu_freg;
  base = find_regno (regcache->tdesc, "fd0");
  for (i = 0; i < num; i++)
    collect_register (regcache, base + i, (char *) buf + i * 8);

  collect_register_by_name (regcache, "fpscr", (char *) buf + 32 * 8);
}

static void
nds32_store_fpregset (struct regcache *regcache, const void *buf)
{
  int i, num, base;

  num = 4 << nds32_fpu_freg;
  base = find_regno (regcache->tdesc, "fd0");
  for (i = 0; i < num; i++)
    supply_register (regcache, base + i, (char *) buf + i * 8);

  supply_register_by_name (regcache, "fpscr", (char *) buf + 32 * 8);
}

extern int debug_threads;

static CORE_ADDR
nds32_get_pc (struct regcache *regcache)
{
  unsigned long pc;
  collect_register_by_name (regcache, "pc", &pc);
  if (debug_threads)
    fprintf (stderr, "stop pc is %08lx\n", pc);
  return pc;
}

static void
nds32_set_pc (struct regcache *regcache, CORE_ADDR pc)
{
  unsigned long newpc = pc;
  supply_register_by_name (regcache, "pc", &newpc);
}

static int
nds32_breakpoint_at (CORE_ADDR where)
{
  unsigned char insn[4];

  (*the_target->read_memory) (where, insn, 4);

  if (memcmp (insn, NDS32_BREAK, 4) == 0)
    return 1;
  else if (memcmp (insn, NDS32_BREAK16, 2) == 0)
    return 1;
  else
    return 0;
}

/* We only place breakpoints in empty marker functions, and thread locking
   is outside of the function.  So rather than importing software single-step,
   we can just run until exit.  */

static CORE_ADDR
nds32_reinsert_addr (void)
{
  struct regcache *regcache = get_thread_regcache (current_inferior, 1);
  unsigned long pc;

  collect_register_by_name (regcache, "lp", &pc);
  return pc;
}

static void
nds32_arch_setup (void)
{
  const struct target_desc *tdesc = tdesc_nds32_linux;

  nds32_fpu_freg = -1;

#if defined (__NDS32_EXT_FPU_SP__) || defined (__NDS32_EXT_FPU_DP__)
    {
      /* To find out the FPU register configuration, we should 1. Check whether
	 COP/FPU extensions if set in CPU_VER.CFGID. 2. Check whether CP0EX and
	 CP0ISFPU are set in CUCOP_EXIST. 3. Check FPCFG.FREG with fmfcfg
	 instruction.

	 If COP/FPU doesn't exist, executing fmfcfg will cause
	 reserved-instruction exception.  However, both CPU_VER and CUCOP_EXIST
	 are system registers and inaccessible from user programs.  In the
	 future, kernel should provide these information through AUXV HWCAP.
	 Currently, we only check whether FPU SP/DP Extension is set.  */

      int fpcfg = 0;

      __asm__ ("fmfcfg %0\n\t" : "=r" (fpcfg));
      nds32_fpu_freg = (fpcfg >> 2) & 0x3;
    }

  switch (nds32_fpu_freg)
    {
    case 0:
      tdesc = tdesc_nds32_freg0_linux;
      break;
    case 1:
      tdesc = tdesc_nds32_freg1_linux;
      break;
    case 2:
      tdesc = tdesc_nds32_freg2_linux;
      break;
    case 3:
      tdesc = tdesc_nds32_freg3_linux;
      break;
    }
#endif

  current_process ()->tdesc = tdesc;
}

/* used by linux-low.c for PTRACE_[GS]ETREGS */
static struct regset_info nds32_regsets[] = {
  { PTRACE_GETREGS, PTRACE_SETREGS, 0, 18 * 4,
    GENERAL_REGS,
    nds32_fill_gregset, nds32_store_gregset },
  { PTRACE_GETFPREGS, PTRACE_SETFPREGS, 0, 32 * 8 + 4,
    EXTENDED_REGS,
    nds32_fill_fpregset, nds32_store_fpregset },
  { 0, 0, 0, -1, -1, NULL, NULL }
};

static struct regsets_info nds32_regsets_info =
{
  nds32_regsets, /* regsets */
  0, /* num_regsets */
  NULL, /* disabled_regsets */
};

static struct usrregs_info nds32_usrregs_info =
{
  nds32_num_regs,
  nds32_regmap,
};

static struct regs_info regs_info =
{
  NULL, /* regset_bitmap */
  &nds32_usrregs_info,
  &nds32_regsets_info,
};

static const struct regs_info *
nds32_regs_info (void)
{
  return &regs_info;
}

struct linux_target_ops the_low_target = {
  nds32_arch_setup,
  nds32_regs_info,
  nds32_cannot_fetch_register,
  nds32_cannot_store_register,
  NULL, /* fetch_register */
  nds32_get_pc,
  nds32_set_pc,
  NDS32_BREAK16,
  sizeof(NDS32_BREAK16),
  nds32_reinsert_addr,
  0,
  nds32_breakpoint_at,
};

void
initialize_low_arch (void)
{
  /* Initialize the Linux target descriptions.  */
  init_registers_nds32_linux ();
  init_registers_nds32_freg0_linux ();
  init_registers_nds32_freg1_linux ();
  init_registers_nds32_freg2_linux ();
  init_registers_nds32_freg3_linux ();

  initialize_regsets_info (&nds32_regsets_info);
}
