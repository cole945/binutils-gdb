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

#include <asm/ptrace.h>
#include <elf.h>                 /* AT_HWCAP */
#include "server.h"
#include "linux-low.h"

#define HWCAP_FPU                0x000008
#define HWCAP_AUDIO              0x000010
#define HWCAP_REDUCED_REGS       0x000080
#define HWCAP_FPU_DP             0x040000

static unsigned long nds32_hwcap;


/* Defined in auto-generated files.  */
void init_registers_nds32 (void);
void init_registers_nds32_linux (void);

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


  /* TODO: add AUDIO and FPU
           or implment it using PTRACE_GETFPREG
           and PTRACE_GETAUDIOREGS */
#if 0
  /* nds32.audio */
  /* AUDIO */
  500, 501, 502, 503, 504, 505, 506, 507,
  508, 509, 510, 511, 512, 513, 514, 515,
  516, 517, 518, 519, 520, 521, 522, 523,
  524, 525, 526, 527, 528, 529, 530, 531

  /* nds32.fpu */
  /* FPU */
#endif
};
#define nds32_num_regs (sizeof (nds32_regmap) / sizeof (nds32_regmap[0]))

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

static const unsigned char NDS32_BREAK[] = { 0x64, 0x00, 0x00, 0x0A };
static const unsigned char NDS32_BREAK16[] = { 0xEA, 0x00 };

static int
nds32_breakpoint_at (CORE_ADDR where)
{
  unsigned char insn[4];

  (*the_target->read_memory) (where, insn, 4);

  if (memcmp(insn, NDS32_BREAK, 4) == 0)
    return 1;
  else if (memcmp(insn, NDS32_BREAK16, 2) == 0)
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

static int
nds32_get_hwcap (unsigned long *valp)
{
  unsigned char *data = alloca (8);
  int offset = 0;

  while ((*the_target->read_auxv) (offset, data, 8) == 8)
    {
      unsigned int *data_p = (unsigned int *)data;
      if (data_p[0] == AT_HWCAP)
	{
	  *valp = data_p[1];
	  return 1;
	}

      offset += 8;
    }

  *valp = 0;
  return 0;
}

static void
nds32_arch_setup (void)
{
#if 0
  nds32_hwcap = 0;
  if (nds32_get_hwcap (&nds32_hwcap) == 0)
    {
      init_registers_nds32 ();
      return;
    }
#endif

  /*
   * TODO:
   * HWCAP_FPU HWCAP_AUDIO HWCAP_REDUCED_REGS HWCAP_FPU_DP
   */

  /*
    1. COP0ISFPU
    2. SP or DP is set
    3. FPCFG.FREG
   */

  /*
    1. AUDIO
   */

  init_registers_nds32_linux ();
}

#if 0
/* used by linux-low.c for PTRACE_[GS]ETREGS */
struct regset_info target_regsets[] = {
  { PTRACE_GETREGS, PTRACE_SETREGS, 0, 18 * 4,
    GENERAL_REGS,
    nds32_fill_gregset, nds32_store_gregset },
  #if 0
  { PTRACE_GETFPREGS, PTRACE_SETVFPREGS, 0, 32 * 8 + 4,
    EXTENDED_REGS,
    nds32_fill_fpregset, nds32_store_fpregset },
  #endif
  { 0, 0, 0, -1, -1, NULL, NULL }
};
#endif

struct linux_target_ops the_low_target = {
  nds32_arch_setup,
  nds32_num_regs,
  nds32_regmap,
  nds32_cannot_fetch_register,
  nds32_cannot_store_register,
  nds32_get_pc,
  nds32_set_pc,
  NDS32_BREAK,
  sizeof(NDS32_BREAK),
  nds32_reinsert_addr,
  0,
  nds32_breakpoint_at,
};
