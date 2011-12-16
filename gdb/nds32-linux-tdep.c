/* Common target dependent code for GDB on nds32 systems.

   Copyright (C) 2006-2013 Free Software Foundation, Inc.
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

#include "defs.h"
#include "gdbcore.h"
#include "frame.h"
#include "value.h"
#include "regcache.h"
#include "inferior.h"
#include "osabi.h"
#include "reggroups.h"
#include "regset.h"
#include "target-descriptions.h"

#include "gdb_string.h"

#include "glibc-tdep.h"
#include "solib-svr4.h"

#include "trad-frame.h"
#include "frame-unwind.h"

#include "nds32-tdep.h"
#include "nds32-linux-tdep.h"
#include "features/nds32-linux.c"
extern struct nds32_gdb_config nds32_config;

void _initialize_nds32_linux_tdep (void);

/* Recognizing signal handler frames.  */

/* GNU/Linux has two flavors of signals.  Normal signal handlers, and
   "realtime" (RT) signals.  The RT signals can provide additional
   information to the signal handler if the SA_SIGINFO flag is set
   when establishing a signal handler using `sigaction'.  It is not
   unlikely that future versions of GNU/Linux will support SA_SIGINFO
   for normal signals too.  */

/* When the NDS32 Linux kernel calls a signal handler and the
   SA_RESTORER flag isn't set, the return address points to a bit of
   code on the stack.  This function returns whether the PC appears to
   be within this bit of code.

   The instructions for normal and realtime signals are
       syscall   #__NR_sigreturn ( 0x26 0x01 0xDC 0x0B)
       or
       syscall   #__NR_rt_sigreturn ( 0x26 0x02 0xB4 0x0B)

   Checking for the code sequence should be somewhat reliable, because
   the effect is to call the system call sigreturn.  This is unlikely
   to occur anywhere other than in a signal trampoline.

   It kind of sucks that we have to read memory from the process in
   order to identify a signal trampoline, but there doesn't seem to be
   any other way.  Therefore we only do the memory reads if no
   function name could be identified, which should be the case since
   the code is on the stack.

   Detection of signal trampolines for handlers that set the
   SA_RESTORER flag is in general not possible.  Unfortunately this is
   what the GNU C Library has been doing for quite some time now.
   However, as of version 2.1.2, the GNU C Library uses signal
   trampolines (named __restore and __restore_rt) that are identical
   to the ones used by the kernel.  Therefore, these trampolines are
   supported too.  */

/* syscall #0x5077 */
static const unsigned char NDS32_SIGRETURN_INSN[] =
{
  0x64, 0x0a, 0x0e, 0xeb
};

/* syscall #0x50ad */
static const unsigned char NDS32_RT_SIGRETURN_INSN[] =
{
  0x64, 0x0a, 0x15, 0xab
};

int nds32_linux_sc_reg_offset[] =
{
  /* r0 - r9 */
  12, 16, 20, 24, 28, 32, 36, 40, 44, 48,
  /* r10 - r19 */
  52, 56, 60, 64, 68, 72, 76, 80, 84, 88,
  /* r20 - r25, 26, 27 */
  92, 96, 100, 104, 108, 112, -1, -1,
  /* fp, gp, lr, sp */
  116, 120, 124, 128,
  /* pc, d0lo, d0hi, d1lo, d1hi */
  148, 140, 144, 132, 136
};

struct nds32_frame_cache
{
  CORE_ADDR base, pc;
  struct trad_frame_saved_reg *saved_regs;
};

/* Find start of signal frame.  */

static CORE_ADDR
nds32_linux_sigtramp_start (struct frame_info *this_frame)
{
  const int SIGLEN = sizeof (NDS32_SIGRETURN_INSN);
  CORE_ADDR pc = get_frame_pc (this_frame);
  gdb_byte buf[SIGLEN];

  if (!safe_frame_unwind_memory (this_frame, pc, buf, SIGLEN))
    return 0;

  if (memcmp (buf, NDS32_SIGRETURN_INSN, SIGLEN) != 0)
    return 0;

  return pc;
}

/* Find start of rt_signal frame.  */

static CORE_ADDR
nds32_linux_rt_sigtramp_start (struct frame_info *this_frame)
{
  const int SIGLEN = sizeof (NDS32_RT_SIGRETURN_INSN);
  CORE_ADDR pc = get_frame_pc (this_frame);
  gdb_byte buf[SIGLEN];

  if (!safe_frame_unwind_memory (this_frame, pc, buf, SIGLEN))
    return 0;

  if (memcmp (buf, NDS32_RT_SIGRETURN_INSN, SIGLEN) != 0)
    return 0;

  return pc;
}

/* Return whether the frame preceding NEXT_FRAME corresponds to a
   GNU/Linux sigtramp routine.  */

static int
nds32_linux_sigtramp_p (struct frame_info *this_frame)
{
  CORE_ADDR pc = get_frame_pc (this_frame);
  const char *name;

  find_pc_partial_function (pc, &name, NULL, NULL);

  /* If we have NAME, we can optimize the search.  The trampolines are
     named __restore and __restore_rt.  However, they aren't dynamically
     exported from the shared C library, so the trampoline may appear to
     be part of the preceding function.  This should always be sigaction,
     __sigaction, or __libc_sigaction (all aliases to the same function).  */
  if (name == NULL)
    return (nds32_linux_sigtramp_start (this_frame) != 0
	    || nds32_linux_rt_sigtramp_start (this_frame) != 0);

  return (strcmp ("__default_sa_restorer", name) == 0
	  || strcmp ("__default_rt_sa_restorer", name) == 0);
}

/* Offset to struct sigcontext in ucontext, from <asm/ucontext.h>.  */
#define NDS32_LINUX_UCONTEXT_SIGCONTEXT_OFFSET 0x18

/* Assuming NEXT_FRAME is a frame following a GNU/Linux sigtramp
   routine, return the address of the associated sigcontext structure.  */

static CORE_ADDR
nds32_linux_sigcontext_addr (struct frame_info *this_frame)
{
  CORE_ADDR pc;
  CORE_ADDR sp;
  gdb_byte buf[4];

  sp = get_frame_sp (this_frame);

  /* sigcontext is at sp for sigtramp */
  pc = nds32_linux_sigtramp_start (this_frame);
  if (pc)
    return sp;

  pc = nds32_linux_rt_sigtramp_start (this_frame);
  if (pc)
    {
      CORE_ADDR ucontext_addr;
      int r2;

      /* Cole, Dec. 31th, 2010
	 sigcontext is stored in frame->uc.uc_mcontext, Therefore,
	 there are two ways to get sigcontext.
	 The first way, direct access it in the stack.In this way,
	 we needs more knowledge of rt_sigtramp
	 The second way, &us is passed as parameter 3 of handler,
	 that would be R2 in NDS32 ABI.As long as we use generic
	 ucontext struct, I think it's easier to get sigcontext.  */

      r2 = get_frame_register_unsigned (this_frame, NDS32_R0_REGNUM + 2);
      sp = r2;
      /* This value is dependent on kernel.  */
      sp += NDS32_LINUX_UCONTEXT_SIGCONTEXT_OFFSET;
      return sp;
    }

  error (_("Couldn't recognize signal trampoline."));
  return 0;
}

/* Supply GPR regset.

   Fill GDB register array with the general-purpose register values
   in *GREGSETP.  */

void
nds32_linux_supply_gregset (const struct regset *regset,
			    struct regcache *regcache, int regnum,
			    const void *gregs, size_t size)
{
  int i;
  const char *regp = gregs;

  /* pseudo_shift = size == 200 ? 24 : 0; */
  for (i = NDS32_R0_REGNUM; i < NDS32_LINUX_NUM_GPRS; i++)
    {
      /* FIXME: Review me after <linux/user.h>, <asm/ptrace.h>, and SR regs
	 spec clear. [Harry@Mar.14.2006] */
      if (nds32_ptreg_map[i] == -1)
	continue;

      regcache_raw_supply (regcache, i, regp + nds32_ptreg_map[i] * 4);
    }
}

/* Collect GPR regset.  */

void
nds32_linux_collect_gregset (const struct regset *regset,
			     const struct regcache *regcache,
			     int regnum, void *gregs_buf, size_t len)
{
  gdb_byte *regp = gregs_buf;
  int regno;

  for (regno = NDS32_R0_REGNUM; regno < NDS32_LINUX_NUM_GPRS; regno++)
    {
      if (nds32_ptreg_map[regno] == -1)
	continue;

      if (regnum == -1 || regnum == regno)
	regcache_raw_collect (regcache, regno,
			      regp + nds32_ptreg_map[regno] * 4);
    }
}

/* Implement gdbarch_regset_from_core_section method.  */

static const struct regset *
nds32_linux_regset_from_core_section (struct gdbarch *core_arch,
				      const char *sect_name, size_t sect_size)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (core_arch);

  if (strcmp (sect_name, ".reg") == 0)
    return regset_alloc (core_arch, nds32_linux_supply_gregset,
			 nds32_linux_collect_gregset);

  /* TODO: fpreg ".reg2" */
  return NULL;
}

static void
nds32_linux_init_abi (struct gdbarch_info info, struct gdbarch *gdbarch)
{
  const struct target_desc *tdesc = info.target_desc;
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  struct tdesc_arch_data *tdesc_data = (void *) info.tdep_info;
  const struct tdesc_feature *feature;

  tdep->sigtramp_p = nds32_linux_sigtramp_p;
  tdep->sigcontext_addr = nds32_linux_sigcontext_addr;
  tdep->sc_pc_offset = 37 * 4;	/* sc.fault_address */
  tdep->sc_sp_offset = 32 * 4;	/* sc.sp */
  tdep->sc_lp_offset = 31 * 4;	/* sc.lp */
  tdep->sc_fp_offset = 29 * 4;	/* sc.fp */

  tdep->sc_reg_offset = nds32_linux_sc_reg_offset;
  tdep->sc_num_regs = ARRAY_SIZE (nds32_linux_sc_reg_offset);

  /* GNU/Linux uses SVR4-style shared libraries.  */
  set_solib_svr4_fetch_link_map_offsets (gdbarch,
					 svr4_ilp32_fetch_link_map_offsets);

  /* Core file support.  */
  /* FIXME: Cole, Dec 31th, 2010
     It seems this doesn't work? */
  set_gdbarch_regset_from_core_section (gdbarch,
					nds32_linux_regset_from_core_section);

  set_gdbarch_skip_solib_resolver (gdbarch, glibc_skip_solib_resolver);
  /* No pseudo register on Linux (monitor rcmd) */
  set_gdbarch_num_pseudo_regs (gdbarch, 0);

  if (!tdesc_has_registers (tdesc))
    tdesc = tdesc_nds32_linux;
  tdep->tdesc = tdesc;

  if (tdesc_data)
    {
      set_gdbarch_num_regs (gdbarch, NDS32_LINUX_FUCPR_REGNUM + 1);
      feature = tdesc_find_feature (tdesc, "org.gnu.gdb.nds32.linux");
      if (feature)
	{
	  tdesc_numbered_register (feature, tdesc_data,
				   NDS32_LINUX_ORIG_R0_REGNUM, "orig_r0");
	  tdesc_numbered_register (feature, tdesc_data,
				   NDS32_LINUX_FUCPR_REGNUM, "fucpr");
	}
    }
}

void
_initialize_nds32_linux_tdep (void)
{
  gdbarch_register_osabi (bfd_arch_nds32, 0, GDB_OSABI_LINUX,
			  nds32_linux_init_abi);

  initialize_tdesc_nds32_linux ();
}
