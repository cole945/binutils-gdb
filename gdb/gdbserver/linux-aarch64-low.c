/* GNU/Linux/AArch64 specific low level interface, for the remote server for
   GDB.

   Copyright (C) 2009-2015 Free Software Foundation, Inc.
   Contributed by ARM Ltd.

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
#include "elf/common.h"

#include <signal.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <sys/uio.h>

#include "gdb_proc_service.h"
#include "ax.h"
#include "tracepoint.h"

/* Defined in auto-generated files.  */
void init_registers_aarch64 (void);
extern const struct target_desc *tdesc_aarch64;

#ifdef HAVE_SYS_REG_H
#include <sys/reg.h>
#endif

#define AARCH64_X_REGS_NUM 31
#define AARCH64_V_REGS_NUM 32
#define AARCH64_X0_REGNO    0
#define AARCH64_SP_REGNO   31
#define AARCH64_PC_REGNO   32
#define AARCH64_CPSR_REGNO 33
#define AARCH64_V0_REGNO   34
#define AARCH64_FPSR_REGNO (AARCH64_V0_REGNO + AARCH64_V_REGS_NUM)
#define AARCH64_FPCR_REGNO (AARCH64_V0_REGNO + AARCH64_V_REGS_NUM + 1)

#define AARCH64_NUM_REGS (AARCH64_V0_REGNO + AARCH64_V_REGS_NUM + 2)

static int
aarch64_regmap [] =
{
  /* These offsets correspond to GET/SETREGSET */
  /* x0...  */
   0*8,  1*8,  2*8,  3*8,  4*8,  5*8,  6*8,  7*8,
   8*8,  9*8, 10*8, 11*8, 12*8, 13*8, 14*8, 15*8,
  16*8, 17*8, 18*8, 19*8, 20*8, 21*8, 22*8, 23*8,
  24*8, 25*8, 26*8, 27*8, 28*8,
  29*8,
  30*8,				/* x30 lr */
  31*8,				/* x31 sp */
  32*8,				/*     pc */
  33*8,				/*     cpsr    4 bytes!*/

  /* FP register offsets correspond to GET/SETFPREGSET */
   0*16,  1*16,  2*16,  3*16,  4*16,  5*16,  6*16,  7*16,
   8*16,  9*16, 10*16, 11*16, 12*16, 13*16, 14*16, 15*16,
  16*16, 17*16, 18*16, 19*16, 20*16, 21*16, 22*16, 23*16,
  24*16, 25*16, 26*16, 27*16, 28*16, 29*16, 30*16, 31*16
};

/* Here starts the macro definitions, data structures, and code for
   the hardware breakpoint and hardware watchpoint support.  The
   following is the abbreviations that are used frequently in the code
   and comment:

   hw - hardware
   bp - breakpoint
   wp - watchpoint  */

/* Maximum number of hardware breakpoint and watchpoint registers.
   Neither of these values may exceed the width of dr_changed_t
   measured in bits.  */

#define AARCH64_HBP_MAX_NUM 16
#define AARCH64_HWP_MAX_NUM 16

/* Alignment requirement in bytes of hardware breakpoint and
   watchpoint address.  This is the requirement for the addresses that
   can be written to the hardware breakpoint/watchpoint value
   registers.  The kernel currently does not do any alignment on
   addresses when receiving a writing request (via ptrace call) to
   these debug registers, and it will reject any address that is
   unaligned.
   Some limited support has been provided in this gdbserver port for
   unaligned watchpoints, so that from a gdb user point of view, an
   unaligned watchpoint can still be set.  This is achieved by
   minimally enlarging the watched area to meet the alignment
   requirement, and if necessary, splitting the watchpoint over
   several hardware watchpoint registers.  */

#define AARCH64_HBP_ALIGNMENT 4
#define AARCH64_HWP_ALIGNMENT 8

/* The maximum length of a memory region that can be watched by one
   hardware watchpoint register.  */

#define AARCH64_HWP_MAX_LEN_PER_REG 8

/* Each bit of a variable of this type is used to indicate whether a
   hardware breakpoint or watchpoint setting has been changed since
   the last updating.  Bit N corresponds to the Nth hardware
   breakpoint or watchpoint setting which is managed in
   aarch64_debug_reg_state.  Where N is valid between 0 and the total
   number of the hardware breakpoint or watchpoint debug registers
   minus 1.  When the bit N is 1, it indicates the corresponding
   breakpoint or watchpoint setting is changed, and thus the
   corresponding hardware debug register needs to be updated via the
   ptrace interface.

   In the per-thread arch-specific data area, we define two such
   variables for per-thread hardware breakpoint and watchpoint
   settings respectively.

   This type is part of the mechanism which helps reduce the number of
   ptrace calls to the kernel, i.e. avoid asking the kernel to write
   to the debug registers with unchanged values.  */

typedef unsigned long long dr_changed_t;

/* Set each of the lower M bits of X to 1; assert X is wide enough.  */

#define DR_MARK_ALL_CHANGED(x, m)					\
  do									\
    {									\
      gdb_assert (sizeof ((x)) * 8 >= (m));				\
      (x) = (((dr_changed_t)1 << (m)) - 1);				\
    } while (0)

#define DR_MARK_N_CHANGED(x, n)						\
  do									\
    {									\
      (x) |= ((dr_changed_t)1 << (n));					\
    } while (0)

#define DR_CLEAR_CHANGED(x)						\
  do									\
    {									\
      (x) = 0;								\
    } while (0)

#define DR_HAS_CHANGED(x) ((x) != 0)
#define DR_N_HAS_CHANGED(x, n) ((x) & ((dr_changed_t)1 << (n)))

/* Structure for managing the hardware breakpoint/watchpoint resources.
   DR_ADDR_* stores the address, DR_CTRL_* stores the control register
   content, and DR_REF_COUNT_* counts the numbers of references to the
   corresponding bp/wp, by which way the limited hardware resources
   are not wasted on duplicated bp/wp settings (though so far gdb has
   done a good job by not sending duplicated bp/wp requests).  */

struct aarch64_debug_reg_state
{
  /* hardware breakpoint */
  CORE_ADDR dr_addr_bp[AARCH64_HBP_MAX_NUM];
  unsigned int dr_ctrl_bp[AARCH64_HBP_MAX_NUM];
  unsigned int dr_ref_count_bp[AARCH64_HBP_MAX_NUM];

  /* hardware watchpoint */
  CORE_ADDR dr_addr_wp[AARCH64_HWP_MAX_NUM];
  unsigned int dr_ctrl_wp[AARCH64_HWP_MAX_NUM];
  unsigned int dr_ref_count_wp[AARCH64_HWP_MAX_NUM];
};

/* Per-process arch-specific data we want to keep.  */

struct arch_process_info
{
  /* Hardware breakpoint/watchpoint data.
     The reason for them to be per-process rather than per-thread is
     due to the lack of information in the gdbserver environment;
     gdbserver is not told that whether a requested hardware
     breakpoint/watchpoint is thread specific or not, so it has to set
     each hw bp/wp for every thread in the current process.  The
     higher level bp/wp management in gdb will resume a thread if a hw
     bp/wp trap is not expected for it.  Since the hw bp/wp setting is
     same for each thread, it is reasonable for the data to live here.
     */
  struct aarch64_debug_reg_state debug_reg_state;
};

/* Per-thread arch-specific data we want to keep.  */

struct arch_lwp_info
{
  /* When bit N is 1, it indicates the Nth hardware breakpoint or
     watchpoint register pair needs to be updated when the thread is
     resumed; see aarch64_linux_prepare_to_resume.  */
  dr_changed_t dr_changed_bp;
  dr_changed_t dr_changed_wp;
};

/* Number of hardware breakpoints/watchpoints the target supports.
   They are initialized with values obtained via the ptrace calls
   with NT_ARM_HW_BREAK and NT_ARM_HW_WATCH respectively.  */

static int aarch64_num_bp_regs;
static int aarch64_num_wp_regs;

static int
aarch64_cannot_store_register (int regno)
{
  return regno >= AARCH64_NUM_REGS;
}

static int
aarch64_cannot_fetch_register (int regno)
{
  return regno >= AARCH64_NUM_REGS;
}

static void
aarch64_fill_gregset (struct regcache *regcache, void *buf)
{
  struct user_pt_regs *regset = buf;
  int i;

  for (i = 0; i < AARCH64_X_REGS_NUM; i++)
    collect_register (regcache, AARCH64_X0_REGNO + i, &regset->regs[i]);
  collect_register (regcache, AARCH64_SP_REGNO, &regset->sp);
  collect_register (regcache, AARCH64_PC_REGNO, &regset->pc);
  collect_register (regcache, AARCH64_CPSR_REGNO, &regset->pstate);
}

static void
aarch64_store_gregset (struct regcache *regcache, const void *buf)
{
  const struct user_pt_regs *regset = buf;
  int i;

  for (i = 0; i < AARCH64_X_REGS_NUM; i++)
    supply_register (regcache, AARCH64_X0_REGNO + i, &regset->regs[i]);
  supply_register (regcache, AARCH64_SP_REGNO, &regset->sp);
  supply_register (regcache, AARCH64_PC_REGNO, &regset->pc);
  supply_register (regcache, AARCH64_CPSR_REGNO, &regset->pstate);
}

static void
aarch64_fill_fpregset (struct regcache *regcache, void *buf)
{
  struct user_fpsimd_state *regset = buf;
  int i;

  for (i = 0; i < AARCH64_V_REGS_NUM; i++)
    collect_register (regcache, AARCH64_V0_REGNO + i, &regset->vregs[i]);
  collect_register (regcache, AARCH64_FPSR_REGNO, &regset->fpsr);
  collect_register (regcache, AARCH64_FPCR_REGNO, &regset->fpcr);
}

static void
aarch64_store_fpregset (struct regcache *regcache, const void *buf)
{
  const struct user_fpsimd_state *regset = buf;
  int i;

  for (i = 0; i < AARCH64_V_REGS_NUM; i++)
    supply_register (regcache, AARCH64_V0_REGNO + i, &regset->vregs[i]);
  supply_register (regcache, AARCH64_FPSR_REGNO, &regset->fpsr);
  supply_register (regcache, AARCH64_FPCR_REGNO, &regset->fpcr);
}

/* Enable miscellaneous debugging output.  The name is historical - it
   was originally used to debug LinuxThreads support.  */
extern int debug_threads;

static CORE_ADDR
aarch64_get_pc (struct regcache *regcache)
{
  unsigned long pc;

  collect_register_by_name (regcache, "pc", &pc);
  if (debug_threads)
    debug_printf ("stop pc is %08lx\n", pc);
  return pc;
}

static void
aarch64_set_pc (struct regcache *regcache, CORE_ADDR pc)
{
  unsigned long newpc = pc;
  supply_register_by_name (regcache, "pc", &newpc);
}

/* Correct in either endianness.  */

#define aarch64_breakpoint_len 4

static const unsigned long aarch64_breakpoint = 0x00800011;

static int
aarch64_breakpoint_at (CORE_ADDR where)
{
  unsigned long insn = 0;

  (*the_target->read_memory) (where, (unsigned char *) &insn, 4);
  if (insn == aarch64_breakpoint)
    return 1;

  return 0;
}

/* Print the values of the cached breakpoint/watchpoint registers.
   This is enabled via the "set debug-hw-points" monitor command.  */

static void
aarch64_show_debug_reg_state (struct aarch64_debug_reg_state *state,
			      const char *func, CORE_ADDR addr,
			      int len, enum target_hw_bp_type type)
{
  int i;

  fprintf (stderr, "%s", func);
  if (addr || len)
    fprintf (stderr, " (addr=0x%08lx, len=%d, type=%s)",
	     (unsigned long) addr, len,
	     type == hw_write ? "hw-write-watchpoint"
	     : (type == hw_read ? "hw-read-watchpoint"
		: (type == hw_access ? "hw-access-watchpoint"
		   : (type == hw_execute ? "hw-breakpoint"
		      : "??unknown??"))));
  fprintf (stderr, ":\n");

  fprintf (stderr, "\tBREAKPOINTs:\n");
  for (i = 0; i < aarch64_num_bp_regs; i++)
    fprintf (stderr, "\tBP%d: addr=0x%s, ctrl=0x%08x, ref.count=%d\n",
	     i, paddress (state->dr_addr_bp[i]),
	     state->dr_ctrl_bp[i], state->dr_ref_count_bp[i]);

  fprintf (stderr, "\tWATCHPOINTs:\n");
  for (i = 0; i < aarch64_num_wp_regs; i++)
    fprintf (stderr, "\tWP%d: addr=0x%s, ctrl=0x%08x, ref.count=%d\n",
	     i, paddress (state->dr_addr_wp[i]),
	     state->dr_ctrl_wp[i], state->dr_ref_count_wp[i]);
}

static void
aarch64_init_debug_reg_state (struct aarch64_debug_reg_state *state)
{
  int i;

  for (i = 0; i < AARCH64_HBP_MAX_NUM; ++i)
    {
      state->dr_addr_bp[i] = 0;
      state->dr_ctrl_bp[i] = 0;
      state->dr_ref_count_bp[i] = 0;
    }

  for (i = 0; i < AARCH64_HWP_MAX_NUM; ++i)
    {
      state->dr_addr_wp[i] = 0;
      state->dr_ctrl_wp[i] = 0;
      state->dr_ref_count_wp[i] = 0;
    }
}

/* ptrace expects control registers to be formatted as follows:

   31                             13          5      3      1     0
   +--------------------------------+----------+------+------+----+
   |         RESERVED (SBZ)         |  LENGTH  | TYPE | PRIV | EN |
   +--------------------------------+----------+------+------+----+

   The TYPE field is ignored for breakpoints.  */

#define DR_CONTROL_ENABLED(ctrl)	(((ctrl) & 0x1) == 1)
#define DR_CONTROL_LENGTH(ctrl)		(((ctrl) >> 5) & 0xff)

/* Utility function that returns the length in bytes of a watchpoint
   according to the content of a hardware debug control register CTRL.
   Note that the kernel currently only supports the following Byte
   Address Select (BAS) values: 0x1, 0x3, 0xf and 0xff, which means
   that for a hardware watchpoint, its valid length can only be 1
   byte, 2 bytes, 4 bytes or 8 bytes.  */

static inline unsigned int
aarch64_watchpoint_length (unsigned int ctrl)
{
  switch (DR_CONTROL_LENGTH (ctrl))
    {
    case 0x01:
      return 1;
    case 0x03:
      return 2;
    case 0x0f:
      return 4;
    case 0xff:
      return 8;
    default:
      return 0;
    }
}

/* Given the hardware breakpoint or watchpoint type TYPE and its
   length LEN, return the expected encoding for a hardware
   breakpoint/watchpoint control register.  */

static unsigned int
aarch64_point_encode_ctrl_reg (enum target_hw_bp_type type, int len)
{
  unsigned int ctrl, ttype;

  /* type */
  switch (type)
    {
    case hw_write:
      ttype = 2;
      break;
    case hw_read:
      ttype = 1;
      break;
    case hw_access:
      ttype = 3;
      break;
    case hw_execute:
      ttype = 0;
      break;
    default:
      perror_with_name (_("Unrecognized breakpoint/watchpoint type"));
    }

  /* type */
  ctrl = ttype << 3;
  /* length bitmask */
  ctrl |= ((1 << len) - 1) << 5;
  /* enabled at el0 */
  ctrl |= (2 << 1) | 1;

  return ctrl;
}

/* Addresses to be written to the hardware breakpoint and watchpoint
   value registers need to be aligned; the alignment is 4-byte and
   8-type respectively.  Linux kernel rejects any non-aligned address
   it receives from the related ptrace call.  Furthermore, the kernel
   currently only supports the following Byte Address Select (BAS)
   values: 0x1, 0x3, 0xf and 0xff, which means that for a hardware
   watchpoint to be accepted by the kernel (via ptrace call), its
   valid length can only be 1 byte, 2 bytes, 4 bytes or 8 bytes.
   Despite these limitations, the unaligned watchpoint is supported in
   this gdbserver port.

   Return 0 for any non-compliant ADDR and/or LEN; return 1 otherwise.  */

static int
aarch64_point_is_aligned (int is_watchpoint, CORE_ADDR addr, int len)
{
  unsigned int alignment = is_watchpoint ? AARCH64_HWP_ALIGNMENT
    : AARCH64_HBP_ALIGNMENT;

  if (addr & (alignment - 1))
    return 0;

  if (len != 8 && len != 4 && len != 2 && len != 1)
    return 0;

  return 1;
}

/* Given the (potentially unaligned) watchpoint address in ADDR and
   length in LEN, return the aligned address and aligned length in
   *ALIGNED_ADDR_P and *ALIGNED_LEN_P, respectively.  The returned
   aligned address and length will be valid to be written to the
   hardware watchpoint value and control registers.  See the comment
   above aarch64_point_is_aligned for the information about the
   alignment requirement.  The given watchpoint may get truncated if
   more than one hardware register is needed to cover the watched
   region.  *NEXT_ADDR_P and *NEXT_LEN_P, if non-NULL, will return the
   address and length of the remaining part of the watchpoint (which
   can be processed by calling this routine again to generate another
   aligned address and length pair.

   Essentially, unaligned watchpoint is achieved by minimally
   enlarging the watched area to meet the alignment requirement, and
   if necessary, splitting the watchpoint over several hardware
   watchpoint registers.  The trade-off is that there will be
   false-positive hits for the read-type or the access-type hardware
   watchpoints; for the write type, which is more commonly used, there
   will be no such issues, as the higher-level breakpoint management
   in gdb always examines the exact watched region for any content
   change, and transparently resumes a thread from a watchpoint trap
   if there is no change to the watched region.

   Another limitation is that because the watched region is enlarged,
   the watchpoint fault address returned by
   aarch64_stopped_data_address may be outside of the original watched
   region, especially when the triggering instruction is accessing a
   larger region.  When the fault address is not within any known
   range, watchpoints_triggered in gdb will get confused, as the
   higher-level watchpoint management is only aware of original
   watched regions, and will think that some unknown watchpoint has
   been triggered.  In such a case, gdb may stop without displaying
   any detailed information.

   Once the kernel provides the full support for Byte Address Select
   (BAS) in the hardware watchpoint control register, these
   limitations can be largely relaxed with some further work.  */

static void
aarch64_align_watchpoint (CORE_ADDR addr, int len, CORE_ADDR *aligned_addr_p,
			  int *aligned_len_p, CORE_ADDR *next_addr_p,
			  int *next_len_p)
{
  int aligned_len;
  unsigned int offset;
  CORE_ADDR aligned_addr;
  const unsigned int alignment = AARCH64_HWP_ALIGNMENT;
  const unsigned int max_wp_len = AARCH64_HWP_MAX_LEN_PER_REG;

  /* As assumed by the algorithm.  */
  gdb_assert (alignment == max_wp_len);

  if (len <= 0)
    return;

  /* Address to be put into the hardware watchpoint value register
     must be aligned.  */
  offset = addr & (alignment - 1);
  aligned_addr = addr - offset;

  gdb_assert (offset >= 0 && offset < alignment);
  gdb_assert (aligned_addr >= 0 && aligned_addr <= addr);
  gdb_assert ((offset + len) > 0);

  if (offset + len >= max_wp_len)
    {
      /* Need more than one watchpoint registers; truncate it at the
	 alignment boundary.  */
      aligned_len = max_wp_len;
      len -= (max_wp_len - offset);
      addr += (max_wp_len - offset);
      gdb_assert ((addr & (alignment - 1)) == 0);
    }
  else
    {
      /* Find the smallest valid length that is large enough to
	 accommodate this watchpoint.  */
      static const unsigned char
	aligned_len_array[AARCH64_HWP_MAX_LEN_PER_REG] =
	{ 1, 2, 4, 4, 8, 8, 8, 8 };

      aligned_len = aligned_len_array[offset + len - 1];
      addr += len;
      len = 0;
    }

  if (aligned_addr_p != NULL)
    *aligned_addr_p = aligned_addr;
  if (aligned_len_p != NULL)
    *aligned_len_p = aligned_len;
  if (next_addr_p != NULL)
    *next_addr_p = addr;
  if (next_len_p != NULL)
    *next_len_p = len;
}

/* Call ptrace to set the thread TID's hardware breakpoint/watchpoint
   registers with data from *STATE.  */

static void
aarch64_linux_set_debug_regs (const struct aarch64_debug_reg_state *state,
			      int tid, int watchpoint)
{
  int i, count;
  struct iovec iov;
  struct user_hwdebug_state regs;
  const CORE_ADDR *addr;
  const unsigned int *ctrl;

  memset (&regs, 0, sizeof (regs));
  iov.iov_base = &regs;
  count = watchpoint ? aarch64_num_wp_regs : aarch64_num_bp_regs;
  addr = watchpoint ? state->dr_addr_wp : state->dr_addr_bp;
  ctrl = watchpoint ? state->dr_ctrl_wp : state->dr_ctrl_bp;
  if (count == 0)
    return;
  iov.iov_len = (offsetof (struct user_hwdebug_state, dbg_regs[count - 1])
		 + sizeof (regs.dbg_regs [count - 1]));

  for (i = 0; i < count; i++)
    {
      regs.dbg_regs[i].addr = addr[i];
      regs.dbg_regs[i].ctrl = ctrl[i];
    }

  if (ptrace (PTRACE_SETREGSET, tid,
	      watchpoint ? NT_ARM_HW_WATCH : NT_ARM_HW_BREAK,
	      (void *) &iov))
    error (_("Unexpected error setting hardware debug registers"));
}

struct aarch64_dr_update_callback_param
{
  int pid;
  int is_watchpoint;
  unsigned int idx;
};

/* Callback function which records the information about the change of
   one hardware breakpoint/watchpoint setting for the thread ENTRY.
   The information is passed in via PTR.
   N.B.  The actual updating of hardware debug registers is not
   carried out until the moment the thread is resumed.  */

static int
debug_reg_change_callback (struct inferior_list_entry *entry, void *ptr)
{
  struct thread_info *thread = (struct thread_info *) entry;
  struct lwp_info *lwp = get_thread_lwp (thread);
  struct aarch64_dr_update_callback_param *param_p
    = (struct aarch64_dr_update_callback_param *) ptr;
  int pid = param_p->pid;
  int idx = param_p->idx;
  int is_watchpoint = param_p->is_watchpoint;
  struct arch_lwp_info *info = lwp->arch_private;
  dr_changed_t *dr_changed_ptr;
  dr_changed_t dr_changed;

  if (show_debug_regs)
    {
      fprintf (stderr, "debug_reg_change_callback: \n\tOn entry:\n");
      fprintf (stderr, "\tpid%d, tid: %ld, dr_changed_bp=0x%llx, "
	       "dr_changed_wp=0x%llx\n",
	       pid, lwpid_of (thread), info->dr_changed_bp,
	       info->dr_changed_wp);
    }

  dr_changed_ptr = is_watchpoint ? &info->dr_changed_wp
    : &info->dr_changed_bp;
  dr_changed = *dr_changed_ptr;

  /* Only update the threads of this process.  */
  if (pid_of (thread) == pid)
    {
      gdb_assert (idx >= 0
		  && (idx <= (is_watchpoint ? aarch64_num_wp_regs
			      : aarch64_num_bp_regs)));

      /* The following assertion is not right, as there can be changes
	 that have not been made to the hardware debug registers
	 before new changes overwrite the old ones.  This can happen,
	 for instance, when the breakpoint/watchpoint hit one of the
	 threads and the user enters continue; then what happens is:
	 1) all breakpoints/watchpoints are removed for all threads;
	 2) a single step is carried out for the thread that was hit;
	 3) all of the points are inserted again for all threads;
	 4) all threads are resumed.
	 The 2nd step will only affect the one thread in which the
	 bp/wp was hit, which means only that one thread is resumed;
	 remember that the actual updating only happen in
	 aarch64_linux_prepare_to_resume, so other threads remain
	 stopped during the removal and insertion of bp/wp.  Therefore
	 for those threads, the change of insertion of the bp/wp
	 overwrites that of the earlier removals.  (The situation may
	 be different when bp/wp is steppable, or in the non-stop
	 mode.)  */
      /* gdb_assert (DR_N_HAS_CHANGED (dr_changed, idx) == 0);  */

      /* The actual update is done later just before resuming the lwp,
         we just mark that one register pair needs updating.  */
      DR_MARK_N_CHANGED (dr_changed, idx);
      *dr_changed_ptr = dr_changed;

      /* If the lwp isn't stopped, force it to momentarily pause, so
         we can update its debug registers.  */
      if (!lwp->stopped)
	linux_stop_lwp (lwp);
    }

  if (show_debug_regs)
    {
      fprintf (stderr, "\tOn exit:\n\tpid%d, tid: %ld, dr_changed_bp=0x%llx, "
	       "dr_changed_wp=0x%llx\n",
	       pid, lwpid_of (thread), info->dr_changed_bp,
	       info->dr_changed_wp);
    }

  return 0;
}

/* Notify each thread that their IDXth breakpoint/watchpoint register
   pair needs to be updated.  The message will be recorded in each
   thread's arch-specific data area, the actual updating will be done
   when the thread is resumed.  */

void
aarch64_notify_debug_reg_change (const struct aarch64_debug_reg_state *state,
				 int is_watchpoint, unsigned int idx)
{
  struct aarch64_dr_update_callback_param param;

  /* Only update the threads of this process.  */
  param.pid = pid_of (current_thread);

  param.is_watchpoint = is_watchpoint;
  param.idx = idx;

  find_inferior (&all_threads, debug_reg_change_callback, (void *) &param);
}


/* Return the pointer to the debug register state structure in the
   current process' arch-specific data area.  */

static struct aarch64_debug_reg_state *
aarch64_get_debug_reg_state ()
{
  struct process_info *proc;

  proc = current_process ();
  return &proc->private->arch_private->debug_reg_state;
}

/* Record the insertion of one breakpoint/watchpoint, as represented
   by ADDR and CTRL, in the process' arch-specific data area *STATE.  */

static int
aarch64_dr_state_insert_one_point (struct aarch64_debug_reg_state *state,
				   enum target_hw_bp_type type,
				   CORE_ADDR addr, int len)
{
  int i, idx, num_regs, is_watchpoint;
  unsigned int ctrl, *dr_ctrl_p, *dr_ref_count;
  CORE_ADDR *dr_addr_p;

  /* Set up state pointers.  */
  is_watchpoint = (type != hw_execute);
  gdb_assert (aarch64_point_is_aligned (is_watchpoint, addr, len));
  if (is_watchpoint)
    {
      num_regs = aarch64_num_wp_regs;
      dr_addr_p = state->dr_addr_wp;
      dr_ctrl_p = state->dr_ctrl_wp;
      dr_ref_count = state->dr_ref_count_wp;
    }
  else
    {
      num_regs = aarch64_num_bp_regs;
      dr_addr_p = state->dr_addr_bp;
      dr_ctrl_p = state->dr_ctrl_bp;
      dr_ref_count = state->dr_ref_count_bp;
    }

  ctrl = aarch64_point_encode_ctrl_reg (type, len);

  /* Find an existing or free register in our cache.  */
  idx = -1;
  for (i = 0; i < num_regs; ++i)
    {
      if ((dr_ctrl_p[i] & 1) == 0)
	{
	  gdb_assert (dr_ref_count[i] == 0);
	  idx = i;
	  /* no break; continue hunting for an exising one.  */
	}
      else if (dr_addr_p[i] == addr && dr_ctrl_p[i] == ctrl)
	{
	  gdb_assert (dr_ref_count[i] != 0);
	  idx = i;
	  break;
	}
    }

  /* No space.  */
  if (idx == -1)
    return -1;

  /* Update our cache.  */
  if ((dr_ctrl_p[idx] & 1) == 0)
    {
      /* new entry */
      dr_addr_p[idx] = addr;
      dr_ctrl_p[idx] = ctrl;
      dr_ref_count[idx] = 1;
      /* Notify the change.  */
      aarch64_notify_debug_reg_change (state, is_watchpoint, idx);
    }
  else
    {
      /* existing entry */
      dr_ref_count[idx]++;
    }

  return 0;
}

/* Record the removal of one breakpoint/watchpoint, as represented by
   ADDR and CTRL, in the process' arch-specific data area *STATE.  */

static int
aarch64_dr_state_remove_one_point (struct aarch64_debug_reg_state *state,
				   enum target_hw_bp_type type,
				   CORE_ADDR addr, int len)
{
  int i, num_regs, is_watchpoint;
  unsigned int ctrl, *dr_ctrl_p, *dr_ref_count;
  CORE_ADDR *dr_addr_p;

  /* Set up state pointers.  */
  is_watchpoint = (type != hw_execute);
  gdb_assert (aarch64_point_is_aligned (is_watchpoint, addr, len));
  if (is_watchpoint)
    {
      num_regs = aarch64_num_wp_regs;
      dr_addr_p = state->dr_addr_wp;
      dr_ctrl_p = state->dr_ctrl_wp;
      dr_ref_count = state->dr_ref_count_wp;
    }
  else
    {
      num_regs = aarch64_num_bp_regs;
      dr_addr_p = state->dr_addr_bp;
      dr_ctrl_p = state->dr_ctrl_bp;
      dr_ref_count = state->dr_ref_count_bp;
    }

  ctrl = aarch64_point_encode_ctrl_reg (type, len);

  /* Find the entry that matches the ADDR and CTRL.  */
  for (i = 0; i < num_regs; ++i)
    if (dr_addr_p[i] == addr && dr_ctrl_p[i] == ctrl)
      {
	gdb_assert (dr_ref_count[i] != 0);
	break;
      }

  /* Not found.  */
  if (i == num_regs)
    return -1;

  /* Clear our cache.  */
  if (--dr_ref_count[i] == 0)
    {
      /* Clear the enable bit.  */
      ctrl &= ~1;
      dr_addr_p[i] = 0;
      dr_ctrl_p[i] = ctrl;
      /* Notify the change.  */
      aarch64_notify_debug_reg_change (state, is_watchpoint, i);
    }

  return 0;
}

static int
aarch64_handle_breakpoint (enum target_hw_bp_type type, CORE_ADDR addr,
			   int len, int is_insert)
{
  struct aarch64_debug_reg_state *state;

  /* The hardware breakpoint on AArch64 should always be 4-byte
     aligned.  */
  if (!aarch64_point_is_aligned (0 /* is_watchpoint */ , addr, len))
    return -1;

  state = aarch64_get_debug_reg_state ();

  if (is_insert)
    return aarch64_dr_state_insert_one_point (state, type, addr, len);
  else
    return aarch64_dr_state_remove_one_point (state, type, addr, len);
}

/* This is essentially the same as aarch64_handle_breakpoint, apart
   from that it is an aligned watchpoint to be handled.  */

static int
aarch64_handle_aligned_watchpoint (enum target_hw_bp_type type,
				   CORE_ADDR addr, int len, int is_insert)
{
  struct aarch64_debug_reg_state *state;

  state = aarch64_get_debug_reg_state ();

  if (is_insert)
    return aarch64_dr_state_insert_one_point (state, type, addr, len);
  else
    return aarch64_dr_state_remove_one_point (state, type, addr, len);
}

/* Insert/remove unaligned watchpoint by calling
   aarch64_align_watchpoint repeatedly until the whole watched region,
   as represented by ADDR and LEN, has been properly aligned and ready
   to be written to one or more hardware watchpoint registers.
   IS_INSERT indicates whether this is an insertion or a deletion.
   Return 0 if succeed.  */

static int
aarch64_handle_unaligned_watchpoint (enum target_hw_bp_type type,
				     CORE_ADDR addr, int len, int is_insert)
{
  struct aarch64_debug_reg_state *state
    = aarch64_get_debug_reg_state ();

  while (len > 0)
    {
      CORE_ADDR aligned_addr;
      int aligned_len, ret;

      aarch64_align_watchpoint (addr, len, &aligned_addr, &aligned_len,
				&addr, &len);

      if (is_insert)
	ret = aarch64_dr_state_insert_one_point (state, type, aligned_addr,
						 aligned_len);
      else
	ret = aarch64_dr_state_remove_one_point (state, type, aligned_addr,
						 aligned_len);

      if (show_debug_regs)
	fprintf (stderr,
 "handle_unaligned_watchpoint: is_insert: %d\n"
 "                             aligned_addr: 0x%s, aligned_len: %d\n"
 "                                next_addr: 0x%s,    next_len: %d\n",
		 is_insert, paddress (aligned_addr), aligned_len,
		 paddress (addr), len);

      if (ret != 0)
	return ret;
    }

  return 0;
}

static int
aarch64_handle_watchpoint (enum target_hw_bp_type type, CORE_ADDR addr,
			   int len, int is_insert)
{
  if (aarch64_point_is_aligned (1 /* is_watchpoint */ , addr, len))
    return aarch64_handle_aligned_watchpoint (type, addr, len, is_insert);
  else
    return aarch64_handle_unaligned_watchpoint (type, addr, len, is_insert);
}

static int
aarch64_supports_z_point_type (char z_type)
{
  switch (z_type)
    {
    case Z_PACKET_SW_BP:
    case Z_PACKET_HW_BP:
    case Z_PACKET_WRITE_WP:
    case Z_PACKET_READ_WP:
    case Z_PACKET_ACCESS_WP:
      return 1;
    default:
      return 0;
    }
}

/* Insert a hardware breakpoint/watchpoint.
   It actually only records the info of the to-be-inserted bp/wp;
   the actual insertion will happen when threads are resumed.

   Return 0 if succeed;
   Return 1 if TYPE is unsupported type;
   Return -1 if an error occurs.  */

static int
aarch64_insert_point (enum raw_bkpt_type type, CORE_ADDR addr,
		      int len, struct raw_breakpoint *bp)
{
  int ret;
  enum target_hw_bp_type targ_type;

  if (show_debug_regs)
    fprintf (stderr, "insert_point on entry (addr=0x%08lx, len=%d)\n",
	     (unsigned long) addr, len);

  if (type == raw_bkpt_type_sw)
    return insert_memory_breakpoint (bp);

  /* Determine the type from the raw breakpoint type.  */
  targ_type = raw_bkpt_type_to_target_hw_bp_type (type);

  if (targ_type != hw_execute)
    ret =
      aarch64_handle_watchpoint (targ_type, addr, len, 1 /* is_insert */);
  else
    ret =
      aarch64_handle_breakpoint (targ_type, addr, len, 1 /* is_insert */);

  if (show_debug_regs > 1)
    aarch64_show_debug_reg_state (aarch64_get_debug_reg_state (),
				  "insert_point", addr, len, targ_type);

  return ret;
}

/* Remove a hardware breakpoint/watchpoint.
   It actually only records the info of the to-be-removed bp/wp,
   the actual removal will be done when threads are resumed.

   Return 0 if succeed;
   Return 1 if TYPE is an unsupported type;
   Return -1 if an error occurs.  */

static int
aarch64_remove_point (enum raw_bkpt_type type, CORE_ADDR addr,
		      int len, struct raw_breakpoint *bp)
{
  int ret;
  enum target_hw_bp_type targ_type;

  if (show_debug_regs)
    fprintf (stderr, "remove_point on entry (addr=0x%08lx, len=%d)\n",
	     (unsigned long) addr, len);

  if (type == raw_bkpt_type_sw)
    return remove_memory_breakpoint (bp);

  /* Determine the type from the raw breakpoint type.  */
  targ_type = raw_bkpt_type_to_target_hw_bp_type (type);

  /* Set up state pointers.  */
  if (targ_type != hw_execute)
    ret =
      aarch64_handle_watchpoint (targ_type, addr, len, 0 /* is_insert */);
  else
    ret =
      aarch64_handle_breakpoint (targ_type, addr, len, 0 /* is_insert */);

  if (show_debug_regs > 1)
    aarch64_show_debug_reg_state (aarch64_get_debug_reg_state (),
				  "remove_point", addr, len, targ_type);

  return ret;
}

/* Returns the address associated with the watchpoint that hit, if
   any; returns 0 otherwise.  */

static CORE_ADDR
aarch64_stopped_data_address (void)
{
  siginfo_t siginfo;
  int pid, i;
  struct aarch64_debug_reg_state *state;

  pid = lwpid_of (current_thread);

  /* Get the siginfo.  */
  if (ptrace (PTRACE_GETSIGINFO, pid, NULL, &siginfo) != 0)
    return (CORE_ADDR) 0;

  /* Need to be a hardware breakpoint/watchpoint trap.  */
  if (siginfo.si_signo != SIGTRAP
      || (siginfo.si_code & 0xffff) != 0x0004 /* TRAP_HWBKPT */)
    return (CORE_ADDR) 0;

  /* Check if the address matches any watched address.  */
  state = aarch64_get_debug_reg_state ();
  for (i = aarch64_num_wp_regs - 1; i >= 0; --i)
    {
      const unsigned int len = aarch64_watchpoint_length (state->dr_ctrl_wp[i]);
      const CORE_ADDR addr_trap = (CORE_ADDR) siginfo.si_addr;
      const CORE_ADDR addr_watch = state->dr_addr_wp[i];
      if (state->dr_ref_count_wp[i]
	  && DR_CONTROL_ENABLED (state->dr_ctrl_wp[i])
	  && addr_trap >= addr_watch
	  && addr_trap < addr_watch + len)
	return addr_trap;
    }

  return (CORE_ADDR) 0;
}

/* Returns 1 if target was stopped due to a watchpoint hit, 0
   otherwise.  */

static int
aarch64_stopped_by_watchpoint (void)
{
  if (aarch64_stopped_data_address () != 0)
    return 1;
  else
    return 0;
}

/* Fetch the thread-local storage pointer for libthread_db.  */

ps_err_e
ps_get_thread_area (const struct ps_prochandle *ph,
		    lwpid_t lwpid, int idx, void **base)
{
  struct iovec iovec;
  uint64_t reg;

  iovec.iov_base = &reg;
  iovec.iov_len = sizeof (reg);

  if (ptrace (PTRACE_GETREGSET, lwpid, NT_ARM_TLS, &iovec) != 0)
    return PS_ERR;

  /* IDX is the bias from the thread pointer to the beginning of the
     thread descriptor.  It has to be subtracted due to implementation
     quirks in libthread_db.  */
  *base = (void *) (reg - idx);

  return PS_OK;
}

/* Called when a new process is created.  */

static struct arch_process_info *
aarch64_linux_new_process (void)
{
  struct arch_process_info *info = xcalloc (1, sizeof (*info));

  aarch64_init_debug_reg_state (&info->debug_reg_state);

  return info;
}

/* Called when a new thread is detected.  */

static struct arch_lwp_info *
aarch64_linux_new_thread (void)
{
  struct arch_lwp_info *info = xcalloc (1, sizeof (*info));

  /* Mark that all the hardware breakpoint/watchpoint register pairs
     for this thread need to be initialized (with data from
     aarch_process_info.debug_reg_state).  */
  DR_MARK_ALL_CHANGED (info->dr_changed_bp, aarch64_num_bp_regs);
  DR_MARK_ALL_CHANGED (info->dr_changed_wp, aarch64_num_wp_regs);

  return info;
}

/* Called when resuming a thread.
   If the debug regs have changed, update the thread's copies.  */

static void
aarch64_linux_prepare_to_resume (struct lwp_info *lwp)
{
  struct thread_info *thread = get_lwp_thread (lwp);
  ptid_t ptid = ptid_of (thread);
  struct arch_lwp_info *info = lwp->arch_private;

  if (DR_HAS_CHANGED (info->dr_changed_bp)
      || DR_HAS_CHANGED (info->dr_changed_wp))
    {
      int tid = ptid_get_lwp (ptid);
      struct process_info *proc = find_process_pid (ptid_get_pid (ptid));
      struct aarch64_debug_reg_state *state
	= &proc->private->arch_private->debug_reg_state;

      if (show_debug_regs)
	fprintf (stderr, "prepare_to_resume thread %ld\n", lwpid_of (thread));

      /* Watchpoints.  */
      if (DR_HAS_CHANGED (info->dr_changed_wp))
	{
	  aarch64_linux_set_debug_regs (state, tid, 1);
	  DR_CLEAR_CHANGED (info->dr_changed_wp);
	}

      /* Breakpoints.  */
      if (DR_HAS_CHANGED (info->dr_changed_bp))
	{
	  aarch64_linux_set_debug_regs (state, tid, 0);
	  DR_CLEAR_CHANGED (info->dr_changed_bp);
	}
    }
}

static int
aarch64_supports_tracepoints (void)
{
  return 1;
}

static int
aarch64_get_min_fast_tracepoint_insn_len (void)
{
  return 4;
}

static int
aarch64_supports_range_stepping (void)
{
  return 1;
}

/* Put a 32-bit INSN instruction in BUF in target endian.  */

static int
put_i32 (unsigned char *buf, uint32_t insn)
{
  buf[3] = (insn >> 24) & 0xff;
  buf[2] = (insn >> 16) & 0xff;
  buf[1] = (insn >> 8) & 0xff;
  buf[0] = insn & 0xff;

  return 4;
}

/* return a 32-bit value in target endian in BUF.  */

static uint32_t
get_i32 (unsigned char *buf)
{
  uint32_t r;

  r = (buf[3] << 24) | (buf[2] << 16) | (buf[1] << 8) | buf[0];

  return r;
}

static void
emit_insns (unsigned char *buf, int n)
{
  write_inferior_memory (current_insn_ptr, buf, n);
  current_insn_ptr += n;
}

#define __EMIT_ASM(NAME, INSNS)					\
  do								\
    {								\
      extern unsigned char start_bcax_ ## NAME [];		\
      extern unsigned char end_bcax_ ## NAME [];		\
      emit_insns (start_bcax_ ## NAME,				\
		  end_bcax_ ## NAME - start_bcax_ ## NAME);	\
      __asm__ (".section .text.__a64bcax\n\t"			\
	       "start_bcax_" #NAME ":\n\t"			\
	       INSNS "\n\t"					\
	       "end_bcax_" #NAME ":\n\t"			\
	       ".previous\n\t");				\
    } while (0)

#define _EMIT_ASM(NAME, INSNS)	__EMIT_ASM(NAME, INSNS)
#define EMIT_ASM(INSNS)		_EMIT_ASM(__LINE__, INSNS)

#define GEN_STP(buf, rt, rt2, rn, imm7)				\
	put_i32 (buf, 0xa9000000 | (rt) | ((rn) << 5)		\
		| ((rt2) << 10)	| ((((imm7) >> 3) & 0x7f) << 15))

#define GEN_STR(buf, rt, rn, imm9)				\
	put_i32 (buf, 0xf9000001 | (rt) | (((rn) & 0x1ff) << 5))


#define GEN_LDP(buf, rt, rt2, rn, imm7)				\
	put_i32 (buf, 0xa94003e0 | (rt) | ((rn) << 5)		\
		| ((rt2) << 10)	| ((((imm7) >> 3) & 0x7f) << 15))

#define GEN_LDR(buf, rt, rn, imm9)				\
	put_i32 (buf, 0xf94003e0 | (rt) | (((rn) & 0x1ff) << 5))

#define GEN_ADDI(buf, rd, rn, imm12)				\
	put_i32 (buf, 0x91000000 | (rd)				\
		 | ((rn) << 5) | (((imm12) & 0xfff) << 10))

#define GEN_MOV(buf, rd, rn)					\
	GEN_ADDI (buf, rd, rn, 0)

#define GEN_SUBI(buf, rd, rn, imm12)				\
	put_i32 (buf, 0xd1000000 | (rd)				\
		 | ((rn) << 5) | (((imm12) & 0xfff) << 10))

#define GEN_MOVZ(buf, rd, imm16, shift)				\
	put_i32 (buf, 0xd2800000 | (((shift) >> 4) << 21)	\
		 | (rd) | (((imm16) & 0xffff) << 5))

#define GEN_MOVK(buf, rd, imm16, shift)				\
	put_i32 (buf, 0xf2800000 | (((shift) >> 4) << 21)	\
		 | (rd) | (((imm16) & 0xffff) << 5))

#define GEN_BLR(buf, rt)					\
	put_i32 (buf, 0xd63f0000 | ((rt) << 5))

#define GEN_B(buf, offset)					\
	put_i32 (buf, 0x14000000 | ((offset >> 2) & 0x3ffffff))

static int
gen_limm (unsigned char *buf, int rt, uint64_t imm)
{
  unsigned char *p = buf;
  unsigned shift = 0;


  p += GEN_MOVZ (p, rt, imm & 0xffff, shift);

  imm >>= 16;
  shift += 16;

  while (imm)
    {
      p += GEN_MOVK (p, rt, imm & 0xffff, shift);
      imm >>= 16;
      shift += 16;
    }

  return p - buf;
}

static int
aarch64_install_fast_tracepoint_jump_pad (CORE_ADDR tpoint,
					  CORE_ADDR tpaddr,
					  CORE_ADDR collector,
					  CORE_ADDR lockaddr,
					  ULONGEST orig_size,
					  CORE_ADDR *jump_entry,
					  CORE_ADDR *trampoline,
					  ULONGEST *trampoline_size,
					  unsigned char *jjump_pad_insn,
					  ULONGEST *jjump_pad_insn_size,
					  CORE_ADDR *adjusted_insn_addr,
					  CORE_ADDR *adjusted_insn_addr_end,
					  char *err)
{
  CORE_ADDR buildaddr = *jump_entry;
  unsigned char buf[1024];
  unsigned char *p = buf;
  int i, offset;
  const int framesz = 272;

  debug_printf ("install fast tracepoint jump pad at 0x%lx\n",
		(unsigned long) buildaddr);

  /* Stack frame layout for thie jump pad,

     High	PC (tpaddr)
		SP
		NZCV
		x30
		...
		x1
     Low	x0

     (32 GPRs + PC + NZCV) = (32 + 1 + 1) * 8 = 272

     The code flow of this jump pad,

     1. Save GPR and NZCV
     3. Adjust SP
     4. Prepare argument
     5. Call gdb_collector
     6. Restore SP
     7. Restore GPR and NZCV
     8. Build a jump for back to the program
     9. Copy/relocate original instruction
    10. Build a jump for replacing orignal instruction.  */

  for (i = 0; i < 30; i += 2)
    p += GEN_STP (p, i, i + 1, 31, -framesz + i * 8);

  p += put_i32 (p, 0xd53b4200);			/* mrs     x0, nzcv */
  p += GEN_ADDI (p, 1, 31, 0);			/* mov     x1, sp */
  p += gen_limm (p, 2, tpaddr);			/* li      x2, TPADDR */

  p += GEN_STP (p, 30, 0, 31, -framesz + 30 * 8);
  p += GEN_STP (p, 1, 2, 31, -framesz + 32 * 8);

  /* Adjust SP.  */
  p += GEN_SUBI (p, 31, 31, framesz);

  /* Prepare argument.  */
  p += gen_limm (p, 0, tpoint);
  p += GEN_ADDI (p, 1, 31, 0);

  p += gen_limm (p, 2, collector);
  p += GEN_BLR (p, 2);

  /* Restore SP.  */
  p += GEN_ADDI (p, 31, 31, framesz);

  /* Restore NZCV.  */
  p += GEN_LDP (p, 30, 0, 31, -framesz + 30 * 8);
  p += put_i32 (p, 0xd51b4200);			/* msr     nzcv, x0 */

  /* Restore GPRs.  */
  for (i = 0; i < 30; i += 2)
    p += GEN_LDP (p, i, i + 1, 31, -framesz + i * 8);


  /* Flush instructions to inferior memory.  */
  write_inferior_memory (buildaddr, buf, p - buf);

  /* Now, insert the original instruction to execute in the jump pad.  */
  *adjusted_insn_addr = buildaddr + (p - buf);
  *adjusted_insn_addr_end = *adjusted_insn_addr;
  relocate_instruction (adjusted_insn_addr_end, tpaddr);

  /* Verify the relocation size.  If should be 4 for normal copy, or 8
     for some conditional branch.  */
  if ((*adjusted_insn_addr_end - *adjusted_insn_addr == 0)
      || (*adjusted_insn_addr_end - *adjusted_insn_addr > 8))
    {
      sprintf (err, "E.Unexpected instruction length = %d"
		    "when relocate instruction.",
		    (int) (*adjusted_insn_addr_end - *adjusted_insn_addr));
      return 1;
    }

  buildaddr = *adjusted_insn_addr_end;
  p = buf;
  /* Finally, write a jump back to the program.  */
  offset = (tpaddr + 4) - buildaddr;
  if (offset >= (1 << 27) || offset < -(1 << 27))
    {
      sprintf (err, "E.Jump back from jump pad too far from tracepoint "
		    "(offset 0x%x > 26-bit).", offset);
      return 1;
    }
  /* b <tpaddr+4> */
  p += GEN_B (p, offset);
  write_inferior_memory (buildaddr, buf, p - buf);

  /* The jump pad is now built.  Wire in a jump to our jump pad.  This
     is always done last (by our caller actually), so that we can
     install fast tracepoints with threads running.  This relies on
     the agent's atomic write support.  */
  offset = *jump_entry - tpaddr;
  if (offset >= (1 << 27) || offset < -(1 << 27))
    {
      sprintf (err, "E.Jump back from jump pad too far from tracepoint "
		    "(offset 0x%x > 26-bit).", offset);
      return 1;
    }
  /* b <jentry> */
  GEN_B (jjump_pad_insn, offset);
  *jjump_pad_insn_size = 4;

  *jump_entry = buildaddr + (p - buf);

  return 0;
}

/*

  Bytecode execution stack frame

   x30 is link register.
   x29 is the frame-base for restoring stack-pointer.
   x28 is the stack-pointer for bytecode machine.
       It should point to next-empty, so we can use LDU for pop.
   x0  is used for cache of TOP value.
       It is the first argument, pointer to CTX.
   x1  is the second argument, pointer to the result.


 */

enum { bc_framesz = 208 };

/* Emit prologue in inferior memory.  See above comments.  */

static void
aarch64_emit_prologue (void)
{
  EMIT_ASM ("stp    x0, x1, [sp, -48]!		\n"
	    "stp    x27, x28, [sp, 16]		\n"
	    "stp    x29, x30, [sp, 32]		\n"
	    "mov    x29, x1			\n"
	    "sub    x28, x1, 8			\n"
	    "sub    x1, x1, 64			\n"
	    "mov    x0, 0			\n"
	);
}

/* Emit epilogue in inferior memory.  See above comments.  */

static void
aarch64_emit_epilogue (void)
{
  EMIT_ASM ("mov    sp, x29			\n"
	    "ldr    x1, [sp, 8]			\n"
	    "ldp    x27, x28, [sp, 16]		\n"
	    "ldp    x29, x30, [sp, 32]		\n"
	    /* *value = TOP */
	    "str    x0, [x1]			\n"
	    "mov    x0, 0			\n"
	    "add    sp, sp, 48			\n");
}

/* TOP = stack[--sp] + TOP  */

static void
aarch64_emit_add (void)
{
  EMIT_ASM ("ldr  x1, [x28, 8]!	\n"
	    "add  x0, x1, x0	\n");
}

/* TOP = stack[--sp] - TOP  */

static void
aarch64_emit_sub (void)
{
  EMIT_ASM ("ldr  x1, [x28, 8]!	\n"
	    "sub  x0, x1, x0	\n");
}

/* TOP = stack[--sp] * TOP  */

static void
aarch64_emit_mul (void)
{
  EMIT_ASM ("ldr  x1, [x28, 8]!	\n"
	    "mul  x0, x1, x0	\n");
}

/* TOP = stack[--sp] << TOP  */

static void
aarch64_emit_lsh (void)
{
  EMIT_ASM ("ldr  x1, [x28, 8]!	\n"
	    "lsl  x0, x1, x0	\n");
}

/* Top = stack[--sp] >> TOP
   (Arithmetic shift right)  */

static void
aarch64_emit_rsh_signed (void)
{
  EMIT_ASM ("ldr  x1, [x28, 8]!	\n"
	    "asr  x0, x1, x0	\n");
}

/* Top = stack[--sp] >> TOP
   (Logical shift right)  */

static void
aarch64_emit_rsh_unsigned (void)
{
  EMIT_ASM ("ldr  x1, [x28, 8]!	\n"
	    "lsr  x0, x1, x0	\n");
}

/* Emit code for signed-extension specified by ARG.  */

static void
aarch64_emit_ext (int arg)
{
  switch (arg)
    {
    case 8:
      EMIT_ASM ("sxtb  w3, w3	\n");
      break;
    case 16:
      EMIT_ASM ("sxth  w3, w3	\n");
      break;
    case 32:
      EMIT_ASM ("sxtw  x0, w3	\n");
      break;
    default:
      emit_error = 1;
    }
}

/* Emit code for zero-extension specified by ARG.  */

static void
aarch64_emit_zero_ext (int arg)
{
  switch (arg)
    {
    case 8:
      EMIT_ASM ("and  w0, w0, 0xff	\n");
      /* break; */
    case 16:
      EMIT_ASM ("and  w0, w0, 0xffff	\n");
      break;
    case 32:
      EMIT_ASM ("and  x0, x0, 0xffffffff	\n");
      break;
    default:
      emit_error = 1;
    }
}

/* TOP = !TOP
   i.e., TOP = (TOP == 0) ? 1 : 0;  */

static void
aarch64_emit_log_not (void)
{
  EMIT_ASM ("cmp  x0, xzr	\n"
	    "cset x0, eq	\n");
}

/* TOP = stack[--sp] & TOP  */

static void
aarch64_emit_bit_and (void)
{
  EMIT_ASM ("ldr  x1, [x28, 8]!	\n"
	    "and  x0, x1, x0	\n");
}

/* TOP = stack[--sp] | TOP  */

static void
aarch64_emit_bit_or (void)
{
  EMIT_ASM ("ldr  x1, [x28, 8]!	\n"
	    "orr  x0, x1, x0	\n");
}

/* TOP = stack[--sp] ^ TOP  */

static void
aarch64_emit_bit_xor (void)
{
  EMIT_ASM ("ldr  x1, [x28, 8]!	\n"
	    "eor  x0, x1, x0	\n");
}

/* TOP = ~TOP  */

static void
aarch64_emit_bit_not (void)
{
  EMIT_ASM ("mvn  x0, x0	\n");
}

/* TOP = stack[--sp] == TOP  */

static void
aarch64_emit_equal (void)
{
  EMIT_ASM ("ldr  x1, [x28, 8]!	\n"
	    "cmp  x0, x1	\n"
	    "cset x0, eq	\n");
}

/* TOP = stack[--sp] < TOP
   (Signed comparison)  */

static void
aarch64_emit_less_signed (void)
{
  EMIT_ASM ("ldr  x1, [x28, 8]!	\n"
	    "cmp  x0, x1	\n"
	    "cset x0, lt	\n");
}

/* TOP = stack[--sp] < TOP
   (Unsigned comparison)  */

static void
aarch64_emit_less_unsigned (void)
{
  EMIT_ASM ("ldr  x1, [x28, 8]!	\n"
	    "cmp  x0, x1	\n"
	    "cset x0, cc	\n");
}

/* Access the memory address in TOP in size of SIZE.
   Zero-extend the read value.  */

static void
aarch64_emit_ref (int size)
{
  switch (size)
    {
    case 1:
      EMIT_ASM ("ldrb  w0, [x0]	\n");
      break;
    case 2:
      EMIT_ASM ("ldrh  w0, [x0]	\n");
      break;
    case 4:
      EMIT_ASM ("ldr   w0, [x0]	\n");
      break;
    case 8:
      EMIT_ASM ("ldr   x0, [x0]	\n");
      break;
    }
}

/* TOP = NUM  */

static void
aarch64_emit_const (LONGEST num)
{
  unsigned char buf[5 * 4];
  int i = 0;

  i += gen_limm (buf + i, 3, num);

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

/* Set TOP to the value of register REG by calling get_raw_reg function
   with two argument, collected buffer and register number.  */

static void
aarch64_emit_reg (int reg)
{
  unsigned char buf[16 * 4];
  unsigned char *p = buf;

  p += GEN_LDR (p, 0, 29, 0);
  p += GEN_LDR (p, 0, 0, 48);
  p += gen_limm (p, 1, reg);
  p += gen_limm (p, 2, get_raw_reg_func_addr ());
  p += GEN_BLR (p, 2);

  write_inferior_memory (current_insn_ptr, buf, (p - buf));
  current_insn_ptr += (p - buf);
}

/* TOP = stack[--sp] */

static void
aarch64_emit_pop (void)
{
  EMIT_ASM ("ldr  x1, [x28, 8]!	\n");
}

/* stack[sp++] = TOP

   Because we may use up bytecode stack, expand 8 doublewords more
   if needed.  */

static void
aarch64_emit_stack_flush (void)
{
  /* Make sure bytecode stack is big enough before push.
     Otherwise, expand 64-byte more.  */

  EMIT_ASM ("  str   x0, [x28], -8	\n"
	    "  mov   x2, sp		\n"
	    "  cmp   x28, x2		\n"
	    "  bhi   1f			\n"
	    "  sub   sp, sp, 64		\n"
	    "1:				\n"
	   );
}

/* Swap TOP and stack[sp-1]  */

static void
aarch64_emit_swap (void)
{
  EMIT_ASM ("ldr  x1, [x28, 8]		\n"
	    "str  x0, [x28, 8]		\n"
	    "mov  x0, x1\n");
}

/* Discard N elements in the stack.  */

static void
aarch64_emit_stack_adjust (int n)
{
  unsigned char buf[4];
  int i = 0;

  i += GEN_ADDI (buf, 30, 30, n << 3);	/* addi	r30, r30, (n << 3) */

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
  gdb_assert (i <= sizeof (buf));
}

/* Call function FN.  */

static void
aarch64_emit_call (CORE_ADDR fn)
{
  unsigned char buf[16 * 4];
  unsigned char *p = buf;

  p += GEN_MOV (p, 27, 0);
  p += gen_limm (p, 2, get_raw_reg_func_addr ());
  p += GEN_BLR (p, 2);
  p += GEN_MOV (p, 0, 27);

  write_inferior_memory (current_insn_ptr, buf, (p - buf));
  current_insn_ptr += (p - buf);
  gdb_assert ((p - buf) <= sizeof (buf));
}

/* FN's prototype is `LONGEST(*fn)(int)'.
   TOP = fn (arg1)
  */

static void
aarch64_emit_int_call_1 (CORE_ADDR fn, int arg1)
{
  unsigned char buf[16 * 4];
  unsigned char *p = buf;

  p += gen_limm (p, 0, arg1);
  p += gen_limm (p, 2, fn);
  p += GEN_BLR (p, 2);

  write_inferior_memory (current_insn_ptr, buf, (p - buf));
  current_insn_ptr += (p - buf);
  gdb_assert ((p - buf) <= sizeof (buf));
}

/* FN's prototype is `void(*fn)(int,LONGEST)'.
   fn (arg1, TOP)

   TOP should be preserved/restored before/after the call.  */

static void
aarch64_emit_void_call_2 (CORE_ADDR fn, int arg1)
{
  unsigned char buf[16 * 4];
  unsigned char *p = buf;

  p += GEN_MOV (p, 27, 0);
  p += GEN_MOV (p, 1, 0);
  p += gen_limm (p, 0, arg1);
  p += gen_limm (p, 2, fn);
  p += GEN_BLR (p, 2);
  p += GEN_MOV (p, 0, 27);

  write_inferior_memory (current_insn_ptr, buf, (p - buf));
  current_insn_ptr += (p - buf);
  gdb_assert ((p - buf) <= sizeof (buf));
}

/* Note in the following goto ops:

   When emitting goto, the target address is later relocated by
   write_goto_address.  OFFSET_P is the offset of the branch instruction
   in the code sequence, and SIZE_P is how to relocate the instruction,
   recognized by aarch64_write_goto_address.  In current implementation,
   SIZE can be either 26 or 19 for branch of conditional-branch instruction.  */

/* If TOP is true, goto somewhere.  Otherwise, just fall-through.  */

static void
aarch64_emit_if_goto (int *offset_p, int *size_p)
{
  EMIT_ASM ("  mov   x1, x0		\n"
	    "  ldr   x0, [x28, 8]!	\n"
	    "1:cbnz  x1, 1b		\n");

  if (offset_p)
    *offset_p = 8;
  if (size_p)
    *size_p = 19;
}

/* Unconditional goto.  */

static void
aarch64_emit_goto (int *offset_p, int *size_p)
{
  EMIT_ASM ("1:b	1b	\n");

  if (offset_p)
    *offset_p = 0;
  if (size_p)
    *size_p = 26;
}

/* Goto if stack[--sp] == TOP  */

static void
aarch64_emit_eq_goto (int *offset_p, int *size_p)
{
  EMIT_ASM ("ldr     x4, [x28, 8]	\n"
	    "cmp     x4, x3		\n"
	    "ldr     x3, [x28, 16]!	\n"
	    "1:beq   1b			\n");

  if (offset_p)
    *offset_p = 12;
  if (size_p)
    *size_p = 19;
}

/* Goto if stack[--sp] != TOP  */

static void
aarch64_emit_ne_goto (int *offset_p, int *size_p)
{
  EMIT_ASM ("ldr     x4, [x28, 8]	\n"
	    "cmp     x4, x3		\n"
	    "ldr     x3, [x28, 16]!	\n"
	    "1:bne   1b			\n");

  if (offset_p)
    *offset_p = 12;
  if (size_p)
    *size_p = 19;
}

/* Goto if stack[--sp] < TOP  */

static void
aarch64_emit_lt_goto (int *offset_p, int *size_p)
{
  EMIT_ASM ("ldr     x4, [x28, 8]	\n"
	    "cmp     x4, x3		\n"
	    "ldr     x3, [x28, 16]!	\n"
	    "1:blt   1b			\n");

  if (offset_p)
    *offset_p = 12;
  if (size_p)
    *size_p = 19;
}

/* Goto if stack[--sp] <= TOP  */

static void
aarch64_emit_le_goto (int *offset_p, int *size_p)
{
  EMIT_ASM ("ldr     x4, [x28, 8]	\n"
	    "cmp     x4, x3		\n"
	    "ldr     x3, [x28, 16]!	\n"
	    "1:ble   1b			\n");

  if (offset_p)
    *offset_p = 12;
  if (size_p)
    *size_p = 19;
}

/* Goto if stack[--sp] > TOP  */

static void
aarch64_emit_gt_goto (int *offset_p, int *size_p)
{
  EMIT_ASM ("ldr     x4, [x28, 8]	\n"
	    "cmp     x4, x3		\n"
	    "ldr     x3, [x28, 16]!	\n"
	    "1:bgt   1b			\n");

  if (offset_p)
    *offset_p = 12;
  if (size_p)
    *size_p = 19;
}

/* Goto if stack[--sp] >= TOP  */

static void
aarch64_emit_ge_goto (int *offset_p, int *size_p)
{
  EMIT_ASM ("ldr     x4, [x28, 8]	\n"
	    "cmp     x4, x3		\n"
	    "ldr     x3, [x28, 16]!	\n"
	    "1:bge   1b			\n");

  if (offset_p)
    *offset_p = 12;
  if (size_p)
    *size_p = 19;
}

/* Relocate previous emitted branch instruction.  FROM is the address
   of the branch instruction, TO is the goto target address, and SIZE
   if the value we set by *SIZE_P before.  Currently, it is either
   24 or 14 of branch and conditional-branch instruction.  */

static void
aarch64_write_goto_address (CORE_ADDR from, CORE_ADDR to, int size)
{
  int rel = to - from;
  uint32_t insn;
  unsigned char buf[4];

  read_inferior_memory (from, buf, 4);
  insn = get_i32 (buf);

  switch (size)
    {
    case 19:
      insn = (insn & ~(0x7ffff << 5)) | (((rel >> 2) & 0x7ffff) << 5);
      break;
    case 26:
      insn = (insn & ~0x3ffffff) | ((rel >> 2) & 0x3ffffff);
      break;
    default:
      emit_error = 1;
    }

  put_i32 (buf, insn);
  write_inferior_memory (from, buf, 4);
}

/* Vector of emit ops for PowerPC64.  */

static struct emit_ops aarch64_emit_ops_vector =
{
  aarch64_emit_prologue,
  aarch64_emit_epilogue,
  aarch64_emit_add,
  aarch64_emit_sub,
  aarch64_emit_mul,
  aarch64_emit_lsh,
  aarch64_emit_rsh_signed,
  aarch64_emit_rsh_unsigned,
  aarch64_emit_ext,
  aarch64_emit_log_not,
  aarch64_emit_bit_and,
  aarch64_emit_bit_or,
  aarch64_emit_bit_xor,
  aarch64_emit_bit_not,
  aarch64_emit_equal,
  aarch64_emit_less_signed,
  aarch64_emit_less_unsigned,
  aarch64_emit_ref,
  aarch64_emit_if_goto,
  aarch64_emit_goto,
  aarch64_write_goto_address,
  aarch64_emit_const,
  aarch64_emit_call,
  aarch64_emit_reg,
  aarch64_emit_pop,
  aarch64_emit_stack_flush,
  aarch64_emit_zero_ext,
  aarch64_emit_swap,
  aarch64_emit_stack_adjust,
  aarch64_emit_int_call_1,
  aarch64_emit_void_call_2,
  aarch64_emit_eq_goto,
  aarch64_emit_ne_goto,
  aarch64_emit_lt_goto,
  aarch64_emit_le_goto,
  aarch64_emit_gt_goto,
  aarch64_emit_ge_goto
};

/*  Implementation of emit_ops target ops.   */

__attribute__ ((unused))
static struct emit_ops *
aarch64_emit_ops (void)
{
  return &aarch64_emit_ops_vector;
}

/* ptrace hardware breakpoint resource info is formatted as follows:

   31             24             16               8              0
   +---------------+--------------+---------------+---------------+
   |   RESERVED    |   RESERVED   |   DEBUG_ARCH  |  NUM_SLOTS    |
   +---------------+--------------+---------------+---------------+  */

#define AARCH64_DEBUG_NUM_SLOTS(x) ((x) & 0xff)
#define AARCH64_DEBUG_ARCH(x) (((x) >> 8) & 0xff)
#define AARCH64_DEBUG_ARCH_V8 0x6

static void
aarch64_arch_setup (void)
{
  int pid;
  struct iovec iov;
  struct user_hwdebug_state dreg_state;

  current_process ()->tdesc = tdesc_aarch64;

  pid = lwpid_of (current_thread);
  iov.iov_base = &dreg_state;
  iov.iov_len = sizeof (dreg_state);

  /* Get hardware watchpoint register info.  */
  if (ptrace (PTRACE_GETREGSET, pid, NT_ARM_HW_WATCH, &iov) == 0
      && AARCH64_DEBUG_ARCH (dreg_state.dbg_info) == AARCH64_DEBUG_ARCH_V8)
    {
      aarch64_num_wp_regs = AARCH64_DEBUG_NUM_SLOTS (dreg_state.dbg_info);
      if (aarch64_num_wp_regs > AARCH64_HWP_MAX_NUM)
	{
	  warning ("Unexpected number of hardware watchpoint registers reported"
		   " by ptrace, got %d, expected %d.",
		   aarch64_num_wp_regs, AARCH64_HWP_MAX_NUM);
	  aarch64_num_wp_regs = AARCH64_HWP_MAX_NUM;
	}
    }
  else
    {
      warning ("Unable to determine the number of hardware watchpoints"
	       " available.");
      aarch64_num_wp_regs = 0;
    }

  /* Get hardware breakpoint register info.  */
  if (ptrace (PTRACE_GETREGSET, pid, NT_ARM_HW_BREAK, &iov) == 0
      && AARCH64_DEBUG_ARCH (dreg_state.dbg_info) == AARCH64_DEBUG_ARCH_V8)
    {
      aarch64_num_bp_regs = AARCH64_DEBUG_NUM_SLOTS (dreg_state.dbg_info);
      if (aarch64_num_bp_regs > AARCH64_HBP_MAX_NUM)
	{
	  warning ("Unexpected number of hardware breakpoint registers reported"
		   " by ptrace, got %d, expected %d.",
		   aarch64_num_bp_regs, AARCH64_HBP_MAX_NUM);
	  aarch64_num_bp_regs = AARCH64_HBP_MAX_NUM;
	}
    }
  else
    {
      warning ("Unable to determine the number of hardware breakpoints"
	       " available.");
      aarch64_num_bp_regs = 0;
    }
}

static struct regset_info aarch64_regsets[] =
{
  { PTRACE_GETREGSET, PTRACE_SETREGSET, NT_PRSTATUS,
    sizeof (struct user_pt_regs), GENERAL_REGS,
    aarch64_fill_gregset, aarch64_store_gregset },
  { PTRACE_GETREGSET, PTRACE_SETREGSET, NT_FPREGSET,
    sizeof (struct user_fpsimd_state), FP_REGS,
    aarch64_fill_fpregset, aarch64_store_fpregset
  },
  { 0, 0, 0, -1, -1, NULL, NULL }
};

static struct regsets_info aarch64_regsets_info =
  {
    aarch64_regsets, /* regsets */
    0, /* num_regsets */
    NULL, /* disabled_regsets */
  };

static struct usrregs_info aarch64_usrregs_info =
  {
    AARCH64_NUM_REGS,
    aarch64_regmap,
  };

static struct regs_info regs_info =
  {
    NULL, /* regset_bitmap */
    &aarch64_usrregs_info,
    &aarch64_regsets_info,
  };

static const struct regs_info *
aarch64_regs_info (void)
{
  return &regs_info;
}

struct linux_target_ops the_low_target =
{
  aarch64_arch_setup,
  aarch64_regs_info,
  aarch64_cannot_fetch_register,
  aarch64_cannot_store_register,
  NULL,
  aarch64_get_pc,
  aarch64_set_pc,
  (const unsigned char *) &aarch64_breakpoint,
  aarch64_breakpoint_len,
  NULL,
  0,
  aarch64_breakpoint_at,
  aarch64_supports_z_point_type,
  aarch64_insert_point,
  aarch64_remove_point,
  aarch64_stopped_by_watchpoint,
  aarch64_stopped_data_address,
  NULL,
  NULL,
  NULL,
  aarch64_linux_new_process,
  aarch64_linux_new_thread,
  aarch64_linux_prepare_to_resume,
  NULL, /* linux_process_qsupported */
  aarch64_supports_tracepoints,
  NULL, /* get_thread_area */
  aarch64_install_fast_tracepoint_jump_pad,
  NULL, /* Use interpreter for ppc32.  */
  aarch64_get_min_fast_tracepoint_insn_len,
  aarch64_supports_range_stepping,
};

void
initialize_low_arch (void)
{
  init_registers_aarch64 ();

  initialize_regsets_info (&aarch64_regsets_info);
}
