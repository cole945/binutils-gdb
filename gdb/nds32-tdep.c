/* Target-dependent code for NDS32 architecture, for GDB.

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
#include <stdint.h>
#include "frame.h"
#include "frame-unwind.h"
#include "frame-base.h"
#include "symtab.h"
#include "gdbtypes.h"
#include "gdbcmd.h"
#include "gdbcore.h"
#include "value.h"
#include "reggroups.h"
#include "inferior.h"
#include "symfile.h"
#include "objfiles.h"
#include "osabi.h"
#include "language.h"
#include "arch-utils.h"
#include "regcache.h"
#include "trad-frame.h"
#include "dis-asm.h"
#include "gdb_assert.h"
#include "user-regs.h"
#include "elf-bfd.h"
#include "dwarf2-frame.h"
#include "ui-file.h"
#include "remote.h"
#include "target-descriptions.h"
#include "sim-regno.h"
#include "gdb/sim-nds32.h"

#include "nds32-tdep.h"
#include "elf/nds32.h"
#include "opcode/nds32.h"
#include "features/nds32.c"

/* Simple macros for instruction analysis.  */
#define CHOP_BITS(insn, n)	(insn & ~__MASK (n))
#define N32_LSMW_ENABLE4(insn)	(((insn) >> 6) & 0xf)
#define N32_SMW_ADM \
N32_TYPE4 (LSMW, 0, 0, 0, 1, (N32_LSMW_ADM << 2) | N32_LSMW_LSMW)


extern void _initialize_nds32_tdep (void);

/* "break16 0" for breakpoint_from_pc.
   It is always supported now, so always insert break16.  */
static const gdb_byte NDS32_BREAK16[] = { 0xEA, 0x00 };

/* The standard register names.  */
static const char *nds32_regnames[] =
{
  /* 32 GPRs.  */
  "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
  "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
  "r24", "r25", "r26", "r27", "fp", "gp", "lp", "sp",

  /* 5 User Registers. */
  "pc", "d0lo", "d0hi", "d1lo", "d1hi",
};

static const char *nds32_fdr_regnames[] =
{
  "fd0", "fd1", "fd2", "fd3", "fd4", "fd5", "fd6", "fd7",
  "fd8", "fd9", "fd10", "fd11", "fd12", "fd13", "fd14", "fd15",
  "fd16", "fd17", "fd18", "fd19", "fd20", "fd21", "fd22", "fd23",
  "fd24", "fd25", "fd26", "fd27", "fd28", "fd29", "fd30", "fd31"
};

static const char *nds32_fsr_regnames[] =
{
  "fs0", "fs1", "fs2", "fs3", "fs4", "fs5", "fs6", "fs7",
  "fs8", "fs9", "fs10", "fs11", "fs12", "fs13", "fs14", "fs15",
  "fs16", "fs17", "fs18", "fs19", "fs20", "fs21", "fs22", "fs23",
  "fs24", "fs25", "fs26", "fs27", "fs28", "fs29", "fs30", "fs31"
};

/* Mnemonic names for registers.  */
static const struct
{
  const char *name;
  const char *alias;
} nds32_register_aliases[] =
{
  {"r15", "ta"},
  {"r26", "p0"},
  {"r27", "p1"},
  {"fp", "r28"},
  {"gp", "r29"},
  {"lp", "r30"},
  {"sp", "r31"},

  {"cr0", "cpu_ver"},
  {"cr1", "icm_cfg"},
  {"cr2", "dcm_cfg"},
  {"cr3", "mmu_cfg"},
  {"cr4", "msc_cfg"},
  {"cr5", "core_id"},
  {"cr6", "fucop_exist"},
  {"cr7", "msc_cfg2"},

  {"ir0", "psw"},
  {"ir1", "ipsw"},
  {"ir2", "p_psw"},
  {"ir3", "ivb"},
  {"ir4", "eva"},
  {"ir5", "p_eva"},
  {"ir6", "itype"},
  {"ir7", "p_itype"},
  {"ir8", "merr"},
  {"ir9", "ipc"},
  {"ir10", "p_ipc"},
  {"ir11", "oipc"},
  {"ir12", "p_p0"},
  {"ir13", "p_p1"},
  {"ir14", "int_mask"},
  {"ir15", "int_pend"},
  {"ir16", "sp_usr"},
  {"ir17", "sp_priv"},
  {"ir18", "int_pri"},
  {"ir19", "int_ctrl"},
  {"ir20", "sp_usr1"},
  {"ir21", "sp_priv1"},
  {"ir22", "sp_usr2"},
  {"ir23", "sp_priv2"},
  {"ir24", "sp_usr3"},
  {"ir25", "sp_priv3"},
  {"ir26", "int_mask2"},
  {"ir27", "int_pend2"},
  {"ir28", "int_pri2"},
  {"ir29", "int_trigger"},

  {"mr0", "mmu_ctl"},
  {"mr1", "l1_pptb"},
  {"mr2", "tlb_vpn"},
  {"mr3", "tlb_data"},
  {"mr4", "tlb_misc"},
  {"mr5", "vlpt_idx"},
  {"mr6", "ilmb"},
  {"mr7", "dlmb"},
  {"mr8", "cache_ctl"},
  {"mr9", "hsmp_saddr"},
  {"mr10", "hsmp_eaddr"},
  {"mr11", "bg_region"},

  {"dr0", "bpc0"},
  {"dr1", "bpc1"},
  {"dr2", "bpc2"},
  {"dr3", "bpc3"},
  {"dr4", "bpc4"},
  {"dr5", "bpc5"},
  {"dr6", "bpc6"},
  {"dr7", "bpc7"},
  {"dr8", "bpa0"},
  {"dr9", "bpa1"},
  {"dr10", "bpa2"},
  {"dr11", "bpa3"},
  {"dr12", "bpa4"},
  {"dr13", "bpa5"},
  {"dr14", "bpa6"},
  {"dr15", "bpa7"},
  {"dr16", "bpam0"},
  {"dr17", "bpam1"},
  {"dr18", "bpam2"},
  {"dr19", "bpam3"},
  {"dr20", "bpam4"},
  {"dr21", "bpam5"},
  {"dr22", "bpam6"},
  {"dr23", "bpam7"},
  {"dr24", "bpv0"},
  {"dr25", "bpv1"},
  {"dr26", "bpv2"},
  {"dr27", "bpv3"},
  {"dr28", "bpv4"},
  {"dr29", "bpv5"},
  {"dr30", "bpv6"},
  {"dr31", "bpv7"},
  {"dr32", "bpcid0"},
  {"dr33", "bpcid1"},
  {"dr34", "bpcid2"},
  {"dr35", "bpcid3"},
  {"dr36", "bpcid4"},
  {"dr37", "bpcid5"},
  {"dr38", "bpcid6"},
  {"dr39", "bpcid7"},
  {"dr40", "edm_cfg"},
  {"dr41", "edmsw"},
  {"dr42", "edm_ctl"},
  {"dr43", "edm_dtr"},
  {"dr44", "bpmtc"},
  {"dr45", "dimbr"},
  {"dr46", "tecr0"},
  {"dr47", "tecr1"},

  {"hspr0", "hsp_ctl"},
  {"hspr1", "sp_bound"},
  {"hspr2", "sp_bound_priv"},

  {"pfr0", "pfmc0"},
  {"pfr1", "pfmc1"},
  {"pfr2", "pfmc2"},
  {"pfr3", "pfm_ctl"},
  {"pfr4", "pft_ctl"},

  {"dmar0", "dma_cfg"},
  {"dmar1", "dma_gcsw"},
  {"dmar2", "dma_chnsel"},
  {"dmar3", "dma_act"},
  {"dmar4", "dma_setup"},
  {"dmar5", "dma_isaddr"},
  {"dmar6", "dma_esaddr"},
  {"dmar7", "dma_tcnt"},
  {"dmar8", "dma_status"},
  {"dmar9", "dma_2dset"},
  {"dmar10", "dma_2dsctl"},
  {"dmar11", "dma_rcnt"},
  {"dmar12", "dma_hstatus"},

  {"racr0", "prusr_acc_ctl"},
  {"fucpr", "fucop_ctl"},

  {"idr0", "sdz_ctl"},
  {"idr1", "misc_ctl"},
  {"idr2", "ecc_misc"},

  {"secur0", "sfcr"},
  {"secur1", "sign"},
  {"secur2", "isign"},
  {"secur3", "p_isign"},
};

/* Value of a register alias.  BATON is the regnum of the corresponding
   register.  */

static struct value *
value_of_nds32_reg (struct frame_info *frame, const void *baton)
{
  return value_of_register ((int) baton, frame);
}

/* Implement the gdbarch_frame_align method.  */

static CORE_ADDR
nds32_frame_align (struct gdbarch *gdbarch, CORE_ADDR sp)
{
  /* 8-byte aligned.  */
  return align_down (sp, 8);
}

/* Implement the gdbarch_breakpoint_from_pc method.  */

static const gdb_byte *
nds32_breakpoint_from_pc (struct gdbarch *gdbarch, CORE_ADDR *pcptr,
			  int *lenptr)
{
  /* Always insert 16-bit break instruction.  */
  *lenptr = 2;
  return NDS32_BREAK16;
}

/* Implement the gdbarch_dwarf2_reg_to_regnum method.
   Map DWARF regnum from GCC to GDB regnum.  */

static int
nds32_dwarf2_reg_to_regnum (struct gdbarch *gdbarch, int num)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  const int DXR = 34;
  const int FSR = 38;
  const int FDR = FSR + 32;

  if (num >= 0 && num < 32)
    {
      /* General-purpose registers (R0 - R31).  */
      return num;
    }
  else if (num >= DXR && num < DXR + 4)
    {
      /* Special user registers (D0/D1).  */
      return num - DXR + NDS32_D0LO_REGNUM;
    }
  else if (num >= FSR && num < FSR + 32)
    {
      /* Single precision floating-point registers (FS0 - FS31).  */
      return num - FSR + tdep->fs0_regnum;
    }
  else if (num >= FDR && num < FDR + 32)
    {
      /* Double precision floating-point registers (FD0 - FD31).  */
      return num - FDR + tdep->fd0_regnum;
    }

  /* No match, return a inaccessible register number.  */
  return -1;
}

/* Implement gdbarch_register_sim_regno method.  */

static int
nds32_register_sim_regno (struct gdbarch *gdbarch, int regnum)
{
  /* Use target-descriptions for register mapping. */

  /* Only makes sense to supply raw registers.  */
  gdb_assert (regnum >= 0 && regnum < gdbarch_num_regs (gdbarch));

  if (regnum < NDS32_NUM_REGS)
    return regnum;
  if (regnum >= NDS32_SIM_FD0_REGNUM && regnum < NDS32_SIM_FD0_REGNUM + 32)
    return SIM_NDS32_FD0_REGNUM + regnum - NDS32_SIM_FD0_REGNUM;
  switch (regnum)
    {
    case NDS32_SIM_PSW_REGNUM:
      return SIM_NDS32_PSW_REGNUM;
    case NDS32_SIM_ITB_REGNUM:
      return SIM_NDS32_ITB_REGNUM;
    case NDS32_SIM_IFCLP_REGNUM:
      return SIM_NDS32_IFCLP_REGNUM;
    }

  return LEGACY_SIM_REGNO_IGNORE;
}


/* NDS32 register groups.  */
static struct reggroup *nds32_cr_reggroup;
static struct reggroup *nds32_ir_reggroup;
static struct reggroup *nds32_mr_reggroup;
static struct reggroup *nds32_dr_reggroup;
static struct reggroup *nds32_pfr_reggroup;
static struct reggroup *nds32_hspr_reggroup;
static struct reggroup *nds32_dmar_reggroup;
static struct reggroup *nds32_racr_reggroup;
static struct reggroup *nds32_idr_reggroup;
static struct reggroup *nds32_secur_reggroup;

static void
nds32_init_reggroups (void)
{
  /* gpr usr sr */
  nds32_cr_reggroup = reggroup_new ("cr", USER_REGGROUP);
  nds32_ir_reggroup = reggroup_new ("ir", USER_REGGROUP);
  nds32_mr_reggroup = reggroup_new ("mr", USER_REGGROUP);
  nds32_dr_reggroup = reggroup_new ("dr", USER_REGGROUP);
  nds32_pfr_reggroup = reggroup_new ("pfr", USER_REGGROUP);
  nds32_hspr_reggroup = reggroup_new ("hspr", USER_REGGROUP);
  nds32_dmar_reggroup = reggroup_new ("dmar", USER_REGGROUP);
  nds32_racr_reggroup = reggroup_new ("racr", USER_REGGROUP);
  nds32_idr_reggroup = reggroup_new ("idr", USER_REGGROUP);
  nds32_secur_reggroup = reggroup_new ("secur", USER_REGGROUP);
}

static void
nds32_add_reggroups (struct gdbarch *gdbarch)
{
  /* Add pre-defined register groups.  */
  reggroup_add (gdbarch, general_reggroup);
  reggroup_add (gdbarch, float_reggroup);
  reggroup_add (gdbarch, system_reggroup);
  reggroup_add (gdbarch, all_reggroup);
  reggroup_add (gdbarch, save_reggroup);
  reggroup_add (gdbarch, restore_reggroup);

  /* Add NDS32 register groups.  */
  reggroup_add (gdbarch, nds32_cr_reggroup);
  reggroup_add (gdbarch, nds32_ir_reggroup);
  reggroup_add (gdbarch, nds32_mr_reggroup);
  reggroup_add (gdbarch, nds32_dr_reggroup);
  reggroup_add (gdbarch, nds32_pfr_reggroup);
  reggroup_add (gdbarch, nds32_hspr_reggroup);
  reggroup_add (gdbarch, nds32_dmar_reggroup);
  reggroup_add (gdbarch, nds32_racr_reggroup);
  reggroup_add (gdbarch, nds32_idr_reggroup);
  reggroup_add (gdbarch, nds32_secur_reggroup);
}

/* Implement the gdbarch_register_reggroup_p method.  */

static int
nds32_register_reggroup_p (struct gdbarch *gdbarch, int regnum,
			   struct reggroup *group)
{
  const char *regname = gdbarch_register_name (gdbarch, regnum);
  const char *groupname;

  if (regname == NULL || *regname == '\0')
    return 0;

  if (group == all_reggroup)
    return 1;

  /* General reggroup contains only GPRs and PC.  */
  if (group == general_reggroup)
    return regnum <= NDS32_PC_REGNUM;

  if (group == float_reggroup)
    return TYPE_CODE (register_type (gdbarch, regnum)) == TYPE_CODE_FLT;

  if (group == system_reggroup)
    return (regnum > NDS32_PC_REGNUM)
	    && TYPE_CODE (register_type (gdbarch, regnum)) != TYPE_CODE_FLT;

  if (group == save_reggroup || group == restore_reggroup)
    return regnum < gdbarch_num_regs (gdbarch);

  /* The NDS32 reggroup contains registers whose name is prefixed
     by reggroup name.  */
  groupname = reggroup_name (group);
  return !strncmp (regname, groupname, strlen (groupname));
}

/* Implement the tdesc_pseudo_register_type method.  */

static struct type *
nds32_pseudo_register_type (struct gdbarch *gdbarch, int regnum)
{
  regnum -= gdbarch_num_regs (gdbarch);

  /* Currently, only FSRs could be defined as pseudo registers.  */
  if (regnum < gdbarch_num_pseudo_regs (gdbarch))
    return arch_float_type (gdbarch, -1, "builtin_type_ieee_single",
			    floatformats_ieee_single);

  warning (_("Unknown nds32 pseudo register %d."), regnum);
  return NULL;
}

/* Implement the tdesc_pseudo_register_name method.  */

static const char *
nds32_pseudo_register_name (struct gdbarch *gdbarch, int regnum)
{
  regnum -= gdbarch_num_regs (gdbarch);

  /* Currently, only FSRs could be defined as pseudo registers.  */
  if (regnum < gdbarch_num_pseudo_regs (gdbarch))
    return nds32_fsr_regnames[regnum];

  warning (_("Unknown nds32 pseudo register %d."), regnum);
  return NULL;
}

/* Implement the gdbarch_pseudo_register_read method.  */

static enum register_status
nds32_pseudo_register_read (struct gdbarch *gdbarch,
			    struct regcache *regcache, int regnum,
			    gdb_byte *buf)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  gdb_byte reg_buf[8];
  int offset, fd_regnum;
  enum register_status status = REG_UNKNOWN;

  /* Sanity check.  */
  if (tdep->fpu_freg == -1 || tdep->use_pseudo_fsrs == 0)
    return status;

  regnum -= gdbarch_num_regs (gdbarch);

  /* Currently, only FSRs could be defined as pseudo registers.  */
  if (regnum < gdbarch_num_pseudo_regs (gdbarch))
    {
      /* fs0 is always the most significant half of fd0.  */
      if (gdbarch_byte_order (gdbarch) == BFD_ENDIAN_BIG)
	offset = (regnum & 1) ? 4 : 0;
      else
	offset = (regnum & 1) ? 0 : 4;

      fd_regnum = tdep->fd0_regnum + (regnum >> 1);
      status = regcache_raw_read (regcache, fd_regnum, reg_buf);
      if (status == REG_VALID)
	memcpy (buf, reg_buf + offset, 4);
    }

  return status;
}

/* Implement the gdbarch_pseudo_register_write method.  */

static void
nds32_pseudo_register_write (struct gdbarch *gdbarch,
			     struct regcache *regcache, int regnum,
			     const gdb_byte *buf)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  gdb_byte reg_buf[8];
  int offset, fd_regnum;

  /* Sanity check.  */
  if (tdep->fpu_freg == -1 || tdep->use_pseudo_fsrs == 0)
    return;

  regnum -= gdbarch_num_regs (gdbarch);

  /* Currently, only FSRs could be defined as pseudo registers.  */
  if (regnum < gdbarch_num_pseudo_regs (gdbarch))
    {
      /* fs0 is always the most significant half of fd0.  */
      if (gdbarch_byte_order (gdbarch) == BFD_ENDIAN_BIG)
	offset = (regnum & 1) ? 4 : 0;
      else
	offset = (regnum & 1) ? 0 : 4;

      fd_regnum = tdep->fd0_regnum + (regnum >> 1);
      regcache_raw_read (regcache, fd_regnum, reg_buf);
      memcpy (reg_buf + offset, buf, 4);
      regcache_raw_write (regcache, fd_regnum, reg_buf);
    }
}

/* Helper function for NDS32 ABI.  Return true if FPRs can be used
   to pass function arguments and return value.  */

static int
nds32_abi_use_fpr (int abi)
{
  return abi == E_NDS_ABI_V2FP_PLUS;
}

/* Helper function for NDS32 ABI.  Return true if GPRs and stack
   can be used together to pass an argument.  */

static int
nds32_abi_split (int abi)
{
  return abi == E_NDS_ABI_AABI;
}

struct nds32_frame_cache
{
  /* The previous frame's inner most stack address.
     Used as this frame ID's stack_addr.  */
  CORE_ADDR prev_sp;

  /* The frame's base, optionally used by the high-level debug info.  */
  CORE_ADDR base;

  /* How far the SP and FP have been offset from the start of
     the stack frame (as defined by the previous frame's stack
     pointer).  */
  LONGEST sp_offset;
  LONGEST fp_offset;
  int use_frame;

  /* The address of the first instruction in this function.  */
  CORE_ADDR pc;

  /* Table indicating the location of each and every register.  */
  struct trad_frame_saved_reg *saved_regs;
};

static struct nds32_frame_cache *
nds32_alloc_frame_cache (struct frame_info *this_frame)
{
  struct nds32_frame_cache *cache;

  cache = FRAME_OBSTACK_ZALLOC (struct nds32_frame_cache);
  cache->saved_regs = trad_frame_alloc_saved_regs (this_frame);
  cache->sp_offset = 0;
  cache->fp_offset = 0;
  cache->use_frame = 0;
  cache->base = 0;
  cache->prev_sp = -1;

  return cache;
}

/* Helper function for instructions used to push multiple words.  */

static void
nds32_push_multiple_words (struct nds32_frame_cache *cache, int rb, int re,
			   int enable4)
{
  LONGEST sp_offset = cache->sp_offset;
  int i;

  /* Check LP, GP, FP in enable4.  */
  for (i = 1; i <= 3; i++)
    {
      if ((enable4 >> i) & 0x1)
	{
	  sp_offset -= 4;
	  cache->saved_regs[NDS32_SP_REGNUM - i].addr = sp_offset;
	}
    }

  /* Skip case where re == rb == sp.  */
  if ((rb < REG_FP) && (re < REG_FP))
    {
      for (i = re; i >= rb; i--)
	{
	  sp_offset -= 4;
	  cache->saved_regs[i].addr = sp_offset;
	}
    }

  /* For sp, update the offset.  */
  cache->sp_offset = sp_offset;
}

/* Analyze the instructions within the given address range.  If CACHE
   is non-NULL, fill it in.  Return the first address beyond the given
   address range.  If CACHE is NULL, return the first address not
   recognized as a prologue instruction.  */

static CORE_ADDR
nds32_analyze_prologue (struct gdbarch *gdbarch, CORE_ADDR pc,
			CORE_ADDR limit_pc, struct nds32_frame_cache *cache)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  int abi_use_fpr = nds32_abi_use_fpr (tdep->abi);
  /* Current scanning status.  */
  int in_prologue_bb = 0;
  int val_ta = 0;
  uint32_t insn, insn_len;

  for (; pc < limit_pc; pc += insn_len)
    {
      insn = read_memory_unsigned_integer (pc, 4, BFD_ENDIAN_BIG);

      if ((insn & 0x80000000) == 0)
	{
	  /* 32-bit instruction */
	  insn_len = 4;

	  if (CHOP_BITS (insn, 15) == N32_TYPE2 (ADDI, REG_SP, REG_SP, 0))
	    {
	      /* addi $sp, $sp, imm15s */
	      int imm15s = N32_IMM15S (insn);

	      if (imm15s < 0)
		{
		  if (cache != NULL)
		    cache->sp_offset += imm15s;

		  in_prologue_bb = 1;
		  continue;
		}
	    }
	  else if (CHOP_BITS (insn, 15) == N32_TYPE2 (ADDI, REG_FP, REG_SP, 0))
	    {
	      /* addi $fp, $sp, imm15s */
	      int imm15s = N32_IMM15S (insn);

	      if (imm15s > 0)
		{
		  if (cache != NULL)
		    {
		      cache->fp_offset = cache->sp_offset + imm15s;
		      cache->use_frame = 1;
		    }

		  in_prologue_bb = 1;
		  continue;
		}
	    }
	  else if ((insn & ~(__MASK (19) << 6)) == N32_SMW_ADM
		   && N32_RA5 (insn) == REG_SP)
	    {
	      /* smw.adm Rb, [$sp], Re, enable4 */
	      if (cache != NULL)
		nds32_push_multiple_words (cache, N32_RT5 (insn),
					   N32_RB5 (insn),
					   N32_LSMW_ENABLE4 (insn));
	      in_prologue_bb = 1;
	      continue;
	    }
	  else if (insn == N32_ALU1 (ADD, REG_SP, REG_SP, REG_TA)
		   || insn == N32_ALU1 (ADD, REG_SP, REG_TA, REG_SP))
	    {
	      /* add $sp, $sp, $ta */
	      /* add $sp, $ta, $sp */
	      if (val_ta < 0)
		{
		  if (cache != NULL)
		    cache->sp_offset += val_ta;

		  in_prologue_bb = 1;
		  continue;
		}
	    }
	  else if (CHOP_BITS (insn, 20) == N32_TYPE1 (MOVI, REG_TA, 0))
	    {
	      /* movi $ta, imm20s */
	      if (cache != NULL)
		val_ta = N32_IMM20S (insn);

	      continue;
	    }
	  else if (CHOP_BITS (insn, 20) == N32_TYPE1 (SETHI, REG_TA, 0))
	    {
	      /* sethi $ta, imm20u */
	      if (cache != NULL)
		val_ta = N32_IMM20U (insn) << 12;

	      continue;
	    }
	  else if (CHOP_BITS (insn, 15) == N32_TYPE2 (ORI, REG_TA, REG_TA, 0))
	    {
	      /* ori $ta, $ta, imm15u */
	      if (cache != NULL)
		val_ta |= N32_IMM15U (insn);

	      continue;
	    }
	  else if (CHOP_BITS (insn, 15) == N32_TYPE2 (ADDI, REG_TA, REG_TA, 0))
	    {
	      /* addi $ta, $ta, imm15s */
	      if (cache != NULL)
		val_ta += N32_IMM15S (insn);

	      continue;
	    }
	  if (insn == N32_ALU1 (ADD, REG_GP, REG_TA, REG_GP)
	      || insn == N32_ALU1 (ADD, REG_GP, REG_GP, REG_TA))
	    {
	      /* add $gp, $ta, $gp */
	      /* add $gp, $gp, $ta */
	      in_prologue_bb = 1;
	      continue;
	    }
	  else if (CHOP_BITS (insn, 20) == N32_TYPE1 (MOVI, REG_GP, 0))
	    {
	      /* movi $gp, imm20s */
	      in_prologue_bb = 1;
	      continue;
	    }
	  else if (CHOP_BITS (insn, 20) == N32_TYPE1 (SETHI, REG_GP, 0))
	    {
	      /* sethi $gp, imm20u */
	      in_prologue_bb = 1;
	      continue;
	    }
	  else if (CHOP_BITS (insn, 15) == N32_TYPE2 (ORI, REG_GP, REG_GP, 0))
	    {
	      /* ori $gp, $gp, imm15u */
	      in_prologue_bb = 1;
	      continue;
	    }
	  else
	    {
	      /* Jump/Branch insns never appear in prologue basic block.
		 The loop can be escaped early when these insns are met.  */
	      if (in_prologue_bb == 1)
		{
		  int op = N32_OP6 (insn);

		  if (op == N32_OP6_JI
		      || op == N32_OP6_JREG
		      || op == N32_OP6_BR1
		      || op == N32_OP6_BR2
		      || op == N32_OP6_BR3)
		    break;
		}
	    }

	  if (abi_use_fpr && N32_OP6 (insn) == N32_OP6_SDC
	      && __GF (insn, 12, 3) == 0)
	    {
	      /* For FPU insns, CP (bit [13:14]) should be CP0,  and only
		 normal form (bit [12] == 0) is used.  */

	      /* fsdi FDt, [$sp + (imm12s << 2)] */
	      if (N32_RA5 (insn) == REG_SP)
		continue;
	    }

	  /* The optimizer might shove anything into the prologue, if
	     we build up cache (cache != NULL) from analyzing prologue,
	     we just skip what we don't recognize and analyze further to
	     make cache as complete as possible.  However, if we skip
	     prologue, we'll stop immediately on unrecognized
	     instruction.  */
	  if (cache == NULL)
	    break;
	}
      else
	{
	  /* 16-bit instruction */
	  insn_len = 2;

	  insn >>= 16;

	  if (CHOP_BITS (insn, 10) == N16_TYPE10 (ADDI10S, 0))
	    {
	      /* addi10s.sp */
	      int imm10s = N16_IMM10S (insn);

	      if (imm10s < 0)
		{
		  if (cache != NULL)
		    cache->sp_offset += imm10s;

		  in_prologue_bb = 1;
		  continue;
		}
	    }
	  else if (__GF (insn, 7, 8) == N16_T25_PUSH25)
	    {
	      /* push25 */
	      if (cache != NULL)
		{
		  int imm8u = (insn & 0x1f) << 3;
		  int re = (insn >> 5) & 0x3;
		  int reg_map[] = { 6, 8, 10, 14 };

		  /* Operation 1 -- smw.adm R6, [$sp], Re, #0xe */
		  nds32_push_multiple_words (cache, 6, reg_map[re], 0xe);

		  /* Operation 2 -- sp = sp - (imm5u << 3) */
		  cache->sp_offset -= imm8u;
		}

	      in_prologue_bb = 1;
	      continue;
	    }
	  else if (insn == N16_TYPE5 (ADD5PC, REG_GP))
	    {
	      /* add5.pc $gp */
	      in_prologue_bb = 1;
	      continue;
	    }
	  else if (CHOP_BITS (insn, 5) == N16_TYPE55 (MOVI55, REG_GP, 0))
	    {
	      /* movi55 $gp, imm5s */
	      in_prologue_bb = 1;
	      continue;
	    }
	  else
	    {
	      /* Jump/Branch insns never appear in prologue basic block.
		 The loop can be escaped early when these insns are met.  */
	      if (in_prologue_bb == 1)
		{
		  uint32_t insn5 = CHOP_BITS (insn, 5);
		  uint32_t insn8 = CHOP_BITS (insn, 8);
		  uint32_t insn38 = CHOP_BITS (insn, 11);

		  if (insn5 == N16_TYPE5 (JR5, 0)
		      || insn5 == N16_TYPE5 (JRAL5, 0)
		      || insn5 == N16_TYPE5 (RET5, 0)
		      || insn8 == N16_TYPE8 (J8, 0)
		      || insn8 == N16_TYPE8 (BEQZS8, 0)
		      || insn8 == N16_TYPE8 (BNEZS8, 0)
		      || insn38 == N16_TYPE38 (BEQZ38, 0, 0)
		      || insn38 == N16_TYPE38 (BNEZ38, 0, 0)
		      || insn38 == N16_TYPE38 (BEQS38, 0, 0)
		      || insn38 == N16_TYPE38 (BNES38, 0, 0))
		    break;
		}
	    }

	  /* The optimizer might shove anything into the prologue, if
	     we build up cache (cache != NULL) from analyzing prologue,
	     we just skip what we don't recognize and analyze further to
	     make cache as complete as possible.  However, if we skip
	     prologue, we'll stop immediately on unrecognized
	     instruction.  */
	  if (cache == NULL)
	    break;
	}
    }

  return pc;
}

/* Implement the gdbarch_skip_prologue method.

   Find the end of function prologue.  */

static CORE_ADDR
nds32_skip_prologue (struct gdbarch *gdbarch, CORE_ADDR pc)
{
  LONGEST return_value;
  const char *func_name;
  const int search_limit = 128; /* Magic.  */
  CORE_ADDR func_addr, limit_pc;

  /* See what the symbol table says */
  if (find_pc_partial_function (pc, NULL, &func_addr, NULL))
    {
      CORE_ADDR post_prologue_pc
	= skip_prologue_using_sal (gdbarch, func_addr);

      if (post_prologue_pc != 0)
	return max (pc, post_prologue_pc);
    }

  limit_pc = skip_prologue_using_sal (gdbarch, pc);
  if (limit_pc == 0)
    limit_pc = pc + search_limit;

  /* If current instruction is not readable, just quit.  */
  if (!safe_read_memory_integer (pc, 4, BFD_ENDIAN_BIG, &return_value))
    return pc;

  /* Find the end of prologue.  */
  return nds32_analyze_prologue (gdbarch, pc, limit_pc, NULL);
}

/* Implement the stack_frame_destroyed_p gdbarch method.  */

static int
nds32_stack_frame_destroyed_p (struct gdbarch *gdbarch, CORE_ADDR addr)
{
  uint32_t insn;
  int r = 0;

  insn = read_memory_unsigned_integer (addr, 4, BFD_ENDIAN_BIG);
  if ((insn & 0x80000000) == 0)
    {
      /* ret */
      if (insn == N32_JREG (JR, 0, REG_LP, 0, 1))
	r = 1;
      /* iret */
      else if (insn == N32_TYPE0 (MISC, N32_MISC_IRET))
	r = 2;
    }
  else if (insn == N16_TYPE5 (RET5, REG_LP))
    r = 3;

  return r > 0;
}

/* Put here the code to store, into fi->saved_regs, the addresses of
   the saved registers of frame described by FRAME_INFO.  This
   includes special registers such as pc and fp saved in special ways
   in the stack frame.  sp is even more special: the address we return
   for it IS the sp for the next frame.  */

static struct nds32_frame_cache *
nds32_frame_cache (struct frame_info *this_frame, void **this_cache)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  struct nds32_frame_cache *cache;
  CORE_ADDR current_pc;
  ULONGEST prev_sp;
  ULONGEST this_base;
  int i;

  if (*this_cache)
    return (struct nds32_frame_cache *) *this_cache;

  cache = nds32_alloc_frame_cache (this_frame);
  *this_cache = cache;

  cache->pc = get_frame_func (this_frame);
  current_pc = get_frame_pc (this_frame);
  nds32_analyze_prologue (gdbarch, cache->pc, current_pc, cache);

  /* Compute the previous frame's stack pointer (which is also the
     frame's ID's stack address), and this frame's base pointer.  */
  if (cache->use_frame)
    {
      this_base = get_frame_register_unsigned (this_frame, NDS32_FP_REGNUM);
      prev_sp = this_base - cache->fp_offset;
    }
  else
    {
      this_base = get_frame_register_unsigned (this_frame, NDS32_SP_REGNUM);
      prev_sp = this_base - cache->sp_offset;
    }

  cache->prev_sp = prev_sp;
  cache->base = this_base;

  /* Adjust all the saved registers so that they contain addresses and
     not offsets.  */
  for (i = 0; i < gdbarch_num_regs (gdbarch) - 1; i++)
    {
      if (trad_frame_addr_p (cache->saved_regs, i))
	{
	  cache->saved_regs[i].addr = cache->prev_sp + cache->saved_regs[i].addr;
	}
    }

  /* The previous frame's SP needed to be computed.
     Save the computed value.  */
  trad_frame_set_value (cache->saved_regs, NDS32_SP_REGNUM, prev_sp);

  return cache;
}

/* Implement the gdbarch_unwind_pc method.  */

static CORE_ADDR
nds32_unwind_pc (struct gdbarch *gdbarch, struct frame_info *this_frame)
{
  /* This snippet code is a mess.

     In most case, LP is the actually register being saved.
     Hence when unwinding pc for backtrace, LP should be the one.
     That is, for frames (level > 0), unwinding the PC means
     unwinding LP from the this_frame.

     However, for a top frame (level==0), unwinding PC means
     the current program counter (PC).
     Besides, for dummy frame, PC stored in dummy_frame is the one
     we want.

     We have to have these cases to make backtrace work properly.  */

  CORE_ADDR pc;
  pc = frame_unwind_register_unsigned (this_frame, NDS32_PC_REGNUM);
  return pc;
}

/* Implement the gdbarch_unwind_sp method.  */

static CORE_ADDR
nds32_unwind_sp (struct gdbarch *gdbarch, struct frame_info *this_frame)
{
  return frame_unwind_register_unsigned (this_frame, NDS32_SP_REGNUM);
}

/* Floating type and struct type that has only one floating type member
   can pass value using FPU registers (when FPU ABI is used).  */

static int
nds32_check_calling_use_fpr (struct type *type)
{
  struct type *t;
  enum type_code typecode;

  t = type;
  while (1)
    {
      t = check_typedef (t);
      typecode = TYPE_CODE (t);
      if (typecode != TYPE_CODE_STRUCT)
	break;
      else if (TYPE_NFIELDS (t) != 1)
	return 0;
      else
	t = TYPE_FIELD_TYPE (t, 0);
    }

  return typecode == TYPE_CODE_FLT;
}

/* Get the alignment of the type.

   The alignment requirement of a structure is the largest alignment
   requirement of its member, so we should traverse every member to
   find the largest alignment.

   For example,
     struct { int a; int b; char c } is 4-byte aligned,
   and
     struct {long long a; char c} is 8-byte aligned.  */

static int
nds32_type_align (struct type *type)
{
  int n;
  int align;
  int falign;

  type = check_typedef (type);
  switch (TYPE_CODE (type))
    {
    default:
      /* Should never happen.  */
      internal_error (__FILE__, __LINE__, _("unknown type alignment"));
      return 4;

    case TYPE_CODE_PTR:
    case TYPE_CODE_ENUM:
    case TYPE_CODE_INT:
    case TYPE_CODE_FLT:
    case TYPE_CODE_SET:
    case TYPE_CODE_RANGE:
    case TYPE_CODE_REF:
    case TYPE_CODE_CHAR:
    case TYPE_CODE_BOOL:
      return TYPE_LENGTH (type);

    case TYPE_CODE_ARRAY:
    case TYPE_CODE_COMPLEX:
      return nds32_type_align (TYPE_TARGET_TYPE (type));

    case TYPE_CODE_STRUCT:
    case TYPE_CODE_UNION:
      align = 1;
      for (n = 0; n < TYPE_NFIELDS (type); n++)
	{
	  falign = nds32_type_align (TYPE_FIELD_TYPE (type, n));
	  if (falign > align)
	    align = falign;
	}
      return align;
    }
}

/* Implement the gdbarch_push_dummy_call method.  */

static CORE_ADDR
nds32_push_dummy_call (struct gdbarch *gdbarch, struct value *function,
		       struct regcache *regcache, CORE_ADDR bp_addr,
		       int nargs, struct value **args, CORE_ADDR sp,
		       int struct_return, CORE_ADDR struct_addr)
{
  const int REND = 6;		/* End for register offset.  */
  int goff = 0;			/* Current gpr offset for argument.  */
  int foff = 0;			/* Current fpr offset for argument.  */
  int soff = 0;			/* Current stack offset for argument.  */
  int i;
  ULONGEST regval;
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  struct type *func_type = value_type (function);
  int abi_use_fpr = nds32_abi_use_fpr (tdep->abi);
  int abi_split = nds32_abi_split (tdep->abi);

  /* Set the return address.  For the nds32, the return breakpoint is
     always at BP_ADDR.  */
  regcache_cooked_write_unsigned (regcache, NDS32_LP_REGNUM, bp_addr);

  /* If STRUCT_RETURN is true, then the struct return address (in
     STRUCT_ADDR) will consume the first argument-passing register.
     Both adjust the register count and store that value.  */
  if (struct_return)
    {
      regcache_cooked_write_unsigned (regcache, NDS32_R0_REGNUM, struct_addr);
      goff++;
    }

  /* Now make sure there's space on the stack */
  for (i = 0; i < nargs; i++)
    {
      struct type *type = value_type (args[i]);
      int align = nds32_type_align (type);

      /* If align is zero, it may be an empty struct.
	 Just ignore the argument of empty struct.  */
      if (align == 0)
	continue;

      sp -= TYPE_LENGTH (type);
      sp = align_down (sp, align);
    }

  /* Stack must be 8-byte aligned.  */
  sp = align_down (sp, 8);

  soff = 0;
  for (i = 0; i < nargs; i++)
    {
      const gdb_byte *val;
      int align, len;
      struct type *type;
      int calling_use_fpr;
      int use_fpr = 0;

      type = value_type (args[i]);
      calling_use_fpr = nds32_check_calling_use_fpr (type);
      len = TYPE_LENGTH (type);
      align = nds32_type_align (type);
      val = value_contents (args[i]);

      /* The size of a composite type larger than 4 bytes will be rounded
	 up to the nearest multiple of 4.  */
      if (len > 4)
	len = align_up (len, 4);

      /* Variadic functions are handled differently between AABI and ABI2FP+.

	 For AABI, the caller pushes arguments in registers, callee stores
	 unnamed arguments in stack, and then va_arg fetch arguments in stack.
	 Therefore, we don't have to handle variadic functions specially.

	 For ABI2FP+, the caller pushes only named arguments in registers
	 and pushes all unnamed arguments in stack.  */

      if (abi_use_fpr && TYPE_VARARGS (func_type)
	  && i >= TYPE_NFIELDS (func_type))
	goto use_stack;

      /* Try to use FPRs to pass arguments only when
	 1. The program is built using toolchain with FPU support.
	 2. The type of this argument can use FPR to pass value.  */
      use_fpr = abi_use_fpr && calling_use_fpr;

      if (use_fpr)
	{
	  /* Adjust alignment.  */
	  if ((align >> 2) > 0)
	    foff = align_up (foff, align >> 2);

	  if (foff < REND)
	    {
	      int fs0_regnum = tdep->fs0_regnum;
	      int fd0_regnum = tdep->fd0_regnum;

	      if (fs0_regnum == -1)
		goto error_no_fpr;

	      switch (len)
		{
		case 4:
		  regcache_cooked_write (regcache, fs0_regnum + foff, val);
		  foff++;
		  break;
		case 8:
		  regcache_cooked_write (regcache, fd0_regnum + foff / 2, val);
		  foff += 2;
		  break;
		default:
		  /* Long double?  */
		  internal_error (__FILE__, __LINE__,
				  "Do not know how to handle %d-byte double.\n",
				  len);
		  break;
		}
	      continue;
	    }
	}
      else
	{
	  /*
	     When passing arguments using GPRs,

	     * A composite type not larger than 4 bytes is passed in $rN.
	       The format is as if the value is loaded with load instruction
	       of corresponding size (e.g., LB, LH, LW).

	       For example,

		       r0
		       31      0
	       LITTLE: [x x b a]
		  BIG: [x x a b]

	     * Otherwise, a composite type is passed in consecutive registers.
	       The size is rounded up to the nearest multiple of 4.
	       The successive registers hold the parts of the argument as if
	       were loaded using lmw instructions.

	       For example,

		       r0	r1
		       31      0 31      0
	       LITTLE: [d c b a] [x x x e]
		  BIG: [a b c d] [e x x x]
	   */

	  /* Adjust alignment.  */
	  if ((align >> 2) > 0)
	    goff = align_up (goff, align >> 2);

	  if (len <= (REND - goff) * 4)
	    {
	      /* This argument can be passed wholly via GPRs.  */
	      while (len > 0)
		{
		  regval = extract_unsigned_integer (val, (len > 4) ? 4 : len,
						     byte_order);
		  regcache_cooked_write_unsigned (regcache,
						  NDS32_R0_REGNUM + goff,
						  regval);
		  len -= 4;
		  val += 4;
		  goff++;
		}
	      continue;
	    }
	  else if (abi_split)
	    {
	      /* Some parts of this argument can be passed via GPRs.  */
	      while (goff < REND)
		{
		  regval = extract_unsigned_integer (val, (len > 4) ? 4 : len,
						     byte_order);
		  regcache_cooked_write_unsigned (regcache,
						  NDS32_R0_REGNUM + goff,
						  regval);
		  len -= 4;
		  val += 4;
		  goff++;
		}
	    }
	}

use_stack:
      /*
	 When pushing (split parts of) an argument into stack,

	 * A composite type not larger than 4 bytes is copied to different
	   base address.
	   In little-endian, the first byte of this argument is aligned
	   at the low address of the next free word.
	   In big-endian, the last byte of this argument is aligned
	   at the high address of the next free word.

	   For example,

	   sp [ - ]  [ c ] hi
	      [ c ]  [ b ]
	      [ b ]  [ a ]
	      [ a ]  [ - ] lo
	     LITTLE   BIG
       */

      /* Adjust alignment.  */
      soff = align_up (soff, align);

      while (len > 0)
	{
	  int rlen = (len > 4) ? 4 : len;

	  if (byte_order == BFD_ENDIAN_BIG)
	    write_memory (sp + soff + 4 - rlen, val, rlen);
	  else
	    write_memory (sp + soff, val, rlen);

	  len -= 4;
	  val += 4;
	  soff += 4;
	}
    }

  /* Finally, update the SP register.  */
  regcache_cooked_write_unsigned (regcache, NDS32_SP_REGNUM, sp);

  return sp;

error_no_fpr:
  /* If use_fpr, but no floating-point register exists,
     then it is an error.  */
  error (_("Fail to call. FPU registers are required."));
}

/* Read, for architecture GDBARCH, a function return value of TYPE
   from REGCACHE, and copy that into VALBUF.  */

static void
nds32_extract_return_value (struct gdbarch *gdbarch, struct type *type,
			    struct regcache *regcache, gdb_byte *valbuf)
{
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  int abi_use_fpr = nds32_abi_use_fpr (tdep->abi);
  int calling_use_fpr;
  int len;

  calling_use_fpr = nds32_check_calling_use_fpr (type);
  len = TYPE_LENGTH (type);

  if (abi_use_fpr && calling_use_fpr)
    {
      if (len == 4)
	regcache_cooked_read (regcache, tdep->fs0_regnum, valbuf);
      else if (len == 8)
	regcache_cooked_read (regcache, tdep->fd0_regnum, valbuf);
      else
	internal_error (__FILE__, __LINE__,
			_("Cannot extract return value of %d bytes "
			  "long floating-point."), len);
    }
  else
    {
      /*
	 When returning result,

	 * A composite type not larger than 4 bytes is returned in $r0.
	   The format is as if the result is loaded with load instruction
	   of corresponding size (e.g., LB, LH, LW).

	   For example,

		   r0
		   31      0
	   LITTLE: [x x b a]
	      BIG: [x x a b]

	 * Otherwise, a composite type not larger than 8 bytes is returned
	   in $r0 and $r1.
	   In little-endian, the first word is loaded in $r0.
	   In big-endian, the last word is loaded in $r1.

	   For example,

		   r0	     r1
		   31      0 31      0
	   LITTLE: [d c b a] [x x x e]
	      BIG: [x x x a] [b c d e]
       */

      ULONGEST tmp;

      if (len < 4)
	{
	  /* By using store_unsigned_integer we avoid having to do
	     anything special for small big-endian values.  */
	  regcache_cooked_read_unsigned (regcache, NDS32_R0_REGNUM, &tmp);
	  store_unsigned_integer (valbuf, len, byte_order, tmp);
	}
      else if (len == 4)
	{
	  regcache_cooked_read (regcache, NDS32_R0_REGNUM, valbuf);
	}
      else if (len < 8)
	{
	  int len1, len2;

	  len1 = byte_order == BFD_ENDIAN_BIG ? len - 4 : 4;
	  len2 = len - len1;

	  regcache_cooked_read_unsigned (regcache, NDS32_R0_REGNUM, &tmp);
	  store_unsigned_integer (valbuf, len1, byte_order, tmp);

	  regcache_cooked_read_unsigned (regcache, NDS32_R0_REGNUM + 1, &tmp);
	  store_unsigned_integer (valbuf + len1, len2, byte_order, tmp);
	}
      else
	{
	  regcache_cooked_read (regcache, NDS32_R0_REGNUM, valbuf);
	  regcache_cooked_read (regcache, NDS32_R0_REGNUM + 1, valbuf + 4);
	}
    }
}

/* Write, for architecture GDBARCH, a function return value of TYPE
   from VALBUF into REGCACHE.  */

static void
nds32_store_return_value (struct gdbarch *gdbarch, struct type *type,
			  struct regcache *regcache, const gdb_byte *valbuf)
{
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  int abi_use_fpr = nds32_abi_use_fpr (tdep->abi);
  int calling_use_fpr;
  int len;

  calling_use_fpr = nds32_check_calling_use_fpr (type);
  len = TYPE_LENGTH (type);

  if (abi_use_fpr && calling_use_fpr)
    {
      if (len == 4)
	regcache_cooked_write (regcache, tdep->fs0_regnum, valbuf);
      else if (len == 8)
	regcache_cooked_write (regcache, tdep->fd0_regnum, valbuf);
      else
	internal_error (__FILE__, __LINE__,
			_("Cannot store return value of %d bytes "
			  "long floating-point."), len);
    }
  else
    {
      ULONGEST regval;

      if (len < 4)
	{
	  regval = extract_unsigned_integer (valbuf, len, byte_order);
	  regcache_cooked_write_unsigned (regcache, NDS32_R0_REGNUM, regval);
	}
      else if (len == 4)
	{
	  regcache_cooked_write (regcache, NDS32_R0_REGNUM, valbuf);
	}
      else if (len < 8)
	{
	  int len1, len2;

	  len1 = byte_order == BFD_ENDIAN_BIG ? len - 4 : 4;
	  len2 = len - len1;

	  regval = extract_unsigned_integer (valbuf, len1, byte_order);
	  regcache_cooked_write_unsigned (regcache, NDS32_R0_REGNUM, regval);

	  regval = extract_unsigned_integer (valbuf + len1, len2, byte_order);
	  regcache_cooked_write_unsigned (regcache, NDS32_R0_REGNUM + 1,
					  regval);
	}
      else
	{
	  regcache_cooked_write (regcache, NDS32_R0_REGNUM, valbuf);
	  regcache_cooked_write (regcache, NDS32_R0_REGNUM + 1, valbuf + 4);
	}
    }
}

/* Determine, for architecture GDBARCH, how a return value of TYPE
   should be returned.  If it is supposed to be returned in registers,
   and READBUF is non-zero, read the appropriate value from REGCACHE,
   and copy it into READBUF.  If WRITEBUF is non-zero, write the value
   from WRITEBUF into REGCACHE.  */

static enum return_value_convention
nds32_return_value (struct gdbarch *gdbarch, struct value *func_type,
		    struct type *type, struct regcache *regcache,
		    gdb_byte *readbuf, const gdb_byte *writebuf)
{
  if (TYPE_LENGTH (type) > 8)
    {
      return RETURN_VALUE_STRUCT_CONVENTION;
    }
  else
    {
      if (readbuf != NULL)
	nds32_extract_return_value (gdbarch, type, regcache, readbuf);
      if (writebuf != NULL)
	nds32_store_return_value (gdbarch, type, regcache, writebuf);

      return RETURN_VALUE_REGISTER_CONVENTION;
    }
}

/* Assuming NEXT_FRAME->prev is a dummy, return the frame ID of that
   dummy frame.  The frame ID's base needs to match the TOS value
   saved by save_dummy_frame_tos(), and the PC match the dummy frame's
   breakpoint.  */

static struct frame_id
nds32_dummy_id (struct gdbarch *gdbarch, struct frame_info *this_frame)
{
  CORE_ADDR sp, pc;

  sp = get_frame_register_unsigned (this_frame, NDS32_SP_REGNUM);
  pc = get_frame_pc (this_frame);
  return frame_id_build (sp, pc);
}

/* Given a GDB frame, determine the address of the calling function's
   frame.  This will be used to create a new GDB frame struct.  */

static void
nds32_frame_this_id (struct frame_info *this_frame, void **this_cache,
		     struct frame_id *this_id)
{
  struct nds32_frame_cache *cache;
  CORE_ADDR base;
  struct frame_id id;

  cache = nds32_frame_cache (this_frame, this_cache);

  /* Hopefully the prologue analysis either correctly determined the
     frame's base (which is the SP from the previous frame), or set
     that base to "NULL".  */
  base = cache->prev_sp;
  if (base == 0)
    return;

  id = frame_id_build (base, cache->pc);
  (*this_id) = id;
}

/* Get the value of register REGNUM in previous frame.  */

static struct value *
nds32_frame_prev_register (struct frame_info *this_frame, void **this_cache,
			   int regnum)
{
  struct nds32_frame_cache *cache;
  cache = nds32_frame_cache (this_frame, this_cache);

  if (regnum == NDS32_PC_REGNUM)
    {
      CORE_ADDR lr;

      lr = frame_unwind_register_unsigned (this_frame, NDS32_LP_REGNUM);
      return frame_unwind_got_constant (this_frame, regnum, lr);
    }

  return trad_frame_get_prev_register (this_frame, cache->saved_regs, regnum);
}

static const struct frame_unwind nds32_frame_unwind =
{
  NORMAL_FRAME,
  default_frame_unwind_stop_reason,
  nds32_frame_this_id,
  nds32_frame_prev_register,
  NULL /* unwind_data */,
  default_frame_sniffer,
  NULL /* dealloc_cache */,
  NULL /* prev_arch */
};

static CORE_ADDR
nds32_frame_base_address (struct frame_info *this_frame, void **this_cache)
{
  struct nds32_frame_cache *cache = nds32_frame_cache (this_frame, this_cache);

  return cache->base;
}

static const struct frame_base nds32_frame_base =
{
  &nds32_frame_unwind,
  nds32_frame_base_address,
  nds32_frame_base_address,
  nds32_frame_base_address
};

/* Implement the gdbarch_get_longjmp_target method.  */

static int
nds32_get_longjmp_target (struct frame_info *frame, CORE_ADDR *pc)
{
  gdb_byte buf[4];
  CORE_ADDR jmp_buf_p;
  struct gdbarch *gdbarch = get_frame_arch (frame);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  jmp_buf_p = get_frame_register_unsigned (frame, 0);

  /* Key is in setjmp():
     lmw.bim   r6, [r0], r14
     lmw.bim  r16, [r0], r19, 0xf */

  if (target_read_memory (jmp_buf_p + 15 * 4, buf, 4))
    return 0;

  *pc = extract_unsigned_integer (buf, 4, byte_order);

  return 1;
}

static int
nds32_epilogue_frame_sniffer (const struct frame_unwind *self,
			      struct frame_info *this_frame, void **this_cache)
{
  if (frame_relative_level (this_frame) == 0)
    return nds32_stack_frame_destroyed_p (get_frame_arch (this_frame),
					  get_frame_pc (this_frame));
  else
    return 0;
}

static struct nds32_frame_cache *
nds32_epilogue_frame_cache (struct frame_info *this_frame, void **this_cache)
{
  struct nds32_frame_cache *cache;
  CORE_ADDR sp;

  if (*this_cache)
    return (struct nds32_frame_cache *) *this_cache;

  cache = nds32_alloc_frame_cache (this_frame);
  *this_cache = cache;

  TRY
    {
      /* At this point the stack looks as if we just entered the
	 function, with the return address at the top of the
	 stack.  */
      sp = get_frame_register_unsigned (this_frame, NDS32_SP_REGNUM);
      cache->prev_sp = sp;
    }
  CATCH (ex, RETURN_MASK_ERROR)
    {
      if (ex.error != NOT_AVAILABLE_ERROR)
	throw_exception (ex);
    }
  END_CATCH

  return cache;
}

static enum unwind_stop_reason
nds32_epilogue_frame_unwind_stop_reason (struct frame_info *this_frame,
					 void **this_cache)
{
  struct nds32_frame_cache *cache =
    nds32_epilogue_frame_cache (this_frame, this_cache);

  if (!cache->prev_sp)
    return UNWIND_UNAVAILABLE;

  return UNWIND_NO_REASON;
}

static void
nds32_epilogue_frame_this_id (struct frame_info *this_frame, void **this_cache,
			      struct frame_id *this_id)
{
  CORE_ADDR func, base;
  struct nds32_frame_cache *cache =
    nds32_epilogue_frame_cache (this_frame, this_cache);

  base = cache->prev_sp;
  func = get_frame_func (this_frame);

  if (base == -1)
    (*this_id) = frame_id_build_unavailable_stack (func);
  else
    (*this_id) = frame_id_build (base + 8, func);
}

static struct value *
nds32_epilogue_frame_prev_register (struct frame_info *this_frame,
				    void **this_cache, int regnum)
{
  /* Make sure we've initialized the cache.  */
  nds32_epilogue_frame_cache (this_frame, this_cache);

  return nds32_frame_prev_register (this_frame, this_cache, regnum);
}

static const struct frame_unwind nds32_epilogue_frame_unwind = {
    NORMAL_FRAME,
    nds32_epilogue_frame_unwind_stop_reason,
    nds32_epilogue_frame_this_id,
    nds32_epilogue_frame_prev_register,
    NULL,
    nds32_epilogue_frame_sniffer
};

/* Implement the gdbarch_overlay_update method.  */

static void
nds32_simple_overlay_update (struct obj_section *osect)
{
  struct bound_minimal_symbol minsym;

  minsym = lookup_minimal_symbol (".nds32.fixed.size", NULL, NULL);
  if (minsym.minsym != NULL && osect != NULL)
    {
      bfd *obfd = osect->objfile->obfd;
      asection *bsect = osect->the_bfd_section;
      if (bfd_section_vma (obfd, bsect) < BMSYMBOL_VALUE_ADDRESS (minsym))
	{
	  osect->ovly_mapped = 1;
	  return;
	}
    }

  simple_overlay_update (osect);
}

/* Implement gdbarch_print_insn method.  */

static int
gdb_print_insn_nds32 (bfd_vma memaddr, disassemble_info *info)
{
  struct obj_section * s = find_pc_section (memaddr);

  /* When disassembling ex9 instructions, annotating them with
     the original instructions at the end of line.  For example,

	0x00500122 <+82>:    ex9.it #4		! movi $r13, 10

     Dissembler needs the symbol table to extract the original instruction
     in _ITB_BASE_ table.  If the object file is changed, reload symbol
     table.  */

  if (s == NULL || info->section != s->the_bfd_section)
    {
      xfree (info->symtab);
      info->symtab = NULL;
      info->symtab_size = 0;
    }

  if (info->symtab == NULL && s && s->the_bfd_section)
    {
      long storage = bfd_get_symtab_upper_bound (s->objfile->obfd);

      if (storage <= 0)
	goto done;

      info->section = s->the_bfd_section;
      info->symtab = (asymbol **) xmalloc (storage);
      info->symtab_size =
	bfd_canonicalize_symtab (s->the_bfd_section->owner, info->symtab);
    }

done:
  return print_insn_nds32 (memaddr, info);
}

/* Validate and fixed-number registers in target-description.  */

static int
nds32_preprocess_tdesc_p (const struct target_desc *tdesc,
			  struct tdesc_arch_data *tdesc_data,
			  struct gdbarch_tdep *tdep)
{
  const struct tdesc_feature *feature;
  int i, freg = -1;
  int valid_p;

  feature = tdesc_find_feature (tdesc, "org.gnu.gdb.nds32.core");
  if (feature == NULL)
    return 0;

  valid_p = 1;
  /* Validate and fixed-number R0-R10.  */
  for (i = NDS32_R0_REGNUM; i <= NDS32_R0_REGNUM + 10; i++)
    valid_p &= tdesc_numbered_register (feature, tdesc_data, i,
					nds32_regnames[i]);

  /* Validate R15, and it will be fix-numbered later.  */
  valid_p &= tdesc_unnumbered_register (feature,
					nds32_regnames[NDS32_TA_REGNUM]);

  /* Validate and fixed-number FP, GP, LP, SP, PC.  */
  for (i = NDS32_FP_REGNUM; i <= NDS32_PC_REGNUM; i++)
    valid_p &= tdesc_numbered_register (feature, tdesc_data, i,
					nds32_regnames[i]);

  if (!valid_p)
    return 0;

  /* Fixed-number R11-R27.  */
  for (i = NDS32_R0_REGNUM + 11; i <= NDS32_R0_REGNUM + 27; i++)
    tdesc_numbered_register (feature, tdesc_data, i, nds32_regnames[i]);

  /* Fixed-number D0 and D1.  */
  for (i = NDS32_D0LO_REGNUM; i <= NDS32_D1HI_REGNUM; i++)
    tdesc_numbered_register (feature, tdesc_data, i, nds32_regnames[i]);

  /* Guess FPU configuration via existing registers.  */
  feature = tdesc_find_feature (tdesc, "org.gnu.gdb.nds32.fpu");
  if (feature != NULL)
    {
      if (tdesc_unnumbered_register (feature, "fd31"))
	freg = 3;
      else if (tdesc_unnumbered_register (feature, "fd15"))
	freg = 2;
      else if (tdesc_unnumbered_register (feature, "fd7"))
	freg = 1;
      else if (tdesc_unnumbered_register (feature, "fd3"))
	freg = 0;
    }

  /* Record guessed FPU configuration.  */
  tdep->fpu_freg = freg;

  if (freg != -1)
    {
      int num_fdr_regs = (1 << freg) * 4;

      /* Validate and fixed-number required FDRs.  */
      for (i = 0; i < num_fdr_regs; i++)
	valid_p &= tdesc_numbered_register (feature, tdesc_data,
					    NDS32_FD0_REGNUM + i,
					    nds32_fdr_regnames[i]);
      tdep->num_fdr_regs = num_fdr_regs;
    }

  if (!valid_p)
    return 0;

  tdep->use_pseudo_fsrs = 0;
  if (freg != -1)
    {
      int num_fsr_regs = (1 << freg) * 8;

      if (num_fsr_regs > 32)
	num_fsr_regs = 32;

      tdep->num_fsr_regs = num_fsr_regs;

      /* Assume that when FSRs are specified in target description, FS0 must
	 exist.  */
      if (tdesc_unnumbered_register (feature, "fs0") == 0)
	{
	  /* If FSRs are not specified in target-description, make them
	     pseudo registers of FDRs.  */
	  tdep->use_pseudo_fsrs = 1;
	}
      else
	{
	  /* Validate and fixed-number required FSRs.  */
	  for (i = 0; i < num_fsr_regs; i++)
	    valid_p &= tdesc_numbered_register (feature, tdesc_data,
						NDS32_FS0_REGNUM + i,
						nds32_fsr_regnames[i]);
	  if (!valid_p)
	    return 0;
	}
    }

  return 1;
}

/* Callback for gdbarch_init.  */

static struct gdbarch *
nds32_gdbarch_init (struct gdbarch_info info, struct gdbarch_list *arches)
{
  struct gdbarch *gdbarch;
  struct gdbarch_tdep *tdep;
  struct gdbarch_list *best_arch;
  struct tdesc_arch_data *tdesc_data = NULL;
  const struct target_desc *tdesc = info.target_desc;
  int i, maxregs;

  tdep = XCNEW (struct gdbarch_tdep);

  /* Extract the elf_flags if available.  */
  tdep->abi = E_NDS_ABI_AABI;
  if (info.abfd && bfd_get_flavour (info.abfd) == bfd_target_elf_flavour)
    {
      int eflags = elf_elfheader (info.abfd)->e_flags;
      tdep->abi = eflags & EF_NDS_ABI;
    }

  /* If there is already a candidate, use it.  */
  for (best_arch = gdbarch_list_lookup_by_info (arches, &info);
       best_arch != NULL;
       best_arch = gdbarch_list_lookup_by_info (best_arch->next, &info))
    {
      struct gdbarch_tdep *idep = gdbarch_tdep (best_arch->gdbarch);

      if (idep->abi != tdep->abi)
	continue;

      /* Found a match.  */
      break;
    }

  if (best_arch != NULL)
    {
      xfree (tdep);
      return best_arch->gdbarch;
    }

  if (!tdesc_has_registers (tdesc))
    tdesc = tdesc_nds32;

  tdesc_data = tdesc_data_alloc ();

  if (!nds32_preprocess_tdesc_p (tdesc, tdesc_data, tdep))
    {
      tdesc_data_cleanup (tdesc_data);
      xfree (tdep);
      return NULL;
    }

  /* Allocate space for the new architecture.  */
  gdbarch = gdbarch_alloc (&info, tdep);

  if (tdep->use_pseudo_fsrs)
    {
      set_gdbarch_num_pseudo_regs (gdbarch, tdep->num_fsr_regs);
      set_gdbarch_pseudo_register_read (gdbarch, nds32_pseudo_register_read);
      set_gdbarch_pseudo_register_write (gdbarch, nds32_pseudo_register_write);
      set_tdesc_pseudo_register_name (gdbarch, nds32_pseudo_register_name);
      set_tdesc_pseudo_register_type (gdbarch, nds32_pseudo_register_type);
    }

  if (tdep->fpu_freg == -1)
    set_gdbarch_num_regs (gdbarch, NDS32_NUM_REGS);
  else if (tdep->use_pseudo_fsrs == 1)
    set_gdbarch_num_regs (gdbarch, NDS32_FD0_REGNUM + tdep->num_fdr_regs);
  else
    set_gdbarch_num_regs (gdbarch, NDS32_FS0_REGNUM + tdep->num_fsr_regs);
  tdesc_use_registers (gdbarch, tdesc, tdesc_data);

  /* Cache the register number of fs0 and fd0.  */
  tdep->fs0_regnum = -1;
  tdep->fd0_regnum = -1;
  if (tdep->fpu_freg != -1)
    {
      tdep->fs0_regnum = user_reg_map_name_to_regnum (gdbarch, "fs0", -1);
      tdep->fd0_regnum = user_reg_map_name_to_regnum (gdbarch, "fd0", -1);
    }

  /* Add NDS32 register aliases.  To avoid search in user register name space,
     user_reg_map_name_to_regnum is not used.  */
  maxregs = (gdbarch_num_regs (gdbarch) + gdbarch_num_pseudo_regs (gdbarch));
  for (i = 0; i < ARRAY_SIZE (nds32_register_aliases); i++)
    {
      int regnum, j;

      regnum = -1;
      /* Search register name space.  */
      for (j = 0; j < maxregs; j++)
	{
	  const char *regname = gdbarch_register_name (gdbarch, j);

	  if (regname != NULL
	      && strcmp (regname, nds32_register_aliases[i].name) == 0)
	    {
	      regnum = j;
	      break;
	    }
	}

      /* Try next alias entry if the given name can not be found in register
	 name space.  */
      if (regnum == -1)
	continue;

      user_reg_add (gdbarch, nds32_register_aliases[i].alias,
		    value_of_nds32_reg, (const void *) regnum);
    }

  nds32_add_reggroups (gdbarch);

  /* Hook in ABI-specific overrides, if they have been registered.  */
  info.tdep_info = (void *) tdesc_data;
  gdbarch_init_osabi (info, gdbarch);

  /* Override tdesc_register callbacks for system registers.  */
  set_gdbarch_register_reggroup_p (gdbarch, nds32_register_reggroup_p);

  set_gdbarch_sp_regnum (gdbarch, NDS32_SP_REGNUM);
  set_gdbarch_pc_regnum (gdbarch, NDS32_PC_REGNUM);
  set_gdbarch_unwind_sp (gdbarch, nds32_unwind_sp);
  set_gdbarch_unwind_pc (gdbarch, nds32_unwind_pc);
  set_gdbarch_stack_frame_destroyed_p (gdbarch, nds32_stack_frame_destroyed_p);
  set_gdbarch_dwarf2_reg_to_regnum (gdbarch, nds32_dwarf2_reg_to_regnum);
  set_gdbarch_register_sim_regno (gdbarch, nds32_register_sim_regno);
  set_gdbarch_push_dummy_call (gdbarch, nds32_push_dummy_call);
  set_gdbarch_return_value (gdbarch, nds32_return_value);
  set_gdbarch_skip_prologue (gdbarch, nds32_skip_prologue);
  set_gdbarch_inner_than (gdbarch, core_addr_lessthan);
  set_gdbarch_breakpoint_from_pc (gdbarch, nds32_breakpoint_from_pc);

  set_gdbarch_frame_align (gdbarch, nds32_frame_align);
  frame_base_set_default (gdbarch, &nds32_frame_base);

  /* Methods for saving / extracting a dummy frame's ID.
     The ID's stack address must match the SP value returned by
     PUSH_DUMMY_CALL, and saved by generic_save_dummy_frame_tos.  */
  set_gdbarch_dummy_id (gdbarch, nds32_dummy_id);
  set_gdbarch_print_insn (gdbarch, gdb_print_insn_nds32);
  /* Support simple overlay manager.  */
  set_gdbarch_overlay_update (gdbarch, nds32_simple_overlay_update);

  /* Handle longjmp.  */
  set_gdbarch_get_longjmp_target (gdbarch, nds32_get_longjmp_target);

  /* The order of appending is the order it check frame.  */
  frame_unwind_append_unwinder (gdbarch, &nds32_epilogue_frame_unwind);
  dwarf2_append_unwinders (gdbarch);
  frame_unwind_append_unwinder (gdbarch, &nds32_frame_unwind);
  frame_base_append_sniffer (gdbarch, dwarf2_frame_base_sniffer);

  return gdbarch;
}

void
_initialize_nds32_tdep (void)
{
  /* Initialize gdbarch.  */
  register_gdbarch_init (bfd_arch_nds32, nds32_gdbarch_init);

  initialize_tdesc_nds32 ();
  nds32_init_reggroups ();

  register_remote_support_xml ("nds32");
}
