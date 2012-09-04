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

#include <assert.h>
#include <stdint.h>

#include "defs.h"
#include "frame.h"
#include "frame-unwind.h"
#include "frame-base.h"
#include "symtab.h"
#include "gdbtypes.h"
#include "gdbcmd.h"
#include "gdbcore.h"
#include "gdb_string.h"
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
#include "sim-regno.h"

#include "nds32-tdep.h"
#include "nds32-utils.h"
#include "nds32-remote.h"
#include "elf/nds32.h"
#include "opcode/nds32.h"
#include "features/nds32.c"
#include "features/nds32-sim.c"

/* Simple macro for chop LSB immediate bits from an instruction.  */
#define CHOP_BITS(insn, n)	(insn & ~__MASK (n))

extern void _initialize_nds32_tdep (void);

struct nds32_gdb_config nds32_config;

/* The standard register names.  */
static char *nds32_regnames[] =
{
  /* 32 GPRs.  */
  "r0", "r1", "r2", "r3",
  "r4", "r5", "r6", "r7",
  "r8", "r9", "r10", "r11",
  "r12", "r13", "r14", "r15",
  "r16", "r17", "r18", "r19",
  "r20", "r21", "r22", "r23",
  "r24", "r25", "r26", "r27",
  "fp", "gp", "lp", "sp",
  /* USR : 5 */
  "pc",
  "d0lo", "d0hi", "d1lo", "d1hi",
};

static char *nds32_fpu_regnames[] = {
  /* 64 + 2 FPRs.  */
  "fpcfg", "fpcsr",
  "fs0", "fs1", "fs2", "fs3", "fs4", "fs5", "fs6", "fs7", "fs8", "fs9",
  "fs10", "fs11", "fs12", "fs13", "fs14", "fs15",
  "fs16", "fs17", "fs18", "fs19", "fs20", "fs21", "fs22", "fs23", "fs24",
  "fs25", "fs26", "fs27", "fs28", "fs29", "fs30", "fs31",
  "fd0", "fd1", "fd2", "fd3", "fd4", "fd5", "fd6", "fd7", "fd8", "fd9",
  "fd10", "fd11", "fd12", "fd13", "fd14", "fd15",
  "fd16", "fd17", "fd18", "fd19", "fd20", "fd21", "fd22", "fd23", "fd24",
  "fd25", "fd26", "fd27", "fd28", "fd29", "fd30", "fd31"
};

/* Mnemonic names for registers.  */
struct nds32_register_alias
{
  const char *name;
  const char *alias;
};

/* Register alias for user_reg_map_name_to_regnum ().  */
struct nds32_register_alias nds32_register_aliases[] =
{
  {"r15", "ta"},
  {"r26", "p0"},
  {"r27", "p1"},
  {"fp", "r28"},
  {"gp", "r29"},
  {"lp", "r30"},
  {"sp", "r31"},

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

  {"cr0", "cpu_ver"},
  {"cr1", "icm_cfg"},
  {"cr2", "dcm_cfg"},
  {"cr3", "mmu_cfg"},
  {"cr4", "msc_cfg"},
  {"cr5", "core_id"},
  {"cr6", "fucop_exist"},

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

  {"pfr0", "pfmc0"},
  {"pfr1", "pfmc1"},
  {"pfr2", "pfmc2"},
  {"pfr3", "pfm_ctl"},

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
};

/* Get the values of register alias for user_reg_map_name_to_regnum ().  */

static struct value *
nds32_value_of_reg (struct frame_info *frame, const void *baton)
{
  struct gdbarch *gdbarch = get_frame_arch (frame);

  return value_of_register ((int) baton, frame);
}

/* Swap byte orders.  */

static inline void
swapbytes (unsigned char *buf, int len)
{
  char t;
  register int i, j;

  i = 0;
  j = len - 1;
  while (i < j)
    {
      t = buf[i];
      buf[i] = buf[j];
      buf[j] = t;
      i++;
      j--;
    }
}

/* nib to hex.  */

static int
tohex (int nib)
{
  if (nib < 10)
    return '0' + nib;
  else
    return 'a' + nib - 10;
}

/* Implement the gdbarch_frame_align method.  */

static CORE_ADDR
nds32_frame_align (struct gdbarch *gdbarch, CORE_ADDR sp)
{
  /* 8-byte aligned.  */
  return sp & ~(8 - 1);
}

/* Implement the gdbarch_breakpoint_from_pc method.  */

static const gdb_byte *
nds32_breakpoint_from_pc (struct gdbarch *gdbarch, CORE_ADDR *pcptr,
			  int *lenptr)
{
  static const gdb_byte NDS32_BREAK16[] = { 0xEA, 0x00 };
  const unsigned char *bp;

  gdb_assert (pcptr);
  gdb_assert (lenptr);

  if ((*pcptr) & 1)
    error (_("Bad address %p for inserting breakpoint.\n"
	     "Address must be at least 2-byte aligned."), (void *) *pcptr);

  /* Always insert 16-bit break instruction.  */
  *lenptr = 2;
  return NDS32_BREAK16;
}

/* Implement the gdbarch_dwarf2_reg_to_regnum method.
   Map DWARF regnum from GCC to GDB regnum.  */

static int
nds32_dwarf_dwarf2_reg_to_regnum (struct gdbarch *gdbarch, int num)
{
  /* R0 - R31 */
  if (num >= 0 && num < 32)
    return num;
  else if (num >= 34 && num < 34 + 4)
    return num - 34 + NDS32_D0LO_REGNUM;
  else if (num >= 38 && num < 38 + 64)
    return num - 38 + NDS32_FS0_REGNUM;

  /* No match, return a inaccessible register number.  */
  return gdbarch_num_regs (gdbarch) + gdbarch_num_pseudo_regs (gdbarch);
}

static int
nds32_register_sim_regno (struct gdbarch *gdbarch, int regnum)
{
  /* Use target-descriptions for register mapping. */

  /* Only makes sense to supply raw registers.  */
  gdb_assert (regnum >= 0 && regnum < gdbarch_num_regs (gdbarch));

  /* It should have a non-empty name. */
  if (gdbarch_register_name (gdbarch, regnum) != NULL
      && gdbarch_register_name (gdbarch, regnum)[0] != '\0')
    return gdbarch_remote_register_number (gdbarch, regnum);
  else
    return LEGACY_SIM_REGNO_IGNORE;
}

/* Create types for registers and insert them to type table by name.  */

static void
nds32_alloc_types (struct gdbarch *gdbarch)
{
  const struct builtin_type *bt = builtin_type (gdbarch);
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  struct type *type, *stype1, *stype2;

  tdep->type_tab = nds32_alloc_type_tab (24);

  /* fucpr */
  type = arch_flags_type (gdbarch, "builtin_type_nds32_fucpr", 4);
  append_flags_type_flag (type, 0, "CP0EN");
  append_flags_type_flag (type, 1, "CP1EN");
  append_flags_type_flag (type, 2, "CP2EN");
  append_flags_type_flag (type, 3, "CP3EN");
  append_flags_type_flag (type, 31, "AUEN");
  nds32_type_insert (tdep->type_tab, "fucpr", type);

  /* fpcfg */
  type = nds32_init_enum (gdbarch, "builtin_type_nds32_fpcfg");
  nds32_append_enum (type, 0, "8SP_4DP");
  nds32_append_enum (type, 1, "16SP_8DP");
  nds32_append_enum (type, 2, "32SP_16DP");
  nds32_append_enum (type, 3, "32SP_32DP");
  stype1 = type;

  type = nds32_init_type (gdbarch, "builtin_fpcfg_type", USE_FLAGS);
  nds32_append_flag (type, 0, "SP");
  nds32_append_flag (type, 1, "DP");
  nds32_append_bitfield (type, stype1, 2, 3, "FREG");
  nds32_append_flag (type, 4, "FMA");
  nds32_append_bitfield (type, bt->builtin_uint8, 22, 26, "IMVER");
  nds32_append_bitfield (type, bt->builtin_uint8, 27, 31, "AVER");
  nds32_type_insert (tdep->type_tab, "fpcfg", type);

  /* fpcsr */
  type = nds32_init_enum (gdbarch, "builtin_type_nds32_fpcsr_rm");
  nds32_append_enum (type, 0, "RTNE");
  nds32_append_enum (type, 1, "RTPI");
  nds32_append_enum (type, 2, "RTMI");
  nds32_append_enum (type, 3, "RTZ");
  stype1 = type;

  type = nds32_init_type (gdbarch, "builtin_type_nds32_fpcsr", USE_FLAGS);
  nds32_append_bitfield (type, stype1, 0, 1, "RM");
  nds32_append_flag (type, 2, "IVO");
  nds32_append_flag (type, 3, "DBZ");
  nds32_append_flag (type, 4, "OVF");
  nds32_append_flag (type, 5, "UDF");
  nds32_append_flag (type, 6, "IEX");
  nds32_append_flag (type, 7, "IVOE");
  nds32_append_flag (type, 8, "DBZE");
  nds32_append_flag (type, 9, "OVFE");
  nds32_append_flag (type, 10, "UDFE");
  nds32_append_flag (type, 11, "IEXE");
  nds32_append_flag (type, 12, "DNZ");
  nds32_append_flag (type, 13, "IVOT");
  nds32_append_flag (type, 14, "DBZT");
  nds32_append_flag (type, 15, "OVFT");
  nds32_append_flag (type, 16, "UDFT");
  nds32_append_flag (type, 17, "IEXT");
  nds32_append_flag (type, 18, "DNIT");
  nds32_append_flag (type, 19, "RIT");
  nds32_type_insert (tdep->type_tab, "fpcsr", type);

  /* ir0 - processor status word register
     ir1 - interruption PSW register
     ir2 - previous IPSW register */
  type = nds32_init_enum (gdbarch, "builtin_type_nds32_psw_intl");
  nds32_append_enum (type, 0, "NO");
  nds32_append_enum (type, 1, "Lv1");
  nds32_append_enum (type, 2, "Lv2");
  nds32_append_enum (type, 3, "Lv3");
  stype1 = type;

  type = nds32_init_enum (gdbarch, "builtin_type_nds32_psw_pow");
  nds32_append_enum (type, 0, "User");
  nds32_append_enum (type, 1, "Superuser");
  nds32_append_enum (type, 2, "Reserved(2)");
  nds32_append_enum (type, 3, "Reserved(3)");
  stype2 = type;

  type = nds32_init_type (gdbarch, "builtin_type_nds32_psw", USE_FLAGS);
  nds32_append_flag (type, 0, "GIE");
  nds32_append_bitfield (type, stype1, 1, 2, "INTL");
  nds32_append_bitfield (type, stype2, 3, 4, "POM");
  nds32_append_flag (type, 5, "BE");
  nds32_append_flag (type, 6, "IT");
  nds32_append_flag (type, 7, "DT");
  nds32_append_flag (type, 8, "IME");
  nds32_append_flag (type, 9, "DME");
  nds32_append_flag (type, 10, "DEX");
  nds32_append_flag (type, 11, "HSS");
  nds32_append_flag (type, 12, "DRBE");
  nds32_append_flag (type, 13, "AEN");
  nds32_append_flag (type, 14, "WBNA");
  nds32_append_flag (type, 15, "IFCON");
  nds32_append_flag (type, 20, "OV");
  nds32_type_insert (tdep->type_tab, "ir0", type);
  nds32_type_insert (tdep->type_tab, "ir1", type);
  nds32_type_insert (tdep->type_tab, "ir2", type);

  /* ir3 - Interrupt Vector Base Register */
  type = nds32_init_enum (gdbarch, "builtin_type_nds32_ivb_esz");
  nds32_append_enum (type, 0, "4_byte");
  nds32_append_enum (type, 1, "16_byte");
  nds32_append_enum (type, 2, "64_byte");
  nds32_append_enum (type, 3, "256_byte");
  stype1 = type;

  type = nds32_init_type (gdbarch, "builtin_type_nds32_ivb", USE_FLAGS);
  nds32_append_flag (type, 13, "EVIC");
  nds32_append_bitfield (type, stype1, 14, 15, "ESZ");
  nds32_append_bitfield (type, bt->builtin_uint16, 16, 31, "IVBASE");
  nds32_type_insert (tdep->type_tab, "ir3", type);

  /* ir6 - Interruption Type Register
     ir7 - Previous ITYPE */
  type = nds32_init_type (gdbarch, "builtin_type_nds32_itype", USE_FLAGS);
  nds32_append_bitfield (type, bt->builtin_uint8, 0, 3, "ETYPE");
  nds32_append_flag (type, 4, "INST");
  nds32_append_bitfield (type, bt->builtin_uint16, 16, 30, "SWID");
  nds32_type_insert (tdep->type_tab, "ir6", type);
  nds32_type_insert (tdep->type_tab, "ir7", type);

  /* ir14 - Interruption Masking Register */
  type = arch_flags_type (gdbarch, "builtin_type_nds32_int_mask", 4);
  append_flags_type_flag (type, 0, "H0IM");
  append_flags_type_flag (type, 1, "H1IM");
  append_flags_type_flag (type, 2, "H2IM");
  append_flags_type_flag (type, 3, "H3IM");
  append_flags_type_flag (type, 4, "H4IM");
  append_flags_type_flag (type, 5, "H5IM");
  append_flags_type_flag (type, 16, "SIM");
  append_flags_type_flag (type, 29, "ALZ");
  append_flags_type_flag (type, 30, "IDIVZE");
  append_flags_type_flag (type, 31, "DSSIM");
  nds32_type_insert (tdep->type_tab, "ir14", type);

  /* ir18 - Interruption Prioirty Register */
  type = nds32_init_type (gdbarch, "builtin_type_nds32_int_pri", NO_FLAGS);
  nds32_append_bitfield (type, bt->builtin_uint8, 0, 1, "H0PRI");
  nds32_append_bitfield (type, bt->builtin_uint8, 2, 3, "H1PRI");
  nds32_append_bitfield (type, bt->builtin_uint8, 4, 5, "H2PRI");
  nds32_append_bitfield (type, bt->builtin_uint8, 6, 7, "H3PRI");
  nds32_append_bitfield (type, bt->builtin_uint8, 8, 9, "H4PRI");
  nds32_append_bitfield (type, bt->builtin_uint8, 10, 11, "H5PRI");
  nds32_append_bitfield (type, bt->builtin_uint8, 12, 13, "H6PRI");
  nds32_append_bitfield (type, bt->builtin_uint8, 14, 15, "H7PRI");
  nds32_append_bitfield (type, bt->builtin_uint8, 16, 17, "H8PRI");
  nds32_append_bitfield (type, bt->builtin_uint8, 18, 19, "H9PRI");
  nds32_append_bitfield (type, bt->builtin_uint8, 20, 21, "H10PRI");
  nds32_append_bitfield (type, bt->builtin_uint8, 22, 23, "H11PRI");
  nds32_append_bitfield (type, bt->builtin_uint8, 24, 25, "H12PRI");
  nds32_append_bitfield (type, bt->builtin_uint8, 26, 27, "H13PRI");
  nds32_append_bitfield (type, bt->builtin_uint8, 28, 29, "H14PRI");
  nds32_append_bitfield (type, bt->builtin_uint8, 30, 31, "H15PRI");
  nds32_type_insert (tdep->type_tab, "ir18", type);

  /* mr0 - MMU Control Register */
  type = nds32_init_enum (gdbarch, "builtin_type_nds32_mmuctl_ntc");
  nds32_append_enum (type, 0, "NCA_NCO");
  nds32_append_enum (type, 1, "NCA_CO");
  nds32_append_enum (type, 2, "CA_WB");
  nds32_append_enum (type, 3, "CA_WT");
  stype1 = type;

  type = nds32_init_type (gdbarch, "builtin_type_nds32_mmu_ctl", USE_FLAGS);
  nds32_append_flag (type, 0, "D");
  nds32_append_bitfield (type, stype1, 1, 2, "NTC0");
  nds32_append_bitfield (type, stype1, 3, 4, "NTC1");
  nds32_append_bitfield (type, stype1, 5, 6, "NTC2");
  nds32_append_bitfield (type, stype1, 7, 8, "NTC3");
  nds32_append_flag (type, 9, "TBALCK");
  nds32_append_flag (type, 10, "MPZIU");
  nds32_append_bitfield (type, bt->builtin_uint8, 11, 12, "NTM0");
  nds32_append_bitfield (type, bt->builtin_uint8, 13, 14, "NTM1");
  nds32_append_bitfield (type, bt->builtin_uint8, 15, 16, "NTM2");
  nds32_append_bitfield (type, bt->builtin_uint8, 17, 18, "NTM3");
  nds32_append_flag (type, 19, "DREE");
  nds32_type_insert (tdep->type_tab, "mr0", type);

  /* mr1 */
  type = nds32_init_type (gdbarch, "builtin_type_nds32_l1_pptb", USE_FLAGS);
  nds32_append_flag (type, 0, "NV");
  nds32_append_bitfield (type, bt->builtin_uint32, 12, 31, "L1_PPT_BASE");
  nds32_type_insert (tdep->type_tab, "mr1", type);

  /* mr2 */
  type = nds32_init_type (gdbarch, "builtin_type_nds32_tlb_vpn", NO_FLAGS);
  nds32_append_bitfield (type, bt->builtin_uint32, 12, 31, "VPN");
  nds32_type_insert (tdep->type_tab, "mr2", type);

  /* mr3 */
  type = nds32_init_type (gdbarch, "builtin_type_nds32_tlb_data", USE_FLAGS);
  nds32_append_flag (type, 0, "V");
  nds32_append_bitfield (type, bt->builtin_uint8, 1, 3, "M");
  nds32_append_flag (type, 4, "D");
  nds32_append_flag (type, 5, "X");
  nds32_append_flag (type, 6, "A");
  nds32_append_flag (type, 7, "G");
  nds32_append_bitfield (type, bt->builtin_uint8, 8, 10, "C");
  nds32_append_bitfield (type, bt->builtin_uint32, 12, 31, "PPN");
  nds32_type_insert (tdep->type_tab, "mr3", type);

  /* mr4 - TLB Access Misc Register */
  type = nds32_init_enum (gdbarch, "builtin_type_nds32_tlb_misc_acc_psz");
  nds32_append_enum (type, 0, "4KB");
  nds32_append_enum (type, 1, "8KB");
  nds32_append_enum (type, 2, "16KB");
  nds32_append_enum (type, 3, "64KB");
  nds32_append_enum (type, 4, "256KB");
  nds32_append_enum (type, 5, "1MB");
  nds32_append_enum (type, 6, "4MB");
  nds32_append_enum (type, 7, "16MB");
  nds32_append_enum (type, 8, "64MB");
  nds32_append_enum (type, 9, "256MB");
  stype1 = type;

  type = nds32_init_type (gdbarch, "builtin_type_nds32_tlb_misc", NO_FLAGS);
  nds32_append_bitfield (type, stype1, 0, 3, "ACC_PSZ");
  nds32_append_bitfield (type, bt->builtin_uint32, 4, 12, "CID");
  nds32_type_insert (tdep->type_tab, "mr4", type);

  /* mr6 */
  type = nds32_init_enum (gdbarch, "builtin_type_nds32_ilm_size");
  nds32_append_enum (type, 0, "4KB");
  nds32_append_enum (type, 1, "8KB");
  nds32_append_enum (type, 2, "16KB");
  nds32_append_enum (type, 3, "32KB");
  nds32_append_enum (type, 4, "64KB");
  nds32_append_enum (type, 5, "128KB");
  nds32_append_enum (type, 6, "256KB");
  nds32_append_enum (type, 7, "512KB");
  nds32_append_enum (type, 8, "1024KB");
  nds32_append_enum (type, 9, "1KB");
  nds32_append_enum (type, 10, "2KB");
  nds32_append_enum (type, 15, "0KB");
  stype1 = type;

  type = nds32_init_type (gdbarch, "builtin_type_nds32_ilmb", NO_FLAGS);
  nds32_append_bitfield (type, bt->builtin_uint8, 0, 0, "IEN");
  nds32_append_bitfield (type, stype1, 1, 4, "ILMSZ");
  nds32_append_bitfield (type, bt->builtin_data_ptr, 0, 31, "(raw)");
  nds32_type_insert (tdep->type_tab, "mr6", type);

  /* mr7 */
  type = nds32_init_enum (gdbarch, "builtin_type_nds32_dlm_size");
  nds32_append_enum (type, 0, "4KB");
  nds32_append_enum (type, 1, "8KB");
  nds32_append_enum (type, 2, "16KB");
  nds32_append_enum (type, 3, "32KB");
  nds32_append_enum (type, 4, "64KB");
  nds32_append_enum (type, 5, "128KB");
  nds32_append_enum (type, 6, "256KB");
  nds32_append_enum (type, 7, "512KB");
  nds32_append_enum (type, 8, "1024KB");
  nds32_append_enum (type, 9, "1KB");
  nds32_append_enum (type, 10, "2KB");
  nds32_append_enum (type, 15, "0KB");
  stype1 = type;

  type = nds32_init_type (gdbarch, "builtin_type_nds32_dlmb", NO_FLAGS);
  nds32_append_bitfield (type, bt->builtin_uint8, 0, 0, "DEN");
  nds32_append_bitfield (type, stype1, 1, 4, "DLMSZ");
  nds32_append_bitfield (type, bt->builtin_uint8, 5, 5, "DBM");
  nds32_append_bitfield (type, bt->builtin_uint8, 6, 6, "DBB");
  nds32_append_bitfield (type, bt->builtin_data_ptr, 0, 31, "(raw)");
  nds32_type_insert (tdep->type_tab, "mr7", type);

  /* mr8 - Cache Control Register */
  type = arch_flags_type (gdbarch, "builtin_type_nds32_cache_ctl", 4);
  append_flags_type_flag (type, 0, "IC_EN");
  append_flags_type_flag (type, 1, "DC_EN");
  append_flags_type_flag (type, 2, "ICALCK");
  append_flags_type_flag (type, 3, "DCALCK");
  append_flags_type_flag (type, 4, "DCCWF");
  append_flags_type_flag (type, 5, "DCPMW");
  nds32_type_insert (tdep->type_tab, "mr8", type);

  /* dr40 - EDM Configuration Register */
  type = nds32_init_type (gdbarch, "builtin_type_nds32_edm_cfg", USE_FLAGS);
  nds32_append_bitfield (type, bt->builtin_uint8, 0, 2, "BC");
  nds32_append_flag (type, 3, "DIMU");
  nds32_append_flag (type, 4, "DALM");
  nds32_append_bitfield (type, bt->builtin_uint16, 16, 31, "VER");
  nds32_type_insert (tdep->type_tab, "dr40", type);

  /* dmar0 - DMA Configuration Register */
  type = nds32_init_type (gdbarch, "builtin_type_nds32_dma_cfg", USE_FLAGS);
  nds32_append_bitfield (type, bt->builtin_uint8, 0, 1, "NCHN");
  nds32_append_flag (type, 2, "UNEA");
  nds32_append_flag (type, 3, "2DET");
  nds32_append_bitfield (type, bt->builtin_uint16, 16, 31, "VER");
  nds32_type_insert (tdep->type_tab, "dmar0", type);

  /* cr0 - CPU Version Register */
  type = arch_flags_type (gdbarch, "builtin_type_nds32_cpuver_cfgid", 2);
  append_flags_type_flag (type, 0, "PERF_EXT");
  append_flags_type_flag (type, 1, "16_EXT");
  append_flags_type_flag (type, 2, "PERF_EXT2");
  append_flags_type_flag (type, 3, "COP_EXT");
  append_flags_type_flag (type, 4, "STR_EXT");
  stype1 = type;

  type = nds32_init_enum (gdbarch, "builtin_type_nds32_cpuver_cpuid");
  nds32_append_enum (type, 0x8, "N8");
  nds32_append_enum (type, 0x9, "N9");
  nds32_append_enum (type, 0xA, "N10");
  nds32_append_enum (type, 0xC, "N12");
  nds32_append_enum (type, 0xD, "N13");
  nds32_append_enum (type, 0xE, "N14");
  stype2 = type;

  type = nds32_init_type (gdbarch, "builtin_type_nds32_cpuver", NO_FLAGS);
  nds32_append_bitfield (type, stype1, 0, 15, "CFGID");
  nds32_append_bitfield (type, bt->builtin_uint8, 16, 23, "REV");
  nds32_append_bitfield (type, stype2, 24, 31, "CPUID");
  nds32_type_insert (tdep->type_tab, "cr0", type);

  /* cr4 - Misc Configuration Register */
  type = nds32_init_type (gdbarch, "builtin_type_nds32_msc_cfg", USE_FLAGS);
  nds32_append_flag (type, 0, "EDM");
  nds32_append_flag (type, 1, "LMDMA");
  nds32_append_flag (type, 2, "PFM");
  nds32_append_flag (type, 3, "HSMP");
  nds32_append_flag (type, 4, "TRACE");
  nds32_append_flag (type, 5, "DIV");
  nds32_append_flag (type, 6, "MAC");
  nds32_append_bitfield (type, bt->builtin_uint8, 7, 8, "AUDIO");
  nds32_append_flag (type, 9, "L2c");
  nds32_append_flag (type, 10, "RDREG");
  nds32_append_flag (type, 11, "ADR24");
  nds32_append_flag (type, 12, "INTLC");
  nds32_append_bitfield (type, bt->builtin_uint8, 13, 15, "BASEV");
  nds32_append_flag (type, 16, "NOD");
  nds32_append_flag (type, 17, "IMV");
  nds32_append_flag (type, 18, "IMR");
  nds32_append_flag (type, 19, "IFC");
  nds32_append_flag (type, 20, "MCU");
  nds32_type_insert (tdep->type_tab, "cr4", type);

  /* cr6 - FPU and Coprocessor Existence Configuration Register */
  type = arch_flags_type (gdbarch, "builtin_type_nds32_fucop_exist", 4);
  append_flags_type_flag (type, 0, "CP0EX");
  append_flags_type_flag (type, 1, "CP1EX");
  append_flags_type_flag (type, 2, "CP2EX");
  append_flags_type_flag (type, 3, "CP3EX");
  append_flags_type_flag (type, 31, "AUEX");
  nds32_type_insert (tdep->type_tab, "cr6", type);
}

static struct type *
nds32_types (struct gdbarch *gdbarch, const char *reg_name)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  if (reg_name == NULL || reg_name[0] == '\0')
    return NULL;

  /* lookup the list for reg_name */
  if (tdep->type_tab == NULL)
    nds32_alloc_types (gdbarch);

  return nds32_type_lookup (tdep->type_tab, reg_name);
}

/* Implement the gdbarch_register_type method.

   Return the GDB type object for the "standard" data type
   of data in register N.
   It get pretty messy here. I need enum-types and bit-fields
   for better representation. But they cannot be done by
   tdesc-xml.  */

static struct type *
nds32_register_type (struct gdbarch *gdbarch, int reg_nr)
{
  const struct builtin_type *bt = builtin_type (gdbarch);
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  struct type *type;

  if (reg_nr == NDS32_PC_REGNUM || reg_nr == NDS32_LP_REGNUM)
    return bt->builtin_func_ptr;
  else if (reg_nr == NDS32_SP_REGNUM || reg_nr == NDS32_FP_REGNUM)
    return bt->builtin_data_ptr;
  else if ((reg_nr >= NDS32_FS0_REGNUM)
	   && (reg_nr < NDS32_FS0_REGNUM + tdep->nds32_fpu_sp_num))
    return bt->builtin_float;
  else if ((reg_nr >= NDS32_FD0_REGNUM)
	   && (reg_nr < NDS32_FD0_REGNUM + tdep->nds32_fpu_dp_num))
    return bt->builtin_double;
  else if (reg_nr >= NDS32_R0_REGNUM && reg_nr <= NDS32_R0_REGNUM + 27)
    return tdesc_register_type (gdbarch, reg_nr);

  type = nds32_types (gdbarch, user_reg_map_regnum_to_name (gdbarch, reg_nr));
  if (type)
    return type;
  return tdesc_register_type (gdbarch, reg_nr);
}

/* nds32 register groups.  */
static struct reggroup *nds32_cr_reggroup;
static struct reggroup *nds32_ir_reggroup;
static struct reggroup *nds32_mr_reggroup;
static struct reggroup *nds32_dr_reggroup;
static struct reggroup *nds32_pfr_reggroup;
static struct reggroup *nds32_dmar_reggroup;
static struct reggroup *nds32_racr_reggroup;
static struct reggroup *nds32_idr_reggroup;
static struct reggroup *nds32_audio_reggroup;

static void
nds32_init_reggroups (void)
{
  /* gpr usr sr */
  nds32_cr_reggroup = reggroup_new ("cr", USER_REGGROUP);
  nds32_ir_reggroup = reggroup_new ("ir", USER_REGGROUP);
  nds32_mr_reggroup = reggroup_new ("mr", USER_REGGROUP);
  nds32_dr_reggroup = reggroup_new ("dr", USER_REGGROUP);
  nds32_pfr_reggroup = reggroup_new ("pfr", USER_REGGROUP);
  nds32_dmar_reggroup = reggroup_new ("dmar", USER_REGGROUP);
  nds32_racr_reggroup = reggroup_new ("racr", USER_REGGROUP);
  nds32_idr_reggroup = reggroup_new ("idr", USER_REGGROUP);

  nds32_audio_reggroup = reggroup_new ("audio", USER_REGGROUP);
}

static void
nds32_add_reggroups (struct gdbarch *gdbarch)
{
  /* Target-independent groups.  */
  reggroup_add (gdbarch, general_reggroup);
  reggroup_add (gdbarch, float_reggroup);
  reggroup_add (gdbarch, all_reggroup);
  reggroup_add (gdbarch, system_reggroup);

  /* System register groups.  */
  reggroup_add (gdbarch, nds32_cr_reggroup);
  reggroup_add (gdbarch, nds32_ir_reggroup);
  reggroup_add (gdbarch, nds32_mr_reggroup);
  reggroup_add (gdbarch, nds32_dr_reggroup);
  reggroup_add (gdbarch, nds32_pfr_reggroup);
  reggroup_add (gdbarch, nds32_dmar_reggroup);
  reggroup_add (gdbarch, nds32_racr_reggroup);
  reggroup_add (gdbarch, nds32_idr_reggroup);
}

/* Implement the gdbarch_register_reggroup_p method.  */

static int
nds32_register_reggroup_p (struct gdbarch *gdbarch, int regnum,
			   struct reggroup *group)
{
  int i;
  struct reggroup *groups[] =
  {
      nds32_cr_reggroup, nds32_ir_reggroup, nds32_mr_reggroup,
      nds32_dr_reggroup, nds32_pfr_reggroup, nds32_dmar_reggroup,
      nds32_racr_reggroup, nds32_idr_reggroup
  };
  static const char *prefix[] =
  {
      "cr", "ir", "mr", "dr", "pfr", "dmar", "racr", "idr"
  };

  gdb_assert (sizeof (groups) == sizeof (prefix));

  /* GPRs. */
  if (group == general_reggroup)
    return regnum <= NDS32_PC_REGNUM;

  /* System Registers are grouped by prefix.  */
  else if (group == system_reggroup)
    return (regnum > NDS32_PC_REGNUM)
	   && TYPE_CODE (register_type (gdbarch, regnum)) != TYPE_CODE_FLT;

  for (i = 0; i < ARRAY_SIZE (groups); i++)
    {
      if (group == groups[i])
	{
	  const char *regname = tdesc_register_name (gdbarch, regnum);

	  if (!regname)
	    return 0;
	  return strstr (regname, prefix[i]) == regname;
	}
    }

  return default_register_reggroup_p (gdbarch, regnum, group);
}

static enum register_status
nds32_remote_mfcp (struct gdbarch *gdbarch, int cpid, int fsa, int f14_10,
		   int f9_8, int len, gdb_byte *buf)
{
  struct ui_file *res;
  struct ui_file_buffer ui_buf;
  char cmd[128];
  struct cleanup *back_to;

  /* Cole Jan. 7th 2011
     the arguments used in Rcmd is quiet not straight forward.
	monitor mfcp (word|double) $arg0 $arg1

     When access sp/dr,
     word or double determine field 9-5 for SR(0000) or DR (0001),
     and fsa determine which fp register.
     Correspond to arg0 and arg1, arg0 is composited from 19-15 (FSa),
     14-10(00000), and field 9-6. arg1 should be cp0 for FPu.

     When access FPCFR and CPCSR, field 9-5 should be XR (1100),
     so field89 would be 0x3.  And 14-10 should be CFR (00000)
     or CSR (00001).  */

  res = mem_fileopen ();
  gdb_assert ((fsa & ~0x1F) == 0);
  gdb_assert ((f14_10 & ~0x1F) == 0);
  gdb_assert ((f9_8 & ~0x3) == 0);

  res = mem_fileopen ();
  ui_file_buffer_init (&ui_buf, 16);

  sprintf (cmd, "mfcp %s %d 0x%x", (len == 4) ? "word" : "double", cpid,
	   (fsa << 7) | (f14_10 << 2) | f9_8);
  target_rcmd (cmd, res);

  /* Copy the result to buffer.  */
  /* FIXME: Handle buffer overflow.  */
  ui_file_put (res, do_ui_file_put_memcpy, &ui_buf);

  /* Rcmd always returns big-endian, but gdb expects target-byte-order.  */
  if (gdbarch_byte_order (gdbarch) == BFD_ENDIAN_LITTLE)
    swapbytes (ui_buf.buf, len);
  memcpy (buf, ui_buf.buf, len);

  ui_file_delete (res);
  free_ui_file_buffer (&ui_buf);

  return REG_VALID;
}

static enum register_status
nds32_remote_mtcp (struct gdbarch *gdbarch, int cpid, int fsa, int f14_10,
		   int f9_8, int len, const gdb_byte *buf)
{
  struct ui_file *res = mem_fileopen ();
  char cmd[64];
  char value[17] = { 0 };	/* 1 for tailing \0.  */
  unsigned char tmp[8];		/* 8 bytes for double at most.  */
  int i;

  gdb_assert ((fsa & ~0x1F) == 0);
  gdb_assert ((f14_10 & ~0x1F) == 0);
  gdb_assert ((f9_8 & ~0x3) == 0);

  /* Rcmd wants big-endian */
  memcpy (tmp, buf, len);
  if (gdbarch_byte_order (gdbarch) == BFD_ENDIAN_LITTLE)
    swapbytes (tmp, len);

  for (i = 0; i < len; i++)
    {
      value[(i << 1)] = tohex ((tmp[i] >> 4) & 0xF);
      value[(i << 1) + 1] = tohex (tmp[i] & 0xF);
    }

  sprintf (cmd, "mtcp %s %d 0x%x 0x%s",
	   (len == 4) ? "word" : "double", cpid,
	   (fsa << 7) | (f14_10 << 2) | f9_8, value);
  target_rcmd (cmd, res);

  return REG_VALID;
}

/* Implement the tdesc_pseudo_register_name method.  */

static const char *
nds32_pseudo_register_name (struct gdbarch *gdbarch, int regnum)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  ULONGEST fucpr = 0;

  if (regnum > gdbarch_num_regs (gdbarch) + gdbarch_num_pseudo_regs (gdbarch))
    return NULL;

  /* Target doesn't support tdesc, default is used.  */
  gdb_assert (tdep->tdesc == tdesc_nds32);

  if (regnum >= NDS32_FS0_REGNUM && regnum < NDS32_FS0_REGNUM + 32)
    {
      if (regnum < NDS32_FS0_REGNUM + tdep->nds32_fpu_sp_num)
	return nds32_fpu_regnames[regnum - NDS32_FPU_REGNUM];
    }
  else if (regnum >= NDS32_FD0_REGNUM && regnum < NDS32_FD0_REGNUM + 32)
    {
      if (regnum < NDS32_FD0_REGNUM + tdep->nds32_fpu_dp_num)
	return nds32_fpu_regnames[regnum - NDS32_FPU_REGNUM];
    }
  else if ((regnum >= NDS32_FPU_REGNUM)
	   && (regnum < NDS32_FPU_REGNUM + ARRAY_SIZE (nds32_fpu_regnames)))
    {
      return nds32_fpu_regnames[regnum - NDS32_FPU_REGNUM];
    }

  return NULL;
}

/* Implement the tdesc_pseudo_register_type method.  */

static struct type *
nds32_pseudo_register_type (struct gdbarch *gdbarch, int regnum)
{
  if (regnum == NDS32_FPCSR_REGNUM)
    return builtin_type (gdbarch)->builtin_data_ptr;
  if (regnum == NDS32_FPCFG_REGNUM)
    return builtin_type (gdbarch)->builtin_data_ptr;
  if (regnum >= NDS32_FS0_REGNUM && regnum < NDS32_FS0_REGNUM + 32)
    return builtin_type (gdbarch)->builtin_float;
  if (regnum >= NDS32_FD0_REGNUM && regnum < NDS32_FD0_REGNUM + 32)
    return builtin_type (gdbarch)->builtin_double;

  return NULL;
}

/* Implement the gdbarch_pseudo_register_read method.

   For legacy target, target-description and FPRs are not support.
   Use Rcmd to access FPU registers.  */

static enum register_status
nds32_pseudo_register_read (struct gdbarch *gdbarch,
			    struct regcache *regcache, int regnum,
			    gdb_byte *buf)
{
  if (regnum >= NDS32_FD0_REGNUM)
    {
      regnum = ((regnum - NDS32_FD0_REGNUM) << 1) + NDS32_FS0_REGNUM;
      if (gdbarch_byte_order (gdbarch) == BFD_ENDIAN_LITTLE)
	{
	  nds32_pseudo_register_read (gdbarch, regcache, regnum, buf + 4);
	  nds32_pseudo_register_read (gdbarch, regcache, regnum + 1, buf);
	}
      else
	{
	  nds32_pseudo_register_read (gdbarch, regcache, regnum, buf);
	  nds32_pseudo_register_read (gdbarch, regcache, regnum + 1, buf + 4);
	}
      return REG_VALID;
    }

  if (regnum >= NDS32_FS0_REGNUM && regnum < NDS32_FS0_REGNUM + 64)
    nds32_remote_mfcp (gdbarch, 0, (regnum - NDS32_FS0_REGNUM) % 32, 0, 0,
		       register_size (gdbarch, regnum), buf);
  else if (regnum >= NDS32_FPU_REGNUM)
    nds32_remote_mfcp (gdbarch, 0, 0, regnum - NDS32_FPU_REGNUM, 0x3,
		       register_size (gdbarch, regnum), buf);
      return REG_VALID;
}

/* Implement the gdbarch_pseudo_register_write method.  */

static void
nds32_pseudo_register_write (struct gdbarch *gdbarch,
			     struct regcache *regcache, int regnum,
			     const gdb_byte *buf)
{
  if (regnum >= NDS32_FD0_REGNUM)
    {
      regnum = ((regnum - NDS32_FD0_REGNUM) << 1) + NDS32_FS0_REGNUM;
      if (gdbarch_byte_order (gdbarch) == BFD_ENDIAN_LITTLE)
	{
	  nds32_pseudo_register_write (gdbarch, regcache, regnum, buf + 4);
	  nds32_pseudo_register_write (gdbarch, regcache, regnum + 1, buf);
	}
      else
	{
	  nds32_pseudo_register_write (gdbarch, regcache, regnum, buf);
	  nds32_pseudo_register_write (gdbarch, regcache, regnum + 1, buf + 4);
	}
      return;
    }

  if (regnum >= NDS32_FS0_REGNUM && regnum < NDS32_FS0_REGNUM + 64)
    nds32_remote_mtcp (gdbarch, 0, (regnum - NDS32_FS0_REGNUM) % 32, 0, 0,
		       register_size (gdbarch, regnum), buf);
  else if (regnum >= NDS32_FPU_REGNUM)
    nds32_remote_mtcp (gdbarch, 0, 0, regnum - NDS32_FPU_REGNUM, 0x3,
		       register_size (gdbarch, regnum), buf);
}

/* Skip prologue should be conservative, and frame-unwind should be
   relative-aggressive.*/

static int
nds32_analyze_prologue (struct gdbarch *gdbarch, CORE_ADDR pc,
			CORE_ADDR scan_limit, CORE_ADDR *pl_endptr)
{
  uint32_t insn;
  CORE_ADDR cpc = -1;		/* Candidate PC if no suitable PC is found.  */
  LONGEST return_value;

  /* If there is no buffer to store result, ignore this prologue decoding.  */
  if (pl_endptr == NULL)
    return 0;

  /* Look up end of prologue */
  for (; pc < scan_limit; )
    {
      insn = read_memory_unsigned_integer (pc, 4, BFD_ENDIAN_BIG);

      if ((insn & 0x80000000) == 0)
	{
	  /* 32-bit instruction */

	  pc += 4;
	  if (insn == N32_ALU1 (ADD, REG_GP, REG_TA, REG_GP))
	    {
	      /* add $gp, $ta, $gp */
	      continue;
	    }
	  else if (CHOP_BITS (insn, 15) == N32_TYPE2 (ADDI, REG_SP, REG_SP, 0))
	    {
	      /* addi $sp, $sp, imm15 */
	      cpc = pc;
	      continue;
	    }
	  else if (CHOP_BITS (insn, 15) == N32_TYPE2 (ADDI, REG_FP, REG_FP, 0))
	    {
	      /* addi $fp, $sp, imm15 */
	      cpc = pc;
	      continue;
	    }
	  else if (insn == N32_ALU2 (MFUSR, REG_TA, 31, 0))
	    {
	      /* mfusr $ta, PC  ; group=0, sub=0x20=mfusr */
	      continue;
	    }
	  else if (CHOP_BITS (insn, 20) == N32_TYPE1 (MOVI, REG_TA, 0))
	    {
	      /* movi $ta, imm20s */
	      continue;
	    }
	  else if (CHOP_BITS (insn, 20) == N32_TYPE1 (SETHI, REG_GP, 0))
	    {
	      /* sethi $gp, imm20 */
	      continue;
	    }
	  else if (CHOP_BITS (insn, 15) == N32_TYPE2 (ORI, REG_GP, REG_GP, 0))
	    {
	      /* ori $gp, $gp, imm15 */
	      continue;
	    }
	  else if (CHOP_BITS (insn, 15) == N32_TYPE2 (SWI, REG_LP, REG_FP, 0))
	    {
	      /* Unlike swi, we should stop when lwi.  */
	      /* swi $lp, [$sp + (imm15s<<2)] */
	      continue;
	    }
	  else if (CHOP_BITS (insn, 15) == N32_TYPE2 (SWI_BI, REG_LP, REG_FP, 0))
	    {
	      /* swi.bi $rt, [$sp], (imm15s<<2) */
	      continue;
	    }
	  else if (N32_OP6 (insn) == N32_OP6_LSMW && (insn & __BIT (5)))
	    {
	      /* bit-5 for SMW */

	      /* smwa?.(a|b)(d|i)m? rb,[ra],re,enable4 */

	      int rb, re, ra, enable4, i;
	      int aligned;
	      int m = 0;
	      int di;		/* dec=-1 or inc=1 */
	      char enb4map[2][4] = {
		  {0, 1, 2, 3} /* smw */,
		  {3, 1, 2, 0} /* smwa */};
	      LONGEST base = ~1 + 1;

	      rb = N32_RT5 (insn);
	      ra = N32_RA5 (insn);
	      re = N32_RB5 (insn);
	      enable4 = (insn >> 6) & 0x0F;
	      aligned = (insn & 3) ? 1 : 0;
	      di = (insn & (1 << 3)) ? -1 : 1;

	      switch (ra)
		{
		case NDS32_FP_REGNUM:
		case NDS32_SP_REGNUM:
		  cpc = pc;
		  continue; /* found and continue */
		default:
		  break;
		}
	    }

	  if (N32_OP6 (insn) == N32_OP6_COP && N32_COP_CP (insn) == 0
	      && (N32_COP_SUB (insn) == N32_FPU_FSS
		  || N32_COP_SUB (insn) == N32_FPU_FSD)
	      && (N32_RA5 (insn) == REG_SP || N32_RA5 (insn) == REG_FP))
	    {
	      /* CP shoud be CP0 */
	      /* fs[sd][.bi] $fst, [$sp + ($r0 << sv)] */
	      continue;
	    }

	  /* fssi    $fst, [$ra + (imm12s << 2)]
	     fssi.bi $fst, [$ra], (imm12s << 2)
	     fsdi    $fdt, [$ra + (imm12s << 2)]
	     fsdi.bi $fdt, [$ra], (imm12s << 2) */
	  if ((N32_OP6 (insn) == N32_OP6_SWC || N32_OP6 (insn) == N32_OP6_SDC)
	      && (N32_RA5 (insn) == REG_SP || N32_RA5 (insn) == REG_FP))
	    {
	      /* BI bit is dont-care.  */
	      continue;
	    }

	  pc -= 4;
	  break;
	}
      else
	{
	  /* 16-bit instruction */
	  pc += 2;
	  insn >>= 16;

	  /* 1. If the instruction is j/b, then we stop
		i.e., OP starts with 10, and beqzs8, bnezs8.
	     2. If the operations will change sp/fp or based on sp/fp,
		then we are in the prologue.
	     3. If we don't know what's it, then stop.  */

	  if (__GF (insn, 13, 2) == 2)
	    {
	      /* These are all branch instructions.  */
	      pc -= 2;
	      break;
	    }
	  else if (__GF (insn, 9, 6) == 0x34)
	    {
	      /* beqzs8, bnezs8 */
	      pc -= 2;
	      break;
	    }

	  if (CHOP_BITS (insn, 10) == N16_TYPE10 (ADDI10S, 0))
	    {
	      /* addi10s */
	      continue;
	    }
	  else if (__GF (insn, 7, 8) == N16_T25_PUSH25)
	    {
	      /* push25 */
	      continue;
	    }
	  else if (insn == N16_TYPE55 (MOV55, REG_FP, REG_SP))
	    {
	      /* mov55 fp, sp */
	      continue;
	    }

	  /* swi450 */
	  switch (insn & ~__MF (-1, 5, 4))
	    {
	      case N16_TYPE45 (SWI450, 0, REG_SP):
	      case N16_TYPE45 (SWI450, 0, REG_FP):
		break;
	    }
	  /* swi37 - implied fp */
	  if (__GF (insn, 11, 4) == N16_T37_XWI37
	      && (insn & __BIT (7)))
	    continue;

	  /* swi37sp - implied */
	  if (__GF (insn, 11, 4) == N16_T37_XWI37SP
	      && (insn & __BIT (7)))
	    continue;

	  pc -= 2;
	  break;
	}
    }

  if (pc >= scan_limit)
    {
      /* If we can not find end of prologue before scan_limit,
	 we assume that end of prologue is on pc_after_stack_adject. */
      if (cpc != -1)
	pc = cpc;
    }

  *pl_endptr = pc;

  return 0;
}

/* Implement the gdbarch_skip_prologue method.

   Find the end of function prologue.  */

static CORE_ADDR
nds32_skip_prologue (struct gdbarch *gdbarch, CORE_ADDR pc)
{
  CORE_ADDR func_addr, func_end;
  struct symtab_and_line sal = { 0 };
  LONGEST return_value;
  const char *func_name;
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  const int search_limit = 128;

  /* See what the symbol table says */
  if (find_pc_partial_function (pc, &func_name, &func_addr, &func_end))
    {
      sal = find_pc_line (func_addr, 0);

      if (sal.line != 0 && sal.end <= func_end)
	{
	  func_end = sal.end;
	}
      else
	{
	  /* Either there's no line info, or the line after the prologue
	     is after the end of the function.  In this case, there probably
	     isn't a prologue.  */
	  func_end = min (func_end, func_addr + search_limit);
	}
    }
  else
    func_end = pc + search_limit;

  /* If current instruction is not readable, just quit.  */
  if (!safe_read_memory_integer (pc, 4, byte_order, &return_value))
    return pc;

  /* Find the end of prologue.  */
  if (nds32_analyze_prologue (gdbarch, pc, func_end, &sal.end) < 0)
    return pc;

  return sal.end;
}

struct nds32_unwind_cache
{
  /* The previous frame's inner most stack address.
     Used as this frame ID's stack_addr.  */
  CORE_ADDR prev_sp;

  /* The frame's base, optionally used by the high-level debug info.  */
  CORE_ADDR base;
  int size;

  /* How far the SP and FP have been offset from the start of
     the stack frame (as defined by the previous frame's stack
     pointer).  */
  LONGEST sp_offset;
  LONGEST fp_offset;
  int use_frame;

  /* Table indicating the location of each and every register.  */
  struct trad_frame_saved_reg *saved_regs;
};

static struct nds32_unwind_cache *
nds32_alloc_frame_cache (struct frame_info *this_frame)
{
  struct nds32_unwind_cache *cache;
  cache = FRAME_OBSTACK_ZALLOC (struct nds32_unwind_cache);

  cache->saved_regs = trad_frame_alloc_saved_regs (this_frame);
  cache->size = 0;
  cache->sp_offset = 0;
  cache->fp_offset = 0;
  cache->use_frame = 0;
  cache->base = 0;

  return cache;
}

/* Implement the gdbarch_in_function_epilogue_p method.  */

static int
nds32_in_function_epilogue_p (struct gdbarch *gdbarch, CORE_ADDR addr)
{
  uint32_t insn;
  int r = 0;

  insn = read_memory_unsigned_integer (addr, 4, BFD_ENDIAN_BIG);
  if ((insn & 0x80000000) == 0)
    {
      /* 32-bit instruction */

      /* ret */
      if (insn == N32_JREG (JR, 0, REG_LP, 0, 1))
	r = 1;
      /* iret */
      else if (insn == N32_TYPE0 (MISC, N32_MISC_IRET))
	r = 2;
    }
  else
    {
      if (insn == N16_TYPE5 (RET5, REG_LP))
	r = 3;
    }
  return r > 0;
}

/* Put here the code to store, into fi->saved_regs, the addresses of
   the saved registers of frame described by FRAME_INFO.  This
   includes special registers such as pc and fp saved in special ways
   in the stack frame.  sp is even more special: the address we return
   for it IS the sp for the next frame.  */

static struct nds32_unwind_cache *
nds32_frame_unwind_cache (struct frame_info *this_frame,
			  void **this_prologue_cache)
{
  CORE_ADDR pc, scan_limit;
  ULONGEST prev_sp;
  ULONGEST next_base;
  ULONGEST fp_base;
  int i;
  uint32_t insn;
  struct nds32_unwind_cache *info;
  struct gdbarch *gdbarch = get_frame_arch (this_frame);

  if ((*this_prologue_cache))
    return (*this_prologue_cache);

  info = nds32_alloc_frame_cache (this_frame);

  info->base = get_frame_register_unsigned (this_frame, NDS32_FP_REGNUM);
  (*this_prologue_cache) = info;

  if (info->base == 0 && nds32_config.use_stop_zfp)
    return info;

  pc = get_frame_func (this_frame);
  scan_limit = get_frame_pc (this_frame);

  for (; pc > 0 && pc < scan_limit; )
    {
      insn = read_memory_unsigned_integer (pc, 4, BFD_ENDIAN_BIG);

      if ((insn & 0x80000000) == 0)
	{
	  /* 32-bit instruction */

	  pc += 4;
	  if (insn == N32_ALU1 (ADD, REG_GP, REG_TA, REG_GP))
	    {
	      /* add $gp, $ta, $gp */
	      continue;
	    }
	  if (N32_OP6 (insn) == N32_OP6_ADDI)
	    {
	      int rt = N32_RT5 (insn);
	      int ra = N32_RA5 (insn);
	      int imm15s = N32_IMM15S (insn);

	      if (rt == ra && rt == NDS32_SP_REGNUM)
		{
		  info->sp_offset += imm15s;
		  continue;
		}
	      else if (rt == NDS32_FP_REGNUM && ra == NDS32_SP_REGNUM)
		{
		  info->fp_offset = info->sp_offset + imm15s;
		  info->use_frame = 1;
		  continue;
		}
	      else if (rt == ra)
		/* Prevent stop analyzing form iframe.  */
		continue;
	    }

	  if (insn == N32_ALU2 (MFUSR, REG_TA, 31, 0))
	    {
	      /* mfusr $ta, PC  ; group=0, sub=0x20=mfusr */
	      continue;
	    }
	  if (CHOP_BITS (insn, 20) == N32_TYPE1 (MOVI, REG_TA, 0))
	    {
	      /* movi $ta, imm20s */
	      continue;
	    }
	  if (CHOP_BITS (insn, 20) == N32_TYPE1 (SETHI, REG_GP, 0))
	    {
	      /* sethi $gp, imm20 */
	      continue;
	    }
	  if (CHOP_BITS (insn, 15) == N32_TYPE2 (ORI, REG_GP, REG_GP, 0))
	    {
	      /* ori $gp, $gp, imm15 */
	      continue;
	    }
	  if (N32_OP6 (insn) == N32_OP6_LSMW && (insn & __BIT (5)))
	    {
	      /* smwa?.(a|b)(d|i)m? rb,[ra],re,enable4 */

	      int rb, re, ra, enable4, i;
	      int aligned;
	      int m = 0;
	      int di;	   /* dec=-1 or inc=1 */
	      char enb4map[2][4] = {
		  {0, 1, 2, 3} /* smw */,
		  {3, 1, 2, 0} /* smwa */ };
	      LONGEST base = ~1 + 1;

	      rb = N32_RT5 (insn);
	      ra = N32_RA5 (insn);
	      re = N32_RB5 (insn);
	      enable4 = (insn >> 6) & 0x0F;
	      aligned = (insn & 3) ? 1 : 0;
	      di = (insn & (1 << 3)) ? -1 : 1;

	      /* Let's consider how Ra should update.  */
	      if (insn & (1 << 0x2))    /* m-bit is set */
		{
		  m += (enable4 & 0x1) ? 1 : 0;
		  m += (enable4 & 0x2) ? 1 : 0;
		  m += (enable4 & 0x4) ? 1 : 0;
		  m += (enable4 & 0x8) ? 1 : 0;
		  if (rb < NDS32_FP_REGNUM && re < NDS32_FP_REGNUM)
		    {
		      /* Reg-list should not include fp, gp, lp, sp
			 i.e., the rb==re==sp case, anyway... */
		      m += (re - rb) + 1;
		    }
		  m *= 4;       /* 4 * TNReg */
		}
	      else
		m = 0;	  /* don't update Ra */

	      switch (ra)
		{
		case NDS32_FP_REGNUM:
		  base = info->fp_offset;
		  info->fp_offset += m * di;
		  break;
		case NDS32_SP_REGNUM:
		  base = info->sp_offset;
		  info->sp_offset += m * di;
		  break;
		default:
		  /* sorry, only ra==sp || ra==fp is handled */
		  break;
		}
	      if (base == ~1 + 1)
		break;	  /* skip */

	      if (insn & (1 << 0x4))	/* b:0, a:1 */
		base += 4 * di;		/* a: use Ra+4 (for i),
					      or Ra-4 (for d) */
	      /* else base = base;	b use Ra */

	      /* Cole 3th Nov. 2010
		 We should consider both increasing and decreasing case.

		 Either case stores registers in the same order.
		 To simplify the code (yes, the loops),
		 I used the same pushing order, but from different side.  */

	      if (di == 1)		/* Increasing.  */
		base += (m - 4);
	      /* else, in des case, we already are on the top */

	      for (i = 0; i < 4; i++)
		{
		  if (enable4 & (1 << enb4map[aligned][i]))
		    {
		      info->saved_regs[NDS32_SP_REGNUM -
				       (enb4map[aligned][i])].addr = base;
		      base -= 4;
		    }
		}

	      /* Skip re == rb == sp > fp.  */
	      for (i = re; i >= rb && rb < NDS32_FP_REGNUM; i--)
		{
		  info->saved_regs[i].addr = base;
		  base -= 4;
		}

	      continue;
	    }
	  /* swi $lp, [$sp + (imm15s << 2)] */
	  /* We must check if $rt is $lp to determine it is
	     in prologue or not.  */
	  if (CHOP_BITS (insn, 15) == N32_TYPE2 (SWI, REG_LP, REG_FP, 0))
	    {
	      int imm15s;

	      /* swi $lp, [$sp + (imm15s<<2)] */
	      imm15s = N32_IMM15S (insn);
	      info->saved_regs[NDS32_LP_REGNUM].addr = info->sp_offset
						       + (imm15s << 2);
	      continue;
	    }
	  /* swi.bi $rt, [$sp], (imm15s << 2) */
	  if (CHOP_BITS (insn, 15) == N32_TYPE2 (SWI_BI, REG_LP, REG_FP, 0))
	    {
	      unsigned int rt5 = 0;
	      unsigned int ra5 = 0;
	      int imm15s = 0;
	      rt5 = N32_RT5 (insn);
	      ra5 = N32_RA5 (insn);
	      imm15s = N32_IMM15S (insn);

	      if (ra5 == NDS32_SP_REGNUM)
		{
		  info->saved_regs[rt5].addr = info->sp_offset;
		  info->sp_offset += (imm15s << 2);
		}
	      else if (ra5 == NDS32_FP_REGNUM)
		{
		  info->saved_regs[rt5].addr = info->fp_offset;
		  info->fp_offset += (imm15s << 2);
		}
	      continue;
	    }

	  if (N32_OP6 (insn) == N32_OP6_COP && N32_COP_CP (insn) == 0
	      && (N32_COP_SUB (insn) == N32_FPU_FSS
		  || N32_COP_SUB (insn) == N32_FPU_FSD)
	      && (N32_RA5 (insn) == REG_SP || N32_RA5 (insn) == REG_FP))
	    {
	      /* CP shoud be CP0 */
	      /* fs[sd][.bi] $fst, [$sp + ($r0 << sv)] */
	      continue;
	    }

	  /* fssi $fst, [$ra + (imm12s << 2)]
	     fssi.bi $fst, [$ra], (imm12s << 2)
	     fsdi $fdt, [$ra + (imm12s << 2)]
	     fsdi.bi $fdt, [$ra], (imm12s << 2) */
	  if ((N32_OP6 (insn) == N32_OP6_SWC || N32_OP6 (insn) == N32_OP6_SDC)
	      && (N32_RA5 (insn) == REG_SP || N32_RA5 (insn) == REG_FP))
	    {
	      /* fssi and fsdi have the same form.  */
	      /* Only .bi form should be handled to adjust reg.  */
	      unsigned int ra5 = 0;
	      unsigned int fs5 = 0;
	      int imm12s = 0;

	      fs5 = N32_RT5 (insn);
	      ra5 = N32_RA5 (insn);
	      imm12s = N32_IMM12S (insn);

	      if (imm12s & 0x800)
		imm12s = (imm12s - (0x800 << 1));

	      switch (ra5)
		{
		case NDS32_FP_REGNUM:
		  info->fp_offset += (imm12s << 2);
		  break;
		case NDS32_SP_REGNUM:
		  info->sp_offset += (imm12s << 2);
		  break;
		}

	      continue;
	    }

	  /* TODO: Handle mfsr and addi for interrupt handlers.  */
	  break;
	}
      else
	{
	  /* 16-bit instruction */
	  pc += 2;
	  insn >>= 16;

	  /* 1. If the instruction is j/b, then we stop
		i.e., OP starts with 10, and beqzs8, bnezs8.
	     2. If the operations will change sp/fp or based on sp/fp,
		then we are in the prologue.
	     3. If we don't know what's it, then stop.  */

	  if (__GF (insn, 13, 2) == 2)
	    {
	      /* These are all branch instructions.  */
	      pc -= 2;
	      break;
	    }
	  else if (__GF (insn, 9, 6) == 0x34)
	    {
	      /* beqzs8, bnezs8 */
	      pc -= 2;
	      break;
	    }

	  if (CHOP_BITS (insn, 10) == N16_TYPE10 (ADDI10S, 0))
	    {
	      /* addi10s */
	      info->sp_offset += N16_IMM10S (insn);
	      continue;
	    }

	  if (__GF (insn, 7, 8) == N16_T25_PUSH25)
	    {
	      /* push25 */
	      int imm8u = (insn & 0x1f) << 3;
	      int re = ((insn & 0x60) >> 5) & 0x3;
	      int res[] = {6, 8, 10, 14};
	      int m[] = {4, 6, 8, 12};
	      LONGEST base = info->sp_offset - 4;

	      /* Operation 1 - smw.adm R6, [sp], Re, #0xe */
	      info->saved_regs[NDS32_LP_REGNUM].addr = info->sp_offset - 0x4;
	      info->saved_regs[NDS32_GP_REGNUM].addr = info->sp_offset - 0x8;
	      info->saved_regs[NDS32_FP_REGNUM].addr = info->sp_offset - 0xC;
	      info->sp_offset -= m[re] * 4;

	      switch (re)
		{
		  case 3:
		    info->saved_regs[14].addr = info->sp_offset + 0x20;
		    info->saved_regs[13].addr = info->sp_offset + 0x1C;
		    info->saved_regs[12].addr = info->sp_offset + 0x18;
		    info->saved_regs[11].addr = info->sp_offset + 0x14;
		  case 2:
		    info->saved_regs[10].addr = info->sp_offset + 0x10;
		    info->saved_regs[9].addr = info->sp_offset + 0xC;
		  case 1:
		    info->saved_regs[8].addr = info->sp_offset + 0x8;
		    info->saved_regs[7].addr = info->sp_offset + 0x4;
		  case 0:
		    info->saved_regs[6].addr = info->sp_offset;
		}

	      /* Operation 2 - sp = sp - imm5u<<3 */
	      info->sp_offset -= imm8u;

	      /* Operation 3 - if (Re >= 1) R8 = concat (PC(31,2), 2`b0) */
	     }

	  /* mov55 fp, sp */
	  if (insn == N16_TYPE55 (MOV55, REG_FP, REG_SP))
	    {
		info->fp_offset = info->sp_offset;
		info->use_frame = 1;
		continue;
	    }
	  /* swi450 */
	  switch (insn & ~__MF (-1, 5, 4))
	    {
	      case N16_TYPE45 (SWI450, 0, REG_SP):
	      case N16_TYPE45 (SWI450, 0, REG_FP):
		break;
	    }
	  /* swi37 - implied fp */
	  if (__GF (insn, 11, 4) == N16_T37_XWI37
	      && (insn & __BIT (7)))
	    continue;

	  /* swi37sp - implied */
	  if (__GF (insn, 11, 4) == N16_T37_XWI37SP
	      && (insn & __BIT (7)))
	    continue;

	  break;
	  }
    }

  info->size = -info->sp_offset;
  /* Compute the previous frame's stack pointer (which is also the
     frame's ID's stack address), and this frame's base pointer.

     Assume that the FP is this frame's SP but with that pushed
     stack space added back.  */
  next_base = get_frame_register_unsigned (this_frame, NDS32_SP_REGNUM);
  prev_sp = next_base + info->size;
  fp_base = get_frame_register_unsigned (this_frame, NDS32_FP_REGNUM);
  if (info->use_frame && nds32_config.use_fp && fp_base > 0)
    {
      /* Try to use FP if possible. */
      prev_sp = fp_base - info->fp_offset;
    }

  /* Convert that SP/BASE into real addresses.  */
  info->prev_sp = prev_sp;
  info->base = next_base;

  /* Adjust all the saved registers so that they contain addresses and
     not offsets.  */
  for (i = 0; i < gdbarch_num_regs (gdbarch) - 1; i++)
    {
      if (trad_frame_addr_p (info->saved_regs, i))
	{
	  info->saved_regs[i].addr = info->prev_sp + info->saved_regs[i].addr;
	}
    }

  /* The previous frame's SP needed to be computed.
     Save the computed value.  */
  trad_frame_set_value (info->saved_regs, NDS32_SP_REGNUM, prev_sp);

  return info;
}

/* Implement the gdbarch_skip_permanent_breakpoint method.  */

static void
nds32_skip_permanent_breakpoint (struct regcache *regcache)
{
  int insn;
  CORE_ADDR current_pc = regcache_read_pc (regcache);

  /* On nds32, breakpoint may be BREAK or BREAK16.  */
  insn = read_memory_unsigned_integer (current_pc, 4, BFD_ENDIAN_BIG);

  /* FIXME: Review this code.  */
  if (N32_OP6 (insn) == N32_OP6_MISC && N32_SUB5 (insn) == N32_MISC_BREAK)
    current_pc += 4;
  else if (__GF (insn, 9, 6) == 35 && N16_IMM9U (insn) < 32)
    current_pc += 2;
  else
    return;

  regcache_write_pc (regcache, current_pc);
}

/* Implement the gdbarch_read_pc method.  */

static CORE_ADDR
nds32_read_pc (struct regcache *regcache)
{
  ULONGEST pc;
  regcache_cooked_read_unsigned (regcache, NDS32_PC_REGNUM, &pc);
  return pc;
}

/* Implement the gdbarch_write_pc method.  */

static void
nds32_write_pc (struct regcache *regcache, CORE_ADDR val)
{
  regcache_cooked_write_unsigned (regcache, NDS32_PC_REGNUM, val);
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

/* If these is exactly one float point type field in the struct,
   the alignment of the struct is the size of the float pointer type.  */

static int
nds32_float_in_struct (struct type *type)
{
  struct type *actual_type;

  type = check_typedef (type);
  if (TYPE_CODE (type) != TYPE_CODE_STRUCT || TYPE_NFIELDS (type) != 1)
    return 0;

  actual_type = check_typedef (TYPE_FIELD_TYPE (type, 0));
  if (TYPE_CODE (actual_type) == TYPE_CODE_FLT)
    {
      gdb_assert (TYPE_LENGTH (type) == 8 || TYPE_LENGTH (type) == 4);
      return TYPE_LENGTH (type);
    }
  return 0;
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
  int align = 0;		/* Current max alignment.  */
  int i;

  gdb_assert (type != NULL);
  if (type == NULL)
    return 0;

  if (type->main_type->nfields == 0)
    return type->length;

  switch (TYPE_CODE (type))
    {
    case TYPE_CODE_ARRAY:
      return nds32_type_align (TYPE_TARGET_TYPE (type));
    case TYPE_CODE_ENUM:
      return TYPE_LENGTH (type);
    }

  /* For structs with only one float/double are treated as float/double.  */
  align = nds32_float_in_struct (type);
  if (align)
    return align;

  for (i = 0; i < TYPE_NFIELDS (type); i++)
    {
      int r = nds32_type_align (TYPE_FIELD_TYPE (type, i));

      if (r > align)
	align = r;
    }

  return align;
}

/* Implement the gdbarch_push_dummy_call method.  */

static CORE_ADDR
nds32_push_dummy_call (struct gdbarch *gdbarch, struct value *function,
		       struct regcache *regcache, CORE_ADDR bp_addr,
		       int nargs, struct value **args, CORE_ADDR sp,
		       int struct_return, CORE_ADDR struct_addr)
{
  const int REND = 6;		/* Max arguments number.  */
  int goff = 0;			/* Current gpr for argument.  */
  int foff = 0;			/* Currnet gpr for argument.  */
  int soff = 0;			/* Current stack offset.  */
  int i;
  struct type *type;
  enum type_code typecode;
  CORE_ADDR regval;
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

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

      gdb_assert (align != 0);
      sp -= TYPE_LENGTH (type);
      if (align)
	{
	  /* FIXME: Handle empty structure?  */
	  sp &= ~(align - 1);
	}
    }

  /* Stack must be 8-byte aligned.  */
  sp = sp & ~7;

  soff = 0;
  for (i = 0; i < nargs; i++)
    {
      const gdb_byte *val;
      int align, len;

      type = value_type (args[i]);
      typecode = TYPE_CODE (type);
      align = nds32_float_in_struct (type);
      if (align)
	typecode = TYPE_CODE_FLT;
      else
	align = nds32_type_align (type);
      len = TYPE_LENGTH (type);

      /* TODO: handle variables-size argument and variable-length arguments

	 COLE, GDB cannot know whether a type is variable-sized,
	       so we don't know whether push it as reference or value.  */

      val = value_contents (args[i]);

      /* Once we start using stack, all arguments should go to stack
	 When use_fpr, all flt must go to fs/fd; otherwise go to stack.  */
      if (tdep->use_fpr && typecode == TYPE_CODE_FLT)
	{
	  /* Adjust alignment.  */
	  foff = (foff + ((align - 1) >> 2)) & ~((align - 1) >> 2);

	  if (foff < REND && !soff)
	    {
	      if (tdep->use_fpr && tdep->nds32_fpu_sp_num < 6)
		goto error_no_fpr;

	      switch (len)
		{
		case 4:
		  regcache_cooked_write (regcache, NDS32_FS0_REGNUM + foff,
					 val);
		  foff++;
		  continue;
		case 8:
		  regcache_cooked_write (regcache,
					 NDS32_FD0_REGNUM + foff / 2, val);
		  foff += 2;
		  continue;
		default:
		  /* Long double? */
		  internal_error (__FILE__, __LINE__,
				  "Do not know how to handle %d-byte double.\n",
				  len);
		  break;
		}
	    }
	}
      else if (!soff)
	{
	  /* Adjust alignment, and only adjust one time for one argument.  */
	  goff = (goff + ((align - 1) >> 2)) & ~((align - 1) >> 2);
	  if (!tdep->use_spill && len > (REND - goff) * 4)
	    goff = REND;
	}

      while (len > 0)
	{
	  if (soff
	      || (typecode == TYPE_CODE_FLT && tdep->use_fpr && foff == REND)
	      || goff == REND)
	    {
	      write_memory (sp + soff, val, (len > 4) ? 4 : len);
	      soff += 4;
	    }
	  else
	    {
	      regval = extract_unsigned_integer (val, (len > 4) ? 4 : len,
						 byte_order);
	      regcache_cooked_write (regcache, goff + NDS32_R0_REGNUM, val);
	      goff++;
	    }

	  len -= register_size (gdbarch, goff);
	  val += register_size (gdbarch, goff);
	}
    }

  /* Finally, update the SP register.  */
  regcache_cooked_write_unsigned (regcache, NDS32_SP_REGNUM, sp);

  return sp;

error_no_fpr:
  /* If use_fpr, but no fs reigster exists, then it is an error.  */
  error (_("Fail to call. FS0-FS5 is required."));
}

/* Given a return value in `regbuf' with a type `valtype',
   extract and copy its value into `valbuf'.  */

static void
nds32_extract_return_value (struct type *type, struct regcache *regcache,
			    gdb_byte *readbuf)
{
  int len = TYPE_LENGTH (type);
  int typecode = TYPE_CODE (type);
  struct gdbarch_tdep *tdep = gdbarch_tdep (get_regcache_arch (regcache));
  int i;

  /* TODO: one-float, one-double is special case in V2FP.
     Passed in FS/FD */
  gdb_assert (TYPE_LENGTH (type) <= 8);
  if (nds32_float_in_struct (type))
    typecode = TYPE_CODE_FLT;

  if (typecode == TYPE_CODE_FLT && tdep->use_fpr)
    {
      if (len == 4)
	regcache_cooked_read (regcache, NDS32_FS0_REGNUM, readbuf);
      else if (len == 8)
	regcache_cooked_read (regcache, NDS32_FD0_REGNUM, readbuf);
      else
	internal_error (__FILE__, __LINE__,
			_("Cannot extract return value of %d bytes "
			  "long floating point."),
			len);
    }
  else
    {
      if (len <= 4)
	regcache_raw_read_part (regcache, NDS32_R0_REGNUM, 0, len, readbuf);
      else if (len <= 8)
	{
	  regcache_raw_read (regcache, NDS32_R0_REGNUM, readbuf);
	  regcache_raw_read_part (regcache, NDS32_R0_REGNUM + 1, 0, len - 4,
				  readbuf + 4);
	}
      else
	internal_error (__FILE__, __LINE__,
			_("Cannot extract return value of %d bytes long."),
			len);
    }
}

/* Write into appropriate registers a function return value
   of type TYPE, given in virtual format.
   Things always get returned in RET1_REGNUM, RET2_REGNUM.  */

static void
nds32_store_return_value (struct type *type, struct regcache *regcache,
			  const gdb_byte *writebuf)
{
  int len = TYPE_LENGTH (type);
  int typecode = TYPE_CODE (type);
  struct gdbarch_tdep *tdep = gdbarch_tdep (get_regcache_arch (regcache));
  int i;

  /* TODO: one-float, one-double is special case in V2FP.
     Passed in FS/FD */
  gdb_assert (TYPE_LENGTH (type) <= 8);
  if (nds32_float_in_struct (type))
    typecode = TYPE_CODE_FLT;

  if (typecode == TYPE_CODE_FLT && tdep->use_fpr)
    {
      if (len == 4)
	regcache_cooked_write (regcache, NDS32_FS0_REGNUM, writebuf);
      else if (len == 8)
	regcache_cooked_write (regcache, NDS32_FD0_REGNUM, writebuf);
      else
	internal_error (__FILE__, __LINE__,
			_("Cannot store return value of %d bytes long "
			  "floating point."),
			len);
    }
  else
    {
      if (len <= 4)
	regcache_raw_write_part (regcache, NDS32_R0_REGNUM, 0, len, writebuf);
      else if (len <= 8)
	{
	  regcache_raw_write (regcache, NDS32_R0_REGNUM, writebuf);
	  regcache_raw_write_part (regcache, NDS32_R0_REGNUM + 1, 0, len - 4,
				   writebuf + 4);
	}
      else
	internal_error (__FILE__, __LINE__,
			_("Cannot store return value of %d bytes long."),
			len);
    }
}

/* Implement the gdbarch_return_value method.  */

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
      /* `readbuf' is used for 'call' to get the return value.
	 `writebuf' is used for 'return' to set the return value.  */
      if (readbuf != NULL)
	nds32_extract_return_value (type, regcache, readbuf);
      if (writebuf != NULL)
	nds32_store_return_value (type, regcache, writebuf);
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
  return frame_id_build (sp, get_frame_pc (this_frame));
}

/* Given a GDB frame, determine the address of the calling function's
   frame.  This will be used to create a new GDB frame struct.  */

static void
nds32_frame_this_id (struct frame_info *this_frame,
		     void **this_prologue_cache, struct frame_id *this_id)
{
  struct nds32_unwind_cache *info;
  CORE_ADDR base;
  CORE_ADDR func;
  struct minimal_symbol *msym_stack;
  struct frame_id id;
  enum bfd_endian byte_order_for_code = BFD_ENDIAN_BIG;

  info = nds32_frame_unwind_cache (this_frame, this_prologue_cache);

  /* Get function entry address */
  func = get_frame_func (this_frame);

  /* Hopefully the prologue analysis either correctly determined the
     frame's base (which is the SP from the previous frame), or set
     that base to "NULL".  */
  base = info->prev_sp;
  if (base == 0)
    return;

  id = frame_id_build (base, func);
  (*this_id) = id;
}

/* Get the value of register REGNUM in previous frame.  */

static struct value *
nds32_frame_prev_register (struct frame_info *this_frame,
			   void **this_prologue_cache, int regnum)
{
  struct nds32_unwind_cache *cache;
  cache = nds32_frame_unwind_cache (this_frame, this_prologue_cache);

  if (regnum == NDS32_PC_REGNUM)
    {
      CORE_ADDR lr;
      struct frame_info *next_frame;

      lr = frame_unwind_register_unsigned (this_frame, NDS32_LP_REGNUM);
      return frame_unwind_got_constant (this_frame, regnum, lr);
    }

  return trad_frame_get_prev_register (this_frame, cache->saved_regs, regnum);
}

/* The register in previous frame.  For example, the previous PC is
   current LP.  */

static struct value *
nds32_dwarf2_prev_register (struct frame_info *this_frame,
			    void **this_cache, int regnum)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  CORE_ADDR lp;

  switch (regnum)
    {
    case NDS32_PC_REGNUM:
      lp = frame_unwind_register_unsigned (this_frame, NDS32_LP_REGNUM);
      return frame_unwind_got_constant (this_frame, regnum, lp);
    default:
      internal_error (__FILE__, __LINE__,
		      _("Unexpected register %d"), regnum);
    }

   return NULL;
}

/* Callback of dwarf2_frame_set_init_reg.  */

static void
nds32_dwarf2_frame_init_reg (struct gdbarch *gdbarch, int regnum,
			     struct dwarf2_frame_state_reg *reg,
			     struct frame_info *this_frame)
{
  switch (regnum)
    {
    case NDS32_PC_REGNUM:
      reg->how = DWARF2_FRAME_REG_FN;
      reg->loc.fn = nds32_dwarf2_prev_register;
      break;
    case NDS32_SP_REGNUM:
      reg->how = DWARF2_FRAME_REG_CFA;
      break;
    }
}

/* Implement the gdbarch_get_longjmp_target method.  */

static int
nds32_get_longjmp_target (struct frame_info *frame, CORE_ADDR *pc)
{
  gdb_byte buf[4];
  CORE_ADDR jmp_buf_p;
  struct gdbarch *gdbarch = get_frame_arch (frame);
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
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

static const struct frame_unwind nds32_frame_unwind =
{
  NORMAL_FRAME,
  default_frame_unwind_stop_reason,
  nds32_frame_this_id,
  nds32_frame_prev_register,
  NULL /* unwind_data */,
  default_frame_sniffer
};

/* Signal trampolines.  */

static struct nds32_unwind_cache *
nds32_sigtramp_frame_cache (struct frame_info *this_frame, void **this_cache)
{
  struct nds32_unwind_cache *cache;
  CORE_ADDR addr;
  gdb_byte buf[4];
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);

  if (*this_cache)
    return *this_cache;

  cache = nds32_alloc_frame_cache (this_frame);

  cache->base = get_frame_register_unsigned (this_frame, NDS32_SP_REGNUM);

  addr = tdep->sigcontext_addr (this_frame);

  if (tdep->sc_reg_offset)
    {
      int i;

      /* GPRs, PC and d[01](lo|hi) */
      gdb_assert (tdep->sc_num_regs <= 37);

      for (i = 0; i < tdep->sc_num_regs; i++)
	if (tdep->sc_reg_offset[i] != -1)
	  cache->saved_regs[i].addr = addr + tdep->sc_reg_offset[i];
    }
  else
    {
      cache->saved_regs[NDS32_PC_REGNUM].addr = addr + tdep->sc_pc_offset;
      cache->saved_regs[NDS32_LP_REGNUM].addr = addr + tdep->sc_lp_offset;
      cache->saved_regs[NDS32_SP_REGNUM].addr = addr + tdep->sc_sp_offset;
      cache->saved_regs[NDS32_FP_REGNUM].addr = addr + tdep->sc_fp_offset;
    }

  *this_cache = cache;
  return cache;
}

static void
nds32_sigtramp_frame_this_id (struct frame_info *this_frame,
			      void **this_cache, struct frame_id *this_id)
{
  struct nds32_unwind_cache *cache;

  cache = nds32_sigtramp_frame_cache (this_frame, this_cache);

  (*this_id) = frame_id_build (cache->base, get_frame_pc (this_frame));
}

static struct value *
nds32_sigtramp_frame_prev_register (struct frame_info *this_frame,
				    void **this_cache, int regnum)
{
  struct nds32_unwind_cache *cache;

  /* Make sure we've initialized the cache.  */
  cache = nds32_sigtramp_frame_cache (this_frame, this_cache);

  /* For signal frame, unwind PC for PC and LP for LP;
     otherwise, we will fail to unwind a leaf-function.
     This different from unwinding a normal-frame.  */
  return trad_frame_get_prev_register (this_frame, cache->saved_regs, regnum);
}

static int
nds32_sigtramp_frame_sniffer (const struct frame_unwind *self,
			      struct frame_info *this_frame,
			      void **this_prologue_cache)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (get_frame_arch (this_frame));

  /* We shouldn't even bother if we don't have a sigcontext_addr
     handler.  */
  if (tdep->sigcontext_addr == NULL)
    return 0;

  if (tdep->sigtramp_p != NULL)
    {
      if (tdep->sigtramp_p (this_frame))
	return 1;
    }

#if 0
    /* TODO: extend the sniffer as following if (tdep->sigtramp_start != 0) */
    {
      CORE_ADDR pc = frame_pc_unwind (this_frame);

      gdb_assert (tdep->sigtramp_end != 0);
      if (pc >= tdep->sigtramp_start && pc < tdep->sigtramp_end)
	return &nds32_sigtramp_frame_unwind;
    }
#endif
  return 0;
}

static const struct frame_unwind nds32_sigtramp_frame_unwind =
{
  SIGTRAMP_FRAME,
  default_frame_unwind_stop_reason,
  nds32_sigtramp_frame_this_id,
  nds32_sigtramp_frame_prev_register,
  NULL /* unwind_data */,
  nds32_sigtramp_frame_sniffer
};

static void
nds32_ifc_frame_this_id (struct frame_info *this_frame,
			 void **this_cache, struct frame_id *this_id)
{
  LONGEST base;

  base = get_frame_register_unsigned (this_frame, NDS32_SP_REGNUM);;
  (*this_id) = frame_id_build (base, get_frame_pc (this_frame));
}

static struct value *
nds32_ifc_frame_prev_register (struct frame_info *this_frame,
			       void **this_cache, int regnum)
{
  struct value *value;

  if (regnum == NDS32_PC_REGNUM)
    value = value_of_register (NDS32_IFCLP_REGNUM, this_frame);
  else
    value = value_of_register (regnum, this_frame);
  return value;
}

static int
nds32_ifc_frame_sniffer (const struct frame_unwind *self,
			 struct frame_info *this_frame,
			 void **this_prologue_cache)
{
  LONGEST psw;
  struct gdbarch_tdep *tdep;

  if (frame_relative_level (this_frame) != 0)
    return 0;

  tdep = gdbarch_tdep (get_frame_arch (this_frame));

  if (!tdep->nds32_psw || !tdep->nds32_ifc)
    return 0;

  psw = get_frame_register_unsigned (this_frame, NDS32_PSW_REGNUM);
  return psw & (1 << 15);
}

static const struct frame_unwind nds32_ifc_frame_unwind = {
  NORMAL_FRAME,
  default_frame_unwind_stop_reason,
  nds32_ifc_frame_this_id,
  nds32_ifc_frame_prev_register,
  NULL /* unwind_data */,
  nds32_ifc_frame_sniffer
};

static CORE_ADDR
nds32_frame_base_address (struct frame_info *this_frame, void **this_cache)
{
  struct nds32_unwind_cache *info;

  info = nds32_frame_unwind_cache (this_frame, this_cache);

  return info->base;
}

static const struct frame_base nds32_frame_base =
{
  &nds32_frame_unwind,
  nds32_frame_base_address,
  nds32_frame_base_address,
  nds32_frame_base_address
};

static int
nds32_validate_tdesc_p (struct gdbarch *gdbarch,
			struct tdesc_arch_data *tdesc_data)
{
  int i;
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  const struct tdesc_feature *feature_core;
  const struct tdesc_feature *feature_fpu, *feature_system;
  const struct target_desc *tdesc = tdep->tdesc;
  unsigned int eflags = tdep->eflags;
  int valid_p;

  /* We only care core registers and FPU registers, since gdb only
     needs FP, LP, SP, PC for handling frames and R0-R5, FS0-FS5 for
     call setup.

     If ABI is not 2FP, FS0-FS5 is optional.  User may change ABI
     after initilization, so FS0-FS5 should be optional

    FIXME: Properly validate registers.  */

  /* If tdesc == tdesc_nds32, we use the built-in tdesc,
     because target doesn't support tdesc. */

  feature_core = tdesc_find_feature (tdesc, "org.gnu.gdb.nds32.core");
  if (!feature_core)
    return 0;

  for (i = NDS32_R0_REGNUM; i <= NDS32_D1HI_REGNUM; i++)
    {
      valid_p = tdesc_numbered_register (feature_core, tdesc_data, i,
					 nds32_regnames[i]);
    }

  tdep->nds32_ifc = tdesc_numbered_register
      (feature_core, tdesc_data, NDS32_IFCLP_REGNUM, "ifc_lp");
  if (!tdep->nds32_ifc)
    tdep->nds32_ifc = tdesc_numbered_register
      (feature_core, tdesc_data, NDS32_IFCLP_REGNUM, "ifclp");


  feature_system = tdesc_find_feature (tdesc, "org.gnu.gdb.nds32.system");
  if (feature_system)
    {
	tdep->nds32_psw = tdesc_numbered_register (feature_system, tdesc_data,
						   NDS32_PSW_REGNUM, "ir0");
	if (!tdep->nds32_psw)
	  tdep->nds32_psw = tdesc_numbered_register (feature_system, tdesc_data,
						     NDS32_PSW_REGNUM, "psw");
    }

  feature_fpu = tdesc_find_feature (tdesc, "org.gnu.gdb.nds32.fpu");
  if (feature_fpu)
    {
      /* FP control register.  */
      for (i = NDS32_FPU_REGNUM; i < NDS32_FS0_REGNUM; i++)
	  tdesc_numbered_register (feature_fpu, tdesc_data, i,
				   nds32_fpu_regnames[i - NDS32_FPU_REGNUM]);
      /* FS register.  */
      valid_p = 1;
      tdep->nds32_fpu_sp_num = 0;
      for (i = NDS32_FS0_REGNUM; (i < NDS32_FS0_REGNUM + 32) && valid_p; i++)
	{
	  valid_p = tdesc_numbered_register (feature_fpu, tdesc_data, i,
					     nds32_fpu_regnames[i - NDS32_FPU_REGNUM]);
	  if (valid_p)
	    tdep->nds32_fpu_sp_num++;
	}

      /* FD register.  */
      valid_p = 1;
      tdep->nds32_fpu_dp_num = 0;
      for (i = NDS32_FD0_REGNUM; (i < NDS32_FD0_REGNUM + 32) && valid_p; i++)
	{
	  valid_p = tdesc_numbered_register (feature_fpu, tdesc_data, i,
					     nds32_fpu_regnames[i - NDS32_FPU_REGNUM]);
	  if (valid_p)
	    tdep->nds32_fpu_dp_num++;
	}

      set_gdbarch_num_regs (gdbarch, NDS32_FD0_REGNUM + 32);
    }

  return 1;
}

static void
nds32_init_pseudo_registers (struct gdbarch *gdbarch)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  unsigned int eflags = tdep->eflags;
  int fpreg;

  /* For legacy target does not implement target-description,
     so we try to use Rcmd to access FPU registers.  */
  /* TODO build pseudo register */
  fpreg = (eflags >> 22) & 0x3; /* fpcfg */

  switch (nds32_config.use_fpreg)
    {
      case 3232:
	fpreg = NDS32_FPU_32SP_32DP;
	break;
      case 3216:
	fpreg = NDS32_FPU_32SP_16DP;
	break;
      case 168:
      case 1608:
	fpreg = NDS32_FPU_16SP_8DP;
	break;
      case 84:
      case 804:
	fpreg = NDS32_FPU_8SP_4DP;
	break;
    }

  switch (fpreg) /* fpcfg */
    {
    case NDS32_FPU_8SP_4DP:
      tdep->nds32_fpu_sp_num = 8;
      tdep->nds32_fpu_dp_num = 4;
      break;
    case NDS32_FPU_16SP_8DP:
      tdep->nds32_fpu_sp_num = 16;
      tdep->nds32_fpu_dp_num = 8;
      break;
    case NDS32_FPU_32SP_16DP:
      tdep->nds32_fpu_sp_num = 32;
      tdep->nds32_fpu_dp_num = 16;
      break;
    case NDS32_FPU_32SP_32DP:
      tdep->nds32_fpu_sp_num = 32;
      tdep->nds32_fpu_dp_num = 32;
      break;
    default:
      tdep->nds32_fpu_sp_num = 0;
      tdep->nds32_fpu_dp_num = 0;
      break;
    }

  /* Make sure FPU pseudo reg num doesn't overlapped with tdesc reg.  */
  if (tdep->nds32_fpu_sp_num > 0 || tdep->nds32_fpu_dp_num > 0)
    {
      /* Only use FPR for call for FP ABI.  */
      tdep->nds32_fpu_pseudo = TRUE;

      if (gdbarch_num_regs (gdbarch) > NDS32_FPU_REGNUM)
	internal_error (__FILE__, __LINE__,
			"too many gdbarch_num_regs overlapped with "
			"pseudo registers.\n");
      /* Adjust num_regs, since range of regs should be
	 0..(num_regs + num_pesudo_regs) */
      set_gdbarch_num_regs (gdbarch, NDS32_FPU_REGNUM);
      set_gdbarch_num_pseudo_regs (gdbarch, NDS32_NUM_PSEUDO_REGS);

      /* Remote-command is used.  */
      set_gdbarch_pseudo_register_read (gdbarch, nds32_pseudo_register_read);
      set_gdbarch_pseudo_register_write (gdbarch, nds32_pseudo_register_write);

      set_tdesc_pseudo_register_type (gdbarch, nds32_pseudo_register_type);
      set_tdesc_pseudo_register_name (gdbarch, nds32_pseudo_register_name);
    }
}

/* Implement the gdbarch_overlay_update method.  */

static void
nds32_simple_overlay_update (struct obj_section *osect)
{
  struct minimal_symbol *minsym = NULL;

  minsym = lookup_minimal_symbol (".nds32.fixed.size", NULL, NULL);
  if (minsym != NULL && osect != NULL)
    {
      bfd *obfd = osect->objfile->obfd;
      asection *bsect = osect->the_bfd_section;
      if (bfd_section_vma (obfd, bsect) < SYMBOL_VALUE_ADDRESS (minsym))
	{
	  osect->ovly_mapped = 1;
	  return;
	}
    }

  simple_overlay_update (osect);
}

/* Callback for gdbarch_init.  */

static struct gdbarch *
nds32_gdbarch_init (struct gdbarch_info info, struct gdbarch_list *arches)
{
  struct gdbarch *gdbarch;
  struct gdbarch_tdep *tdep;
  struct gdbarch_list *best_arch;
  const struct target_desc *tdesc;
  unsigned int nds32_abi = NDS32_ABI_AUTO;
  const struct tdesc_feature *feature;
  struct tdesc_arch_data *tdesc_data = NULL;
  unsigned int eflags = 0;
  int i;

  /* Extract the elf_flags, if available.  */
  if (info.abfd && bfd_get_flavour (info.abfd) == bfd_target_elf_flavour)
    {
      eflags = elf_elfheader (info.abfd)->e_flags;
      nds32_abi = (eflags >> 4) & 0xF;
    }

  if (!tdesc_has_registers (info.target_desc))
    tdesc = tdesc_nds32;
  else
    tdesc = info.target_desc;

  /* Allocate space for the new architecture.  */
  tdep = XCALLOC (1, struct gdbarch_tdep);
  gdbarch = gdbarch_alloc (&info, tdep);
  /* set_gdbarch_num_regs (gdbarch, NDS32_NUM_GR + NDS32_NUM_SPR); */
  set_gdbarch_num_regs (gdbarch, NDS32_PSW_REGNUM + 1);

  tdep->tdesc = tdesc;
  tdep->nds32_abi = nds32_abi;
  tdep->eflags = eflags;

  /* Overwrite ABI if set explicitly.  */
  if (nds32_config.use_abi != NDS32_ABI_AUTO)
    tdep->nds32_abi = nds32_config.use_abi;

  switch (tdep->nds32_abi)
    {
    case NDS32_ABI_V2:
    case NDS32_ABI_V2FP:
      tdep->use_spill = FALSE;
      break;
    default:
      tdep->use_spill = TRUE;
    break;
  }

  /* Use FP registers for calling iff when ABI==V2FP.  */
  tdep->use_fpr = (tdep->nds32_abi == NDS32_ABI_V2FP);

  tdep->sigtramp_p = NULL;
  tdep->sigcontext_addr = NULL;
  tdep->sc_pc_offset = -1;
  tdep->sc_sp_offset = -1;
  tdep->sc_fp_offset = -1;
  tdesc_data = tdesc_data_alloc ();

  /* Initialize osabi before tdesc_use_reg.  */
  info.tdep_info = (void *) tdesc_data;
  gdbarch_init_osabi (info, gdbarch);
  if (!nds32_validate_tdesc_p (gdbarch, tdesc_data))
  {
    tdesc_data_cleanup (tdesc_data);
    xfree (tdep);
    gdbarch_free (gdbarch);
    return NULL;
  }
  tdesc = tdep->tdesc;

  tdesc_use_registers (gdbarch, tdesc, tdesc_data);

  if (tdesc == tdesc_nds32)
      nds32_init_pseudo_registers (gdbarch);

  /* If there is already a candidate, use it.  */
  for (best_arch = gdbarch_list_lookup_by_info (arches, &info);
       best_arch != NULL;
       best_arch = gdbarch_list_lookup_by_info (best_arch->next, &info))
    {
      struct gdbarch_tdep *idep = gdbarch_tdep (best_arch->gdbarch);

      if (nds32_abi != idep->nds32_abi)
	continue;

      /* Check FPU registers.  */
      if (idep->nds32_fpu_sp_num != tdep->nds32_fpu_sp_num)
	continue;
      if (idep->nds32_fpu_dp_num != tdep->nds32_fpu_dp_num)
	continue;
      if (idep->nds32_fpu_pseudo != tdep->nds32_fpu_pseudo)
	continue;

      /* Found a match.  */
      break;
    }

  if (best_arch != NULL)
    {
      xfree (tdep);
      gdbarch_free (gdbarch);
      return best_arch->gdbarch;
    }

  /* Call after tdesc_use_register to overwrite tdesc_.
     Otherwise, they will be override by target-description.  */

  nds32_add_reggroups (gdbarch);
  /* Use tdesc_ provided version.  */
  set_gdbarch_register_reggroup_p (gdbarch, nds32_register_reggroup_p);
  /* Use tdesc_ provided version.
     set_gdbarch_register_name (gdbarch, nds32_register_name); */

  set_gdbarch_register_type (gdbarch, nds32_register_type);
  set_gdbarch_sp_regnum (gdbarch, NDS32_SP_REGNUM);
  set_gdbarch_pc_regnum (gdbarch, NDS32_PC_REGNUM);
  set_gdbarch_read_pc (gdbarch, nds32_read_pc);
  set_gdbarch_write_pc (gdbarch, nds32_write_pc);
  set_gdbarch_unwind_sp (gdbarch, nds32_unwind_sp);
  set_gdbarch_unwind_pc (gdbarch, nds32_unwind_pc);
  set_gdbarch_in_function_epilogue_p (gdbarch, nds32_in_function_epilogue_p);
  set_gdbarch_dwarf2_reg_to_regnum (gdbarch, nds32_dwarf_dwarf2_reg_to_regnum);
  set_gdbarch_register_sim_regno (gdbarch, nds32_register_sim_regno);
  set_gdbarch_push_dummy_call (gdbarch, nds32_push_dummy_call);
  set_gdbarch_return_value (gdbarch, nds32_return_value);
  set_gdbarch_skip_prologue (gdbarch, nds32_skip_prologue);
  set_gdbarch_inner_than (gdbarch, core_addr_lessthan);
  set_gdbarch_breakpoint_from_pc (gdbarch, nds32_breakpoint_from_pc);
  set_gdbarch_remote_breakpoint_from_pc (gdbarch,
					 nds32_remote_breakpoint_from_pc);

  set_gdbarch_frame_align (gdbarch, nds32_frame_align);
  frame_base_set_default (gdbarch, &nds32_frame_base);

  /* Methods for saving / extracting a dummy frame's ID.
     The ID's stack address must match the SP value returned by
     PUSH_DUMMY_CALL, and saved by generic_save_dummy_frame_tos.  */
  set_gdbarch_dummy_id (gdbarch, nds32_dummy_id);
  set_gdbarch_print_insn (gdbarch, print_insn_nds32);
  set_gdbarch_skip_permanent_breakpoint (gdbarch,
					 nds32_skip_permanent_breakpoint);
  /* Support simple overlay manager.  */
  set_gdbarch_overlay_update (gdbarch, nds32_simple_overlay_update);

  /* Handle longjmp.  */
  set_gdbarch_get_longjmp_target (gdbarch, nds32_get_longjmp_target);

  /* The order of appending is the order it check frame.  */
  if (nds32_config.use_ifcret)
    frame_unwind_append_unwinder (gdbarch, &nds32_ifc_frame_unwind);
  dwarf2_frame_set_init_reg (gdbarch, nds32_dwarf2_frame_init_reg);
  if (nds32_config.use_cfi)
    dwarf2_append_unwinders (gdbarch);
  frame_unwind_append_unwinder (gdbarch, &nds32_sigtramp_frame_unwind);
  frame_unwind_append_unwinder (gdbarch, &nds32_frame_unwind);

  /* Add nds32 register aliases.  */
  for (i = 0; i < ARRAY_SIZE (nds32_register_aliases); i++)
    {
      int regnum;

      regnum = user_reg_map_name_to_regnum (gdbarch,
					    nds32_register_aliases[i].name,
					    -1);
      if (regnum == -1)
	continue;

      user_reg_add (gdbarch, nds32_register_aliases[i].alias,
		    nds32_value_of_reg, (const void *) regnum);
    }

  return gdbarch;
}

/* Callback for "nds32 dump" command.

   Dump current register and stack for debug gdb.  */

static void
nds32_dump_command (char *arg, int from_tty)
{
  ULONGEST val;
  ULONGEST sp;
  FILE *f_script;
  char cmdline[512];
  int i;

  if (arg == NULL)
    {
      printf_unfiltered ("filename to put dump should be given\n");
      return;
    }

  regcache_raw_read_unsigned (get_current_regcache (), NDS32_SP_REGNUM, &sp);

  sprintf (cmdline, "dump binary memory %s.stack 0x%lx 0x%lx",
	   arg, (long) sp, ((long) sp + 1024 - 1) & ~(1024 - 1));
  execute_command (cmdline, from_tty);

  sprintf (cmdline, "%s.gdbinit", arg);
  f_script = fopen (cmdline, "w");
  if (f_script == NULL)
    {
      printf_unfiltered ("fail to generate dump .gdbinit");
      return ;
    }

  /* Gather all user registers.  */
  for (i = 0; i <= NDS32_D1HI_REGNUM; i++)
    {
      regcache_raw_read_unsigned (get_current_regcache (), i, &val);
      fprintf (f_script, "set $%s = 0x%lx\n", nds32_regnames[i], (long) val);
    }

  fprintf (f_script, "restore %s.stack binary 0x%lx\n", arg, (long) sp);
  fclose (f_script);
}

static int
nds32_config_int (const char *str, int def)
{
  int val = def;

  if (getenv (str))
    val = atoi (getenv (str));
  if (val != def)
    printf ("%s=%d\n", str, val);
  return val;
}

static void
nds32_load_config (struct nds32_gdb_config *config)
{
  config->use_cfi = nds32_config_int ("USE_CFI", 1);
  config->use_ifcret = nds32_config_int ("USE_IFC_RET", 1);
  config->use_fp = nds32_config_int ("USE_FP", 1);
  config->use_abi = nds32_config_int ("USE_ABI", NDS32_ABI_AUTO);
  config->use_stop_zfp = nds32_config_int ("USE_STOP_ZFP", 0);
  config->use_fpreg = nds32_config_int ("USE_FPREG", 0);
}

/* Callback for "nds32" command.  */

static void
nds32_command (char *arg, int from_tty)
{
  printf_unfiltered ("\"nds32\" must be followed by arguments\n");
}

struct cmd_list_element *nds32_cmdlist;

void
_initialize_nds32_tdep (void)
{
  /* Internal used config for testing.  */
  nds32_load_config (&nds32_config);

  add_prefix_cmd ("nds32", no_class, nds32_command,
		  _("Various nds32-specific commands."), &nds32_cmdlist,
		  "nds32 ", 0, &cmdlist);

  add_cmd ("dump", class_files, nds32_dump_command,
	   _("dump stack and GPRs for debugging"), &nds32_cmdlist);

  nds32_init_remote_cmds ();

  /* Initialize gdbarch.  */
  register_gdbarch_init (bfd_arch_nds32, nds32_gdbarch_init);

  /* Following are NDS32 specific commands.  */

  nds32_init_reggroups ();
  initialize_tdesc_nds32 ();
  initialize_tdesc_nds32_sim ();
  register_remote_support_xml ("nds32");
}
