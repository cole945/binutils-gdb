/* GNU/Linux/PowerPC specific low level interface, for the remote server for
   GDB.
   Copyright (C) 1995-2015 Free Software Foundation, Inc.

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

#include <elf.h>
#include <asm/ptrace.h>

#include "nat/ppc-linux.h"
#include "ax.h"
#include "tracepoint.h"

static unsigned long ppc_hwcap;


/* Defined in auto-generated file powerpc-32l.c.  */
void init_registers_powerpc_32l (void);
extern const struct target_desc *tdesc_powerpc_32l;

/* Defined in auto-generated file powerpc-altivec32l.c.  */
void init_registers_powerpc_altivec32l (void);
extern const struct target_desc *tdesc_powerpc_altivec32l;

/* Defined in auto-generated file powerpc-cell32l.c.  */
void init_registers_powerpc_cell32l (void);
extern const struct target_desc *tdesc_powerpc_cell32l;

/* Defined in auto-generated file powerpc-vsx32l.c.  */
void init_registers_powerpc_vsx32l (void);
extern const struct target_desc *tdesc_powerpc_vsx32l;

/* Defined in auto-generated file powerpc-isa205-32l.c.  */
void init_registers_powerpc_isa205_32l (void);
extern const struct target_desc *tdesc_powerpc_isa205_32l;

/* Defined in auto-generated file powerpc-isa205-altivec32l.c.  */
void init_registers_powerpc_isa205_altivec32l (void);
extern const struct target_desc *tdesc_powerpc_isa205_altivec32l;

/* Defined in auto-generated file powerpc-isa205-vsx32l.c.  */
void init_registers_powerpc_isa205_vsx32l (void);
extern const struct target_desc *tdesc_powerpc_isa205_vsx32l;

/* Defined in auto-generated file powerpc-e500l.c.  */
void init_registers_powerpc_e500l (void);
extern const struct target_desc *tdesc_powerpc_e500l;

/* Defined in auto-generated file powerpc-64l.c.  */
void init_registers_powerpc_64l (void);
extern const struct target_desc *tdesc_powerpc_64l;

/* Defined in auto-generated file powerpc-altivec64l.c.  */
void init_registers_powerpc_altivec64l (void);
extern const struct target_desc *tdesc_powerpc_altivec64l;

/* Defined in auto-generated file powerpc-cell64l.c.  */
void init_registers_powerpc_cell64l (void);
extern const struct target_desc *tdesc_powerpc_cell64l;

/* Defined in auto-generated file powerpc-vsx64l.c.  */
void init_registers_powerpc_vsx64l (void);
extern const struct target_desc *tdesc_powerpc_vsx64l;

/* Defined in auto-generated file powerpc-isa205-64l.c.  */
void init_registers_powerpc_isa205_64l (void);
extern const struct target_desc *tdesc_powerpc_isa205_64l;

/* Defined in auto-generated file powerpc-isa205-altivec64l.c.  */
void init_registers_powerpc_isa205_altivec64l (void);
extern const struct target_desc *tdesc_powerpc_isa205_altivec64l;

/* Defined in auto-generated file powerpc-isa205-vsx64l.c.  */
void init_registers_powerpc_isa205_vsx64l (void);
extern const struct target_desc *tdesc_powerpc_isa205_vsx64l;

#define ppc_num_regs 73

#ifdef __powerpc64__
/* We use a constant for FPSCR instead of PT_FPSCR, because
   many shipped PPC64 kernels had the wrong value in ptrace.h.  */
static int ppc_regmap[] =
 {PT_R0 * 8,     PT_R1 * 8,     PT_R2 * 8,     PT_R3 * 8,
  PT_R4 * 8,     PT_R5 * 8,     PT_R6 * 8,     PT_R7 * 8,
  PT_R8 * 8,     PT_R9 * 8,     PT_R10 * 8,    PT_R11 * 8,
  PT_R12 * 8,    PT_R13 * 8,    PT_R14 * 8,    PT_R15 * 8,
  PT_R16 * 8,    PT_R17 * 8,    PT_R18 * 8,    PT_R19 * 8,
  PT_R20 * 8,    PT_R21 * 8,    PT_R22 * 8,    PT_R23 * 8,
  PT_R24 * 8,    PT_R25 * 8,    PT_R26 * 8,    PT_R27 * 8,
  PT_R28 * 8,    PT_R29 * 8,    PT_R30 * 8,    PT_R31 * 8,
  PT_FPR0*8,     PT_FPR0*8 + 8, PT_FPR0*8+16,  PT_FPR0*8+24,
  PT_FPR0*8+32,  PT_FPR0*8+40,  PT_FPR0*8+48,  PT_FPR0*8+56,
  PT_FPR0*8+64,  PT_FPR0*8+72,  PT_FPR0*8+80,  PT_FPR0*8+88,
  PT_FPR0*8+96,  PT_FPR0*8+104,  PT_FPR0*8+112,  PT_FPR0*8+120,
  PT_FPR0*8+128, PT_FPR0*8+136,  PT_FPR0*8+144,  PT_FPR0*8+152,
  PT_FPR0*8+160,  PT_FPR0*8+168,  PT_FPR0*8+176,  PT_FPR0*8+184,
  PT_FPR0*8+192,  PT_FPR0*8+200,  PT_FPR0*8+208,  PT_FPR0*8+216,
  PT_FPR0*8+224,  PT_FPR0*8+232,  PT_FPR0*8+240,  PT_FPR0*8+248,
  PT_NIP * 8,    PT_MSR * 8,    PT_CCR * 8,    PT_LNK * 8,
  PT_CTR * 8,    PT_XER * 8,    PT_FPR0*8 + 256,
  PT_ORIG_R3 * 8, PT_TRAP * 8 };
#else
/* Currently, don't check/send MQ.  */
static int ppc_regmap[] =
 {PT_R0 * 4,     PT_R1 * 4,     PT_R2 * 4,     PT_R3 * 4,
  PT_R4 * 4,     PT_R5 * 4,     PT_R6 * 4,     PT_R7 * 4,
  PT_R8 * 4,     PT_R9 * 4,     PT_R10 * 4,    PT_R11 * 4,
  PT_R12 * 4,    PT_R13 * 4,    PT_R14 * 4,    PT_R15 * 4,
  PT_R16 * 4,    PT_R17 * 4,    PT_R18 * 4,    PT_R19 * 4,
  PT_R20 * 4,    PT_R21 * 4,    PT_R22 * 4,    PT_R23 * 4,
  PT_R24 * 4,    PT_R25 * 4,    PT_R26 * 4,    PT_R27 * 4,
  PT_R28 * 4,    PT_R29 * 4,    PT_R30 * 4,    PT_R31 * 4,
  PT_FPR0*4,     PT_FPR0*4 + 8, PT_FPR0*4+16,  PT_FPR0*4+24,
  PT_FPR0*4+32,  PT_FPR0*4+40,  PT_FPR0*4+48,  PT_FPR0*4+56,
  PT_FPR0*4+64,  PT_FPR0*4+72,  PT_FPR0*4+80,  PT_FPR0*4+88,
  PT_FPR0*4+96,  PT_FPR0*4+104,  PT_FPR0*4+112,  PT_FPR0*4+120,
  PT_FPR0*4+128, PT_FPR0*4+136,  PT_FPR0*4+144,  PT_FPR0*4+152,
  PT_FPR0*4+160,  PT_FPR0*4+168,  PT_FPR0*4+176,  PT_FPR0*4+184,
  PT_FPR0*4+192,  PT_FPR0*4+200,  PT_FPR0*4+208,  PT_FPR0*4+216,
  PT_FPR0*4+224,  PT_FPR0*4+232,  PT_FPR0*4+240,  PT_FPR0*4+248,
  PT_NIP * 4,    PT_MSR * 4,    PT_CCR * 4,    PT_LNK * 4,
  PT_CTR * 4,    PT_XER * 4,    PT_FPSCR * 4,
  PT_ORIG_R3 * 4, PT_TRAP * 4
 };

static int ppc_regmap_e500[] =
 {PT_R0 * 4,     PT_R1 * 4,     PT_R2 * 4,     PT_R3 * 4,
  PT_R4 * 4,     PT_R5 * 4,     PT_R6 * 4,     PT_R7 * 4,
  PT_R8 * 4,     PT_R9 * 4,     PT_R10 * 4,    PT_R11 * 4,
  PT_R12 * 4,    PT_R13 * 4,    PT_R14 * 4,    PT_R15 * 4,
  PT_R16 * 4,    PT_R17 * 4,    PT_R18 * 4,    PT_R19 * 4,
  PT_R20 * 4,    PT_R21 * 4,    PT_R22 * 4,    PT_R23 * 4,
  PT_R24 * 4,    PT_R25 * 4,    PT_R26 * 4,    PT_R27 * 4,
  PT_R28 * 4,    PT_R29 * 4,    PT_R30 * 4,    PT_R31 * 4,
  -1,            -1,            -1,            -1,
  -1,            -1,            -1,            -1,
  -1,            -1,            -1,            -1,
  -1,            -1,            -1,            -1,
  -1,            -1,            -1,            -1,
  -1,            -1,            -1,            -1,
  -1,            -1,            -1,            -1,
  -1,            -1,            -1,            -1,
  PT_NIP * 4,    PT_MSR * 4,    PT_CCR * 4,    PT_LNK * 4,
  PT_CTR * 4,    PT_XER * 4,    -1,
  PT_ORIG_R3 * 4, PT_TRAP * 4
 };
#endif

static int
ppc_cannot_store_register (int regno)
{
  const struct target_desc *tdesc = current_process ()->tdesc;

#ifndef __powerpc64__
  /* Some kernels do not allow us to store fpscr.  */
  if (!(ppc_hwcap & PPC_FEATURE_HAS_SPE)
      && regno == find_regno (tdesc, "fpscr"))
    return 2;
#endif

  /* Some kernels do not allow us to store orig_r3 or trap.  */
  if (regno == find_regno (tdesc, "orig_r3")
      || regno == find_regno (tdesc, "trap"))
    return 2;

  return 0;
}

static int
ppc_cannot_fetch_register (int regno)
{
  return 0;
}

static void
ppc_collect_ptrace_register (struct regcache *regcache, int regno, char *buf)
{
  memset (buf, 0, sizeof (long));

  if (__BYTE_ORDER == __LITTLE_ENDIAN)
    {
      /* Little-endian values always sit at the left end of the buffer.  */
      collect_register (regcache, regno, buf);
    }
  else if (__BYTE_ORDER == __BIG_ENDIAN)
    {
      /* Big-endian values sit at the right end of the buffer.  In case of
         registers whose sizes are smaller than sizeof (long), we must use a
         padding to access them correctly.  */
      int size = register_size (regcache->tdesc, regno);

      if (size < sizeof (long))
	collect_register (regcache, regno, buf + sizeof (long) - size);
      else
	collect_register (regcache, regno, buf);
    }
  else
    perror_with_name ("Unexpected byte order");
}

static void
ppc_supply_ptrace_register (struct regcache *regcache,
			    int regno, const char *buf)
{
  if (__BYTE_ORDER == __LITTLE_ENDIAN)
    {
      /* Little-endian values always sit at the left end of the buffer.  */
      supply_register (regcache, regno, buf);
    }
  else if (__BYTE_ORDER == __BIG_ENDIAN)
    {
      /* Big-endian values sit at the right end of the buffer.  In case of
         registers whose sizes are smaller than sizeof (long), we must use a
         padding to access them correctly.  */
      int size = register_size (regcache->tdesc, regno);

      if (size < sizeof (long))
	supply_register (regcache, regno, buf + sizeof (long) - size);
      else
	supply_register (regcache, regno, buf);
    }
  else
    perror_with_name ("Unexpected byte order");
}


#define INSTR_SC        0x44000002
#define NR_spu_run      0x0116

/* If the PPU thread is currently stopped on a spu_run system call,
   return to FD and ADDR the file handle and NPC parameter address
   used with the system call.  Return non-zero if successful.  */
static int
parse_spufs_run (struct regcache *regcache, int *fd, CORE_ADDR *addr)
{
  CORE_ADDR curr_pc;
  int curr_insn;
  int curr_r0;

  if (register_size (regcache->tdesc, 0) == 4)
    {
      unsigned int pc, r0, r3, r4;
      collect_register_by_name (regcache, "pc", &pc);
      collect_register_by_name (regcache, "r0", &r0);
      collect_register_by_name (regcache, "orig_r3", &r3);
      collect_register_by_name (regcache, "r4", &r4);
      curr_pc = (CORE_ADDR) pc;
      curr_r0 = (int) r0;
      *fd = (int) r3;
      *addr = (CORE_ADDR) r4;
    }
  else
    {
      unsigned long pc, r0, r3, r4;
      collect_register_by_name (regcache, "pc", &pc);
      collect_register_by_name (regcache, "r0", &r0);
      collect_register_by_name (regcache, "orig_r3", &r3);
      collect_register_by_name (regcache, "r4", &r4);
      curr_pc = (CORE_ADDR) pc;
      curr_r0 = (int) r0;
      *fd = (int) r3;
      *addr = (CORE_ADDR) r4;
    }

  /* Fetch instruction preceding current NIP.  */
  if ((*the_target->read_memory) (curr_pc - 4,
				  (unsigned char *) &curr_insn, 4) != 0)
    return 0;
  /* It should be a "sc" instruction.  */
  if (curr_insn != INSTR_SC)
    return 0;
  /* System call number should be NR_spu_run.  */
  if (curr_r0 != NR_spu_run)
    return 0;

  return 1;
}

static CORE_ADDR
ppc_get_pc (struct regcache *regcache)
{
  CORE_ADDR addr;
  int fd;

  if (parse_spufs_run (regcache, &fd, &addr))
    {
      unsigned int pc;
      (*the_target->read_memory) (addr, (unsigned char *) &pc, 4);
      return ((CORE_ADDR)1 << 63)
	| ((CORE_ADDR)fd << 32) | (CORE_ADDR) (pc - 4);
    }
  else if (register_size (regcache->tdesc, 0) == 4)
    {
      unsigned int pc;
      collect_register_by_name (regcache, "pc", &pc);
      return (CORE_ADDR) pc;
    }
  else
    {
      unsigned long pc;
      collect_register_by_name (regcache, "pc", &pc);
      return (CORE_ADDR) pc;
    }
}

static void
ppc_set_pc (struct regcache *regcache, CORE_ADDR pc)
{
  CORE_ADDR addr;
  int fd;

  if (parse_spufs_run (regcache, &fd, &addr))
    {
      unsigned int newpc = pc;
      (*the_target->write_memory) (addr, (unsigned char *) &newpc, 4);
    }
  else if (register_size (regcache->tdesc, 0) == 4)
    {
      unsigned int newpc = pc;
      supply_register_by_name (regcache, "pc", &newpc);
    }
  else
    {
      unsigned long newpc = pc;
      supply_register_by_name (regcache, "pc", &newpc);
    }
}


static int
ppc_get_hwcap (unsigned long *valp)
{
  const struct target_desc *tdesc = current_process ()->tdesc;
  int wordsize = register_size (tdesc, 0);
  unsigned char *data = alloca (2 * wordsize);
  int offset = 0;

  while ((*the_target->read_auxv) (offset, data, 2 * wordsize) == 2 * wordsize)
    {
      if (wordsize == 4)
	{
	  unsigned int *data_p = (unsigned int *)data;
	  if (data_p[0] == AT_HWCAP)
	    {
	      *valp = data_p[1];
	      return 1;
	    }
	}
      else
	{
	  unsigned long *data_p = (unsigned long *)data;
	  if (data_p[0] == AT_HWCAP)
	    {
	      *valp = data_p[1];
	      return 1;
	    }
	}

      offset += 2 * wordsize;
    }

  *valp = 0;
  return 0;
}

/* Forward declaration.  */
static struct usrregs_info ppc_usrregs_info;
#ifndef __powerpc64__
static int ppc_regmap_adjusted;
#endif

static void
ppc_arch_setup (void)
{
  const struct target_desc *tdesc;
#ifdef __powerpc64__
  long msr;
  struct regcache *regcache;

  /* On a 64-bit host, assume 64-bit inferior process with no
     AltiVec registers.  Reset ppc_hwcap to ensure that the
     collect_register call below does not fail.  */
  tdesc = tdesc_powerpc_64l;
  current_process ()->tdesc = tdesc;
  ppc_hwcap = 0;

  regcache = new_register_cache (tdesc);
  fetch_inferior_registers (regcache, find_regno (tdesc, "msr"));
  collect_register_by_name (regcache, "msr", &msr);
  free_register_cache (regcache);
  if (ppc64_64bit_inferior_p (msr))
    {
      ppc_get_hwcap (&ppc_hwcap);
      if (ppc_hwcap & PPC_FEATURE_CELL)
	tdesc = tdesc_powerpc_cell64l;
      else if (ppc_hwcap & PPC_FEATURE_HAS_VSX)
	{
	  /* Power ISA 2.05 (implemented by Power 6 and newer processors)
	     increases the FPSCR from 32 bits to 64 bits. Even though Power 7
	     supports this ISA version, it doesn't have PPC_FEATURE_ARCH_2_05
	     set, only PPC_FEATURE_ARCH_2_06.  Since for now the only bits
	     used in the higher half of the register are for Decimal Floating
	     Point, we check if that feature is available to decide the size
	     of the FPSCR.  */
	  if (ppc_hwcap & PPC_FEATURE_HAS_DFP)
	    tdesc = tdesc_powerpc_isa205_vsx64l;
	  else
	    tdesc = tdesc_powerpc_vsx64l;
	}
      else if (ppc_hwcap & PPC_FEATURE_HAS_ALTIVEC)
	{
	  if (ppc_hwcap & PPC_FEATURE_HAS_DFP)
	    tdesc = tdesc_powerpc_isa205_altivec64l;
	  else
	    tdesc = tdesc_powerpc_altivec64l;
	}

      current_process ()->tdesc = tdesc;
      return;
    }
#endif

  /* OK, we have a 32-bit inferior.  */
  tdesc = tdesc_powerpc_32l;
  current_process ()->tdesc = tdesc;

  ppc_get_hwcap (&ppc_hwcap);
  if (ppc_hwcap & PPC_FEATURE_CELL)
    tdesc = tdesc_powerpc_cell32l;
  else if (ppc_hwcap & PPC_FEATURE_HAS_VSX)
    {
      if (ppc_hwcap & PPC_FEATURE_HAS_DFP)
	tdesc = tdesc_powerpc_isa205_vsx32l;
      else
	tdesc = tdesc_powerpc_vsx32l;
    }
  else if (ppc_hwcap & PPC_FEATURE_HAS_ALTIVEC)
    {
      if (ppc_hwcap & PPC_FEATURE_HAS_DFP)
	tdesc = tdesc_powerpc_isa205_altivec32l;
      else
	tdesc = tdesc_powerpc_altivec32l;
    }

  /* On 32-bit machines, check for SPE registers.
     Set the low target's regmap field as appropriately.  */
#ifndef __powerpc64__
  if (ppc_hwcap & PPC_FEATURE_HAS_SPE)
    tdesc = tdesc_powerpc_e500l;

  if (!ppc_regmap_adjusted)
    {
      if (ppc_hwcap & PPC_FEATURE_HAS_SPE)
	ppc_usrregs_info.regmap = ppc_regmap_e500;

      /* If the FPSCR is 64-bit wide, we need to fetch the whole
	 64-bit slot and not just its second word.  The PT_FPSCR
	 supplied in a 32-bit GDB compilation doesn't reflect
	 this.  */
      if (register_size (tdesc, 70) == 8)
	ppc_regmap[70] = (48 + 2*32) * sizeof (long);

      ppc_regmap_adjusted = 1;
   }
#endif
  current_process ()->tdesc = tdesc;
}

/* Correct in either endianness.
   This instruction is "twge r2, r2", which GDB uses as a software
   breakpoint.  */
static const unsigned int ppc_breakpoint = 0x7d821008;
#define ppc_breakpoint_len 4

static int
ppc_breakpoint_at (CORE_ADDR where)
{
  unsigned int insn;

  if (where & ((CORE_ADDR)1 << 63))
    {
      char mem_annex[32];
      sprintf (mem_annex, "%d/mem", (int)((where >> 32) & 0x7fffffff));
      (*the_target->qxfer_spu) (mem_annex, (unsigned char *) &insn,
				NULL, where & 0xffffffff, 4);
      if (insn == 0x3fff)
	return 1;
    }
  else
    {
      (*the_target->read_memory) (where, (unsigned char *) &insn, 4);
      if (insn == ppc_breakpoint)
	return 1;
      /* If necessary, recognize more trap instructions here.  GDB only uses
	 the one.  */
    }

  return 0;
}

static int
ppc_supports_z_point_type (char z_type)
{
  switch (z_type)
    {
    case Z_PACKET_SW_BP:
      return 1;
    case Z_PACKET_HW_BP:
    case Z_PACKET_WRITE_WP:
    case Z_PACKET_ACCESS_WP:
    default:
      return 0;
    }
}

static int
ppc_insert_point (enum raw_bkpt_type type, CORE_ADDR addr,
		  int size, struct raw_breakpoint *bp)
{
  switch (type)
    {
    case raw_bkpt_type_sw:
      return insert_memory_breakpoint (bp);

    case raw_bkpt_type_hw:
    case raw_bkpt_type_write_wp:
    case raw_bkpt_type_access_wp:
    default:
      /* Unsupported.  */
      return 1;
    }
}

static int
ppc_remove_point (enum raw_bkpt_type type, CORE_ADDR addr,
		  int size, struct raw_breakpoint *bp)
{
  switch (type)
    {
    case raw_bkpt_type_sw:
      return remove_memory_breakpoint (bp);

    case raw_bkpt_type_hw:
    case raw_bkpt_type_write_wp:
    case raw_bkpt_type_access_wp:
    default:
      /* Unsupported.  */
      return 1;
    }
}


#ifdef __powerpc64__
static int
put_i32 (unsigned char *buf, uint32_t insn)
{
  if (__BYTE_ORDER == __LITTLE_ENDIAN)
    {
      buf[3] = (insn >> 24) & 0xff;
      buf[2] = (insn >> 16) & 0xff;
      buf[1] = (insn >> 8) & 0xff;
      buf[0] = insn & 0xff;
    }
  else
    {
      buf[0] = (insn >> 24) & 0xff;
      buf[1] = (insn >> 16) & 0xff;
      buf[2] = (insn >> 8) & 0xff;
      buf[3] = insn & 0xff;
    }

  return 4;
}

static uint32_t
get_i32 (unsigned char *buf)
{
  uint32_t r;

  if (__BYTE_ORDER == __LITTLE_ENDIAN)
    r = (buf[3] << 24) | (buf[2] << 16) | (buf[1] << 8) | buf[0];
  else
    r = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];

  return r;
}

static int
gen_ds_form (unsigned char *buf, int op6, int rst, int ra, int ds, int sub2)
{
  uint32_t insn = op6 << 26;

  insn |= (rst << 21) | (ra << 16) | (ds & 0xfffc) | (sub2 & 0x3);
  return put_i32 (buf, insn);
}

#define GEN_STD(buf, rs, ra, offset)	gen_ds_form (buf, 62, rs, ra, offset, 0)
#define GEN_STDU(buf, rs, ra, offset)	gen_ds_form (buf, 62, rs, ra, offset, 1)
#define GEN_LD(buf, rt, ra, offset)	gen_ds_form (buf, 58, rt, ra, offset, 0)
#define GEN_LDU(buf, rt, ra, offset)	gen_ds_form (buf, 58, rt, ra, offset, 1)

static int
gen_d_form (unsigned char *buf, int op6, int rt, int ra, int si)
{
  uint32_t insn = op6 << 26;

  insn |= (rt << 21) | (ra << 16) | (si & 0xffff);
  return put_i32 (buf, insn);
}

#define GEN_ADDI(buf, rt, ra, si)	gen_d_form (buf, 14, rt, ra, si)
#define GEN_ADDIS(buf, rt, ra, si)	gen_d_form (buf, 15, rt, ra, si)
#define GEN_LI(buf, rt, si)		GEN_ADDI (buf, rt, 0, si)
#define GEN_LIS(buf, rt, si)		GEN_ADDIS (buf, rt, 0, si)
#define GEN_ORI(buf, rt, ra, si)	gen_d_form (buf, 24, rt, ra, si)
#define GEN_ORIS(buf, rt, ra, si)	gen_d_form (buf, 25, rt, ra, si)

static int
gen_xfx_form (unsigned char *buf, int op6, int rst, int ri, int subop, int b1)
{
  uint32_t insn = op6 << 26;

  insn |= (rst << 21) | (ri << 11) | (subop << 1) | b1;
  return put_i32 (buf, insn);
}

#define GEN_MFSPR(buf, rt, spr) \
        gen_xfx_form (buf, 31, rt, ((spr & 0x1f) << 5) | ((spr >> 5) & 0x1f), \
                      339, 0)
#define GEN_MTSPR(buf, rt, spr) \
        gen_xfx_form (buf, 31, rt, ((spr & 0x1f) << 5) | ((spr >> 5) & 0x1f), \
                      467, 0)

static int
gen_x_form (unsigned char *buf, int op6, int rs, int ra, int rb,
	    int subop, int rc)
{
  uint32_t insn = op6 << 26;

  insn |= (rs << 21) | (ra << 16) | (rb << 11) | (subop << 1) | rc;
  return put_i32 (buf, insn);
}

#define GEN_MR(buf, rt, ra)		gen_x_form (buf, 31, ra, rt, ra, 444, 0)

static int
gen_xo_form (unsigned char *buf, int op6, int rt, int ra, int rb, int oe,
	     int subop, int rc)
{
  uint32_t insn = op6 << 26;

  insn |= (rt << 21) | (ra << 16) | (rb << 11) | (oe << 10) | (subop << 1) | rc;
  return put_i32 (buf, insn);
}

#define GEN_ADD(buf, rt, ra, rb)   gen_xo_form (buf, 31, rt, ra, rb, 0, 266, 0)
#define GEN_SUBF(buf, rt, ra, rb)  gen_xo_form (buf, 31, rt, ra, rb, 0, 40, 0)
#define GEN_SUB(buf, rt, ra, rb)   GEN_SUBF (buf, rt, rb, ra)

static int
gen_limm64 (unsigned char *buf, int reg, uint64_t imm)
{
  /* lis    reg, <imm[63:48]>
     ori    reg, reg, <imm[48:32]>
     rldicr reg, reg, 32, 31
     oris   reg, reg, <imm[31:16]>
     ori    reg, reg, <imm[15:0]> */
  GEN_LIS (buf + 0, reg, ((imm >> 48) & 0xffff));
  GEN_ORI (buf + 4, reg, reg, ((imm >> 32) & 0xffff));
  put_i32 (buf + 8, 0x780007c6 | (reg << 21) | (reg << 16));
  GEN_ORIS (buf + 12, reg, reg, ((imm >> 16) & 0xffff));
  GEN_ORI (buf + 16, reg, reg, (imm & 0xffff));

  return 5 * 4;
}

static int
gen_call (unsigned char *buf, CORE_ADDR fn)
{
  int i = 0;

#if !defined (_CALL_ELF) || _CALL_ELF == 1
  i += gen_limm64 (buf + i, 12, fn);
  i += GEN_LD (buf + i, 9, 12, 0);			/* ld r9, 0(r12) */
  i += GEN_LD (buf + i, 2, 12, 8);			/* ld r2, 8(r12) */
  i += put_i32 (buf + i, 0x7c0903a6 | (9 << 21));	/* mtctr r9 */
  i += GEN_LD (buf + i, 11, 12, 16);			/* ld r11, 16(r12) */
  i += put_i32 (buf + i, 0x4e800421);			/* bctrl */
#elif _CALL_ELF == 2
  /* Must be called by r12 for caller to calculate TOC address. */
  i += gen_limm64 (buf + i, 12, fn);
  i += put_i32 (buf + i, 0x7c0903a6 | (12 << 21));	/* mtctr r12 */
  i += put_i32 (buf + i, 0x4e800421);			/* bctrl */
#else
  #error "Unknown _CALL_ELF.  Don't know how to call."
#endif
  return i;
}

static int
ppc_supports_tracepoints (void)
{
  return 1;
}

static int
ppc_install_fast_tracepoint_jump_pad (CORE_ADDR tpoint, CORE_ADDR tpaddr,
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
  unsigned char buf[512];
  int i, j, offset;
  CORE_ADDR buildaddr = *jump_entry;
  const int frame_size = (((37 * 8) + 112) + 0xf) & ~0xf;

  /* Save registers.
     High	CTR   -8(sp)
		LR   -16(sp)
		XER
		CR
		R31
		R29
		...
		R1
		R0
     Low	PC<tpaddr> */

  i = 0;
  for (j = 0; j < 32; j++)
    i += GEN_STD (buf + i, j, 1, (-8 * 36 + j * 8));

  /* Save PC<tpaddr>  */
  i += gen_limm64 (buf + i, 3, tpaddr);
  i += GEN_STD (buf + i, 3, 1, (-8 * 37));

  /* Save CR, XER, LR, and CTR.  */
  i += put_i32 (buf + i, 0x7c600026);		/* mfcr   r3 */
  i += GEN_MFSPR (buf + i, 4, 1);		/* mfxer  r4 */
  i += GEN_MFSPR (buf + i, 5, 8);		/* mflr   r5 */
  i += GEN_MFSPR (buf + i, 6, 9);		/* mfctr  r6 */
  i += GEN_STD (buf + i, 3, 1, -32);		/* std    r3, -32(r1) */
  i += GEN_STD (buf + i, 4, 1, -24);		/* std    r4, -24(r1) */
  i += GEN_STD (buf + i, 5, 1, -16);		/* std    r5, -16(r1) */
  i += GEN_STD (buf + i, 6, 1, -8);		/* std    r6, -8(r1) */

  /* Adjust stack pointer.  */
  i += GEN_ADDI (buf + i, 1, 1, -frame_size);	/* subi   r1,r1,FRAME_SIZE */

  /* Setup arguments to collector.  */

  /* Set r4 to collected registers.  */
  i += GEN_ADDI (buf + i, 4, 1, frame_size - 8 * 37);
  /* Set r3 to TPOINT.  */
  i += gen_limm64 (buf + i, 3, tpoint);

  /* Call to collector.  */
  i += gen_call (buf + i, collector);

  /* Restore stack and registers.  */
  i += GEN_ADDI (buf + i, 1, 1, frame_size);	/* addi   r1,r1,FRAME_SIZE */
  i += GEN_LD (buf + i, 3, 1, -32);		/* ld    r3, -32(r1) */
  i += GEN_LD (buf + i, 4, 1, -24);		/* ld    r4, -24(r1) */
  i += GEN_LD (buf + i, 5, 1, -16);		/* ld    r5, -16(r1) */
  i += GEN_LD (buf + i, 6, 1, -8);		/* ld    r6, -8(r1) */
  i += put_i32 (buf + i, 0x7c6ff120);		/* mtcr   r3 */
  i += GEN_MTSPR (buf + i, 4, 1);		/* mtxer  r4 */
  i += GEN_MTSPR (buf + i, 5, 8);		/* mtlr   r5 */
  i += GEN_MTSPR (buf + i, 6, 9);		/* mtctr  r6 */
  for (j = 0; j < 32; j++)
    i += GEN_LD (buf + i, j, 1, (-8 * 36 + j * 8));

  /* Remember the address for inserting original instruction.
     Patch the instruction later.  */
  *adjusted_insn_addr = buildaddr + i;
  i += 4;

  /* Finally, write a jump back to the program.  */
  offset = (tpaddr + 4) - (buildaddr + i);
  if (offset >= (1 << 26) || offset < -(1 << 26))
    {
      sprintf (err, "E.Jump back from jump pad too far from tracepoint "
		    "(offset 0x%x > 26-bit).", offset);
      return 1;
    }
  /* b <tpaddr+4> */
  i += put_i32 (buf + i, 0x48000000 | (offset & 0x3fffffc));
  write_inferior_memory (buildaddr, buf, i);

  /* Now, insert the original instruction to execute in the jump pad.  */
  *adjusted_insn_addr_end = *adjusted_insn_addr;
  relocate_instruction (adjusted_insn_addr_end, tpaddr);
  /* Verify the relocation size.  */
  if (*adjusted_insn_addr_end - *adjusted_insn_addr != 4)
    {
      sprintf (err, "E.Unexpected instruction length "
		    "when relocate instruction. %d != 4",
		    (int) (*adjusted_insn_addr_end - *adjusted_insn_addr));
      return 1;
    }

  /* The jump pad is now built.  Wire in a jump to our jump pad.  This
     is always done last (by our caller actually), so that we can
     install fast tracepoints with threads running.  This relies on
     the agent's atomic write support.  */
  offset = buildaddr - tpaddr;
  if (offset >= (1 << 25) || offset < -(1 << 25))
    {
      sprintf (err, "E.Jump back from jump pad too far from tracepoint "
		    "(offset 0x%x > 26-bit).", offset);
      return 1;
    }
  /* b <jentry> */
  put_i32 (jjump_pad_insn, 0x48000000 | (offset & 0x3fffffc));
  *jjump_pad_insn_size = 4;

  *jump_entry = buildaddr + i;

  return 0;
}

static int
ppc_get_min_fast_tracepoint_insn_len ()
{
  return 4;
}

enum
{
  /* basic stack frame
     + room for callee saved registers
     + initial bytecode execution stack  */
  bytecode_framesize = (48 + 8 * 8) + (2 * 8) + 64,
};

static void
ppc_emit_prologue (void)
{
  /* r31 is the frame-base for restoring stack-pointer.
     r30 is the stack-pointer for bytecode machine.
	 It should point to next-empty, so we can use LDU for pop.
     r3  is cache of TOP value.  */

  unsigned char buf[8 * 4];
  int i = 0;

  i += GEN_MFSPR (buf, 0, 8);		/* mflr	r0 */
  i += GEN_STD (buf + i, 0, 1, 16);	/* std	r0, 16(r1) */
  i += GEN_STD (buf + i, 31, 1, -8);	/* std	r31, -8(r1) */
  i += GEN_STD (buf + i, 30, 1, -16);	/* std	r30, -16(r1) */
  i += GEN_ADDI (buf + i, 30, 1, -24);	/* addi	r30, r1, -24 */
  i += GEN_LI (buf + i, 3, 0);		/* li		r3, 0 */
					/* stdu	r1, -(frame_size)(r1) */
  i += GEN_STDU (buf + i, 1, 1, -bytecode_framesize);
  i += GEN_MR (buf + i, 31, 1);		/* mr	r31, r1 */

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}


static void
ppc_emit_epilogue (void)
{
  unsigned char buf[6 * 4];
  int i = 0;

					/* add	r1, r31, frame_size */
  i += GEN_ADDI (buf, 1, 31, bytecode_framesize);
  i += GEN_LD (buf + i, 0, 1, 16);	/* ld	r0, 16(r1) */
  i += GEN_LD (buf + i, 31, 1, -8);	/* ld	r31, -8(r1) */
  i += GEN_LD (buf + i, 30, 1, -16);	/* ld	r30, -16(r1) */
  i += GEN_MTSPR (buf + i, 0, 8);	/* mtlr	r0 */
  i += put_i32 (buf + i, 0x4e800020);	/* blr */

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

static void
ppc_emit_add (void)
{
  unsigned char buf[2 * 4];
  int i = 0;

  i += GEN_LDU (buf + i, 4, 30, 8);	/* ldu	r4, 8(r30) */
  i += GEN_ADD (buf + i, 3, 4, 3);	/* add	r3, r4, r3 */

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

static void
ppc_emit_sub (void)
{
  unsigned char buf[2 * 4];
  int i = 0;

  i += GEN_LDU (buf + i, 4, 30, 8);	/* ldu	r4, 8(r30) */
  i += GEN_SUB (buf + i, 3, 4, 3);	/* sub	r3, r4, r3 */

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

static void
ppc_emit_mul (void)
{
  unsigned char buf[2 * 4];
  int i = 0;

  i += GEN_LDU (buf + i, 4, 30, 8);	/* ldu    r4, 8(r30) */
  i += put_i32 (buf + i, 0x7c6419d2);	/* mulld  r3, r4, r3 */

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

static void
ppc_emit_lsh (void)
{
  unsigned char buf[2 * 4];
  int i = 0;

  i += GEN_LDU (buf + i, 4, 30, 8);	/* ldu	r4, 8(r30) */
  i += put_i32 (buf + i, 0x7c831836);	/* sld	r3, r4, r3 */

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

static void
ppc_emit_rsh_signed (void)
{
  unsigned char buf[2 * 4];
  int i = 0;

  i += GEN_LDU (buf + i, 4, 30, 8);	/* ldu	r4, 8(r30) */
  i += put_i32 (buf + i, 0x7c831e34);	/* srad	r3, r4, r3 */

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

static void
ppc_emit_rsh_unsigned (void)
{
  unsigned char buf[2 * 4];
  int i = 0;

  i += GEN_LDU (buf + i, 4, 30, 8);	/* ldu	r4, 8(r30) */
  i += put_i32 (buf + i, 0x7c831c36);	/* srd	r3, r4, r3 */

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

static void
ppc_emit_ext (int arg)
{
  unsigned char buf[4];
  int i = 0;

  switch (arg)
    {
    case 8:
      i += put_i32 (buf, 0x7c630774);	/* extsb  r3, r3 */
      break;
    case 16:
      i += put_i32 (buf, 0x7c630734);	/* extsh  r3, r3 */
      break;
    case 32:
      i += put_i32 (buf, 0x7c6307b4);	/* extsw  r3, r3 */
      break;
    default:
      emit_error = 1;
    }

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

static void
ppc_emit_zero_ext (int arg)
{
  unsigned char buf[4];
  int i = 0;

  switch (arg)
    {
    case 8:
      i += put_i32 (buf, 0x78630620);	/* rldicl 3,3,0,56 */
      break;
    case 16:
      i += put_i32 (buf, 0x786301a0);	/* rldicl 3,3,0,38 */
      break;
    case 32:
      i += put_i32 (buf, 0x78630020);	/* rldicl 3,3,0,32 */
      break;
    default:
      emit_error = 1;
    }

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

static void
ppc_emit_log_not (void)
{
  unsigned char buf[2 * 4];
  int i = 0;

  i += put_i32 (buf + i, 0x7c630074);	/* cntlzd r3, r3 */
  i += put_i32 (buf + i, 0x7863d182);	/* srdi   r3, r3, 6 */

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

static void
ppc_emit_bit_and (void)
{
  unsigned char buf[2 * 4];
  int i = 0;

  i += GEN_LDU (buf + i, 4, 30, 8);	/* ldu	r4, 8(r30) */
  i += put_i32 (buf + i, 0x7c831838);	/* and	r3, r4, r3 */

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

static void
ppc_emit_bit_or (void)
{
  unsigned char buf[2 * 4];
  int i = 0;

  i += GEN_LDU (buf + i, 4, 30, 8);	/* ldu	r4, 8(r30) */
  i += put_i32 (buf + i, 0x7c831b78);	/* or	r3, r4, r3 */

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

static void
ppc_emit_bit_xor (void)
{
  unsigned char buf[2 * 4];
  int i = 0;

  i += GEN_LDU (buf + i, 4, 30, 8);	/* ldu	r4, 8(r30) */
  i += put_i32 (buf + i, 0x7c831a78);	/* xor	r3, r4, r3 */

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

static void
ppc_emit_bit_not (void)
{
  unsigned char buf[4];
  int i = 0;

  i += put_i32 (buf, 0x7c6318f8);	/* nor	r3, r3, r3 */

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

static void
ppc_emit_equal (void)
{
  unsigned char buf[3 * 4];
  int i = 0;

  i += put_i32 (buf + i, 0x7c632278);	/* xor     r3,r3,r4 */
  i += put_i32 (buf + i, 0x7c630074);	/* cntlzd  r3,r3 */
  i += put_i32 (buf + i, 0x7863d182);	/* rldicl  r3,r3,58,6 */

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

static void
ppc_emit_less_signed (void)
{
  unsigned char buf[3 * 4];
  int i = 0;

  i += put_i32 (buf + i, 0x7fa32000);	/* cmpd    cr7,r3,r4 */
  i += put_i32 (buf + i, 0x7c701026);	/* mfocrf  r3,1 */
  i += put_i32 (buf + i, 0x5463effe);	/* rlwinm  r3,r3,29,31,31 */

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

static void
ppc_emit_less_unsigned (void)
{
  unsigned char buf[3 * 4];
  int i = 0;

  i += put_i32 (buf + i, 0x7fa32040);	/* cmpld    cr7,r3,r4 */
  i += put_i32 (buf + i, 0x7c701026);	/* mfocrf  r3,1 */
  i += put_i32 (buf + i, 0x5463effe);	/* rlwinm  r3,r3,29,31,31 */

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

static void
ppc_emit_ref (int size)
{
  unsigned char buf[4];
  int i = 0;

  switch (size)
    {
    case 1:
      i += put_i32 (buf + i, 0x88630000);	/* lbz 3,0(3) */
      break;
    case 2:
      i += put_i32 (buf + i, 0xa0630000);	/* lha 3,0(3) */
      break;
    case 4:
      i += put_i32 (buf + i, 0x80630000);	/* lwz 3,0(3) */
      break;
    case 8:
      i += put_i32 (buf + i, 0xe8630000);	/* ld 3,0(3) */
      break;
    }

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

static void
ppc_emit_if_goto (int *offset_p, int *size_p)
{
  unsigned char buf[4 * 4];
  int i = 0;

  i += GEN_MR (buf + i, 4, 3);		/* mr    r4, r3 */
  i += GEN_LDU (buf + i, 3, 30, 8);	/* ldu   r3, 8(r30) */
  i += put_i32 (buf + i, 0x2fa40000);	/* cmpdi cr7, r4, 0 */
  i += put_i32 (buf + i, 0x419e0000);	/* beq   cr7, <addr14> */

  if (offset_p)
    *offset_p = 12;
  if (size_p)
    *size_p = 14;

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

static void
ppc_emit_goto (int *offset_p, int *size_p)
{
  unsigned char buf[4];
  int i = 0;

  i += put_i32 (buf, 0x48000000);	/* b    <addr24> */

  if (offset_p)
    *offset_p = 0;
  if (size_p)
    *size_p = 24;

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

static void
ppc_write_goto_address (CORE_ADDR from, CORE_ADDR to, int size)
{
  int rel = to - from;
  uint32_t insn;
  int op6;
  unsigned char buf[4];

  read_inferior_memory (from, buf, 4);
  insn = get_i32 (buf);
  op6 = (insn >> 26) & 0x3f;

  switch (size)
    {
    case 14:
      if (op6 != 16)
	emit_error = 1;
      insn |= (rel & 0xfffc);
      break;
    case 24:
      if (op6 != 18)
	emit_error = 1;
      insn |= (rel & 0x3fffffc);
      break;
    }

  put_i32 (buf, insn);
  write_inferior_memory (from, buf, 4);
}

static void
ppc_emit_const (LONGEST num)
{
  unsigned char buf[5 * 4];
  int i = 0;

  if ((num >> 8) == 0)
    {
      /* li	3, num[7:0] */
      i += GEN_LI (buf + i, 3, num);
    }
  else if ((num >> 16) == 0)
    {
      /* li	3, 0
	 ori	3, 3, num[15:0] */
      i += GEN_LI (buf + i, 3, 0);
      i += GEN_ORI (buf + i, 3, 3, num);
    }
  else if ((num >> 32) == 0)
    {
      /* lis	3, num[31:16]
	 ori	3,3, num[15:0]
	 rldicl	3,3,0,32 */
      i += GEN_LIS (buf + i, 3, (num >> 16) & 0xffff);
      i += GEN_ORI (buf + i, 3, 3, num & 0xffff);
      i += put_i32 (buf + i, 0x78630020);
    }
  else
    {
      i += gen_limm64 (buf + i, 3, num);
    }

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

static void
ppc_emit_reg (int reg)
{
  unsigned char buf[8 * 8];
  int i = 0;

  i += GEN_MR (buf, 3, reg);	/* mr	r3, reg */
  i += gen_call (buf, get_raw_reg_func_addr ());

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

static void
ppc_emit_pop (void)
{
  unsigned char buf[4];
  int i = 0;

  i += GEN_LDU (buf, 3, 30, 8);	/* ldu	r3, 8(r30) */

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

static void
ppc_emit_stack_flush (void)
{
  unsigned char buf[8 * 4];
  int i = 0;

  /* Make bytecode stack is big enought.  Expand as need.  */

  /* addi	r4, r30, -(112 + 8)
     cmpd	cr7, r4, r1
     bgt	1f
   / ld		r4, 0(r1)
   | addi	r1, r1, -64
   | st		r4, 0(r1)
  1: st		r3, 0(r30)
     addi	r30, r30, -8 */

  i += GEN_ADDI (buf + i, 4, 30, -(112 + 8));
  i += put_i32 (buf + i, 0x7fa40800);
  i += put_i32 (buf + i, 0x41810010);
  {
    /* Expand stack.  */
    i += GEN_LD (buf + i, 4, 1, 0);
    i += GEN_ADDI (buf + i, 1, 1, -64);
    i += GEN_STD (buf + i, 4, 1, 0);
  }
  /* Push TOP in stack.  */
  i += GEN_STD (buf + i, 3, 30, 0);
  i += put_i32 (buf + i, 0x3bdefff8);

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

static void
ppc_emit_swap (void)
{
  unsigned char buf[3 * 4];
  int i = 0;

  i += GEN_LD (buf + i, 4, 30, 0);	/* ld	r4, 0(r30) */
  i += GEN_STD (buf + i, 3, 30, 0);	/* std	r3, 0(r30) */
  i += GEN_MR (buf + i, 3, 4);		/* mr	r3, r4 */

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

static void
ppc_emit_stack_adjust (int n)
{
  unsigned char buf[4];
  int i = 0;

  i += GEN_ADDI (buf, 30, 30, n << 3);	/* addi	r30, r30, (n << 3) */

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

static void
ppc_emit_call (CORE_ADDR fn)
{
  unsigned char buf[8 * 4];
  int i = 0;

  i += gen_call (buf + i, fn);		/* gen_call (fn) */

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

/* FN's prototype is `LONGEST(*fn)(int)'.  */

static void
ppc_emit_int_call_1 (CORE_ADDR fn, int arg1)
{
  unsigned char buf[8 * 4];
  int i = 0;

  /* Setup argument.  arg1 is a 16-bit value.  */
  i += GEN_LI (buf, 3, arg1);		/* li	r3, arg1 */
  i += gen_call (buf + i, fn);		/* gen_call (fn) */

  write_inferior_memory (current_insn_ptr, buf, i);
  current_insn_ptr += i;
}

/* FN's prototype is `void(*fn)(int,LONGEST)'.  */

static void
ppc_emit_void_call_2 (CORE_ADDR fn, int arg1)
{
  unsigned char buf[12 * 4];
  int i = 0;

  /* Save TOP */
  i += GEN_STD (buf, 3, 31, bytecode_framesize + 24);

  /* Setup argument.  arg1 is a 16-bit value.  */
  i += GEN_MR (buf + i, 3, 4);		/* mr	r4, r3 */
  i += GEN_LI (buf + i, 3, arg1);	/* li	r3, arg1 */
  i += gen_call (buf + i, fn);		/* gen_call (fn) */

  /* Restore TOP */
  i += GEN_LD (buf, 3, 31, bytecode_framesize + 24);
}

void
ppc_emit_eq_goto (int *offset_p, int *size_p)
{
}

void
ppc_emit_ne_goto (int *offset_p, int *size_p)
{
}

void
ppc_emit_lt_goto (int *offset_p, int *size_p)
{
}

void
ppc_emit_le_goto (int *offset_p, int *size_p)
{
}

void
ppc_emit_gt_goto (int *offset_p, int *size_p)
{
}

void
ppc_emit_ge_goto (int *offset_p, int *size_p)
{
}

struct emit_ops ppc_emit_ops_vector =
  {
    ppc_emit_prologue,
    ppc_emit_epilogue,
    ppc_emit_add,
    ppc_emit_sub,
    ppc_emit_mul,
    ppc_emit_lsh,
    ppc_emit_rsh_signed,
    ppc_emit_rsh_unsigned,
    ppc_emit_ext,
    ppc_emit_log_not,
    ppc_emit_bit_and,
    ppc_emit_bit_or,
    ppc_emit_bit_xor,
    ppc_emit_bit_not,
    ppc_emit_equal,
    ppc_emit_less_signed,
    ppc_emit_less_unsigned,
    ppc_emit_ref,
    ppc_emit_if_goto,
    ppc_emit_goto,
    ppc_write_goto_address,
    ppc_emit_const,
    ppc_emit_call,
    ppc_emit_reg,
    ppc_emit_pop,
    ppc_emit_stack_flush,
    ppc_emit_zero_ext,
    ppc_emit_swap,
    ppc_emit_stack_adjust,
    ppc_emit_int_call_1,
    ppc_emit_void_call_2,
    NULL, //ppc_emit_eq_goto,
    NULL, //ppc_emit_ne_goto,
    NULL, //ppc_emit_lt_goto,
    NULL, //ppc_emit_le_goto,
    NULL, //ppc_emit_gt_goto,
    NULL, //ppc_emit_ge_goto
  };

static struct emit_ops *
ppc_emit_ops (void)
{
  return &ppc_emit_ops_vector;
}

static int
ppc_supports_range_stepping (void)
{
  return 1;
}
#endif

/* Provide only a fill function for the general register set.  ps_lgetregs
   will use this for NPTL support.  */

static void ppc_fill_gregset (struct regcache *regcache, void *buf)
{
  int i;

  for (i = 0; i < 32; i++)
    ppc_collect_ptrace_register (regcache, i, (char *) buf + ppc_regmap[i]);

  for (i = 64; i < 70; i++)
    ppc_collect_ptrace_register (regcache, i, (char *) buf + ppc_regmap[i]);

  for (i = 71; i < 73; i++)
    ppc_collect_ptrace_register (regcache, i, (char *) buf + ppc_regmap[i]);
}

#define SIZEOF_VSXREGS 32*8

static void
ppc_fill_vsxregset (struct regcache *regcache, void *buf)
{
  int i, base;
  char *regset = buf;

  if (!(ppc_hwcap & PPC_FEATURE_HAS_VSX))
    return;

  base = find_regno (regcache->tdesc, "vs0h");
  for (i = 0; i < 32; i++)
    collect_register (regcache, base + i, &regset[i * 8]);
}

static void
ppc_store_vsxregset (struct regcache *regcache, const void *buf)
{
  int i, base;
  const char *regset = buf;

  if (!(ppc_hwcap & PPC_FEATURE_HAS_VSX))
    return;

  base = find_regno (regcache->tdesc, "vs0h");
  for (i = 0; i < 32; i++)
    supply_register (regcache, base + i, &regset[i * 8]);
}

#define SIZEOF_VRREGS 33*16+4

static void
ppc_fill_vrregset (struct regcache *regcache, void *buf)
{
  int i, base;
  char *regset = buf;

  if (!(ppc_hwcap & PPC_FEATURE_HAS_ALTIVEC))
    return;

  base = find_regno (regcache->tdesc, "vr0");
  for (i = 0; i < 32; i++)
    collect_register (regcache, base + i, &regset[i * 16]);

  collect_register_by_name (regcache, "vscr", &regset[32 * 16 + 12]);
  collect_register_by_name (regcache, "vrsave", &regset[33 * 16]);
}

static void
ppc_store_vrregset (struct regcache *regcache, const void *buf)
{
  int i, base;
  const char *regset = buf;

  if (!(ppc_hwcap & PPC_FEATURE_HAS_ALTIVEC))
    return;

  base = find_regno (regcache->tdesc, "vr0");
  for (i = 0; i < 32; i++)
    supply_register (regcache, base + i, &regset[i * 16]);

  supply_register_by_name (regcache, "vscr", &regset[32 * 16 + 12]);
  supply_register_by_name (regcache, "vrsave", &regset[33 * 16]);
}

struct gdb_evrregset_t
{
  unsigned long evr[32];
  unsigned long long acc;
  unsigned long spefscr;
};

static void
ppc_fill_evrregset (struct regcache *regcache, void *buf)
{
  int i, ev0;
  struct gdb_evrregset_t *regset = buf;

  if (!(ppc_hwcap & PPC_FEATURE_HAS_SPE))
    return;

  ev0 = find_regno (regcache->tdesc, "ev0h");
  for (i = 0; i < 32; i++)
    collect_register (regcache, ev0 + i, &regset->evr[i]);

  collect_register_by_name (regcache, "acc", &regset->acc);
  collect_register_by_name (regcache, "spefscr", &regset->spefscr);
}

static void
ppc_store_evrregset (struct regcache *regcache, const void *buf)
{
  int i, ev0;
  const struct gdb_evrregset_t *regset = buf;

  if (!(ppc_hwcap & PPC_FEATURE_HAS_SPE))
    return;

  ev0 = find_regno (regcache->tdesc, "ev0h");
  for (i = 0; i < 32; i++)
    supply_register (regcache, ev0 + i, &regset->evr[i]);

  supply_register_by_name (regcache, "acc", &regset->acc);
  supply_register_by_name (regcache, "spefscr", &regset->spefscr);
}

static struct regset_info ppc_regsets[] = {
  /* List the extra register sets before GENERAL_REGS.  That way we will
     fetch them every time, but still fall back to PTRACE_PEEKUSER for the
     general registers.  Some kernels support these, but not the newer
     PPC_PTRACE_GETREGS.  */
  { PTRACE_GETVSXREGS, PTRACE_SETVSXREGS, 0, SIZEOF_VSXREGS, EXTENDED_REGS,
  ppc_fill_vsxregset, ppc_store_vsxregset },
  { PTRACE_GETVRREGS, PTRACE_SETVRREGS, 0, SIZEOF_VRREGS, EXTENDED_REGS,
    ppc_fill_vrregset, ppc_store_vrregset },
  { PTRACE_GETEVRREGS, PTRACE_SETEVRREGS, 0, 32 * 4 + 8 + 4, EXTENDED_REGS,
    ppc_fill_evrregset, ppc_store_evrregset },
  { 0, 0, 0, 0, GENERAL_REGS, ppc_fill_gregset, NULL },
  { 0, 0, 0, -1, -1, NULL, NULL }
};

static struct usrregs_info ppc_usrregs_info =
  {
    ppc_num_regs,
    ppc_regmap,
  };

static struct regsets_info ppc_regsets_info =
  {
    ppc_regsets, /* regsets */
    0, /* num_regsets */
    NULL, /* disabled_regsets */
  };

static struct regs_info regs_info =
  {
    NULL, /* regset_bitmap */
    &ppc_usrregs_info,
    &ppc_regsets_info
  };

static const struct regs_info *
ppc_regs_info (void)
{
  return &regs_info;
}

struct linux_target_ops the_low_target = {
  ppc_arch_setup,
  ppc_regs_info,
  ppc_cannot_fetch_register,
  ppc_cannot_store_register,
  NULL, /* fetch_register */
  ppc_get_pc,
  ppc_set_pc,
  (const unsigned char *) &ppc_breakpoint,
  ppc_breakpoint_len,
  NULL, /* breakpoint_reinsert_addr */
  0, /* decr_pc_after_break */
  ppc_breakpoint_at,
  ppc_supports_z_point_type, /* supports_z_point_type */
  ppc_insert_point,
  ppc_remove_point,
  NULL, /* stopped_by_watchpoint */
  NULL, /* stopped_data_address */
  ppc_collect_ptrace_register,
  ppc_supply_ptrace_register,
  NULL, /* siginfo_fixup */
  NULL, /* linux_new_process */
  NULL, /* linux_new_thread */
  NULL, /* linux_prepare_to_resume */
  NULL, /* linux_process_qsupported */
#ifdef __powerpc64__
  ppc_supports_tracepoints,
#else
  NULL,
#endif
  NULL, /* get_thread_area */
#ifdef __powerpc64__
  ppc_install_fast_tracepoint_jump_pad,
  ppc_emit_ops,
#else
  NULL, /* install_fast_tracepoint_jump_pad */
  NULL, /* emit_ops */
#endif
  ppc_get_min_fast_tracepoint_insn_len,
  ppc_supports_range_stepping,
};

void
initialize_low_arch (void)
{
  /* Initialize the Linux target descriptions.  */

  init_registers_powerpc_32l ();
  init_registers_powerpc_altivec32l ();
  init_registers_powerpc_cell32l ();
  init_registers_powerpc_vsx32l ();
  init_registers_powerpc_isa205_32l ();
  init_registers_powerpc_isa205_altivec32l ();
  init_registers_powerpc_isa205_vsx32l ();
  init_registers_powerpc_e500l ();
  init_registers_powerpc_64l ();
  init_registers_powerpc_altivec64l ();
  init_registers_powerpc_cell64l ();
  init_registers_powerpc_vsx64l ();
  init_registers_powerpc_isa205_64l ();
  init_registers_powerpc_isa205_altivec64l ();
  init_registers_powerpc_isa205_vsx64l ();

  initialize_regsets_info (&ppc_regsets_info);
}
