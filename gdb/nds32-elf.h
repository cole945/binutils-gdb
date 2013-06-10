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


/* This file is used for elc-check when downloading an ELF file to
   target board, and it is synced from nds32-sid.  */

#ifndef _NDS32_ELF_CHECK_
#define _NDS32_ELF_CHECK_

#ifdef TEST_ELF_CHECK_FUNC
#include <stdio.h>
#include <stdlib.h>
#endif

#include <stdio.h>

enum
{
  TARGET_ISA_INFO_LEN = 2000
};

enum ELF_HEADER_FLAG_FIELD
{
  EHFF_ARCH_VER = 0xF0000000, EHFF_ARCH_VER_SHIFT = 28,
  EHFF_HAS_PIC = 0x04000000,
  EHFF_ISA_FPU_MAC = 0x01000000,
  EHFF_FPU_REG = 0x00C00000, EHFF_FPU_REG_SHIFT = 22,
  EHFF_ISA_L2C = 0x00200000,
  EHFF_ISA_NO_MAC = 0x00100000,
  EHFF_ISA_MAC_DX = 0x00100000,
  EHFF_ISA_FPU_DP = 0x00080000,
  EHFF_ISA_SATURATION = 0x00020000,
  EHFF_REDUCED_REGS = 0x00010000,
  EHFF_ISA_STRING = 0x00008000,
  EHFF_ISA_16BIT = 0x00004000,
  EHFF_ISA_IFC = 0x00004000,
  EHFF_ISA_DIV = 0x00002000,
  EHFF_ISA_DIV_DX = 0x00002000,
  EHFF_ISA_AUDIO = 0x00001000,
  EHFF_ISA_FPU_SP = 0x00000800,
  EHFF_ISA_EXT2 = 0x00000400,
  EHFF_ISA_EXT = 0x00000200,
  EHFF_ISA_EIT = 0x00000100,
  EHFF_ISA_MFUSR_PC = 0x00000100,
  EHFF_ABI_VER = 0x000000F0,
  EHFF_ELF_VER = 0x0000000F, EHFF_ELF_VER_SHIFT = 0,
};


enum ELF_HEADER_FLAG_FIELD_ARCH_VER
{
  EHFF_ARCH_VER_RESERVED = 0x0,
  EHFF_ARCH_VER_V1 = 0x1,
  EHFF_ARCH_VER_V2 = 0x2,
  EHFF_ARCH_VER_V3 = 0x3,
  EHFF_ARCH_VER_V3M = 0x4,
};

static char *EHFF_ARCH_VER_MSG[] =
{
  "RESERVED",
  "BASE V1",
  "BASE V2",
  "BASE V3",
  "BASE V3M",
};


/* 4-bit for ABI signature, allow up to 16 ABIs.
   0 : for OLD ABI V0, phase out
   1 : for V1 , starting with V0 toolchain
   2 : for V2
   3 : for V2FP (fs0, fs1 as function parameter)
   4 : for AABI
   Only old N1213HC use V0.
   New ABI is used due to return register is changed to r0 from r5.  */
#define E_NDS_ABI_V0		0x00000000
#define E_NDS_ABI_V1		0x00000010
#define E_NDS_ABI_V2		0x00000020
#define E_NDS_ABI_V2FP		0x00000030
#define E_NDS_ABI_AABI		0x00000040

/* This flag signifies the version of Andes ELF
   note :
   1. v1.3.1 and beyond is accompanying with Baseline ISA 1.0b/2.0/... in ELF.
   2. v1.3.1 is accompanying with Baseline ISA 1.0b in ELF.
	... | MAC    | ... | DIV    | ...
   3. v1.3.1 is accompanying with Baseline ISA 2.0 and beyond in ELF.
	... | MAC_DX | ... | DIV_DX | ...  */
enum ELF_HEADER_FLAG_FIELD_ELF_VER
{
  EHFF_ELF_VER_1_3_0 = 0x0,
  EHFF_ELF_VER_1_3_1 = 0x1,
  EHFF_ELF_VER_1_4_0 = 0x2,
};

static char *EHFF_ELF_VER_MSG[] =
{
  "1.3.0",
  "1.3.1",
  "1.4.0",
};

#define INDEX_HW_MASK		0x00007c00
#define INDEX_HW_CPU		0x00000000
#define INDEX_HW_FPU		0x00000400
#define INDEX_HW_AUDIO		0x00000800
#define HW_IS_CPU(sr)		((sr & INDEX_HW_MASK) == INDEX_HW_CPU)
#define HW_IS_FPU(sr)		((sr & INDEX_HW_MASK) == INDEX_HW_FPU)
#define HW_IS_AUDIO(sr)		((sr & INDEX_HW_MASK) == INDEX_HW_AUDIO)

#define SR_INDEX_MASK		0x000003ff
#define SR_INDEX(sr)		(sr & SR_INDEX_MASK)
#define CPU_SR_INDEX(x,y,z)	((x << 7) + (y << 3) + z)
#define FPU_SR_FPCFG()		(INDEX_HW_FPU)

/* FPU-belonged system registers.  */
#define SR_FPU_FPCFG		0x00

#define SR_NOT_EXIST		0xffffffff

typedef unsigned int (*CALLBACK_FUNC) (unsigned int index);

static char *NEC_MSG_FPU_reg[5] =
{
  "N/A",
  " 8SP/ 4DP",
  "16SP/ 8DP",
  "32SP/16DP",
  "32SP/32DP"
};

static char *NEC_MSG_endian[2] =
{
  "little",
  "big"
};

static char *NEC_MSG_ISA[2] =
{
  "OFF",
  "ON"
};

#define EM_NDS32		167
#if defined elf_check_swap_2 || defined elf_check_swap_4
#error "ERROR : elf_check_swap_2 and elf_check_swap_4 are multiple defined"
#endif
#define elf_check_swap_2(data)	(((data & 0x0000ff00) >> 8) \
				| ((data & 0x000000ff) << 8))
#define elf_check_swap_4(data)	(((data & 0xff000000) >> 24) \
				| ((data & 0x00ff0000) >> 8) \
				| ((data & 0x0000ff00) << 8) \
				| ((data & 0x000000ff) << 24))

#define MSC_CFG_BASEV		0x0000e000

#define CPU_VER_EXT		0x00000001
#define CPU_VER_A16		0x00000002
#define CPU_VER_EXT2		0x00000004
#define CPU_VER_FPU		0x00000008
#define CPU_VER_STRING		0x00000010
#define CPU_VER_SATURATION	0x00000020

#define MSC_CFG_DIV		0x00000020
#define MSC_CFG_MAC		0x00000040
#define MSC_CFG_L2C		0x00000200
#define MSC_CFG_REDUCED_REG	0x00000400
#define MSC_CFG_NOD		0x00010000
#define MSC_CFG_AUDIO		0x00000180
#define MSC_CFG_AUDIO_NONE	0x00000000
#define MSC_CFG_IFC		0x00080000
#define MSC_CFG_MCU		0x00100000
#define MSC_CFG_EX9IT		0x01000000

#define MMU_CFG_DE		0x04000000

typedef enum ELF_Fail_Type
{
  EFT_NONE,
  EFT_WARNING,
  EFT_ERROR
} ELF_Fail_Type;

/* NDS32 Elf Check print.  */

static inline void
nec_print (char *buf, ELF_Fail_Type type, char *name, char *cpu, char *elf,
	   char *error_message)
{
  char temp[100];

  switch (type)
    {
    case EFT_NONE:
      sprintf (temp, "\t | %9s | %9s | %14s\n", cpu, elf, name);
      break;
    case EFT_WARNING:
      sprintf (temp, "\t?| %9s | %9s | %14s Warning: %s\n", cpu, elf, name,
	       error_message);
      break;
    case EFT_ERROR:
      sprintf (temp, "\t!| %9s | %9s | %14s Error: %s\n", cpu, elf, name,
	       error_message);
      break;
    }
  strcat (buf, temp);
}

static inline int
nec_check_bool (char *buf, ELF_Fail_Type type, char *isa, int cpu, int elf)
{
  int code;

  if (cpu)
    cpu = 1;
  if (elf)
    elf = 1;
  if ((cpu == 0) && (elf == 1))
    code = 1;
  else
    {
      code = 0;
      type = EFT_NONE;
    }
  nec_print (buf, type, isa, NEC_MSG_ISA[cpu], NEC_MSG_ISA[elf],
	     "Not supported by CPU");
  return code;
}

static inline ELF_Fail_Type
elf_ver_and_arch_ver_compatibility_check (unsigned int elf_ver,
					  unsigned int arch_ver)
{
  switch (elf_ver)
    {
    case EHFF_ELF_VER_1_3_0:
      switch (arch_ver)
	{
	case EHFF_ARCH_VER_V1:
	  return EFT_NONE;
	default:
	  return EFT_ERROR;
	}
    case EHFF_ELF_VER_1_3_1:
      switch (arch_ver)
	{
	case EHFF_ARCH_VER_V1:
	case EHFF_ARCH_VER_V2:
	case EHFF_ARCH_VER_V3M:
	  return EFT_NONE;
	default:
	  return EFT_ERROR;
	}
    case EHFF_ELF_VER_1_4_0:
      switch (arch_ver)
	{
	case EHFF_ARCH_VER_V1:
	case EHFF_ARCH_VER_V2:
	case EHFF_ARCH_VER_V3:
	case EHFF_ARCH_VER_V3M:
	  return EFT_NONE;
	default:
	  return EFT_ERROR;
	}
    }

  return EFT_ERROR;
}

static inline ELF_Fail_Type
arch_ver_check (unsigned int CPU, unsigned int ELF)
{
  switch (CPU)
    {
    case EHFF_ARCH_VER_V1:
      switch (ELF)
	{
	case EHFF_ARCH_VER_V1:
	  return EFT_NONE;
	default:
	  return EFT_ERROR;
	}
    case EHFF_ARCH_VER_V2:
      switch (ELF)
	{
	case EHFF_ARCH_VER_V1:
	case EHFF_ARCH_VER_V2:
	  return EFT_NONE;
	default:
	  return EFT_ERROR;
	}
    case EHFF_ARCH_VER_V3:
      switch (ELF)
	{
	case EHFF_ARCH_VER_V1:
	case EHFF_ARCH_VER_V2:
	case EHFF_ARCH_VER_V3:
	case EHFF_ARCH_VER_V3M:
	  return EFT_NONE;
	default:
	  return EFT_ERROR;
	}
    case EHFF_ARCH_VER_V3M:
      switch (ELF)
	{
	case EHFF_ARCH_VER_V3M:
	  return EFT_NONE;
	default:
	  return EFT_ERROR;
	}
    }

  return EFT_ERROR;
}

/* buf: Buffer for Target ISA Info.
   len: Length of buffer (at least 300 chars in length)
   buf_status: status of buffer.  0: ok, 1: overflow.  */

static inline unsigned int
elf_check (unsigned char *ehdr, CALLBACK_FUNC reg_read_callback, char *buf,
	   unsigned int len, unsigned int *buf_status)
{
  unsigned int SR_msc_cfg, SR_cpu_ver, SR_mmu_cfg;
  unsigned int fpcfg, fucop_exist, fpu_mount;
  unsigned int CPU_DIV_DX_ISA, CPU_MAC_DX_ISA;
  unsigned int eflag, ELF_arch_ver, ELF_elf_ver, CPU_arch_ver;
  unsigned short machine;
  char big_endian_elf, big_endian_cpu;
  char temp[100];
  char temp_cpu[10];
  char temp_elf[10];
  int n_error, n_warning;
  int CPU_support;
  char FPU_reg_elf, FPU_reg_cpu;
  ELF_Fail_Type error_type;
  unsigned int is_N1213HC;

  n_error = 0;
  n_warning = 0;

  buf[0] = '\0';
  *buf_status = 0;
  if (len < TARGET_ISA_INFO_LEN)
    *buf_status = 1;

  SR_cpu_ver = reg_read_callback (CPU_SR_INDEX (0, 0, 0));
  SR_msc_cfg = reg_read_callback (CPU_SR_INDEX (0, 4, 0));
  SR_mmu_cfg = reg_read_callback (CPU_SR_INDEX (0, 3, 0));

  switch (*((char *) (ehdr + 5)))
    {
    case 1:
      big_endian_elf = 0;
      break;
    case 2:
      big_endian_elf = 1;
      break;
    default:
      sprintf (buf,
	       "Error: Unknown ELF endian %d.\n", *((char *) (ehdr + 5)));
      return 1;
    }

  if (SR_mmu_cfg & MMU_CFG_DE)
    big_endian_cpu = 1;
  else
    big_endian_cpu = 0;


  if (((SR_cpu_ver & 0xffff0000) == 0x0c010000)
      || ((SR_cpu_ver & 0xffff0000) == 0x0c020000))
    is_N1213HC = 1;
  else
    is_N1213HC = 0;

  /*  N1213HC has the following features:
	no mfusr_pc
	d0/d1 register
	use V0 toolchain
	mac_dx
	no div_dx
	pex1  */

  /* 20091106 note :
     1. In term of OS, elf_check() would be used in OS kernel and ld.so.
     2. Since OS is running on SID, eflag/machine did not need endian
	conversion for big endian format.
     3. Later, elf_check interface is going to cover "OS" case by
	adding a new parameter.  */

#ifdef ELF_CHECKING_OS
  eflag = *((unsigned int *) (ehdr + 36));
  machine = *((unsigned short *) (ehdr + 18));
#else
  eflag = (big_endian_elf == 0)
	  ? *((unsigned int *) (ehdr + 36))
	  : elf_check_swap_4 (*((unsigned int *) (ehdr + 36)));
  machine = (big_endian_elf == 0)
	    ? *((unsigned short *) (ehdr + 18))
	    : elf_check_swap_2 (*((unsigned short *) (ehdr + 18)));
#endif

  ELF_arch_ver = (eflag & EHFF_ARCH_VER) >> EHFF_ARCH_VER_SHIFT;
  ELF_elf_ver = (eflag & EHFF_ELF_VER) >> EHFF_ELF_VER_SHIFT;

  CPU_arch_ver = ((SR_msc_cfg & MSC_CFG_BASEV) >> 13) + 1;
  if (CPU_arch_ver == 3)
    if (SR_msc_cfg & MSC_CFG_MCU)
      CPU_arch_ver = 4;

  /*Basic version check
    1. ELF version check
    2. Architecture version check
    3. Machine check */
  if (ELF_elf_ver > EHFF_ELF_VER_1_4_0)
    {
      sprintf (temp, "Error: unsupport ELF version: 0x%x\n", ELF_elf_ver);
      strcat (buf, temp);
      return 1;
    }
  sprintf (temp, "ELF version: %s\n", EHFF_ELF_VER_MSG[ELF_elf_ver]);
  strcat (buf, temp);

  if (elf_ver_and_arch_ver_compatibility_check (ELF_elf_ver, ELF_arch_ver)
      == EFT_ERROR)
    {
      sprintf (temp, "Error: architecture version is not supported "
		     "in this ELF version: %s\n",
	       EHFF_ARCH_VER_MSG[ELF_arch_ver]);
      strcat (buf, temp);
      return 1;
    }

  sprintf (temp, "\t   %9s   %9s  \n", "CPU", "ELF");
  strcat (buf, temp);
  if (big_endian_cpu != big_endian_elf)
    {
      error_type = EFT_ERROR;
      n_error++;
    }
  else
    error_type = EFT_NONE;

  nec_print (buf, error_type, "endianess", NEC_MSG_endian[big_endian_cpu],
	     NEC_MSG_endian[big_endian_elf], "endianess mismatch");

  if (EM_NDS32 != machine)
    {
      error_type = EFT_ERROR;
      n_error++;
    }
  else
    error_type = EFT_NONE;
  sprintf (temp_cpu, "%d", EM_NDS32);
  sprintf (temp_elf, "%d", machine);
  nec_print (buf, error_type, "machine", temp_cpu, temp_elf, "wrong machine");

  error_type = arch_ver_check (CPU_arch_ver, ELF_arch_ver);
  if (error_type == EFT_ERROR)
    n_error++;
  nec_print (buf, error_type, "BASELINE ISA", EHFF_ARCH_VER_MSG[CPU_arch_ver],
	     EHFF_ARCH_VER_MSG[ELF_arch_ver], "BASELINE ISA mismatch");

  /* Prepare reference variables
     1. DIV, MAC, DX
     2. FPU */

  CPU_MAC_DX_ISA = 0;
  CPU_DIV_DX_ISA = 0;
  if (is_N1213HC)
    {
      if (SR_msc_cfg & MSC_CFG_MAC)
	CPU_MAC_DX_ISA = 1;
      if (SR_msc_cfg & MSC_CFG_DIV)
	CPU_DIV_DX_ISA = 1;
    }
  else
    {
      switch (CPU_arch_ver)
	{
	case EHFF_ARCH_VER_V1:
	  if (SR_msc_cfg & MSC_CFG_MAC)
	    CPU_MAC_DX_ISA = 1;
	  if (SR_msc_cfg & MSC_CFG_DIV)
	    CPU_DIV_DX_ISA = 1;
	  break;
	case EHFF_ARCH_VER_V2:
	case EHFF_ARCH_VER_V3:
	case EHFF_ARCH_VER_V3M:
	  if (!(SR_msc_cfg & MSC_CFG_NOD))
	    {
	      CPU_MAC_DX_ISA = 1;
	      CPU_DIV_DX_ISA = 1;
	    }
	  break;
	}
    }
  fpu_mount = 0;
  if (SR_cpu_ver & CPU_VER_FPU)
    {
      fucop_exist = reg_read_callback (CPU_SR_INDEX (0, 5, 0));
      if (fucop_exist & 0x80000000)
	{
	  fpu_mount = 1;
	  fpcfg = reg_read_callback (FPU_SR_FPCFG ());
	}
      else
	fpu_mount = 0;
    }

  /* Parse Configuration field (bit 27~8)
     bit 27 Reserved
     bit 26 PIC
     bit 25 Reserved
     bit 24  */
  CPU_support = 0;
  if (fpu_mount)
    if (fpcfg & 0x00000010)
      CPU_support = 1;
  n_error += nec_check_bool (buf, EFT_ERROR, "FPU MAC ISA", CPU_support,
			     eflag & EHFF_ISA_FPU_MAC);

  /* bit 23~22  */
  if (fpu_mount)
    FPU_reg_cpu = ((fpcfg >> 2) & 0x3) + 1;
  else
    FPU_reg_cpu = 0;

  if (eflag & (EHFF_ISA_FPU_SP | EHFF_ISA_FPU_DP | EHFF_ISA_FPU_MAC))
    FPU_reg_elf = ((eflag & EHFF_FPU_REG) >> EHFF_FPU_REG_SHIFT) + 1;
  else
    FPU_reg_elf = 0;
  if (FPU_reg_elf > FPU_reg_cpu)
    {
      error_type = EFT_ERROR;
      n_error++;
    }
  else
    error_type = EFT_NONE;

  nec_print (buf, error_type, "FPU REGISTER", NEC_MSG_FPU_reg[FPU_reg_cpu],
	     NEC_MSG_FPU_reg[FPU_reg_elf],
	     "FPU REGISTERS not supported by CPU");
  /* bit 21  */
  n_error += nec_check_bool (buf, EFT_ERROR, "L2C ISA",
			     SR_msc_cfg & MSC_CFG_L2C, eflag & EHFF_ISA_L2C);

  /* bit 20
     MAC_DX check
     Target Machine certainly has MAC_DX under the following conditions:
     1. Baseline V1 ISA && N1213-U143H (hardcore version).
     2. Baseline V1 ISA && MSC_CFG.MAC (softcore version).
     3. Baseline V2 ISA && D0/D1 support.
     4. Baseline V3 ISA && D0/D1 support. */

  switch (ELF_arch_ver)
    {
    case EHFF_ARCH_VER_V1:
      n_error +=
	nec_check_bool (buf, EFT_ERROR, "MAC DX ISA", CPU_MAC_DX_ISA,
			!(eflag & EHFF_ISA_NO_MAC));
      break;
    case EHFF_ARCH_VER_V2:
    case EHFF_ARCH_VER_V3:
    case EHFF_ARCH_VER_V3M:
      n_error +=
	nec_check_bool (buf, EFT_ERROR, "MAC DX ISA", CPU_MAC_DX_ISA,
			eflag & EHFF_ISA_MAC_DX);
      break;
    }

  /* bit 19  */
  CPU_support = 0;
  if (fpu_mount)
    if (fpcfg & 0x00000002)
      CPU_support = 1;
  n_error += nec_check_bool (buf, EFT_ERROR, "FPU DP ISA", CPU_support,
			     eflag & EHFF_ISA_FPU_DP);

  /* bit 18 Reserved  */
  /* bit 17  */
  switch (ELF_elf_ver)
    {
    case EHFF_ELF_VER_1_3_0:
    case EHFF_ELF_VER_1_3_1:
      break;
    case EHFF_ELF_VER_1_4_0:
      switch (ELF_arch_ver)
	{
	case EHFF_ARCH_VER_V3:
	case EHFF_ARCH_VER_V3M:
	  n_error += nec_check_bool (buf, EFT_ERROR, "SATURATION ISA",
				     SR_cpu_ver & CPU_VER_SATURATION,
				     eflag & EHFF_ISA_SATURATION);
	  break;
	}
      break;
    }

  /* bit 16 */
  if (is_N1213HC)
    CPU_support = 1;
  else
    {
      if (SR_msc_cfg & MSC_CFG_REDUCED_REG)
	CPU_support = 0;
      else
	CPU_support = 1;
    }
  n_error += nec_check_bool (buf, EFT_ERROR, "32 GPR", CPU_support,
			     (eflag & EHFF_REDUCED_REGS) == 0);

  /* bit 15 */
  n_error +=
    nec_check_bool (buf, EFT_ERROR, "STRING ISA", SR_cpu_ver & CPU_VER_STRING,
		    eflag & EHFF_ISA_STRING);

  /* bit 14 */
  switch (ELF_elf_ver)
    {
    case EHFF_ELF_VER_1_3_0:
    case EHFF_ELF_VER_1_3_1:
      n_error +=
	nec_check_bool (buf, EFT_ERROR, "16-BIT ISA",
			SR_cpu_ver & CPU_VER_A16, eflag & EHFF_ISA_16BIT);
      break;
    case EHFF_ELF_VER_1_4_0:
      switch (ELF_arch_ver)
	{
	case EHFF_ARCH_VER_V1:
	case EHFF_ARCH_VER_V2:
	  n_error +=
	    nec_check_bool (buf, EFT_ERROR, "16-BIT ISA",
			    SR_cpu_ver & CPU_VER_A16, eflag & EHFF_ISA_16BIT);
	  break;
	case EHFF_ARCH_VER_V3:
	case EHFF_ARCH_VER_V3M:
	  n_error +=
	    nec_check_bool (buf, EFT_ERROR, "IFC ISA",
			    SR_msc_cfg & MSC_CFG_IFC, eflag & EHFF_ISA_IFC);
	  break;
	}
      break;
    }

  /* bit 13  */
  switch (ELF_arch_ver)
    {
    case EHFF_ARCH_VER_V1:
      n_error +=
	nec_check_bool (buf, EFT_ERROR, "DIV DX ISA", CPU_DIV_DX_ISA,
			eflag & EHFF_ISA_DIV);
      break;
    case EHFF_ARCH_VER_V2:
    case EHFF_ARCH_VER_V3:
    case EHFF_ARCH_VER_V3M:
      n_error +=
	nec_check_bool (buf, EFT_ERROR, "DIV DX ISA", CPU_DIV_DX_ISA,
			eflag & EHFF_ISA_DIV_DX);
      break;
    }

  /* bit 12  */
  n_error += nec_check_bool (buf, EFT_ERROR, "AUDIO/DSP ISA",
			     SR_msc_cfg & MSC_CFG_AUDIO,
			     eflag & EHFF_ISA_AUDIO);
  /* bit 11  */
  CPU_support = 0;
  if (fpu_mount)
    if (fpcfg & 0x00000001)
      CPU_support = 1;
  n_error += nec_check_bool (buf, EFT_ERROR, "FPU SP ISA", CPU_support,
			     eflag & EHFF_ISA_FPU_SP);

  /* bit 10  */
  n_error += nec_check_bool (buf, EFT_ERROR, "PEX2 ISA",
			     SR_cpu_ver & CPU_VER_EXT2,
			     eflag & EHFF_ISA_EXT2);

  /* bit 9  */
  n_error += nec_check_bool (buf, EFT_ERROR, "PEX1 ISA",
			     SR_cpu_ver & CPU_VER_EXT,
			     eflag & EHFF_ISA_EXT);

  /* bit 8  */
  CPU_support = 0;
  if (is_N1213HC)
    CPU_support = 1;
  else if (CPU_arch_ver == EHFF_ARCH_VER_V3M)
    CPU_support = 1;
  switch (ELF_elf_ver)
    {
    case EHFF_ELF_VER_1_3_0:
    case EHFF_ELF_VER_1_3_1:
      n_error += nec_check_bool (buf, EFT_ERROR, "MFUSR_PC ISA", CPU_support,
				 eflag & EHFF_ISA_MFUSR_PC);
      break;
    case EHFF_ELF_VER_1_4_0:
      switch (ELF_arch_ver)
	{
	case EHFF_ARCH_VER_V1:
	case EHFF_ARCH_VER_V2:
	  n_error += nec_check_bool (buf, EFT_ERROR, "MFUSR_PC ISA", CPU_support,
				     eflag & EHFF_ISA_MFUSR_PC);
	  break;
	case EHFF_ARCH_VER_V3:
	case EHFF_ARCH_VER_V3M:
	  n_error += nec_check_bool (buf, EFT_ERROR, "EIT ISA",
				     SR_msc_cfg & MSC_CFG_EX9IT,
				     eflag & EHFF_ISA_EIT);
	  break;
	}
      break;
    }

  if (n_error)
    {
      strcat (buf, "Error: ELF and CPU mismatch\n");
      sprintf (temp, "Total Error: %d\n", n_error);
      strcat (buf, temp);

      strcat (buf, "Usage error, Consult Andes Toolchains and their "
		   "compatible Andes cores for the Toolchain-CPU "
		   "compatibility.\n");
      strcat (buf, "The Loader Checking can be disabled under "
		   "Debug Configuration.\n");
    }
  else
    strcat (buf, "NDS32 ELF checking pass\n");

  if (n_warning)
    {
      sprintf (temp, "Total Warning: %d\n", n_warning);
      strcat (buf, temp);
    }

  return n_error;
}

#undef elf_check_swap_2
#undef elf_check_swap_4

#undef MSC_CFG_BASEV

#undef CPU_VER_STRING
#undef CPU_VER_EXT
#undef CPU_VER_A16
#undef CPU_VER_EXT2
#undef CPU_VER_FPU
#undef CPU_VER_SATURATION

#undef MSC_CFG_DIV
#undef MSC_CFG_MAC
#undef MSC_CFG_L2C
#undef MSC_CFG_REDUCED_REG
#undef MSC_CFG_NOD
#undef MSC_CFG_AUDIO
#undef MSC_CFG_AUDIO_NONE
#undef MSC_CFG_IFC
#undef MSC_CFG_MCU
#undef MSC_CFG_EX9IT

#undef MMU_CFG_DE

#endif
