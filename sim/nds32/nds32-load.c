/* Simulator for NDS32 processors.

   Copyright (C) 2011-2013 Free Software Foundation, Inc.
   Contributed by Andes Technology Corporation.

   This file is part of simulators.

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

#include "config.h"

#include <stdlib.h>
#if defined (__linux__) || defined (__CYGWIN__)
#include <sys/mman.h>
#include <sys/resource.h>
#elif defined (__WIN32__)
#include "mingw32-hdep.h"
#endif

#include "bfd.h"
#include "elf-bfd.h"
#include "sim-main.h"
#include "sim-utils.h"
#include "sim-assert.h"

#include "nds32-sim.h"
#include "nds32-mm.h"
#include "nds32-syscall.h"

static void
nds32_simple_osabi_sniff_sections (bfd *abfd, asection *sect, void *obj)
{
  const char *name;
  int *osabi = (int *) obj;

  name = bfd_get_section_name (abfd, sect);
  if (strcmp (name, ".note.ABI-tag") == 0)
    *osabi = 1;
}

/* Calculate the total size for mapping an ELF.  */

static int
total_mapping_size (Elf_Internal_Phdr *phdr, int n)
{
  int i;
  int first = -1;
  int last = - 1;

  for (i = 0; i < n; i++)
    {
      if (phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0)
	continue;

      if (first == -1)
	first = i;
      last = i;
    }

  return phdr[last].p_vaddr +  phdr[last].p_memsz - phdr[first].p_vaddr;
}


static void
nds32_alloc_memory (SIM_DESC sd, struct bfd *abfd)
{
  int osabi = 0;
  int i;
  char buf[1024];
  Elf_Internal_Phdr *phdr;
  Elf_Internal_Phdr *interp_phdr = NULL;
  uint32_t off;
  uint32_t len;
  int sysroot_len;
  uint32_t interp_base;
  SIM_CPU *cpu = STATE_CPU (sd, 0);
  struct rlimit limit;
  struct nds32_mm *mm = STATE_MM (sd);

  getrlimit (RLIMIT_STACK, &limit);
  mm->limit_sp = limit.rlim_cur;
  getrlimit (RLIMIT_DATA, &limit);
  mm->limit_data = limit.rlim_cur;

  if (mm->limit_sp & 1) /* Unlimited?  */
    mm->limit_sp = 0x800000;
  if (mm->limit_data & 1) /* Unlimited?  */
    mm->limit_data = 0x800000;

  if (STATE_ENVIRONMENT (sd) == ALL_ENVIRONMENT)
    {
      bfd_map_over_sections (abfd, nds32_simple_osabi_sniff_sections, &osabi);
      if (osabi)
	STATE_ENVIRONMENT (sd) = USER_ENVIRONMENT;
      else
	STATE_ENVIRONMENT (sd) = OPERATING_ENVIRONMENT;
    }

  if (STATE_ENVIRONMENT (sd) != USER_ENVIRONMENT)
    {
      /* FIXME: We should only do this if user doesn't allocate one.
		But how can we know it? */
      sim_do_command (sd, "memory region 0,0x4000000"); /* 64 MB */
      return;
    }

    /*
    See sim-config.h for detailed explanation.
	--environment user|virtual|operating

    By default, the setting is 'all' for un-selected.

    In my current design, USER_ENVIRONMENT is used for Linux application,
    so
	1. Load ELF by segment instead of by section.
	2. Load dynamic-link (INTERP) if needed
	3. Prepare stack for arguments, environments and AUXV.
	4. Use nds32-mm for memory mapping
    If the ENVIRONMENT is not USER, the I treat it as normal ELF application,
    so only a single 64MB memory block is allocated,
    and default sim_load_file () is used.  */

  /* For emulating Linux VMA */
  sim_core_attach (sd, NULL, 0, access_read_write_exec, 0, 0x00004000,
		   0xFFFF8000, 0, &nds32_mm_devices, NULL);

  nds32_mm_init (mm);

  /* Allocate stack.  */
  /* TODO: Executable stack.  Currently, EXEC affects vma cache. */
  nds32_mmap (cpu, mm->start_sp - mm->limit_sp, mm->limit_sp,
	      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
	      -1, 0);

  /* FIXME: Handle ET_DYN and ET_EXEC.  */
  phdr = elf_tdata (abfd)->phdr;
  sd->exec_base = -1;
  for (i = 0; i < elf_elfheader (abfd)->e_phnum; i++)
    {
      uint32_t addr, len;
      uint32_t prot = 0;

      if (phdr[i].p_type == PT_INTERP)
	interp_phdr = &phdr[i];

      if (phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0)
	continue;

      addr = phdr[i].p_vaddr;
      len = addr + phdr[i].p_memsz - PAGE_ALIGN (addr);
      len = PAGE_ROUNDUP (len);
      addr = PAGE_ALIGN (addr);

      if (phdr[i].p_flags & PF_X)
	prot |= PROT_EXEC;
      if (phdr[i].p_flags & PF_W)
	prot |= PROT_WRITE;
      if (phdr[i].p_flags & PF_R)
	prot |= PROT_READ;

      if (sd->exec_base == -1)
	sd->exec_base = addr;

      nds32_mmap (cpu, addr, len, prot,
		  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
		  -1, 0);

      if (addr + len > mm->brk)
	mm->brk = addr + len;
    }

  /* TODO: Pre-map brk */

  if (!interp_phdr)
    return;

  /* Read path of interp.  */
  off = interp_phdr->p_offset;
  len = interp_phdr->p_filesz;
  sysroot_len = strlen (simulator_sysroot);

  strcpy (buf, simulator_sysroot);
  if (buf[sysroot_len - 1] == '/')
    buf[--sysroot_len] = '\0';

  if (bfd_seek (abfd, off, SEEK_SET) != 0
      || bfd_bread (buf + sysroot_len, len, abfd) != len)
    return;

  sd->interp_bfd = bfd_openr (buf, 0);

  if (sd->interp_bfd == NULL)
    return;

  bfd_check_format (sd->interp_bfd, bfd_object);

  /* Add memory for interp.  */
  phdr = elf_tdata (sd->interp_bfd)->phdr;
  len = total_mapping_size (phdr, elf_elfheader (sd->interp_bfd)->e_phnum);
  interp_base = nds32_get_unmapped_area (mm, 0, len);
  for (i = 0; i < elf_elfheader (sd->interp_bfd)->e_phnum; i++)
    {
      uint32_t addr, len, prot = 0;

      if (phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0)
	continue;

      addr = interp_base + phdr[i].p_vaddr;
      len = addr + phdr[i].p_memsz - PAGE_ALIGN (addr);
      len = PAGE_ROUNDUP (len);
      addr = PAGE_ALIGN (addr);

      if (phdr[i].p_flags & PF_X)
	prot |= PROT_EXEC;
      if (phdr[i].p_flags & PF_W)
	prot |= PROT_WRITE;
      if (phdr[i].p_flags & PF_R)
	prot |= PROT_READ;

      nds32_mmap (cpu, addr, len, prot,
		  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
		  -1, 0);
    }

  sd->interp_base = interp_base;
}

static void
nds32_load_segments (SIM_DESC sd, bfd *abfd, uint32_t load_base)
{
  Elf_Internal_Phdr *phdr;
  int i;
  int bias = -1;
  int bias_set = 0;

  phdr = elf_tdata (abfd)->phdr;

  for (i = 0; i < elf_elfheader (abfd)->e_phnum; i++)
    {
      uint32_t addr, filesz, memsz;
      char *data = NULL;

      if (phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0)
	continue;

      addr = phdr[i].p_vaddr;
      filesz = phdr[i].p_filesz;
      memsz = phdr[i].p_memsz;

      if (bias_set == 0)
	{
	  bias = load_base - addr;
	  bias_set = 1;
	}

      if (STATE_OPEN_KIND (sd) == SIM_OPEN_DEBUG)
	sim_io_printf (sd, "Load segment, size 0x%x addr 0x%x\n",
		       addr + bias, memsz);

      data = xmalloc (memsz);
      /* Clear for .bss or something else. */
      if (memsz != filesz)
	memset (data + filesz, 0, memsz - filesz);

      if (bfd_seek (abfd, phdr[i].p_offset, SEEK_SET) == 0
	  && bfd_bread (data, filesz, abfd) == filesz)
	sim_write (sd, addr + bias, (unsigned char *) data, memsz);

      free (data);
    }

  return;
}

SIM_RC
sim_load (SIM_DESC sd, char *prog_name, struct bfd *prog_bfd, int from_tty)
{
  bfd *result_bfd;
  struct nds32_mm *mm = STATE_MM (sd);

  if (prog_bfd == NULL)
    prog_bfd = STATE_PROG_BFD (sd);

  SIM_ASSERT (STATE_MAGIC (sd) == SIM_MAGIC_NUMBER);
  if (sim_analyze_program (sd, prog_name, prog_bfd) != SIM_RC_OK)
    return SIM_RC_FAIL;
  SIM_ASSERT (STATE_PROG_BFD (sd) != NULL);

  /* Free vma for previous program.  */
  nds32_freeall_vma (mm);

  /* Allocate core memory if none is specified by user.  */
  if (STATE_MEMOPT (sd) == NULL && sd->mem_attached == FALSE
      && prog_bfd != NULL)
    nds32_alloc_memory (sd, prog_bfd);

  if (STATE_ENVIRONMENT (sd) != USER_ENVIRONMENT)
    {
      /* NOTE: For historical reasons, older hardware simulators
	 incorrectly write the program sections at LMA interpreted as a
	 virtual address.  This is still accommodated for backward
	 compatibility reasons. */

      result_bfd = sim_load_file (sd, STATE_MY_NAME (sd),
				  STATE_CALLBACK (sd),
				  prog_name,
				  STATE_PROG_BFD (sd),
				  STATE_OPEN_KIND (sd) == SIM_OPEN_DEBUG,
				  STATE_LOAD_AT_LMA_P (sd),
				  sim_write);
      if (result_bfd == NULL)
	{
	  bfd_close (STATE_PROG_BFD (sd));
	  STATE_PROG_BFD (sd) = NULL;
	  return SIM_RC_FAIL;
	}
    }
  else
    {
      /* For Linux programs, we should load ELF based on loadable
	 segments, not sections.  Otherwise, ELF/Program headers will
	 not be loaded which are needed by dynamic linker.  */
      nds32_load_segments (sd, prog_bfd, sd->exec_base);
      if (sd->interp_bfd)
	nds32_load_segments (sd, sd->interp_bfd, sd->interp_base);
    }

  return SIM_RC_OK;
}

void
nds32_init_libgloss (SIM_DESC sd, struct bfd *abfd, char **argv, char **env)
{
  int len, mlen, i;

  STATE_CALLBACK (sd)->syscall_map = cb_nds32_libgloss_syscall_map;

  /* Save argv for -mcrt-arg hacking.  */
  memset (sd->cmdline, 0, sizeof (sd->cmdline));
  mlen = sizeof (sd->cmdline) - 1;
  len = 0;
  for (i = 0; argv && argv[i]; i++)
    {
      int l = strlen (argv[i]) + 1;

      if (l + len >= mlen)
	break;

      len += sprintf (sd->cmdline + len, "%s ", argv[i]);
    }

  if (len > 0)
    sd->cmdline[len - 1] = '\0';	/* Trim the last space. */

  return;
}

static uint32_t
nds32_push_auxv (SIM_DESC sd, struct bfd *abfd, uint32_t sp, uint32_t type,
		 uint32_t val)
{
  unsigned char buf[4];

  bfd_put_32 (abfd, type, buf);
  sim_write (sd, sp - 8, buf, sizeof (buf));
  bfd_put_32 (abfd, val, buf);
  sim_write (sd, sp - 4, buf, sizeof (buf));

  return sp - 8;
}

void
nds32_init_linux (SIM_DESC sd, struct bfd *abfd, char **argv, char **env)
{
  int argc = 0, argv_len = 0;
  int envc = 0, env_len = 0;
  int auxvc = 0;
  SIM_CPU *cpu = STATE_CPU (sd, 0);
  uint32_t sp = STACK_TOP;
  uint32_t sp_argv, sp_envp;		/* Pointers to argv amd envp array.  */
  uint32_t flat;			/* Beginning of argv/env strings.  */
  unsigned char buf[8];
  int i;
  Elf_Internal_Ehdr *exec = elf_elfheader (abfd);

  STATE_CALLBACK (sd)->syscall_map = cb_nds32_linux_syscall_map;

  /* Check stack layout in
	http://articles.manugarg.com/aboutelfauxiliaryvectors.html
     for details.

     TODO: Push AUXV vector (especially AT_ENTRY,
	   so we can run dynamically linked executables.  */

  for (argc = 0; argv && argv[argc]; argc++)
    argv_len += strlen (argv[argc]) + 1;

  for (envc = 0; env && env[envc]; envc++)
    env_len += strlen (env[envc]) + 1;

  /*
			<---- STACK_TOP
     env strings
     argv strings	<---- flat pointer
     auxv[term] = AT_NULL
     auxv[...]
     auxv[0]
     envp[term] = NULL
     envp[...]
     envp[0]
     argv[n] = NULL
     argv[...]
     argv[0]
     argc		<---- $sp  */
  sp = flat = STACK_TOP - ROUNDUP (argv_len + env_len, 8);

  /* Adjust sp so that the final $sp is 8-byte aligned.  */
  if ((argc + envc + 1) % 2 != 0)
    sp -= 4;

  /* Push AUXV.  */
  sp = nds32_push_auxv (sd, abfd, sp, AT_NULL, 0);
  sp = nds32_push_auxv (sd, abfd, sp, AT_PAGESZ, PAGE_SIZE);
  sp = nds32_push_auxv (sd, abfd, sp, AT_PHDR, sd->exec_base + exec->e_phoff);
  sp = nds32_push_auxv (sd, abfd, sp, AT_PHENT, sizeof (Elf_Internal_Phdr));
  sp = nds32_push_auxv (sd, abfd, sp, AT_PHNUM, exec->e_phnum);
  sp = nds32_push_auxv (sd, abfd, sp, AT_BASE, sd->interp_base);
  sp = nds32_push_auxv (sd, abfd, sp, AT_ENTRY, exec->e_entry);
  sp = nds32_push_auxv (sd, abfd, sp, AT_HWCAP, 0x9dc6f);

  /* Make room for argc, argv[] and envp[] arrays.  */
  sp -= 4 + (argc + 1 + envc + 1) * 4;
  sp_argv = sp + 4;
  sp_envp = sp_argv + (argc + 1) * 4;
  CCPU_GPR[GPR_SP].u = sp;
  SIM_ASSERT ((sp % 8) == 0);

  /* Write argc.  */
  bfd_put_32 (abfd, argc, buf);
  sim_write (sd, sp, buf, 4);

  /* Write argv[] array and argument strings.  */
  for (i = 0; i < argc; i++)
    {
      int len = strlen (argv[i]) + 1;	/* 1 for trailing \0.  */

      sim_write (sd, flat, (unsigned char *) argv[i], len);
      bfd_put_32 (abfd, flat, buf);
      sim_write (sd, sp_argv + i * 4, buf, 4);
      flat += len;
    }
  bfd_put_32 (abfd, 0, buf);
  sim_write (sd, sp_argv + argc * 4, buf, 4); /* term-zero */

  /* Write envp[] array and environment strings.  */
  for (i = 0; i < envc; i++)
    {
      int len = strlen (env[i]) + 1;	/* 1 for trailing \0.  */

      sim_write (sd, flat, (unsigned char *) env[i], len);
      bfd_put_32 (abfd, flat, buf);
      sim_write (sd, sp_envp + i * 4, buf, 4);
      flat += len;
    }
  bfd_put_32 (abfd, 0, buf);
  sim_write (sd, sp_envp + envc * 4, buf, 4); /* term-zero */

  if (sd->interp_bfd)
    {
      CPU_PC_STORE (cpu) (cpu, sd->interp_base
			  + bfd_get_start_address (sd->interp_bfd));
    }

  return;
}
