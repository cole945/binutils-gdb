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

#include "bfd.h"
#include "elf-bfd.h"
#include "elf.h"
#include "sim-main.h"
#include "sim-utils.h"
#include "sim-assert.h"

#include "nds32-sim.h"
#include "nds32-linux.h"

static void
nds32_simple_osabi_sniff_sections (bfd *abfd, asection *sect, void *obj)
{
  const char *name;
  int *osabi = (int *) obj;

  name = bfd_get_section_name (abfd, sect);
  if (strcmp (name, ".note.ABI-tag") == 0)
    *osabi = 1;
}

static void
nds32_alloc_memory (SIM_DESC sd, struct bfd *abfd)
{
  int osabi = 0;
  int i;
  char buf[1024];
  const int init_sp_size = 0x4000;
  Elf_Internal_Phdr *phdr;
  Elf_Internal_Phdr *interp_phdr = NULL;
  uint32_t off;
  uint32_t len;
  int sysroot_len;
  uint32_t interp_base;

  bfd_map_over_sections (abfd, nds32_simple_osabi_sniff_sections, &osabi);
  if (osabi)
    STATE_ENVIRONMENT (sd) = USER_ENVIRONMENT;
  else
    STATE_ENVIRONMENT (sd) = OPERATING_ENVIRONMENT;

  /* TODO: Allocate memory for
     1. Loadable segments of the program.
	a. LMA
	b. VMA
	c. They might be overlapped, so we should merge them before allocating.
     2. Stack of the program.
	a. _stack for ELF programs.
	b. STACK_TOP for Linux programs.
     3. Loadable segments of the interpreter (loader).  */

  if (STATE_ENVIRONMENT (sd) != USER_ENVIRONMENT)
    {
      /* TODO: See above.  */
      sim_do_command (sd, "memory region 0,0x4000000");	/* 64MB */
      return;
    }

  sd->elf_brk = 0;
  sd->unmapped = TASK_UNMAPPED_BASE;

  /* Create stack page for argv/env.  */
  sd->elf_sp = (long) STACK_TOP - init_sp_size;
  snprintf (buf, sizeof (buf), "memory region 0x%lx,0x%lx",
	    (long) sd->elf_sp, (long) init_sp_size);
  sim_do_command (sd, buf);

  /* FIXME: Handle ET_DYN and ET_EXEC.  */
  phdr = elf_tdata (abfd)->phdr;
  sd->exec_base = -1;
  for (i = 0; i < elf_elfheader (abfd)->e_phnum; i++)
    {
      uint32_t addr, len;

      if (phdr[i].p_type == PT_INTERP)
	interp_phdr = &phdr[i];

      if (phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0)
	continue;

      addr = phdr[i].p_vaddr;
      len = addr + phdr[i].p_memsz - PAGE_ALIGN (addr);
      len = PAGE_ROUNDUP (len);
      addr = PAGE_ALIGN (addr);

      if (sd->exec_base == -1)
	sd->exec_base = addr;

      snprintf (buf, sizeof (buf), "memory region 0x%lx,0x%lx",
		(long) addr, (long) len);
      sim_do_command (sd, buf);

      if (addr + len > sd->elf_brk)
	sd->elf_brk = addr + len;
    }

  SIM_ASSERT (sd->elf_brk < sd->unmapped && sd->unmapped < sd->elf_sp);

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
  interp_base = sd->unmapped;
  for (i = 0; i < elf_elfheader (sd->interp_bfd)->e_phnum; i++)
    {
      uint32_t addr, len;

      if (phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0)
	continue;

      addr = interp_base + phdr[i].p_vaddr;
      len = addr + phdr[i].p_memsz - PAGE_ALIGN (addr);
      len = PAGE_ROUNDUP (len);
      addr = PAGE_ALIGN (addr);
      sd->unmapped = PAGE_ROUNDUP (addr + len);

      snprintf (buf, sizeof (buf), "memory region 0x%lx,0x%lx",
		(long) addr, (long) len);
      sim_do_command (sd, buf);
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
	sim_write (sd, addr + bias, data, memsz);

      free (data);

    }

  return;
}

SIM_RC
sim_load (SIM_DESC sd, char *prog_name, struct bfd *prog_bfd, int from_tty)
{
  bfd *result_bfd;

  if (prog_bfd == NULL)
    prog_bfd = STATE_PROG_BFD (sd);

  SIM_ASSERT (STATE_MAGIC (sd) == SIM_MAGIC_NUMBER);
  if (sim_analyze_program (sd, prog_name, prog_bfd) != SIM_RC_OK)
    return SIM_RC_FAIL;
  SIM_ASSERT (STATE_PROG_BFD (sd) != NULL);

  /* Allocate core memory if none is specified by user.  */
  if (STATE_MEMOPT (sd) == NULL && prog_bfd != NULL)
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
nds32_push_auxv (SIM_DESC sd, struct bfd *abfd,  uint32_t sp, uint32_t type, uint32_t val)
{
  char buf[4];

  bfd_put_32 (abfd, type, buf);
  sim_write (sd, sp, buf, sizeof (buf));
  bfd_put_32 (abfd, val, buf);
  sim_write (sd, sp + 4, buf, sizeof (buf));

  return sp + 8;
}

void
nds32_init_linux (SIM_DESC sd, struct bfd *abfd, char **argv, char **env)
{
  int argc = 0, argv_len = 0;
  int envc = 0, env_len = 0;
  int auxvc = 0;
  SIM_CPU *cpu = STATE_CPU (sd, 0);
  uint32_t sp = STACK_TOP;
  uint32_t sp_argv, sp_envp, sp_auxv;	/* Markers for argv, envp and auxv.  */
  uint32_t flat;			/* Beginning of argv/env strings.  */
  unsigned char buf[8];
  int i;

  /* Check stack layout in
	http://articles.manugarg.com/aboutelfauxiliaryvectors.html
     for details.

     TODO: Push AUXV vector (especially AT_ENTRY,
	   so we can run dynamically linked executables.  */

  if (sd->interp_bfd)
    auxvc = 6;

  for (argc = 0; argv && argv[argc]; argc++)
    argv_len += strlen (argv[argc]) + 1;

  for (envc = 0; env && env[envc]; envc++)
    env_len += strlen (env[envc]) + 1;

  /*
    | argc | argv[0..N] | envp[0..N] | auxv[0..N] | arg-strs | env-strs
    sp						  flat
   */
  flat = sp - (argv_len + env_len);
  sp = flat - (4 + (argc + 1) * 4 + (envc + 1) * 4 + (auxvc + 1) * sizeof (Elf32_auxv_t));
  sp = sp & ~0xf;

  sp_argv = sp + 4;
  sp_envp = sp_argv + (argc + 1) * 4;
  sp_auxv = sp_envp + (envc + 1) * 4;

  /* Write argc.  */
  bfd_put_32 (abfd, argc, buf);
  sim_write (sd, sp, buf, 4);

  for (i = 0; i < argc; i++)
    {
      int len = strlen (argv[i]) + 1;	/* 1 for trailing \0.  */

      sim_write (sd, flat, argv[i], len);
      bfd_put_32 (abfd, flat, buf);
      sim_write (sd, sp_argv + i * 4, buf, 4);
      flat += len;
    }
  bfd_put_32 (abfd, 0, buf);
  sim_write (sd, sp_argv + argc * 4, buf, 4); /* term-zero */

  for (i = 0; i < envc; i++)
    {
      int len = strlen (env[i]) + 1;	/* 1 for trailing \0.  */

      sim_write (sd, flat, env[i], len);
      bfd_put_32 (abfd, flat, buf);
      sim_write (sd, sp_envp + i * 4, buf, 4);
      flat += len;
    }
  bfd_put_32 (abfd, 0, buf);
  sim_write (sd, sp_envp + envc * 4, buf, 4); /* term-zero */

  if (auxvc > 0)
    {
      Elf32_auxv_t auxv;
      Elf_Internal_Ehdr *exec = elf_elfheader (abfd);

      sp_auxv = nds32_push_auxv (sd, abfd, sp_auxv, AT_PAGESZ, PAGE_SIZE);
      sp_auxv = nds32_push_auxv (sd, abfd, sp_auxv, AT_PHDR, sd->exec_base + exec->e_phoff);
      sp_auxv = nds32_push_auxv (sd, abfd, sp_auxv, AT_PHENT, sizeof (Elf32_Phdr));
      sp_auxv = nds32_push_auxv (sd, abfd, sp_auxv, AT_PHNUM, exec->e_phnum);
      sp_auxv = nds32_push_auxv (sd, abfd, sp_auxv, AT_BASE, sd->interp_base);
      sp_auxv = nds32_push_auxv (sd, abfd, sp_auxv, AT_ENTRY, exec->e_entry);
    }
  sp_auxv = nds32_push_auxv (sd, abfd, sp_auxv, AT_NULL, 0);

  CCPU_GPR[NG_SP].u = sp;

  if (sd->interp_bfd)
    {
      CPU_PC_STORE (cpu) (cpu, sd->interp_base
			       + bfd_get_start_address (sd->interp_bfd));
      sim_io_printf (sd, " interp entry : 0x%lx\n",
		     sd->interp_base + bfd_get_start_address (sd->interp_bfd));
    }

  return;
}
