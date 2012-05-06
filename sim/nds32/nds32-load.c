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
  char buf[256];
  const int init_sp_size = 0x4000;
  Elf_Internal_Phdr *phdr;


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

  if (STATE_ENVIRONMENT (sd) != OPERATING_ENVIRONMENT)
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

  phdr = elf_tdata (abfd)->phdr;
  for (i = 0; i < elf_elfheader (abfd)->e_phnum; i++)
    {
      uint32_t addr, len;

      if (phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0)
	continue;

      addr = phdr[i].p_vaddr & ~(phdr[i].p_align - 1);
      len = (phdr[i].p_memsz + (phdr[i].p_align - 1)) & ~(phdr[i].p_align - 1);
      snprintf (buf, sizeof (buf), "memory region 0x%lx,0x%lx",
		(long) addr, (long) len);
      sim_do_command (sd, buf);

      if (addr + len > sd->elf_brk)
	sd->elf_brk = addr + len;
    }

  /* TODO: Handle PT_INTERP.  */

  SIM_ASSERT (sd->elf_brk < sd->unmapped && sd->unmapped < sd->elf_sp);
}

SIM_RC
sim_load (SIM_DESC sd, char *prog_name, struct bfd *prog_bfd, int from_tty)
{
  bfd *result_bfd;

  SIM_ASSERT (STATE_MAGIC (sd) == SIM_MAGIC_NUMBER);
  if (sim_analyze_program (sd, prog_name, prog_bfd) != SIM_RC_OK)
    return SIM_RC_FAIL;
  SIM_ASSERT (STATE_PROG_BFD (sd) != NULL);

  /* Allocate core memory if none is specified by user.  */
  if (STATE_MEMOPT (sd) == NULL && prog_bfd != NULL)
    nds32_alloc_memory (sd, prog_bfd);

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

void
nds32_init_linux (SIM_DESC sd, struct bfd *abfd, char **argv, char **env)
{
  int argc = 0, argv_len = 0;
  int envc = 0, env_len = 0;
  int auxvc = 0, auxv_len = 0;
  SIM_CPU *cpu = STATE_CPU (sd, 0);
  uint32_t sp = STACK_TOP - 16;
  uint32_t flat;			/* Beginning of argv/env strings.  */
  unsigned char buf[8];
  int i;

  /* Check stack layout in
	http://articles.manugarg.com/aboutelfauxiliaryvectors.html
     for details.

     TODO: Push AUXV vector (especially AT_ENTRY,
	   so we can run dynamically linked executables.  */

  for (argc = 0; argv && argv[argc]; argc++)
    argv_len += strlen (argv[argc]) + 1;

  for (envc = 0; env && env[envc]; envc++)
    env_len += strlen (env[envc]) + 1;

  flat = sp - (argv_len + env_len + auxv_len);
  sp = flat - ((argc + 1) * 4 + (envc + 1) * 4 + (auxvc + 1) * 8);
  sp = sp & ~0xf;

  /* Write argc.  */
  bfd_put_32 (abfd, argc, buf);
  sim_write (sd, sp, buf, 4);

  for (i = 0; i < argc; i++)
    {
      int len = strlen (argv[i]) + 1;	/* 1 for trailing \0.  */

      sim_write (sd, flat, argv[i], len);
      bfd_put_32 (abfd, flat, buf);
      /* Skip argc.  */
      sim_write (sd, sp + (i + 1) * 4, buf, 4);
      flat += len;
    }

  for (i = 0; i < envc; i++)
    {
      int len = strlen (env[i]) + 1;	/* 1 for trailing \0.  */

      sim_write (sd, flat, env[i], len);
      bfd_put_32 (abfd, flat, buf);
      /* Skip argc, argv[0..n].  */
      sim_write (sd, sp + (i + 1 + argc + 1) * 4, buf, 4);
      flat += len;
    }

  memset (buf, 0, sizeof (buf));
  sim_write (sd, sp + (1 + argc) * 4, buf, 4);
  sim_write (sd, sp + (1 + argc + 1 + envc) * 4, buf, 4);
  sim_write (sd, sp + (1 + argc + 1 + envc + 1) * 4 + (auxvc) * 8, buf, 8);

  CCPU_GPR[NG_SP].u = sp;

  return;
}
