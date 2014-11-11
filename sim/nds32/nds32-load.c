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
#include "nds32-syscall.h"

SIM_RC
sim_load (SIM_DESC sd, const char *prog_name, struct bfd *prog_bfd, int from_tty)
{
  bfd *result_bfd;

  if (prog_bfd == NULL)
    prog_bfd = STATE_PROG_BFD (sd);

  SIM_ASSERT (STATE_MAGIC (sd) == SIM_MAGIC_NUMBER);
  if (sim_analyze_program (sd, prog_name, prog_bfd) != SIM_RC_OK)
    return SIM_RC_FAIL;
  SIM_ASSERT (STATE_PROG_BFD (sd) != NULL);

  /* Allocate core memory if none is specified by user.  */
  if (STATE_MEMOPT (sd) == NULL && sd->mem_attached == FALSE
      && prog_bfd != NULL)
    {
      sim_do_command (sd, "memory region 0,0x4000000");	/* 64 MB */
    }

  /* NOTE: For historical reasons, older hardware simulators incorrectly
     write the program sections at LMA interpreted as a virtual address.
     This is still accommodated for backward compatibility reasons.  */

  result_bfd = sim_load_file (sd, STATE_MY_NAME (sd), STATE_CALLBACK (sd),
			      prog_name, STATE_PROG_BFD (sd),
			      STATE_OPEN_KIND (sd) == SIM_OPEN_DEBUG,
			      STATE_LOAD_AT_LMA_P (sd), sim_write);

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
