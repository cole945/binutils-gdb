/* gprof for NDS32 simulator.

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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/gmon_out.h>

#include "bfd.h"
#include "elf-bfd.h"

#include "nds32-gmon.h"

#define HIST_GRANULARITY_SHIFT	2
#define HIST_GRANULARITY	(HIST_GRANULARITY_SHIFT << 1)
#define CG_GRANULARITY_SHIFT	2
#define CG_GRANULARITY		(CG_GRANULARITY_SHIFT << 1)

/* Data structure for recording call-graph.  */
struct tostruct
{
  /* PC of current function, callee.  */
  uint32_t self_pc;
  /* The number of times the function was called.  */
  uint32_t count;
  /* Next function called by the same caller.  */
  struct tostruct *next;
};

/* Call edges are index by the caller.  */
static struct tostruct **froms;
/* Histogram.  */
static uint16_t *hist;
/* Range of text.  */
static uint32_t low_pc, high_pc;

/* Find the upper/lower bound of the text.
   FROMS and HIST are allocated based on this range.  */

static void
find_text_range (bfd *abfd, asection *sect, void *obj)
{
  bfd_vma vma, size;

  if ((bfd_get_section_flags (abfd, sect) & SEC_CODE) == 0)
    return;

  vma = bfd_section_vma (abfd, sect);
  size = bfd_section_size (abfd, sect);

  if (vma < low_pc)
    low_pc = vma;
  if (vma + size > high_pc)
    high_pc = vma + size;
}

/* Write histogram to file.  */

static void
write_hist (FILE *fp, bfd *abfd, uint16_t *hist)
{
  struct gmon_hist_hdr hdr;
  int i;
  int tag;

  tag = GMON_TAG_TIME_HIST;
  fwrite (&tag, 1, 1, fp);

  bfd_put_32 (abfd, low_pc, hdr.low_pc);
  bfd_put_32 (abfd, high_pc, hdr.high_pc);
  bfd_put_32 (abfd, (high_pc - low_pc) >> HIST_GRANULARITY_SHIFT, hdr.hist_size);
  bfd_put_32 (abfd, 1, hdr.prof_rate);
  strcpy (hdr.dimen, "cycle");
  hdr.dimen_abbrev = 'c';
  fwrite (&hdr, sizeof (hdr), 1, fp);

  for (i = 0; i < (high_pc - low_pc) >> HIST_GRANULARITY_SHIFT; i++)
    {
      uint16_t h;

      bfd_put_16 (abfd, hist[i], &h);
      fwrite (&h, 2, 1, fp);
    }
}

/* Write call-graph data to file.  */

static void
write_cg (FILE *fp, bfd *abfd, struct tostruct **froms)
{
  int i;
  int tag = GMON_TAG_CG_ARC;

  bfd_put_32 (abfd, tag, &tag);

  for (i = 0; i < (high_pc - low_pc) >> CG_GRANULARITY_SHIFT; i++)
    {
      char buf[4];
      uint32_t from_pc;
      struct tostruct *tos;

      if ((tos = froms[i]) == NULL)
	continue;

      bfd_put_32 (abfd, low_pc + (i << CG_GRANULARITY_SHIFT), &from_pc);
      do
	{
	  fwrite (&tag, 1, 1, fp);
	  fwrite (&from_pc, 4, 1, fp);
	  bfd_put_32 (abfd, tos->self_pc, buf);
	  fwrite (buf, 4, 1, fp);
	  bfd_put_32 (abfd, tos->count, buf);
	  fwrite (buf, 4, 1, fp);
	}
      while ((tos = tos->next) != NULL);
    }
}

/* Initialization called when the program started.  */

void
nds32_gmon_start (struct bfd *abfd)
{
  low_pc = 0xffffffff;
  high_pc = 0;
  bfd_map_over_sections (abfd, find_text_range, NULL);

  free (hist);
  free (froms);

  hist = (uint16_t *)
    calloc ((high_pc - low_pc) >> HIST_GRANULARITY_SHIFT,
	    sizeof (uint16_t));
  froms = (struct tostruct **)
    calloc ((high_pc - low_pc) >> CG_GRANULARITY_SHIFT,
	    sizeof (void *));
}

/* Clean-up and write out collected data.  */

void
nds32_gmon_cleanup (bfd *abfd)
{
  struct gmon_hdr hdr;
  FILE *fp;

  fp = fopen ("gmon.out", "w");

  memset (&hdr, 0, sizeof (hdr));
  memcpy (hdr.cookie, "gmon", 4);
  bfd_put_32 (abfd, 1, hdr.version);

  fwrite (&hdr, sizeof (hdr), 1, fp);

  write_hist (fp, abfd, hist);

  write_cg (fp, abfd, froms);

  fclose (fp);
}

/* Simulate mcount function.
   They should be called by JAL/JRAL instructions.  */

void
nds32_gmon_mcount (uint32_t from_pc, uint32_t self_pc)
{
  int fromidx = (from_pc - low_pc) >> CG_GRANULARITY_SHIFT;
  struct tostruct *tos;

  if (froms[fromidx] == NULL)
    {
      froms[fromidx] = (struct tostruct *) calloc (1, sizeof (struct tostruct));
      tos = froms[fromidx];
      tos->self_pc = self_pc;
      tos->count = 1;
      return;			/* Done */
    }

  tos = froms[fromidx];

  do
    {
      if (tos->self_pc == self_pc)
	break;
    }
  while ((tos = tos->next) != NULL);

  if (tos->self_pc != self_pc)
    {
      /* Not found.  */
      tos->next = (struct tostruct *) calloc (1, sizeof (struct tostruct));
      tos = tos->next;
      tos->self_pc = self_pc;
      tos->count = 1;
      return;
    }
  else
    tos->count++;
}

/* Simulate time-sampling.
   Currently the are called for every instruction.  */

void
nds32_gmon_sample (uint32_t pc)
{
  if (pc < low_pc || pc >= high_pc)
    return;

  hist[(pc - low_pc) >> CG_GRANULARITY_SHIFT]++;
}
