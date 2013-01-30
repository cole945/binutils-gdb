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

#include "bfd.h"
#include "elf-bfd.h"

#include "nds32-gmon.h"
#include "rbtree.h"

#define HIST_GRANULARITY_SHIFT	2
#define HIST_GRANULARITY	(HIST_GRANULARITY_SHIFT << 1)
#define CG_GRANULARITY_SHIFT	2
#define CG_GRANULARITY		(CG_GRANULARITY_SHIFT << 1)
#define CYCLE_GRANULARITY	1

/* Data structure for recording call-graph.  */
struct cg_node
{
  /* PC of caller.  */
  uint32_t from_pc;
  /* PC of callee.  */
  uint32_t self_pc;
  /* The number of times the function was called.  */
  uint32_t count;
};

/* Used for pass handlers for writing call-graph data.  */

struct cg_handlers
{
  bfd *abfd;
  FILE *fp;
};

static uint16_t *hist;
/* Range of text.  */
static uint32_t low_pc, high_pc;
rbtree_t cg_tree;

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
  struct nds32_gmon_hist_hdr hdr;
  int i;
  int tag;

  tag = NDS32_GMON_TAG_TIME_HIST;
  fwrite (&tag, 1, 1, fp);

  bfd_put_32 (abfd, low_pc, hdr.low_pc);
  bfd_put_32 (abfd, high_pc, hdr.high_pc);
  bfd_put_32 (abfd, (high_pc - low_pc) >> HIST_GRANULARITY_SHIFT, hdr.hist_size);
  bfd_put_32 (abfd, CYCLE_GRANULARITY, hdr.prof_rate);
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
cg_free_node (rbtree_t tree, rbnode_t node, void *dontcare)
{
  free (node->key);
}

static int
cg_cmp (void *lhs, void *rhs)
{
  struct cg_node *lcg = (struct cg_node *) lhs;
  struct cg_node *rcg = (struct cg_node *) rhs;

  if (lcg->from_pc == rcg->from_pc)
    {
      if (lcg->self_pc == rcg->self_pc)
	return 0;
      return lcg->self_pc < rcg->self_pc ? -1 : 1;
    }
  return lcg->from_pc < rcg->from_pc ? -1 : 1;
}

/* Initialization called when the program started.  */

void
nds32_gmon_start (struct bfd *abfd)
{
  low_pc = 0xffffffff;
  high_pc = 0;
  bfd_map_over_sections (abfd, find_text_range, NULL);

  if (cg_tree)
    {
      rbtree_traverse_node (cg_tree, cg_tree->root, cg_free_node, NULL);
      rbtree_destroy_tree (cg_tree);
    }
  cg_tree = rbtree_create_tree (cg_cmp, NULL);

  free (hist);
  hist = (uint16_t *)
    calloc ((high_pc - low_pc) >> HIST_GRANULARITY_SHIFT,
	    sizeof (uint16_t));
}

static void
write_cg_trav (rbtree_t tree, rbnode_t n, void *arg)
{
  struct cg_node *cgn = (struct cg_node *) n->key;
  char buf[8];
  struct cg_handlers *hp = (struct cg_handlers *) arg;

  bfd_put_32 (hp->abfd, NDS32_GMON_TAG_CG_ARC, buf);
  fwrite (buf, 1, 1, hp->fp);
  bfd_put_32 (hp->abfd, cgn->from_pc, buf);
  fwrite (buf, 4, 1, hp->fp);
  bfd_put_32 (hp->abfd, cgn->self_pc, buf);
  fwrite (buf, 4, 1, hp->fp);
  bfd_put_32 (hp->abfd, cgn->count, buf);
  fwrite (buf, 4, 1, hp->fp);
}

/* Clean-up and write out collected data.  */

void
nds32_gmon_cleanup (bfd *abfd)
{
  struct nds32_gmon_hdr hdr;
  struct cg_handlers h;

  h.abfd = abfd;
  h.fp = fopen ("gmon.out", "w");

  memset (&hdr, 0, sizeof (hdr));
  memcpy (hdr.cookie, "gmon", 4);
  bfd_put_32 (abfd, 1, hdr.version);

  fwrite (&hdr, sizeof (hdr), 1, h.fp);

  write_hist (h.fp, abfd, hist);

  rbtree_traverse_node (cg_tree, cg_tree->root, write_cg_trav, &h);

  fclose (h.fp);
}

/* Simulate mcount function.
   They should be called by JAL/JRAL instructions.  */

void
nds32_gmon_mcount (uint32_t from_pc, uint32_t self_pc)
{
  struct cg_node n;
  struct cg_node *new_cg;
  rbnode_t p;

  n.from_pc = from_pc;
  n.self_pc = self_pc;
  p = rbtree_find (cg_tree, &n);

  if (p)
    {
      ((struct cg_node *) p->key)->count++;
      return;
    }

  new_cg = (struct cg_node *) calloc (1, sizeof (struct cg_node));
  new_cg->from_pc = from_pc;
  new_cg->self_pc = self_pc;
  new_cg->count = 1;
  rbtree_insert (cg_tree, new_cg);
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
