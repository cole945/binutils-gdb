/* gprof header for NDS32 simulator.

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

#ifndef NDS32_GMON_H
#define NDS32_GMON_H

void nds32_gmon_start (struct bfd *abfd);
void nds32_gmon_cleanup (struct bfd *abfd);
void nds32_gmon_mcount (uint32_t from_pc, uint32_t self_pc);
void nds32_gmon_sample (uint32_t pc);

/* sys/gmon_out.h is missing on cygwin,
   so I copied some declaration here
   in order to avoid portability issues.  */
enum
{
  NDS32_GMON_TAG_TIME_HIST = 0,
  NDS32_GMON_TAG_CG_ARC = 1,
  NDS32_GMON_TAG_BB_COUNT = 2
};

struct nds32_gmon_hdr
{
  char cookie[4];
  char version[4];
  char spare[3 * 4];
};

struct nds32_gmon_hist_hdr
{
  char low_pc[sizeof (char *)];		/* Base pc address of sample buffer.  */
  char high_pc[sizeof (char *)];	/* Max pc address of sampled buffer.  */
  char hist_size[4];			/* Size of sample buffer.  */
  char prof_rate[4];			/* Profiling clock rate.  */
  char dimen[15];			/* Phys. dim., usually "seconds".  */
  char dimen_abbrev;			/* Usually 's' for "seconds".  */
};

#endif
