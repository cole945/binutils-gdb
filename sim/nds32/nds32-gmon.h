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

#endif
