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

#ifndef NDS32_UTILS_H
#define NDS32_UTILS_H

void source_nds32script (void);

/* Declarations for making arch-dependent types.  */
enum type_option
{
  NO_FLAGS = 0,
  USE_FLAGS = 1,
};
struct field *nds32_append_type_field (struct type *type);
struct type *nds32_init_type (struct gdbarch *gdbarch, char *name,
			      enum type_option opt);
void nds32_append_flag (struct type *type, int bitpos, char *name);
void nds32_append_bitfield (struct type *type, struct type *field_type,
			    int bitpos_from, int bitpos_to, char *name);
struct type *nds32_init_enum (struct gdbarch *gdbarch, char *name);
void nds32_append_enum (struct type *type, int bitpos, char *name);

/* Helpers for type table.  */
htab_t nds32_alloc_type_tab (int size);
struct type *nds32_type_lookup (htab_t htab, const char *name);
void nds32_type_insert (htab_t htab, const char *name, struct type *type);

/* UI buffer for output redirection.  */
struct ui_file_buffer
{
  char *buf;
  long buf_size;
};

void do_ui_file_put_memcpy (void *object, const char *buffer,
			    long length_buffer);

#endif
