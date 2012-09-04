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

#include "defs.h"
#include "top.h"		/* for source_script */
#include "exceptions.h"		/* for catch_command_errors */
#include "ui-file.h"		/* struct ui_file_buffer */
#include "nds32-utils.h"
#include "gdbtypes.h"
#include "gdb_assert.h"
#include "floatformat.h"
#include "hashtab.h"
#include <stdio.h>
#include <string.h>

/* Helpers for allocating types.  */

/* Allocate a new type.
   Use this instead of arch_composite_type () or arch_type () directly,
   because it must be a 4-byte word, but we may not append all the fields.
   If `opt' is USE_FLAGS, then a field for flags is appended.  */

struct type *
nds32_init_type (struct gdbarch *gdbarch, char *name, enum type_option opt)
{
  struct type *type;

  gdb_assert (opt == USE_FLAGS || opt == NO_FLAGS);

  type = arch_type (gdbarch, TYPE_CODE_STRUCT, 4, name);
  TYPE_TAG_NAME (type) = name;
  INIT_CPLUS_SPECIFIC (type);

  if (opt == USE_FLAGS)
    {
      int i;
      struct type *flags_type =
	arch_flags_type (TYPE_OWNER (type).gdbarch, "nds32_dummy_flags_type",
			 TYPE_LENGTH (type));
      append_composite_type_field_raw (type, "", flags_type);

      /* Hide all the flags from users,
	 only explicitly appened flags are showen to users.
	 For example,
	 {[ #1 #3 #16 #17 #18 ], INTL = Lv1, POM = Superuser}
	 We don't want users to see this,
	 INTL and POM should be hidden from users.  */
      for (i = 0; i < TYPE_LENGTH (type) * TARGET_CHAR_BIT; i++)
	append_flags_type_flag (flags_type, i, NULL);
    }

  return type;
}

/* Append a flags bit.  */

void
nds32_append_flag (struct type *type, int bitpos, char *name)
{
  struct field *f;
  int nfields;

  gdb_assert (TYPE_CODE (type) == TYPE_CODE_STRUCT);

  nfields = TYPE_NFIELDS (type);

  if (nfields == 0
      || TYPE_CODE (TYPE_FIELD_TYPE (type, 0)) != TYPE_CODE_FLAGS)
    {
      internal_error (__FILE__, __LINE__,
		      _("Pseudo field for flags must be the first one."));
    }

  /* Append flag in the first field.  */
  append_flags_type_flag (TYPE_FIELD_TYPE (type, 0), bitpos, name);
}

/* Append a bit-field.  */

void
nds32_append_bitfield (struct type *type, struct type *field_type,
		       int bitpos_from, int bitpos_to, char *name)
{
  struct field *f;

  gdb_assert (TYPE_CODE (type) == TYPE_CODE_STRUCT);
  gdb_assert (bitpos_to >= bitpos_from);
  gdb_assert (TYPE_NFIELDS (type) != 0 || strcmp (name, "") != 0);

  f = append_composite_type_field_raw (type, xstrdup (name), field_type);
  SET_FIELD_BITPOS (f[0], bitpos_from);
  FIELD_BITSIZE (f[0]) = bitpos_to - bitpos_from + 1;
}

/* Allocate an enumeration type.  The only reason to call this function
   is that we want it to be UNSIGNED instead.  This is only useful for
   enum-type bit-field.  */

struct type *
nds32_init_enum (struct gdbarch *gdbarch, char *name)
{
  struct type *type;

  type = arch_type (gdbarch, TYPE_CODE_ENUM, 4, name);
  TYPE_UNSIGNED (type) = 1;
  return type;
}

void
nds32_append_enum (struct type *type, int enumval, char *name)
{
  struct field *f;

  gdb_assert (TYPE_CODE (type) == TYPE_CODE_ENUM);
  f = append_composite_type_field_raw (type, name, NULL);
  SET_FIELD_ENUMVAL (f[0], enumval);
}

/* Helpers for type table.  */

struct type_entry
{
  const char *name;
  struct type *type;
};

/* Hash code function.  Simply a wrapper for htab_hash_string.  */

static hashval_t
type_hash_string (const PTR p)
{
  struct type_entry *e = (struct type_entry *) p;

  return htab_hash_string (e->name);
}

/* Equal function for hash.  Simply a wrapper for strcmp.  */

static int
type_name_eq (const PTR p1, const PTR p2)
{
  struct type_entry *e1 = (struct type_entry *) p1;
  struct type_entry *e2 = (struct type_entry *) p2;

  return strcmp (e1->name, e2->name) == 0;
}

/* Allocate a hash table for register/type pair.  */

htab_t
nds32_alloc_type_tab (int size)
{
  return htab_create_alloc (size, type_hash_string, type_name_eq,
			    NULL /* htab_del */ ,
			    xcalloc, xfree);
}

/* Look up a register by name.  */

struct type *
nds32_type_lookup (htab_t htab, const char *name)
{
  struct type_entry ent;
  struct type_entry **pe;

  ent.name = name;
  pe = (struct type_entry **) htab_find_slot (htab, &ent, NO_INSERT);
  if (pe)
    return (*pe)->type;
  else
    return NULL;
}

/* Insert a type for a specific register name.  */

void
nds32_type_insert (htab_t htab, const char *name, struct type *type)
{
  struct type_entry ent;
  struct type_entry **pe;

  ent.name = name;

  pe = (struct type_entry **) htab_find_slot (htab, &ent, INSERT);

  if (*pe != NULL)
    return;

  *pe = xmalloc (sizeof (**pe));
  (*pe)->name = xstrdup (name);
  (*pe)->type = type;
}

/* ui_file_put_method_ftype.

   This is used with mem_file_put to get the content of
   the internal stream buffer.  */

void
do_ui_file_put_memcpy (void *object, const char *buffer, long length_buffer)
{
  struct ui_file_buffer *ui_buf;

  ui_buf = (struct ui_file_buffer *) object;
  if (ui_buf->buf_size < length_buffer)
    {
      if (length_buffer < 256 * 1024)
	ui_buf->buf_size = length_buffer += 1024;
      else
	ui_buf->buf_size = length_buffer * 2;
      ui_buf->buf = xrealloc (ui_buf->buf, ui_buf->buf_size);
    }

  memcpy (ui_buf->buf, buffer, length_buffer);
}

void
ui_file_buffer_init (struct ui_file_buffer *ub, int size)
{
  ub->buf_size = size;
  ub->buf = xmalloc (size);
}

void
free_ui_file_buffer (void *ptr)
{
  struct ui_file_buffer *ui_buf = (struct ui_file_buffer *) ptr;

  xfree (ui_buf->buf);
}
