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
#include <stdio.h>
#include <string.h>

struct field *
nds32_append_type_field (struct type *type)
{
  int nfields;
  struct field *f;

  nfields = TYPE_NFIELDS (type) + 1;
  TYPE_NFIELDS (type) = nfields;
  TYPE_FIELDS (type) =
    xrealloc (TYPE_FIELDS (type), sizeof (struct field) * nfields);
  f = &(TYPE_FIELDS (type)[nfields - 1]);
  memset (f, 0, sizeof f[0]);

  return f;
}

static struct field *
nds32_prepend_type_field (struct type *type)
{
  int nfields;
  struct field *f;

  nfields = TYPE_NFIELDS (type) + 1;
  TYPE_NFIELDS (type) = nfields;
  TYPE_FIELDS (type) =
    xrealloc (TYPE_FIELDS (type), sizeof (struct field) * nfields);
  if (nfields > 1)
    {
      memmove (&(TYPE_FIELDS (type)[1]), &(TYPE_FIELDS (type)[0]),
	       sizeof (struct field) * (nfields - 1));
    }
  f = &(TYPE_FIELDS (type)[0]);
  memset (f, 0, sizeof f[0]);

  return f;
}

struct type *
nds32_init_type (struct gdbarch *gdbarch, char *name, int length)
{
  struct type *type;

  type = arch_type (gdbarch, TYPE_CODE_STRUCT, length, name);
  return type;
}

static void
nds32_hide_field_from_flags (struct type *type, int bitpos_from, int bitpos_to)
{
  int bitpos;

  gdb_assert (TYPE_CODE (type) == TYPE_CODE_FLAGS);
  for (bitpos = bitpos_from; bitpos <= bitpos_to; bitpos++)
    append_flags_type_flag (type, bitpos, NULL);
}

void
nds32_append_flag (struct type *type, int bitpos, char *name)
{
  struct field *f;
  int nfields;

  gdb_assert (TYPE_CODE (type) == TYPE_CODE_STRUCT);

  nfields = TYPE_NFIELDS (type);

  /* Append a new flags-field if not exist.  */
  if (nfields == 0
      || TYPE_CODE (TYPE_FIELD_TYPE (type, 0)) != TYPE_CODE_FLAGS
      || strcmp (TYPE_FIELD_NAME (type, 0), "") != 0)
    {
      int i;

      f = nds32_prepend_type_field (type);
      FIELD_NAME (f[0]) = "";
      FIELD_TYPE (f[0]) = arch_flags_type (TYPE_OWNER (type).gdbarch,
					   "nds32_dummy_flags_type",
					   TYPE_LENGTH (type));
      /* Hide fields from flags.  */
      for (i = 1; i < nfields + 1; i++)
	nds32_hide_field_from_flags (FIELD_TYPE (f[0]), FIELD_BITPOS (f[i]),
				     FIELD_BITPOS (f[i]) +
				     FIELD_BITSIZE (f[i]) - 1);
    }

  f = TYPE_FIELDS (type);
  type = FIELD_TYPE (f[0]);
  append_flags_type_flag (type, bitpos, name);
}

void
nds32_append_field (struct type *type, struct type *field_type,
		    int bitpos_from, int bitpos_to, char *name)
{
  struct field *f;

  gdb_assert (TYPE_CODE (type) == TYPE_CODE_STRUCT);
  gdb_assert (bitpos_to >= bitpos_from);
  gdb_assert (TYPE_NFIELDS (type) != 0 || strcmp (name, "") != 0);

  f = nds32_append_type_field (type);
  FIELD_TYPE (f[0]) = field_type;
  FIELD_NAME (f[0]) = xstrdup (name);
  SET_FIELD_BITPOS (f[0], bitpos_from);
  FIELD_BITSIZE (f[0]) = bitpos_to - bitpos_from + 1;

  /* Hide field from flags if used.  */
  if (TYPE_CODE (TYPE_FIELD_TYPE (type, 0)) == TYPE_CODE_FLAGS
      && strcmp (TYPE_FIELD_NAME (type, 0), "") == 0)
    {
      nds32_hide_field_from_flags (TYPE_FIELD_TYPE (type, 0), bitpos_from,
				   bitpos_to);
    }
}

struct type *
nds32_init_enum (struct gdbarch *gdbarch, char *name)
{
  struct type *type;

  type = arch_type (gdbarch, TYPE_CODE_ENUM, 4, name);
  TYPE_UNSIGNED (type) = 1;
  return type;
}

void
nds32_append_enum (struct type *type, int bitpos, char *name)
{
  struct field *f;

  gdb_assert (TYPE_CODE (type) == TYPE_CODE_ENUM);
  f = nds32_append_type_field (type);
  FIELD_NAME (f[0]) = xstrdup (name);
  SET_FIELD_BITPOS (f[0], bitpos);
}

void *
nds32_list_lookup (struct nds32_list *head, const char *key)
{
  struct nds32_list *i;

  for (i = head->next; i != head; i = i->next)
    if (strcmp (key, i->key) == 0)
      return i->value;
  return NULL;
}

void
nds32_list_init (struct nds32_list *head)
{
  head->next = head;
}

void
nds32_list_insert (struct nds32_list *pos, const char *key, void *value)
{
  struct nds32_list *item;

  /* Check for duplicate key.  */
  gdb_assert (!nds32_list_lookup (pos, key));

  item = (struct nds32_list *) xmalloc (sizeof (struct nds32_list));
  item->key = xstrdup (key);
  item->value = value;
  item->next = pos->next;
  pos->next = item;
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
