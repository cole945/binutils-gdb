/* Commands for communication with NDS32 remote target.

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
#include "gdb_string.h"
#include "gdbcore.h"
#include "gdbcmd.h"
#include "gdbtypes.h"
#include "cli/cli-decode.h"
#include "remote.h"
#include "regcache.h"
#include "user-regs.h"
#include "inferior.h"		/* get_inferior_args () */
#include "top.h"		/* set_prompt () */
#include "ui-out.h"		/* current_uiout */
#include "exceptions.h"		/* TRY_CATCH */
#include <ctype.h>

#include "nds32-remote.h"
#include "nds32-tdep.h"

char *nds32_qparts [] =
{
  "qPart:nds32:ask:de",
  "qPart:nds32:ask:mach",
  "qPart:nds32:ask:base16",
  "qPart:nds32:ask:pex1",
  "qPart:nds32:ask:pex2",
  "qPart:nds32:ask:div",
  "qPart:nds32:ask:abi",
  "qPart:nds32:ask:mfusr_pc",
  "qPart:nds32:ask:fpu",
  "qPart:nds32:ask:audio",
  "qPart:nds32:ask:string",
  "qPart:nds32:ask:reduced_regs",
  "qPart:nds32:ask:video",
  "qPart:nds32:ask:ifc",
  "qPart:nds32:ask:elf_ver",
  "qPart:nds32:ask:l2c",
  "qPart:nds32:ask:mac",
  "qPart:nds32:ask:cpu", /* core0, cpu, etc */
  "qPart:nds32:ask:target", /* SID, ICE */

  "qPart:nds32:request:InvalidateCache",
  "qPart:nds32:request:MemAccBus",
  "qPart:nds32:request:MemAccCPU"
};

enum nds32_qparts_enum
{
  NDS32_Q_ENDIAN,
  NDS32_Q_MACH,
  NDS32_Q_BASE16,
  NDS32_Q_PEX1,
  NDS32_Q_PEX2,
  NDS32_Q_DIV,
  NDS32_Q_ABI,
  NDS32_Q_MFUSR_PC,
  NDS32_Q_FPU,
  NDS32_Q_AUDIO,
  NDS32_Q_STRING,
  NDS32_Q_REDUCED_REGS,
  NDS32_Q_VIDEO,
  NDS32_Q_IFC,
  NDS32_Q_ELF_VER,
  NDS32_Q_L2C,
  NDS32_Q_MAC,
  NDS32_Q_CPU,
  NDS32_Q_TARGET,

  NDS32_Q_INVALIDATE_CACHE,
  NDS32_Q_ACC_BUS,
  NDS32_Q_ACC_CPU,
  NDS32_Q_END
};

enum nds32_remote_type
{
  nds32_rt_unknown = 0,
  nds32_rt_sid,
  nds32_rt_ice,
  nds32_rt_ocd,
};

struct
{
  enum nds32_remote_type type;
  char cpu[16];
  enum bfd_endian endian;
} nds32_remote_info;

void
nds32_remote_breakpoint_from_pc (struct gdbarch *gdbarch, CORE_ADDR *pcptr,
				 int *kindptr)
{
  if ((*pcptr) & 1)
    error (_("bad address %p for inserting breakpoint"), (void *) *pcptr);

  /* ICEman/AICE have trouble on reading memory when the pcptr is P/A,
     but CPU is in V/A mode.  This code prevent GDB from reading memory.
     ICEman will read memory itself if needed.

     See: Bug 7430 - GDB can't set a hardware break point with PA
	  if IT/DT is on.  */

  *kindptr = 2;
}

/* Wrapper for execute a GDB CLI command.  */

static void
nds32_execute_command (char *cmd, char *arg, int from_tty)
{
  int len;
  char *line;

  if (arg == NULL)
    arg = "";
  len = strlen (arg) + strlen (cmd) + 2;
  if (len > 1024)
    error (_("Command line too long."));

  line = alloca (len);
  memset (line, 0, len);
  if (arg != NULL)
    xsnprintf (line, len, "%s %s", cmd, arg);
  else
    xsnprintf (line, len, "%s", cmd);
  execute_command (line, from_tty);
}

static void
nds32_restore_remote_timeout (void *p)
{
  int value = *(int *) p;

  remote_timeout = value;
}

/* Reset-target.
   Set remote_timeout to 1000 sec to avoid timeout.  */

static void
nds32_reset_target_command (char *args, int from_tty)
{
  int saved_remote_timeout = remote_timeout;
  struct cleanup *back_to;

  back_to = make_cleanup (nds32_restore_remote_timeout, &saved_remote_timeout);
  remote_timeout = 1000;
  nds32_execute_command ("monitor reset target", NULL, from_tty);
  registers_changed ();
  do_cleanups (back_to);
}

/* Callback for "nds32 reset-hold" command.  */

static void
nds32_reset_hold_command (char *args, int from_tty)
{
  int saved_remote_timeout = remote_timeout;
  struct cleanup *back_to;

  back_to =
    make_cleanup (nds32_restore_remote_timeout, &saved_remote_timeout);
  remote_timeout = 1000;
  nds32_execute_command ("monitor reset hold", NULL, from_tty);
  registers_changed ();
  do_cleanups (back_to);
}

/* Callback for "nds32 pipeline on" command.  */

static void
nds32_pipeline_on_command (char *args, int from_tty)
{
  char cmd[256];

  xsnprintf (cmd, sizeof (cmd), "monitor set %s pipeline-on 1",
	     args == NULL ? "cpu" : args);
  nds32_execute_command (cmd, NULL, from_tty);
}

/* Callback for "nds32 pipeline off" command.  */

static void
nds32_pipeline_off_command (char *args, int from_tty)
{
  char cmd[256];

  xsnprintf (cmd, sizeof (cmd), "monitor set %s pipeline-on 0",
	     args == NULL ? "cpu" : args);
  nds32_execute_command (cmd, NULL, from_tty);
}

/* Callback for "nds32 pipeline" command.  */

static void
nds32_pipeline_command (char *args, int from_tty)
{
  error (_("Usage: nds32 pipeline (on|off) [cpu]"));
}

/* Callback for "nds32 query" command.  */

static void
nds32_query_command (char *args, int from_tty)
{
  error (_("Usage: nds32 query (profiling|perf-meter) [cpu] [human|ide]"));
}

/* Callback for "nds32 reset" command.  */

static void
nds32_reset_command (char *args, int from_tty)
{
  error (_("Usage: nds32 reset (profiling|perf-meter) [cpu]"));
}

/* Pretty-print for profiling data.  */

static void
nds32_print_human_table (int col, int row, const char *scsv)
{
  int i;
  struct cleanup *table_cleanup = NULL;
  struct cleanup *row_cleanup = NULL;
  char *buf = NULL;
  char **col_fldname;
  char **col_hdrtext;
  int *col_width;
  enum ui_align *col_align;
  struct bound_minimal_symbol msymbol;
  CORE_ADDR addr;
  char symbol_text[256];

  buf = xstrdup (scsv);
  make_cleanup (xfree, buf);

  /* Allocate header structures.  */
  col_fldname = (char **) xmalloc (sizeof (col_fldname[0]) * col);
  col_hdrtext = (char **) xmalloc (sizeof (col_hdrtext[0]) * col);
  col_width = (int *) xmalloc (sizeof (col_width[0]) * col);
  col_align = (enum ui_align *) xmalloc (sizeof (col_align[0]) * col);

  make_cleanup (xfree, col_fldname);
  make_cleanup (xfree, col_hdrtext);
  make_cleanup (xfree, col_width);
  make_cleanup (xfree, col_align);

  /* Parsing column header.  */
  i = 0;
  while (*buf != '\0' && i < col)
    {
      CORE_ADDR addr = 0;
      char *sc = strchr (buf, ';');

      *sc = '\0';
      col_fldname[i] = buf;
      col_hdrtext[i] = col_fldname[i];
      if (col_fldname[i][0] == '%')
	col_width[i] = 6;
      else
	col_width[i] = strlen (col_hdrtext[i]) + 1;

      col_align[i] = ui_right;

      i++;
      buf = sc + 1;
    }

  gdb_assert (col == i);

  /* Output table.  */
  table_cleanup = make_cleanup_ui_out_table_begin_end
    (current_uiout, col, row - 1, "ProfilingTable");
  for (i = 0; i < col; i++)
    ui_out_table_header (current_uiout, col_width[i], col_align[i],
			 col_fldname[i], col_hdrtext[i]);

  ui_out_table_body (current_uiout);

  /* Parse buf into col/row.  */
  i = 0;
  row_cleanup = make_cleanup_ui_out_tuple_begin_end (current_uiout, "row");
  while (*buf != '\0')
    {
      char *sc = strchr (buf, ';');
      int offset;

      *sc = '\0';
      switch (i)
	{
	case 0:
	  ui_out_field_string (current_uiout, col_fldname[i], buf);

	  /* Assume first column is address.  */
	  strcpy (symbol_text, "\n");
	  addr = strtol (buf, NULL, 16);
	  msymbol = lookup_minimal_symbol_by_pc (addr);
	  if (!msymbol.minsym)
	    break;

	  offset = addr - SYMBOL_VALUE_ADDRESS (msymbol.minsym);
	  if (offset)
	    xsnprintf (symbol_text, sizeof (symbol_text), "%s + 0x%x\n",
		       SYMBOL_PRINT_NAME (msymbol.minsym), offset);
	  else
	    xsnprintf (symbol_text, sizeof (symbol_text), "%s\n",
		       SYMBOL_PRINT_NAME (msymbol.minsym));
	  break;
	case 1: case 2: case 3: case 4: case 5: case 6:
	  ui_out_field_string (current_uiout, col_fldname[i], buf);
	  break;
	}

      i++;
      buf = sc + 1;
      if (i == col)
	{
	  ui_out_text (current_uiout, symbol_text);
	  do_cleanups (row_cleanup);
	  i = 0;
	  row_cleanup = make_cleanup_ui_out_tuple_begin_end
	    (current_uiout, "row");
	}
    }

  do_cleanups (table_cleanup);
}

/* Callback for "nds32 query profiling" command.  */

static void
nds32_query_profiling_command (char *args, int from_tty)
{
  /* For profiling, there will be multiple responses.  */
  int row, col;
  struct ui_file *res;
  int i;
  long int pkt_size;
  char *pkt_buf = NULL;
  struct ui_file_buffer ui_buf;
  char *arg_cpu = "cpu";
  int arg_human = TRUE;
  struct cleanup *back_to = NULL;
  char **argv = NULL;
  char *p;

  /* Initial size. It may be resized by getpkt.  */
  pkt_size = 1024;

  res = mem_fileopen ();
  back_to = make_cleanup_ui_file_delete (res);

  ui_buf.buf_size = 2048;
  ui_buf.buf = xmalloc (ui_buf.buf_size);
  pkt_buf = xmalloc (pkt_size);

  make_cleanup (free_current_contents, &ui_buf.buf);
  make_cleanup (free_current_contents, &pkt_buf);
  make_cleanup_restore_ui_file (&gdb_stdtarg);

  gdb_stdtarg = res;

  if (args != NULL)
    {
      /* Parse arguments.  */
      argv = gdb_buildargv (args);
      make_cleanup_freeargv (argv);
    }

  for (i = 0; argv && argv[i]; i++)
    {
      switch (i)
	{
	case 0:
	  arg_cpu = argv[i];
	  break;
	case 1:
	  arg_human = strcmp (argv[i], "ide");	/* default human */
	  break;
	}
    }

  /* Fill BUF with monitor command. */
  xsnprintf ((char *) ui_buf.buf, ui_buf.buf_size,
	     "set %s profiling ide-query", args == NULL ? "cpu" : arg_cpu);
  target_rcmd ((char *) ui_buf.buf, res);
  memset (ui_buf.buf, 0, ui_buf.buf_size);
  ui_file_put (res, do_ui_file_put_memcpy, &ui_buf);

  if (!arg_human)
    {
      fprintf_unfiltered (gdb_stdtarg,
			  "=profiling,reason=\"fast_l1_profiling\",data=\"%s\"\n",
			  ui_buf.buf);
      goto bye;
    }

  /* The first response is Row=%d;Column=%d;
     and then comes 'Row' rows, including head row */
  i = sscanf ((char *) ui_buf.buf, "Row=%d;Column=%d;", &row, &col);
  if (i != 2)
    error (_("Failed to query profiling data"));

  p = (char *) ui_buf.buf;

  /* Skip "Row=r;Column=c;".  */
  for (i = 0; i < 2 && p; i++)
    p = strchr (p + 1, ';');
  p++;

  /* Print human-mode table here.  */
  nds32_print_human_table (col, row, p);

bye:
  do_cleanups (back_to);
}

/* Callback for "nds32 query perfmeter" command.  */

static void
nds32_query_perfmeter_command (char *args, int from_tty)
{
  /* For perfmeter, there will be only one response.  */
  char cmd[128];

  xsnprintf (cmd, sizeof (cmd), "set %s perf-meter query",
	     args == NULL ? "cpu" : args);
  target_rcmd (cmd, gdb_stdtarg);
}

/* Callback for "nds32 reset profiling" command.  */

static void
nds32_reset_profiling_command (char *args, int from_tty)
{
  char cmd[256];

  xsnprintf (cmd, sizeof (cmd), "set %s profiling reset",
	     args == NULL ? "cpu" : args);
  target_rcmd (cmd, gdb_stdtarg);
}

/* Callback for "nds32 reset perfmeter" command.  */

static void
nds32_reset_perfmeter_command (char *args, int from_tty)
{
  char cmd[256];

  xsnprintf (cmd, sizeof (cmd), "set %s perf-meter reset",
	     args == NULL ? "cpu" : args);
  target_rcmd (cmd, gdb_stdtarg);
}

static void
nds32_remote_info_init (void)
{
  nds32_remote_info.type = nds32_rt_unknown;
  nds32_remote_info.endian = BFD_ENDIAN_UNKNOWN;
  strcpy (nds32_remote_info.cpu, "cpu");
}

/* Query target information.  */

static struct value *
nds32_target_type_make_value (struct gdbarch *gdbarch, struct internalvar *var,
			      void *ignore)
{
  int val = 0;

  if (strcmp (target_shortname, "remote") == 0
      || strcmp (target_shortname, "extended-remote") == 0)
    val = target_has_registers ? nds32_remote_info.type
			       : nds32_rt_unknown;

  return value_from_longest (builtin_type (gdbarch)->builtin_int,
			     val);
}

static int
nds32_query_target_using_qpart (void)
{
  char *buf;
  long size = 64;
  struct cleanup *back_to;
  int ret = FALSE;

  /* The buffer passed to getpkt must be allocated using xmalloc,
     because it might be xrealloc by read_frame.
     See remote.c for details.  `buf' must be freed before return.  */
  buf = xmalloc (size);

  /* Let caller clean it up.  */
  back_to = make_cleanup (free_current_contents, &buf);

  /* qPart:nds32:ask:target - SID or ICE.  */
  nds32_remote_info.type = nds32_rt_unknown;
  putpkt (nds32_qparts[NDS32_Q_TARGET]);
  getpkt (&buf, &size, 0);
  if (strcmp (buf, "SID") == 0)
    nds32_remote_info.type = nds32_rt_sid;
  else if (strcmp (buf, "ICE") == 0)
    nds32_remote_info.type = nds32_rt_ice;
  else
    goto out;

  /* qPart:nds32:ask:cpu - prompt, e.g., "core0(gdb) ".  */
  putpkt (nds32_qparts[NDS32_Q_CPU]);
  getpkt (&buf, &size, 0);
  if (strlen (buf) > 0 && buf[0] != 'E')
    {
      const int csize = sizeof (nds32_remote_info.cpu);
      memset (nds32_remote_info.cpu, 0, csize);
      strncpy (nds32_remote_info.cpu, buf, csize - 1);
    }

  /* qPart:nds32:ask:de - endian, e.g., LE or BE.  */
  putpkt (nds32_qparts[NDS32_Q_ENDIAN]);
  getpkt (&buf, &size, 0);
  if (strcmp (buf, "LE") == 0)
    nds32_remote_info.endian = BFD_ENDIAN_LITTLE;
  else if (strcmp (buf, "BE") == 0)
    nds32_remote_info.endian = BFD_ENDIAN_BIG;
  else
    nds32_remote_info.endian = BFD_ENDIAN_UNKNOWN;
  ret = TRUE;

out:
  do_cleanups (back_to);
  return ret;
}

static int
nds32_query_target_using_qrcmd (void)
{
  struct cleanup *back_to;
  struct ui_file *res;
  struct ui_file_buffer ui_buf;
  char buf[64];
  int ret = FALSE;
  volatile struct gdb_exception except;
  int len;

  /* ui_file for qRcmd.  */
  res = mem_fileopen ();
  back_to = make_cleanup_ui_file_delete (res);

  /* ui_file_buffer for reading ui_file.  */
  ui_buf.buf_size = 64;
  ui_buf.buf = xmalloc (ui_buf.buf_size);
  make_cleanup (free_current_contents, &ui_buf.buf);

  /* make_cleanup outside TRY_CACHE,
     because it save and reset cleanup-chain.  */
  make_cleanup_restore_ui_file (&gdb_stdtarg);
  /* Supress error messages from gdbserver
     if gdbserver doesn't support the monitor command.  */
  gdb_stdtarg = res;

  TRY_CATCH (except, RETURN_MASK_ERROR)
    {
      target_rcmd ("nds query target", res);
    }
  if (except.reason < 0)
    goto out;

  /* Read data in ui_file.  */
  memset (ui_buf.buf, 0, ui_buf.buf_size);
  ui_file_put (res, do_ui_file_put_memcpy, &ui_buf);

  /* Trim trailing newline characters.  */
  len = strlen ((char *) ui_buf.buf);
  while (isspace (ui_buf.buf[len - 1]) && len > 0)
    len--;
  ui_buf.buf[len] = '\0';

  if (strcmp ((char *) ui_buf.buf, "OCD") == 0)
    nds32_remote_info.type = nds32_rt_ocd;
  else
    {
      printf_unfiltered (_("Unknown remote target %s\n"),
			 ui_buf.buf);
      goto out;
    }

  ret = TRUE;
out:
  do_cleanups (back_to);
  return ret;
}

static void
nds32_query_target_command (char *arg, int from_tty)
{
  nds32_remote_info_init ();

  if (strcmp (target_shortname, "remote") != 0)
    return;
  /* FIXME if we don't know, use ELF. */

  /* Try to find out the type of target - SID, ICE or OCD.  */
  if (!nds32_query_target_using_qpart ())
    nds32_query_target_using_qrcmd ();

end_query:
  /* Set cpu name if ICE and CPU!="cpu".  */
  if (strcmp ("cpu", nds32_remote_info.cpu) != 0)
    {
      char buf[64];

      xsnprintf (buf, sizeof (buf), "%s(gdb) ", nds32_remote_info.cpu);
      set_prompt (buf);
    }
  else
    {
      /* Restore to DEFAULT_PROMPT.  */
      set_prompt ("(gdb) ");
    }
}

/* This is only used for SID.  Set command-line string.  */

static void
nds32_set_gloss_command (char *arg, int from_tty)
{
  int i;
  struct ui_file *out;
  char *arg0;
  char *args;
  char *f;
  char cmdline[0x1000];		/* 4K for max command line.  */
  struct cleanup *back_to;
  asection *s = NULL;
  const char *sectnames[] = { ".text", "code", ".bss", "bss" };

  /* set gloss for SID only. */
  if (nds32_remote_info.type != nds32_rt_sid)
    return;

  back_to = make_cleanup (null_cleanup, 0);
  if (exec_bfd == NULL)
    error (_("Cannot set gloss without executable.\n"
	     "Use the \"file\" or \"exec-file\" command."));

  /* ui_file for target_rcmd.  */
  out = stdio_fileopen (stdout);
  make_cleanup_ui_file_delete (out);

  /* start_code, end_code, start_bss, end_bss,
     brk, command-line.  */
  for (s = exec_bfd->sections; s; s = s->next)
    {
      bfd_vma start, size;
      const char *attr;

      for (i = 0; i < ARRAY_SIZE (sectnames); i += 2)
	if (strcmp (bfd_get_section_name (exec_bfd, s), sectnames[i]) == 0)
	  break;

      if (i >= ARRAY_SIZE (sectnames))
	continue;

      start = bfd_get_section_vma (exec_bfd, s);
      size = bfd_section_size (exec_bfd, s);

      /* Set gloss (start|end)_XXX.  */
      xsnprintf (cmdline, sizeof (cmdline), "set gloss start_%s %u",
		 sectnames[i + 1], (unsigned int) start);
      target_rcmd (cmdline, out);
      xsnprintf (cmdline, sizeof (cmdline), "set gloss end_%s %u",
		 sectnames[i + 1], (unsigned int) (start + size));
      target_rcmd (cmdline, out);
    }

  /* Set gloss command-line for "set args".  */
  arg0 = bfd_get_filename(exec_bfd);
  args = get_inferior_args ();

  f = strrchr (arg0, '/');
  if (f == NULL)
    f = strrchr (arg0, '\\');

  if (f == NULL)
    f = "a.out";
  else
    f++; /* skip separator.  */

  xsnprintf (cmdline, sizeof (cmdline),
	     "set gloss command-line \"%s %s\"", f, args);
  target_rcmd (cmdline, out);

  do_cleanups (back_to);
}

static struct cmd_list_element *nds32_pipeline_cmdlist;
static struct cmd_list_element *nds32_query_cmdlist;
static struct cmd_list_element *nds32_reset_cmdlist;
static struct cmd_list_element *nds32_maint_cmdlist;

static const struct internalvar_funcs nds32_target_type_funcs =
{
    nds32_target_type_make_value,
    NULL,
    NULL
};

void
nds32_init_remote_cmds (void)
{
  nds32_remote_info_init ();

  /* nds32 set-gloss COMMAND_LINE */
  add_cmd ("set-gloss", class_files, nds32_set_gloss_command,
	   _("Check elf/target compatibility before loading. "
	     "Throwing error if failed."),
	   &nds32_cmdlist);

  /* nds32 reset-target */
  add_cmd ("reset-target", no_class, nds32_reset_target_command,
	   _("Turn on pipeline for profiling."), &nds32_cmdlist);
  /* nds32 reset-hold */
  add_cmd ("reset-hold", no_class, nds32_reset_hold_command,
	   _("Turn off pipeline for profiling."), &nds32_cmdlist);

  /* nds32 pipeline (on|off) */
  add_prefix_cmd ("pipeline", no_class, nds32_pipeline_command,
		  _("nds32-sid profiling commands."),
		  &nds32_pipeline_cmdlist, "nds32 ", 0, &nds32_cmdlist);
  add_cmd ("on", no_class, nds32_pipeline_on_command,
	   _("Turn on pipeline for profiling."), &nds32_pipeline_cmdlist);
  add_cmd ("off", no_class, nds32_pipeline_off_command,
	   _("Turn off pipeline for profiling."), &nds32_pipeline_cmdlist);

  /* nds32 query (profiling|perf-meter|target)  */
  add_prefix_cmd ("query", no_class, nds32_query_command,
		  _("Query remote data."), &nds32_query_cmdlist, "query ",
		  0, &nds32_cmdlist);
  add_cmd ("profiling", no_class, nds32_query_profiling_command,
	   _("Query profiling results."), &nds32_query_cmdlist);
  add_cmd ("perf-meter", no_class, nds32_query_perfmeter_command,
	   _("Query perf-meter results."), &nds32_query_cmdlist);
  add_cmd ("target", no_class, nds32_query_target_command,
	   _("Query target information."), &nds32_query_cmdlist);

  /* nds32 reset (profiling|perf-meter)  */
  add_prefix_cmd ("reset", no_class, nds32_reset_command,
		  _("Reset profiling."), &nds32_reset_cmdlist, "reset ",
		  0, &nds32_cmdlist);
  add_cmd ("profiling", no_class, nds32_reset_profiling_command,
	   _("Query profiling results."), &nds32_reset_cmdlist);
  add_cmd ("perf-meter", no_class, nds32_reset_perfmeter_command,
	   _("Query perf-meter results."), &nds32_reset_cmdlist);

  create_internalvar_type_lazy ("_nds32_target_type", &nds32_target_type_funcs,
				NULL);
}
