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

#include <elf/external.h>	/* Elf32_External_Ehdr */
#include <elf/internal.h>	/* Elf_Internal_Ehdr */
#include "elf-bfd.h"		/* elf_elfheader () */
#include "observer.h"		/* observer_attach_inferior_created () */

#include "nds32-remote.h"
#include "nds32-tdep.h"

#include "nds32-elf.h"

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
  nds32_rt_sid,
  nds32_rt_ice,
  nds32_rt_unknown,
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

  /* SID use KINDPTR for software breakpoints,
      but ICEman, linux-gdbserver doesn't use it. */
  if (nds32_remote_info.type == nds32_rt_ice)
    {
      /* ICEman/AICE have trouble on reading memory when the pcptr is P/A,
	 but CPU is in V/A mode.  This code prevent GDB from reading memory.
	 ICEman will read memory itself if needed.  The kind is set to 3,
	 so target knows GDB doesn't actually read the memory.

	 See: Bug 7430 - GDB can't set a hardware break point with PA
	      if IT/DT is on.  */

      *kindptr = 3;
    }
  else
    gdbarch_breakpoint_from_pc (gdbarch, pcptr, kindptr);
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
    snprintf (line, len, "%s %s", cmd, arg);
  else
    snprintf (line, len, "%s", cmd);
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

  snprintf (cmd, sizeof (cmd), "monitor set %s pipeline-on 1",
	    args == NULL ? "cpu" : args);
  nds32_execute_command (cmd, NULL, from_tty);
}

/* Callback for "nds32 pipeline off" command.  */

static void
nds32_pipeline_off_command (char *args, int from_tty)
{
  char cmd[256];

  snprintf (cmd, sizeof (cmd), "monitor set %s pipeline-on 0",
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
	    snprintf (symbol_text, sizeof (symbol_text), "%s + 0x%x\n",
		      SYMBOL_PRINT_NAME (msymbol.minsym), offset);
	  else
	    snprintf (symbol_text, sizeof (symbol_text), "%s\n",
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
  snprintf ((char *) ui_buf.buf, ui_buf.buf_size, "set %s profiling ide-query",
	    args == NULL ? "cpu" : arg_cpu);
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

  snprintf (cmd, sizeof (cmd), "set %s perf-meter query",
	    args == NULL ? "cpu" : args);
  target_rcmd (cmd, gdb_stdtarg);
}

/* Callback for "nds32 reset profiling" command.  */

static void
nds32_reset_profiling_command (char *args, int from_tty)
{
  char cmd[256];

  snprintf (cmd, sizeof (cmd), "set %s profiling reset",
	    args == NULL ? "cpu" : args);
  target_rcmd (cmd, gdb_stdtarg);
}

/* Callback for "nds32 reset perfmeter" command.  */

static void
nds32_reset_perfmeter_command (char *args, int from_tty)
{
  char cmd[256];

  snprintf (cmd, sizeof (cmd), "set %s perf-meter reset",
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

static void
nds32_query_target_command (char *arg, int from_tty)
{
  char *buf;
  long size = 64;
  struct cleanup *back_to;
  char *cpu = nds32_remote_info.cpu;
  int cpu_size = ARRAY_SIZE (nds32_remote_info.cpu);

  nds32_remote_info_init ();

  if (strcmp (current_target.to_shortname, "remote") != 0)
    return;
  /* FIXME if we don't know, use ELF. */

  buf = xmalloc (size);
  back_to = make_cleanup (free_current_contents, &buf);

  /* NDS32_Q_TARGET, "qPart:nds32:ask:target"
     Query target type, "SID" or "ICE"

     NDS32_Q_CPU, "qPart:nds32:ask:cpu"
     Query CPU name, e.g., "core00"
     Prompt is changed accordingly. e.g., "core00(gdb) "

     NDS32_Q_ENDIAN, "qPart:nds32:ask:de"
     Query target default endian, "LE" or "BE" */

  putpkt (nds32_qparts[NDS32_Q_TARGET]);
  getpkt (&buf, &size, 0);
  if (strcmp (buf, "SID") == 0)
    nds32_remote_info.type = nds32_rt_sid;
  else if (strcmp (buf, "ICE") == 0)
    nds32_remote_info.type = nds32_rt_ice;
  else
    {
      nds32_remote_info.type = nds32_rt_unknown;
      goto end_query;
    }

  putpkt (nds32_qparts[NDS32_Q_CPU]);
  getpkt (&buf, &size, 0);
  if (strlen (buf) > 0 && buf[0] != 'E')
    {
      memset (cpu, 0, cpu_size);
      strncpy (cpu, buf, cpu_size - 1);
    }

  putpkt (nds32_qparts[NDS32_Q_ENDIAN]);
  getpkt (&buf, &size, 0);
  if (strcmp (buf, "LE") == 0)
    nds32_remote_info.endian = BFD_ENDIAN_LITTLE;
  else if (strcmp (buf, "BE") == 0)
    nds32_remote_info.endian = BFD_ENDIAN_BIG;
  else
    nds32_remote_info.endian = BFD_ENDIAN_UNKNOWN;

end_query:
  /* Set cpu name if ICE and CPU!="cpu".  */
  if (nds32_remote_info.type == nds32_rt_ice && strcmp ("cpu", cpu) != 0)
    {
      snprintf (buf, size, "%s(gdb) ", cpu);
      set_prompt (buf);
    }
  else
    {
      set_prompt ("(gdb) ");
    }

  do_cleanups (back_to);
}

/* Callback for elf-check.  */

static unsigned int
nds32_elf_check_get_register (unsigned int regno)
{
  ULONGEST regval;
  struct regcache *regcache = get_current_regcache ();
  struct gdbarch *gdbarch = get_regcache_arch (regcache);
  int regnum = -1;
  gdb_byte regbuf[4] = { 0 };

  if (nds32_remote_info.endian == BFD_ENDIAN_UNKNOWN)
    error (_("Cannot get target endian."));

  switch ((INDEX_HW_MASK & regno))
    {
    case INDEX_HW_CPU:
      switch ((regno & SR_INDEX_MASK))
	{
	case CPU_SR_INDEX (0, 0, 0):	/* cr0 */
	  regnum = user_reg_map_name_to_regnum (gdbarch, "cr0", -1);
	  break;
	case CPU_SR_INDEX (0, 1, 0):	/* cr1 */
	  regnum = user_reg_map_name_to_regnum (gdbarch, "cr1", -1);
	  break;
	case CPU_SR_INDEX (0, 2, 0):	/* cr2 */
	  regnum = user_reg_map_name_to_regnum (gdbarch, "cr2", -1);
	  break;
	case CPU_SR_INDEX (0, 3, 0):	/* cr3 */
	  regnum = user_reg_map_name_to_regnum (gdbarch, "cr3", -1);
	  break;
	case CPU_SR_INDEX (0, 4, 0):	/* cr4 */
	  regnum = user_reg_map_name_to_regnum (gdbarch, "cr4", -1);
	  break;
	case CPU_SR_INDEX (0, 0, 1):	/* cr5 */
	  regnum = user_reg_map_name_to_regnum (gdbarch, "cr5", -1);
	  break;
	case CPU_SR_INDEX (0, 5, 0):	/* cr6 */
	  regnum = user_reg_map_name_to_regnum (gdbarch, "cr6", -1);
	  break;
	default:
	  return -1;
	}

      if (regnum == -1)
	error ("Fail to access system registers for elf-check.");

      /* Use target-endian instead of gdbarch-endian.  */
      if (regcache_cooked_read (regcache, regnum, regbuf) != REG_VALID)
	return -1;
      regval = extract_unsigned_integer (regbuf, 4, nds32_remote_info.endian);

      return regval;
    }

  return -1;
}

/* Translate an ELF file header in internal format into an ELF file header in
   external format.

   elf_swap_ehdr_out () is copied from bfd/elfcode.h.  */

#define Elf_External_Ehdr	Elf32_External_Ehdr
#define H_PUT_WORD		H_PUT_32
#define H_PUT_SIGNED_WORD	H_PUT_S32
#define H_GET_WORD		H_GET_32
#define H_GET_SIGNED_WORD	H_GET_S32

static void
elf_swap_ehdr_out (bfd *abfd, const Elf_Internal_Ehdr *src,
		   Elf_External_Ehdr *dst)
{
  unsigned int tmp;
  int signed_vma = get_elf_backend_data (abfd)->sign_extend_vma;

  memcpy (dst->e_ident, src->e_ident, EI_NIDENT);
  /* Note that all elements of dst are *arrays of unsigned char* already...  */
  H_PUT_16 (abfd, src->e_type, dst->e_type);
  H_PUT_16 (abfd, src->e_machine, dst->e_machine);
  H_PUT_32 (abfd, src->e_version, dst->e_version);
  if (signed_vma)
    H_PUT_SIGNED_WORD (abfd, src->e_entry, dst->e_entry);
  else
    H_PUT_WORD (abfd, src->e_entry, dst->e_entry);
  H_PUT_WORD (abfd, src->e_phoff, dst->e_phoff);
  H_PUT_WORD (abfd, src->e_shoff, dst->e_shoff);
  H_PUT_32 (abfd, src->e_flags, dst->e_flags);
  H_PUT_16 (abfd, src->e_ehsize, dst->e_ehsize);
  H_PUT_16 (abfd, src->e_phentsize, dst->e_phentsize);
  tmp = src->e_phnum;
  if (tmp > PN_XNUM)
    tmp = PN_XNUM;
  H_PUT_16 (abfd, tmp, dst->e_phnum);
  H_PUT_16 (abfd, src->e_shentsize, dst->e_shentsize);
  tmp = src->e_shnum;
  if (tmp >= (SHN_LORESERVE & 0xffff))
    tmp = SHN_UNDEF;
  H_PUT_16 (abfd, tmp, dst->e_shnum);
  tmp = src->e_shstrndx;
  if (tmp >= (SHN_LORESERVE & 0xffff))
    tmp = SHN_XINDEX & 0xffff;
  H_PUT_16 (abfd, tmp, dst->e_shstrndx);
}

/* Callback for "nds32 elf-check" command.  */

static void
nds32_elf_check_command (char *arg, int from_tty)
{
  Elf_External_Ehdr x_ehdr;
  Elf_Internal_Ehdr *i_ehdrp;
  char check_msg[0x1000];
  unsigned int buf_status = 0;
  int err;

  if (exec_bfd == NULL)
    error (_("Cannot check ELF without executable.\n"
	     "Use the \"file\" or \"exec-file\" command."));

  /* elf-check with SID/ICE only. */
  if (nds32_remote_info.type == nds32_rt_unknown)
    return;

  i_ehdrp = elf_elfheader (exec_bfd);
  elf_swap_ehdr_out (exec_bfd, i_ehdrp, &x_ehdr);

  err = elf_check ((unsigned char *) &x_ehdr, nds32_elf_check_get_register,
		   check_msg, sizeof (check_msg), &buf_status);

  if (err)
    error ("%s", check_msg);
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
      snprintf (cmdline, sizeof (cmdline), "set gloss start_%s %u",
		sectnames[i + 1], (unsigned int) start);
      target_rcmd (cmdline, out);
      snprintf (cmdline, sizeof (cmdline), "set gloss end_%s %u",
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

  snprintf (cmdline, sizeof (cmdline),
	    "set gloss command-line \"%s %s\"", f, args);
  target_rcmd (cmdline, out);

  do_cleanups (back_to);
}

static void
nds32_remote_inferior_created_observer (struct target_ops *ops, int from_tty)
{
  nds32_query_target_command (NULL, 0);
}

static struct cmd_list_element *nds32_pipeline_cmdlist;
static struct cmd_list_element *nds32_query_cmdlist;
static struct cmd_list_element *nds32_reset_cmdlist;
static struct cmd_list_element *nds32_maint_cmdlist;

void
nds32_init_remote_cmds (void)
{
  /* Hook for query remote target information.  */
  observer_attach_inferior_created (nds32_remote_inferior_created_observer);
  nds32_remote_info_init ();

  /* nds32 elf-check */
  add_cmd ("elf-check", class_files, nds32_elf_check_command,
	   _("Check elf/target compatibility before loading. "
	     "Throwing error if failed."),
	   &nds32_cmdlist);

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
}
