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

#include <errno.h>
#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#include "bfd.h"
#include "elf-bfd.h"

#include "nds32-sim.h"
#include "nds32-mm.h"

/* Linux memory are emulated using `device', so we can have handling
   more sophiscated mapping operations then plain sim-core. */
const struct _device { char dummy; } nds32_mm_devices;

/* Read memory in Linux VMA.  */

int
nds32_mm_read (device *me ATTRIBUTE_UNUSED, void *source,
	       int space ATTRIBUTE_UNUSED, address_word addr,
	       unsigned nr_bytes, SIM_DESC sd, SIM_CPU *cpu,
	       sim_cia cia ATTRIBUTE_UNUSED)
{
  struct nds32_mm *mm = STATE_MM (sd);
  struct nds32_vm_area *vma;
  cpu = STATE_CPU (sd, 0);
  cia = CIA_GET (cpu);

#if defined (USE_TLB)
  if (mm->icache && addr >= mm->icache->vm_start
      && (addr + nr_bytes) <= mm->icache->vm_end)
    {
      mm->cache_ihit++;
      vma = mm->icache;
      goto FOUND;
    }
  else if (mm->dcache && addr >= mm->dcache->vm_start
	   && (addr + nr_bytes) <= mm->dcache->vm_end)
    {
      mm->cache_dhit++;
      vma = mm->dcache;
      goto FOUND;
    }
  /* mm->cache_miss++; */
  vma = nds32_find_vma (mm, addr);
  if (vma->vm_prot & PROT_EXEC)
    mm->icache = vma;
  else
    mm->dcache = vma;
#else
  vma = nds32_find_vma (mm, addr);
#endif

  if (vma == NULL || addr < vma->vm_start
      || (addr + nr_bytes - 1) >= vma->vm_end)
    return 0;

FOUND:
  memcpy (source, vma->vm_buf + (addr - vma->vm_start), nr_bytes);

  return nr_bytes;
}

/* Write memory in Linux VMA.  */

int
nds32_mm_write (device *me ATTRIBUTE_UNUSED, const void *source,
		int space ATTRIBUTE_UNUSED, address_word addr,
		unsigned nr_bytes, SIM_DESC sd, SIM_CPU *cpu,
		sim_cia cia)
{
  struct nds32_mm *mm = STATE_MM (sd);
  struct nds32_vm_area *vma = NULL;
  cpu = STATE_CPU (sd, 0);
  cia = CIA_GET (cpu);

#if defined (USE_TLB)
  if (mm->dcache && addr >= mm->dcache->vm_start
      && (addr + nr_bytes) <= mm->dcache->vm_end)
    {
      mm->cache_dhit++;
      vma = mm->dcache;
      goto FOUND;
    }
  mm->cache_miss++;
  vma = nds32_find_vma (mm, addr);
  mm->dcache = vma;
#else
  vma = nds32_find_vma (mm, addr);
#endif

  if (vma == NULL || addr < vma->vm_start
      || (addr + nr_bytes - 1) >= vma->vm_end)
    return 0;

FOUND:
  memcpy (vma->vm_buf + (addr - vma->vm_start), source, nr_bytes);

  return nr_bytes;
}

/* Allocate a VMA struct.  */

static struct nds32_vm_area *
nds32_alloc_vma ()
{
  struct nds32_vm_area *vma = xmalloc (sizeof (struct nds32_vm_area));
  vma->vm_start = 0;
  vma->vm_end = 0;
  vma->vm_buf = NULL;
  vma->vm_prev = vma->vm_next = vma;
  return vma;
}

/* Free a VMA struct.  */

static void
nds32_free_vma (struct nds32_vm_area *vma)
{
  /* The caller should un-map vm_buf itself.  */
  free (vma);
}

/* Find the first VMA which satisfices addr < vma->vm_end. */

struct nds32_vm_area *
nds32_find_vma (struct nds32_mm *mm, uint32_t addr)
{
  struct nds32_vm_area *vma;

  for (vma = MM_HEAD (mm)->vm_next; vma != MM_HEAD (mm); vma = vma->vm_next)
    {
      if (vma->vm_end > addr)
	break;
    }

  if (vma != MM_HEAD (mm))
    {
      return vma;
    }
  return NULL;
}

/* Find a proper place and insert the VMA.  */

static void
nds32_link_vma (struct nds32_mm *mm, struct nds32_vm_area *vma)
{
  struct nds32_vm_area *prev; /* The vma is to be inserted after prev vma.  */

  prev = nds32_find_vma (mm, vma->vm_start);
  if (prev)
    prev = prev->vm_prev;
  else
    /* If the is not match vma, then vma is to be inserted after LAST vma. */
    prev = MM_HEAD (mm)->vm_prev;

  vma->vm_next = prev->vm_next;
  vma->vm_prev = prev;
  prev->vm_next->vm_prev = vma;
  prev->vm_next = vma;

#if defined (USE_TLB)
  mm->icache = mm->dcache = NULL;
#endif
}

/* Remove a VMA mapping and unmap its buffer.  */

static void
nds32_unlink_vma (struct nds32_mm *mm, uint32_t addr, uint32_t len)
{
  struct nds32_vm_area *vma;
  uint32_t end = addr + len;

  vma = nds32_find_vma (mm, addr);
  if (!vma)
    return;

#if defined (USE_TLB)
  mm->icache = mm->dcache = NULL;
#endif
  /*
    Possible intersection cases:

      |---vma i---|   |---vma i+1---|

    |-----|
	|----|
    |---------------|
	|-----------|
    |-------------------------|
	|---------------------|
   */

  for ( ; end > vma->vm_start && vma != MM_HEAD (mm); vma = vma->vm_next)
    {
      uint32_t os, oe;	/* start-end in this vma  */
      uint32_t ol;	/* len */

      /*
	 buf
	  |--------vma---------|
		|----ol----|
		os	   oe
       */
      os = (addr <= vma->vm_start) ? vma->vm_start : addr;
      oe = (end >= vma->vm_end) ? vma->vm_end : end;
      ol = oe - os;

      munmap (vma->vm_buf + (os - vma->vm_start), ol);

      if (os > vma->vm_start && oe < vma->vm_end)
	{
	  /* Split */
	  struct nds32_vm_area *vma_tmp = nds32_alloc_vma ();
	  vma_tmp->vm_start = oe;
	  vma_tmp->vm_end = vma->vm_end;
	  vma_tmp->vm_buf = vma->vm_buf + (oe - vma->vm_start);
	  vma_tmp->vm_prot = vma->vm_prot;
	  vma->vm_end = os;
	  nds32_link_vma (mm, vma_tmp);
	}
      else if (os == vma->vm_start && oe == vma->vm_end)
	{
	  /* Unlink complelte */
	  vma->vm_prev->vm_next = vma->vm_next;
	  vma->vm_next->vm_prev = vma->vm_prev;
	  nds32_free_vma (vma);
	}
      else if (oe < vma->vm_end)
	vma->vm_start  = oe;
      else if (os > vma->vm_start)
	vma->vm_end = os;
    }
}

void
nds32_freeall_vma (struct nds32_mm *mm)
{
  struct nds32_vm_area *vma;
  struct nds32_vm_area *next;

  if (MM_HEAD (mm)->vm_next == NULL || MM_HEAD (mm)->vm_prev == NULL)
    return;

  for (vma = MM_HEAD (mm)->vm_next; vma != MM_HEAD (mm); vma = next)
    {
      next = vma->vm_next;
      munmap (vma->vm_buf, vma->vm_end - vma->vm_start);
      nds32_free_vma (vma);
    }
}

/* Dump VMA list for debugging.  */

void
nds32_dump_vma (struct nds32_mm *mm)
{
  struct nds32_vm_area *vma;

  for (vma = MM_HEAD (mm)->vm_next; vma != MM_HEAD (mm); vma = vma->vm_next)
    printf ("%08x-%08x @ %p\n", vma->vm_start, vma->vm_end, vma->vm_buf);
}

/* Find a suitable address for addr/len.  */

uint32_t
nds32_get_unmapped_area (struct nds32_mm *mm, uint32_t addr, uint32_t len)
{
  struct nds32_vm_area *vma;

  if (addr == 0)
    addr = mm->free_cache;

  vma = nds32_find_vma (mm, addr);

  if (!vma)
    return addr;

  do
    {
      if (addr + len <= vma->vm_start)
	return addr;
      addr = vma->vm_end;
      vma = vma->vm_next;
    }
  while (vma != MM_HEAD (mm));

  return -1;
}

void
nds32_mm_init (struct nds32_mm *mm)
{
  mm->mmap.vm_start = 0;
  mm->mmap.vm_end = 0;
  mm->mmap.vm_buf = NULL;
  mm->mmap.vm_prev = mm->mmap.vm_next = MM_HEAD (mm);
  mm->start_sp = STACK_TOP;
  mm->free_cache = TASK_UNMAPPED_BASE;
#if defined (USE_TLB)
  mm->icache = mm->dcache = NULL;
  mm->cache_miss = 0;
  mm->cache_ihit = mm->cache_dhit = 0;
#endif
}

/* munmap () for Linux VMA.  */

int
nds32_munmap (sim_cpu *cpu, uint32_t addr, size_t len)
{
  SIM_DESC sd = CPU_STATE (cpu);
  struct nds32_mm *mm = STATE_MM (sd);

  nds32_unlink_vma (mm, PAGE_ALIGN (addr),
		    PAGE_ROUNDUP (addr + len) - PAGE_ALIGN (addr));

  return 0; /* FIXME?  */
}

/* mmap for Linux VMA.  */

void *
nds32_mmap (sim_cpu *cpu, uint32_t addr, size_t len,
	      int prot, int flags, int fd, off_t offset)
{
  SIM_DESC sd = CPU_STATE (cpu);
  struct nds32_mm *mm = STATE_MM (sd);
  host_callback *cb = STATE_CALLBACK (sd);
  void *phy = NULL;
  struct nds32_vm_area *vma;

  /* For debugging */
  prot |= PROT_READ | PROT_WRITE;

  if (flags & MAP_ANONYMOUS)
    phy = mmap (NULL, len, prot, flags & ~MAP_FIXED, fd, offset);
  else if (fd < 0 || fd > MAX_CALLBACK_FDS || cb->fd_buddy[fd] < 0)
    return (void *) EBADF;
  else
    {
      fd = cb->fdmap[fd];
      phy = mmap (NULL, len, prot, flags & ~MAP_FIXED, fd, offset);
    }

  if (phy == MAP_FAILED)
    return phy;

  if (flags & MAP_FIXED)
    {
      /* Detach before attach */
      nds32_munmap (cpu, addr, len);
    }

  addr = nds32_get_unmapped_area (mm, addr, len);
  vma = nds32_alloc_vma ();
  vma->vm_buf = phy;
  vma->vm_start = addr;
  vma->vm_prot = prot;
  vma->vm_end = addr + PAGE_ROUNDUP (len);
  nds32_link_vma (mm, vma);

  return (void *) addr;
}

uint32_t
nds32_sys_brk (sim_cpu *cpu, uint32_t addr)
{
  SIM_DESC sd = CPU_STATE (cpu);
  struct nds32_mm *mm = STATE_MM (sd);

  /* FIXME: Check sys_brk () in kernel/mm/mmap.c for details.  */

  if (mm->brk == 0)
    return 0;

  if (addr == 0)
    return mm->brk;

  if (PAGE_ALIGN (addr) == PAGE_ALIGN (mm->brk))
    return mm->brk = addr;

  if (addr < mm->brk)
    {
      /* delete pages */
      nds32_munmap (cpu, PAGE_ROUNDUP (addr), mm->brk - PAGE_ROUNDUP (addr));
      return mm->brk = addr;
    }
  else
    {
      /* create pages */
      nds32_mmap (cpu, PAGE_ROUNDUP (mm->brk), addr - PAGE_ROUNDUP (mm->brk),
		PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS,
		-1, 0);
      return mm->brk = addr;
    }
}

/* Calculate the total size for mapping an ELF.  */

static int
total_mapping_size (Elf_Internal_Phdr *phdr, int n)
{
  int i;
  int first = -1;
  int last = - 1;

  for (i = 0; i < n; i++)
    {
      if (phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0)
	continue;

      if (first == -1)
	first = i;
      last = i;
    }

  return phdr[last].p_vaddr +  phdr[last].p_memsz - phdr[first].p_vaddr;
}

/* Map memory for loadable segments.  */

void
nds32_map_segments (SIM_DESC sd, struct bfd *abfd)
{
  int i;
  char buf[1024];
  Elf_Internal_Phdr *phdr;
  Elf_Internal_Phdr *interp_phdr = NULL;
  uint32_t off;
  uint32_t len;
  int sysroot_len;
  uint32_t interp_base;
  SIM_CPU *cpu = STATE_CPU (sd, 0);
  struct rlimit limit;
  struct nds32_mm *mm = STATE_MM (sd);

  getrlimit (RLIMIT_STACK, &limit);
  mm->limit_sp = limit.rlim_cur;
  getrlimit (RLIMIT_DATA, &limit);
  mm->limit_data = limit.rlim_cur;

  if (mm->limit_sp & 1) /* Unlimited?  */
    mm->limit_sp = 0x800000;
  if (mm->limit_data & 1) /* Unlimited?  */
    mm->limit_data = 0x800000;

  /* See sim-config.h for detailed explanation.
	--environment user|virtual|operating

     By default, the setting is 'all' for un-selected.

     In my current design, USER_ENVIRONMENT is used for Linux application,
     so
	1. Load ELF by segment instead of by section.
	2. Load dynamic-link (INTERP) if needed
	3. Prepare stack for arguments, environments and AUXV.
	4. Use nds32-mm for memory mapping
     If the ENVIRONMENT is not USER, the I treat it as normal ELF
     application, so only a single 64MB memory block is allocated,
     and default sim_load_file () is used.  */

  /* For emulating Linux VMA */
  sim_core_attach (sd, NULL, 0, access_read_write_exec, 0, 0x00004000,
		   0xFFFF8000, 0, &nds32_mm_devices, NULL);

  nds32_mm_init (mm);

  /* Allocate stack.  */
  /* TODO: Executable stack.  Currently, EXEC affects vma cache. */
  nds32_mmap (cpu, mm->start_sp - mm->limit_sp, mm->limit_sp,
	      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
	      -1, 0);

  /* FIXME: Handle ET_DYN and ET_EXEC.  */
  phdr = elf_tdata (abfd)->phdr;
  sd->exec_base = -1;
  for (i = 0; i < elf_elfheader (abfd)->e_phnum; i++)
    {
      uint32_t addr, len;
      uint32_t prot = 0;

      if (phdr[i].p_type == PT_INTERP)
	interp_phdr = &phdr[i];

      if (phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0)
	continue;

      addr = phdr[i].p_vaddr;
      len = addr + phdr[i].p_memsz - PAGE_ALIGN (addr);
      len = PAGE_ROUNDUP (len);
      addr = PAGE_ALIGN (addr);

      if (phdr[i].p_flags & PF_X)
	prot |= PROT_EXEC;
      if (phdr[i].p_flags & PF_W)
	prot |= PROT_WRITE;
      if (phdr[i].p_flags & PF_R)
	prot |= PROT_READ;

      if (sd->exec_base == -1)
	sd->exec_base = addr;

      nds32_mmap (cpu, addr, len, prot,
		  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
		  -1, 0);

      if (addr + len > mm->brk)
	mm->brk = addr + len;
    }

  /* TODO: Pre-map brk */

  if (!interp_phdr)
    return;

  /* Read path of interp.  */
  off = interp_phdr->p_offset;
  len = interp_phdr->p_filesz;
  sysroot_len = strlen (simulator_sysroot);

  strcpy (buf, simulator_sysroot);
  if (buf[sysroot_len - 1] == '/')
    buf[--sysroot_len] = '\0';

  if (bfd_seek (abfd, off, SEEK_SET) != 0
      || bfd_bread (buf + sysroot_len, len, abfd) != len)
    return;

  sd->interp_bfd = bfd_openr (buf, 0);

  if (sd->interp_bfd == NULL)
    return;

  bfd_check_format (sd->interp_bfd, bfd_object);

  /* Add memory for interp.  */
  phdr = elf_tdata (sd->interp_bfd)->phdr;
  len = total_mapping_size (phdr, elf_elfheader (sd->interp_bfd)->e_phnum);
  interp_base = nds32_get_unmapped_area (mm, 0, len);
  for (i = 0; i < elf_elfheader (sd->interp_bfd)->e_phnum; i++)
    {
      uint32_t addr, len, prot = 0;

      if (phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0)
	continue;

      addr = interp_base + phdr[i].p_vaddr;
      len = addr + phdr[i].p_memsz - PAGE_ALIGN (addr);
      len = PAGE_ROUNDUP (len);
      addr = PAGE_ALIGN (addr);

      if (phdr[i].p_flags & PF_X)
	prot |= PROT_EXEC;
      if (phdr[i].p_flags & PF_W)
	prot |= PROT_WRITE;
      if (phdr[i].p_flags & PF_R)
	prot |= PROT_READ;

      nds32_mmap (cpu, addr, len, prot,
		  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
		  -1, 0);
    }

  sd->interp_base = interp_base;
}
