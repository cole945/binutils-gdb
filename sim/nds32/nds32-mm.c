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
#if defined (__linux__)
#include <sys/mman.h>
#elif defined (__WIN32__)
#include "mingw32-hdep.h"
#endif

#include "bfd.h"
#include "elf-bfd.h"

#include "nds32-sim.h"
#include "nds32-mm.h"

/* Linux memory are emulated using `device',
   so we can have handling more sophiscated maping operations then sim-core. */
struct _device { char dummy; } nds32_mm_devices;

void
device_error (device *me ATTRIBUTE_UNUSED,
		const char *message ATTRIBUTE_UNUSED,
		...)
{
  abort ();
}

/* Read memory in Linux VMA.  */

int
device_io_read_buffer (device *me ATTRIBUTE_UNUSED,
			void *source,
			int space ATTRIBUTE_UNUSED,
			address_word addr, unsigned nr_bytes,
			SIM_DESC sd, SIM_CPU *cpu,
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
      /* mm->cache_ihit++; */
      vma = mm->icache;
      goto FOUND;
    }
  else if (mm->dcache && addr >= mm->dcache->vm_start
	   && (addr + nr_bytes) <= mm->dcache->vm_end)
    {
      /* mm->cache_dhit++; */
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
device_io_write_buffer (device *me ATTRIBUTE_UNUSED,
			const void *source,
			int space ATTRIBUTE_UNUSED,
			address_word addr, unsigned nr_bytes,
			SIM_DESC sd, SIM_CPU *cpu, sim_cia cia)
{
  struct nds32_mm *mm = STATE_MM (sd);
  struct nds32_vm_area *vma = NULL;
  cpu = STATE_CPU (sd, 0);
  cia = CIA_GET (cpu);

#if defined (USE_TLB)
  if (mm->dcache && addr >= mm->dcache->vm_start
      && (addr + nr_bytes) <= mm->dcache->vm_end)
    {
      /* mm->cache_dhit++; */
      vma = mm->dcache;
      goto FOUND;
    }
  /* mm->cache_miss++; */
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

/* Dump VMA list for debugging.  */

void
nds32_dump_vma (struct nds32_mm *mm)
{
  struct nds32_vm_area *vma;

  for (vma = MM_HEAD (mm)->vm_next; vma != MM_HEAD (mm); vma = vma->vm_next)
    printf ("%08x-%08x\n", vma->vm_start, vma->vm_end);
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
  /* mm->cache_miss = 0;
  mm->cache_ihit = mm->cache_dhit = 0; */
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
