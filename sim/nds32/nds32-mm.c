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

#include <sys/mman.h>
#include <errno.h>

#include "nds32-sim.h"
#include "nds32-mm.h"

int
nds32_munmap (sim_cpu *cpu, uint32_t addr, size_t len)
{
  uint32_t p;
  SIM_DESC sd = CPU_STATE (cpu);

  for (p = PAGE_ALIGN (addr); p < addr + len; p += PAGE_SIZE)
    sim_core_detach (sd, cpu, 0, 0, p);

  return 0; /* FIXME?  */
}

void *
nds32_mmap (sim_cpu *cpu, uint32_t addr, size_t len,
	      int prot, int flags, int fd, off_t offset)
{
  SIM_DESC sd = CPU_STATE (cpu);
  host_callback *cb = STATE_CALLBACK (sd);
  void *phy = NULL;
  int i, p;
  struct nds32_mm *mm = STATE_MM (sd);

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

  /* FIXME: FIXME FIXME:

     I implemented this way because I want to emulate Linux mmap,
     "overlapped part of the existing mapping(s) will be discarded."

     But I found it became a VERY severe performance bottleneck,
     since sim_core_find_mapping searches sequentially.
     The same program with dynamically linked could be 9 times slower
     than statically linked one.

     I should study how Linux manage process address space (e.g., vm_struct),
     and implement it here instead of using GDB sim-core.  */

  if (flags & MAP_FIXED)
    {
      /* Detach before attach */
      for (p = addr; p < addr + len; p += PAGE_SIZE)
	sim_core_detach (sd, cpu, 0, 0, p);
    }
  else if ((flags & MAP_STACK) == 0)
    addr = mm->unmapped;

  if (PAGE_ROUNDUP (addr + len) > mm->unmapped
      && (flags & MAP_STACK) == 0)
    mm->unmapped = PAGE_ROUNDUP (addr + len);

  /* FIXME: It just works. Make it solid.
	    It should return MAP_FAILED for fail.  */
  for (i = 0, p = PAGE_ALIGN (addr); p < addr + len; p += PAGE_SIZE, i++)
    sim_core_attach (sd, NULL, 0, access_read_write_exec,
		     0, p, PAGE_SIZE, 0, NULL, (char *) phy + i * PAGE_SIZE);

  return (void *) PAGE_ALIGN (addr);
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
		PROT_READ | PROT_WRITE | PROT_EXEC,
		MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
		-1, 0);
      return mm->brk = addr;
    }
}

void
nds32_expand_stack (sim_cpu *cpu, int size)
{
  SIM_DESC sd = CPU_STATE (cpu);
  /* FIXME and TODO:
     Study how kernel really handle this.
     Re-write this when nds32_vm_area is readly.  */

  size = PAGE_ROUNDUP (size);
  STATE_MM (sd)->sp -= size;
  nds32_mmap (cpu, STATE_MM (sd)->sp, size,
		PROT_READ | PROT_WRITE | PROT_EXEC,
		MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
		-1, 0);
}
