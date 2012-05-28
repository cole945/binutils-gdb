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

#ifndef NDS32_MM_H
#define NDS32_MM_H

#include <stdint.h>
#include "sim-main.h"
#include "sim-base.h"

#define ALIGN(x, a)		((x) & ~(a-1))
#define ROUNDUP(x, a)		(ALIGN ((x) + ((a) - 1), a))

#define PAGE_SIZE		0x1000
#define PAGE_ALIGN(x)		ALIGN (x, PAGE_SIZE)
#define PAGE_ROUNDUP(x)		ROUNDUP (x, PAGE_SIZE)

#define TASK_SIZE		0xbf000000
#define STACK_TOP		TASK_SIZE
#define RLIMIT_STACK_SIZE	(8 * 1024 * 1024)
#define TASK_UNMAPPED_BASE	PAGE_ALIGN (TASK_SIZE / 3)
#define MM_HEAD(mm)     (&(mm)->mmap)

extern struct _device nds32_mm_devices;

struct nds32_vm_area
{
  uint32_t vm_start;			/* First address of this interval */
  uint32_t vm_end;			/* First address after this interval */
  struct nds32_vm_area *vm_next;
  struct nds32_vm_area *vm_prev;
  char *vm_buf;
};

struct nds32_mm
{
  struct nds32_vm_area mmap;		/* Head node for vm_area */

  uint32_t start_brk;			/* Start address of brk */
  uint32_t brk;				/* Final address of brk */
  uint32_t start_sp;			/* Start address of stack */
  uint32_t free_cache;			/* Last address for mmap. */
};

void nds32_mm_init (struct nds32_mm *mm);
int nds32_expand_stack (sim_cpu *cpu, uint32_t addr);
struct nds32_vm_area *nds32_find_vma (struct nds32_mm *mm, uint32_t addr);
void nds32_dump_vma (struct nds32_mm *mm);
uint32_t nds32_sys_brk (sim_cpu *cpu, uint32_t addr);
int nds32_munmap (sim_cpu *cpu, uint32_t addr, size_t len);
void *nds32_mmap (sim_cpu *cpu, uint32_t addr, size_t len,
	      int prot, int flags, int fd, off_t offset);
uint32_t nds32_get_unmapped_area (struct nds32_mm *mm, uint32_t addr,
				  uint32_t len);

#endif
