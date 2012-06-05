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

#ifndef MINGW32_HDEP_H
#define MINGW32_HDEP_H

#include <stdint.h>

/*
 * sys/mman.h
 */

/* Return value of `mmap' in case of an error.  */
#define MAP_FAILED	((void *) -1)

#define PROT_READ	0x1		/* Page can be read.  */
#define PROT_WRITE	0x2		/* Page can be written.  */
#define PROT_EXEC	0x4		/* Page can be executed.  */
#define PROT_NONE	0x0		/* Page can not be accessed.  */
#define PROT_GROWSDOWN	0x01000000	/* Extend change to start of
					   growsdown vma (mprotect only).  */
#define PROT_GROWSUP	0x02000000	/* Extend change to start of
					   growsup vma (mprotect only).  */

/* Sharing types (must choose one and only one of these).  */
#define MAP_SHARED	0x01		/* Share changes.  */
#define MAP_PRIVATE	0x02		/* Changes are private.  */

/* Other flags.  */
#define MAP_FIXED	0x10		/* Interpret addr exactly.  */
#define MAP_ANONYMOUS	0x20		/* Don't use a file.  */
#define MAP_ANON	MAP_ANONYMOUS

/* These are Linux-specific.  */
#define MAP_STACK	0x20000		/* Allocation is for a stack.  */

/*
 * Syscalls
 */

typedef long long loff_t;	/* llseek () */

struct timeval {
  uint32_t tv_sec;
  uint32_t tv_usec;
};

struct timezone {
  uint32_t tz_minuteswest;
  uint32_t tz_dsttime;
};

/* All times reported are in clock ticks.  */
struct tms {
  uint32_t tms_utime;
  uint32_t tms_stime;
  uint32_t tms_cutime;
  uint32_t tms_cstime;
};

struct utsname {
  char sysname[65];	/* Operating system name (e.g., "Linux") */
  char nodename[65];	/* Name within "some implementation-defined
			  network" */
  char release[65];	/* OS release (e.g., "2.6.28") */
  char version[65];	/* OS version */
  char machine[65];	/* Hardware identifier */
#if 0 && defined (_GNU_SOURCE)
  char domainname[65];	/* NIS or YP domain name */
#endif
};

/*
 * rlimit
 */
struct rlimit {
  rlim_t rlim_cur;  /* Soft limit */
  rlim_t rlim_max;  /* Hard limit (ceiling for rlim_cur) */
};

#define RLIMIT_DATA		2	/* max data size */
#define RLIMIT_STACK		3	/* max stack size */

int getrlimit(int resource, struct rlimit *rlim);


#endif
