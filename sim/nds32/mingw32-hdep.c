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

#include <stdio.h>

#define UNIMP(SYSCALL)	\
	void SYSCALL () { puts ("Unimplemented syscall " #SYSCALL); abort (); }

/* These system calls are only used by Linux program.
   It shouldn't bother ELF programs.
   I define these symbol just to make mingw32-build happy.
   It will take time to implement these, especially mmap,
   and unfortunately mmap is the most important syscall for
   Linux dynamically linked program.

   On Windows, non-anonymouse mapping should be done with
     CreateFileMapping () and MapViewOfFile ().
   Anonymous mapping should be done with VirtualAlloc () or just malloc ().

   The allocation granularity seems quiet large, 64 KB,
   returned by GetSystemInfo ().
   See http://msdn.microsoft.com/en-us/library/windows/desktop/aa366761%28v=vs.85%29.aspx
  */

UNIMP(getegid);
UNIMP(uname);
UNIMP(link);
UNIMP(getgid);
UNIMP(getuid);
UNIMP(times);
UNIMP(geteuid);
UNIMP(setgid);
UNIMP(setuid);
UNIMP(ioctl);
UNIMP(fcntl);
UNIMP(munmap);
UNIMP(mmap);
