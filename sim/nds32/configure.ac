dnl Process this file with autoconf to produce a configure script.
AC_PREREQ(2.64)dnl
AC_INIT(Makefile.in)
sinclude(../common/acinclude.m4)

SIM_AC_COMMON

SIM_AC_OPTION_WARNINGS
SIM_AC_OPTION_ALIGNMENT(NONSTRICT_ALIGNMENT)
SIM_AC_OPTION_ENVIRONMENT

NDS32_SIM_EXTRA_OBJS=

AC_CHECK_FUNCS([ \
	getuid getgid geteuid getegid setuid setgid \
	access fcntl link \
	gettimeofday times \
	getrlimit setrlimit \
])

AC_CHECK_FUNCS([mmap munmap], \
	NDS32_SIM_EXTRA_OBJS="${NDS32_SIM_EXTRA_OBJS} nds32-mm.o")

AC_CHECK_HEADERS([ \
	sys/ioctl.h \
	sys/mman.h \
	sys/resource.h \
	sys/times.h \
])

AC_SUBST([NDS32_SIM_EXTRA_OBJS], ${NDS32_SIM_EXTRA_OBJS})

SIM_AC_OUTPUT
