dnl Process this file with autoconf to produce a configure script.
AC_PREREQ(2.64)dnl
AC_INIT(Makefile.in)
sinclude(../common/acinclude.m4)

SIM_AC_COMMON

SIM_AC_OPTION_WARNINGS
SIM_AC_OPTION_ALIGNMENT(NONSTRICT_ALIGNMENT)
SIM_AC_OPTION_ENVIRONMENT

NDS32_SIM_EXTRA_OBJS=

case ${host} in
  *mingw32*)
    NDS32_SIM_EXTRA_OBJS="${NDS32_SIM_EXTRA_OBJS} mingw32-hdep.o"
    ;;
  *) ;;
esac

AC_SUBST([NDS32_SIM_EXTRA_OBJS], ${NDS32_SIM_EXTRA_OBJS})

SIM_AC_OUTPUT
