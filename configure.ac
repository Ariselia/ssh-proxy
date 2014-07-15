#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(ssh-proxy, 1.0, wangfengxy@sina.cn)
AC_CONFIG_HEADER(config.h)
AC_CONFIG_SRCDIR([proxy/ssh-proxy.c])
#AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE()

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_LIBTOOL

#Checks for libraries.
PKG_CHECK_MODULES([LIBAIO],[libaio],[],[AC_MSG_ERROR(["Error! You need to have libaio-3.1 installed!"])])


#PKG_CHECK_MODULES([glib],[glib-2.0],[],[AC_MSG_ERROR(["Error! You need to have glib2.0 installed!"])])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h \
		string.h \
		unistd.h \
		])


# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_STRUCT_TM
AC_HEADER_STDBOOL

# Checks for library functions.
#AC_FUNC_MALLOC

AC_CONFIG_FILES([Makefile \
		misc/Makefile \
		ssh/Makefile \
		proxy/Makefile \
		samples/Makefile
            ])

AC_OUTPUT
