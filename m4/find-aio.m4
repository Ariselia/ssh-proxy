dnl ######################################################################
dnl libaio support
AC_DEFUN([FIND_LIBAIO], [
AC_REQUIRE([NTP_PKG_CONFIG])dnl

case "$enable_libaio" in
 yes)
    have_libaio=no
    case "$PKG_CONFIG" in
     '')
	;;
     *)
	LIBAIO_LIBS=`$PKG_CONFIG --libs libaio 2>/dev/null`
	case "$LIBAIO_LIBS" in
	 '') ;;
	 *) LIBAIO_LIBS="$LIBAIO_LIBS $EV_LIB_GDI $EV_LIB_WS32 $LIBAIO_LIBADD"
	    have_libaio=yes
	    ;;
	esac
	LIBAIO_INCS=`$PKG_CONFIG --cflags libaio 2>/dev/null`
	;;
    esac
    AC_SUBST(LIBAIO_INCS)
    AC_SUBST(LIBAIO_LIBS)
    case "$have_libaio" in
     yes)  AC_DEFINE(HAVE_LIBAIO, 1, [Define if the system has libaio]) ;;
    esac
    ;;
esac

# check if we have and should use libaio
AM_CONDITIONAL(LIBAIO, [test "$enable_libaio" != "no" && test "$have_libaio" = "yes"])
])
