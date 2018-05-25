dnl -*- mode: m4; -*-
dnl Process this file with autoconf to produce a configure script.
AC_REVISION($Revision: 1.4 $)

AC_COPYRIGHT([Copyright 2007-2015 by Massimiliano Pala and OpenCA Labs])

dnl Autoconf
AC_INIT(openca-ocspd, 3.1.2, [ocspd-users@lists.sourceforge.net], [openca-ocspd])

dnl Some variables
VERSION=$PACKAGE_VERSION
PKG_VER=$PACKAGE_VERSION
PKG_MIN=2
RC=1

AC_SUBST(RC)
AC_SUBST(PKG_VER)
AC_SUBST(PKG_MIN)
AC_SUBST(VERSION)


dnl Autoconf boilerplate/
dnl AC_INIT(src/ocspd/ocspd.c)
dnl AC_INIT(openca-ocspd, 2.5.0)
AC_CONFIG_SRCDIR([src/ocspd/ocspd.c])
AC_PREREQ(2.50)
AC_CONFIG_AUX_DIR(build)
AC_CONFIG_MACRO_DIR([m4])

mybits=""
if [[ `uname -m` = "x86_64" ]] ; then
	mybits="64";
fi
AC_SUBST(mybits)

dnl Automake boilerplate.
dnl if ! [[ -f "/etc/issue" ]] ; then
        AC_CANONICAL_SYSTEM
dnl         AC_PROG_LIBTOOL
dnl fi

dnl AC_CANONICAL_SYSTEM
dnl AM_INIT_AUTOMAKE( $PACKAGE_NAME, $PKG_VER )
AM_INIT_AUTOMAKE

dnl Options.
#AC_DISABLE_FAST_INSTALL
#AC_DISABLE_SHARED
AM_MAINTAINER_MODE

myarch=

dnl Select OS specific versions of source files.
rpath_opt="-Wl,-rpath -Wl,"
rpath=
shlext=so
dnl enable_shared=yes
case "${build_os}" in
 *linux*) 
		myarch=linux
		shlext=so
		;;
 *bsd*) myarch=bsd
		shlext=so
		;;
 *iphone*)
		myarch=iphone
		shlext=dylib
		;;
 *darwin*)
		myarch=darwin
		shlext=dylib
		;;
 *sun*) myarch=solaris
		shlext=so
		rpath_opt="-R "
		;;
 *solaris*)
		myarch=solaris
		shlext=so
		rpath_opt="-R "
		;;
 *hpux*)        myarch=hpux
		shlext=so
		;;
 *) AC_MSG_ERROR([Operating system ${build_os} not supported]) ;;
esac

arch_target=

case "$target" in
	i*86-*)           arch_target=x86 ;;
	x86_64-*)         arch_target=x86_64 ;;
	sparc*-*)         arch_target=Sparc ;;
	powerpc*-*)       arch_target=PowerPC ;;
	*sparc*solaris*)  arch_target=Sparc ;;
	*arm*)  	  	  arch_target=armv6 ;;
	*)                arch_target=Unknown ;;
esac

AC_SUBST(shlext)
AC_SUBST(arch_target)
AC_SUBST(myarch)

AM_CONDITIONAL(OCSPD_ARCH_LINUX, test x$arch = xlinux)
AM_CONDITIONAL(OCSPD_ARCH_BSD, test x$arch = xbsd)
AM_CONDITIONAL(OCSPD_ARCH_OSX, test x$arch = xdarwin)
AM_CONDITIONAL(OCSPD_ARCH_SOLARIS, test x$arch = xsolaris)
AM_CONDITIONAL(OCSPD_ARCH_HPUX, test x$arch = xhpux)

AC_CHECK_LIB(pthread, pthread_create, 
	[ AC_DEFINE(HAVE_LIBPTHREAD, 1, [PTHREAD Library])],
	[ AC_MSG_ERROR([pthread library is needed!]) ]
)

sys_cflags=
sys_ldlibs=

if test x$arch = xlinux ; then
  AC_DEFINE(PRQPD_TARGET_LINUX, 1, [Linux])
  sys_ldlibs="-lpthread "
fi

if test x$arch = xbsd ; then
  AC_DEFINE(PRQPD_TARGET_BSD, 1, [BSD])
  sys_ldlibs="-pthread "
fi

if test x$arch = xdarwin ; then
  AC_DEFINE(PRQPD_TARGET_OSX, 1, [OSX])
fi

if test x$arch = xsolaris ; then
  AC_DEFINE(PRQPD_TARGET_SOLARIS, 1, [Solaris])
fi

if test x$arch = xhpux ; then
  AC_DEFINE(PRQPD_TARGET_HPUX, 1, [HP-UX])
fi

AC_SUBST(sys_cflags)
AC_SUBST(sys_ldlibs)


dnl Checks for programs.
dnl AC_CONFIG_HEADERS
AC_STDC_HEADERS
AC_HAVE_HEADERS(string.h stdio.h stdlib.h fcntl.h sys/file.h sys/param.h sys/sem.h sys/ipc.h)

AC_CONFIG_HEADERS(src/ocspd/includes/config.h)

AM_PROG_CC_C_O

dnl AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_LN_S

AM_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

AC_SUBST(ac_aux_dir)


AC_PROG_EGREP

if [[ "x$myarch" = "xsolaris" ]] ; then
	DIST_VERSION=`uname -r`
else
	if [[ -f "/etc/issue" ]] ; then
	   DIST_VERSION=`$EGREP -o [[0-9.]]+ /etc/issue | head -n 1`
	else
	   DIST_VERSION=`echo ${build_os} | $EGREP -o [[0-9.]]+`
	fi
fi

AC_SUBST(DIST_VERSION)

if [[ -f "/etc/issue" ]] ; then
   DIST_NAME=`head -n 1 /etc/issue | cut -f 1,1 -d ' '`
else
   DIST_NAME=`echo ${build_os} | $EGREP -o [[A-Za-z]]+`
fi

AC_SUBST(DIST_NAME)

dnl check for libraries
AC_CHECK_LIB(nsl, gethostbyname)
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(resolv, res_query)

dnl Check for Pod2Man program
AC_PATH_PROG( POD2MAN, pod2man,pod2man,
                $PATH:/sbin:/usr/sbin:/usr/local/sbin)

dnl Check for Pod2Html program
AC_PATH_PROG( POD2HTML, pod2html,pod2html,
                $PATH:/sbin:/usr/sbin:/usr/local/sbin)

dnl Check for package and related programs
AC_PATH_PROG(DATE, date)
AC_PATH_PROG(CHMOD, chmod)
AC_PATH_PROG(PKGMK, pkgmk)
AC_PATH_PROG(RPM, rpm)
if test -n "${PKGMK}"
then
        PKGMK=package
else
        if test -n "${RPM}"
        then
                PKGMK=rpm
        fi
fi
AC_SUBST(PKGMK)
AC_PATH_PROG(PERL, perl)
AC_SUBST(PERL)

AC_MSG_RESULT([architecture            : ${build_os} ])

dnl ======================== GENERAL OPTS ================================

AC_ARG_ENABLE(extra-checks,
	AC_HELP_STRING( [--enable-extra-checks=DEFAULT],
		[enables extra compile-time checks (GCC) (for devel only)]),
			extra_checks=$enableval, extra_checks=no )
AC_SUBST(extra_checks)

dnl check for stack protection of gcc
if [[ "$CC" = "gcc" ]] ; then
	AC_CHECK_C_OPTION(-fstack-check)
	AC_CHECK_C_OPTION(-maccumulate-outgoing-args)
	AC_CHECK_C_OPTION(-Werror)
	AC_CHECK_C_OPTION(-Wfatal-errors)
	if [[ "x${extra_checks}" = "xyes" ]] ; then
		AC_CHECK_C_OPTION(-Wall)
		AC_CHECK_C_OPTION(-Wmissing-field-initializers)
		AC_CHECK_C_OPTION(-Wmissing-parameter-type)
		AC_CHECK_C_OPTION(-Wtype-limits)
		AC_CHECK_C_OPTION(-Wuninitialized)
		AC_CHECK_C_OPTION(-Wconversion)
		AC_CHECK_C_OPTION(-fsanitize=address)
	fi

       if [[ "$DIST_NAME" = "darwin" ]] ; then
                AC_CHECK_C_OPTION(-Wno-deprecated)
        fi

	dnl AC_CHECK_C_OPTION(-m64)
	dnl AC_CHECK_C_OPTION(-rdynamic)
	dnl AC_CHECK_C_OPTION(--export-dynamic)
	dnl AC_CHECK_C_OPTION(--export-all-symbols)
fi

EXTRA_CFLAGS=$CFLAGS
my_cflags=$EXTRA_CFLAGS
AC_SUBST(EXTRA_CFLAGS)
AC_SUBST(my_cflags)

dnl ========================= LIBPKI OPTS ================================

AC_ARG_WITH( libpki-prefix,
[  --with-libpki-prefix=DIR          libpki prefix directory],
[ libpki_prefix=$withval ] , [ libpki_prefix= ] )

AC_SUBST(libpki_prefix)

AC_MSG_RESULT([with libpki-prefix     : $libpki_prefix ])

if [[ "x$libpki_prefix" != x ]]; then
        libpki_path=$libpki_prefix/lib
        libpki_config="${libpki_prefix}/bin/libpki-config"
else
        AC_PATH_PROG( libpki_config, libpki-config, libpki-config,
                ${prefix}/bin:$PATH:/bin:/usr/bin:/usr/local/bin:/usr/local/libpki/bin:/opt/csw/bin:/opt/csw/libpki/bin
)

fi

if ! [[ -x "$libpki_config" ]] ; then
        AC_MSG_ERROR([**** ERROR: Can not find libpki-config ($libpki_config)
command!])
fi

pkiprefix=`${libpki_config} --prefix`
pkipath="${libpki_prefix}/lib"
#libpki_cflags="-I`${libpki_config} --prefix`/include "
pkicflags="`${libpki_config} --cflags`"
# pkildlibs="-L`${libpki_config} --prefix`/lib -lpki"
pkildlibs="`${libpki_config} --libs`"
pkiversion=`${libpki_config} --version`
pkiversion_num=`echo $pkiversion | sed "s|\.||g"`

pkirequired="0.8.9"
pkirequired_num=`echo $pkirequired | sed "s|\.||g"`

if [[ $pkiversion_num -lt $pkirequired_num ]] ; then
	AC_MSG_ERROR([**** ERROR: Min LibPKI supported ver. $pkirequired (found $pkiversion)]);
fi

AC_SUBST(pkiprefix)
AC_SUBST(pkildlibs)
AC_SUBST(pkicflags)
AC_SUBST(pkipath)
AC_SUBST(DESTDIR)

dnl ========================== Install Builder Path Search ===================

builder_path=$default_path:$HOME/installbuilder/bin:$HOME/installbuilder-5.4.10/bin:$HOME/installbuilder/bin/Builder.app/Contents/MacOS/

ibuilder="builder"

if [[ "x$DIST_NAME" = "xdarwin" ]] ; then
	ibuilder="installbuilder.sh"
fi
AC_PATH_PROG(INSTALL_BUILDER, $ibuilder, , $builder_path )
AC_SUBST(INSTALL_BUILDER)

dnl AC_MSG_ERROR( [****** ($DIST_NAME) IBUILDER is : $ibuilder and INSTALL_BUILDER is $INSTALL_BUILDER] );

dnl ======================== DAEMON OPTIONS =============================

default_user=nobody
default_group=nobody

if [[ "x$DIST_NAME" = "xUbuntu" ]] ; then
	default_user=www-data
	default_group=www-data
fi

dnl OCSP daemon default user
AC_ARG_WITH( ocspd-user,  
[  --with-ocspd-user=ARG              user to run processes as [ocspd]],
[  user=$withval  ] , [  user=$default_user ] )

AC_MSG_RESULT([default ocspd user      : $user ])
AC_SUBST(user)

dnl OCSP daemon default group
AC_ARG_WITH( ocspd-group,  
[  --with-ocspd-group=ARG             group to run processes as [daemon]],
[  group=$withval  ] , [  group=$default_group  ] )

AC_MSG_RESULT([default ocspd group     : $group ])
AC_SUBST(group)

dnl Semaphores vs Flock Support
AC_ARG_ENABLE( semaphores,
[  --enable-semaphores          use semaphores locking method (yes)],
[case "${enableval}" in
  yes)	sem=true ;;
  no)	sem=false ;;
  *) AC_MSG_ERROR([bad value ${sem} for --enable-semaphores]) ;;
 esac], [sem=true])


AC_ARG_ENABLE( flock,
[  --enable-flock               use semaphores locking method (no)],
[case "${enableval}" in
  yes)	flock=true && sem=false ;;
  no)	flock=false && sem=true ;;
  *) AC_MSG_ERROR([bad value ${flock} for --enable-flock]) ;;
 esac], [flock=false])

if [[ x$sem = xtrue ]] ; then
	AC_DEFINE(HAVE_SEMAPHORES, [1], [Support for Semaphores])
	AC_MSG_RESULT([enable semaphores       : ${sem}])
else
	flock=true;
	AC_DEFINE(HAVE_FLOCK, [1], [Support for File Locking])
	AC_MSG_RESULT([enable flock            : ${flock}])
fi

AM_CONDITIONAL(HAVE_SEMAPHORES, test x$sem = xtrue)
AM_CONDITIONAL(HAVE_FLOCK, test x$flock = xtrue)

dnl Debug option
AC_ARG_ENABLE(debug,
[  --enable-debug          enable debug messages.],
[ case "${enableval}" in
  yes)	
    debug=true ;;
  no)	
    debug=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
 esac], [debug=false])

AC_MSG_RESULT([enable debug messages   : $debug])

if test x${debug} = xtrue ; then
  AC_DEFINE(OCSPD_DEBUG, 1, [enable full OCSPD debug messaging.])
fi

if [[ x${prefix} = xNONE ]]; then
	prefix="/usr";
fi

dnl OpenCA prefix
AC_ARG_WITH( openca-prefix,
[  --with-openca-prefix=ARG    OpenCA install prefix (PREFIX/OpenCA)],
[ openca_prefix=$withval], [openca_prefix=${prefix}/OpenCA] )

if [[ x${openca_prefix} = x ]] ; then
  AC_MSG_ERROR([bad value ${openca_prefix} for --with-openca-prefix])
fi

dnl AC_MSG_RESULT([with openca-prefix      : $openca_prefix ])
AC_SUBST(openca_prefix)

dnl AC_MSG_RESULT([install prefix          : $prefix])

dnl Write Makefiles.
AC_OUTPUT(
	Makefile
	src/Makefile
	src/global-vars
	src/ocspd/Makefile
	docs/Makefile
	etc/Makefile
	etc/ocspd
	etc/ocspd.xml
	etc/token.d/software.xml
	etc/token.d/etoken.xml
	etc/token.d/eracom.xml
	contrib/openca-ocspd.pc
	contrib/openca-ocspd.xml
	contrib/openca-ocspd-common.xml
	scripts/ocspd-genreq.sh
)


echo "
Configuration for $PACKAGE_NAME $VERSION :
--------------------------------------

 Install Prefix .......: $prefix
 Host System Type .....: $host
 Install path .........: $prefix
 Preprocessor .........: $CC $CPPFLAGS
 Compiler .............: $CC $CFLAGS $pkicflags
 Linker ...............: $CC $LDFLAGS $LIBS $pkildlibs
"

echo "
 Now type 'make' to build $PACKAGE_NAME $VERSION,
 and then 'make install' for installation.
"

