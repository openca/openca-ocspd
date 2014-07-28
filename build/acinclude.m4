dnl Check for OCSP support libraries in installed openssl
dnl maybe a better check for the libraries should be required
dnl expecially because if we support openssl_prefix we should
dnl support it here too

dnl AC_DEFUN(AC_PTHREAD_FLAGS, [ 
dnl opts=""
dnl AC_TRY_COMPILE ([ #include <sys/types.h>][#include <threads.h>],
dnl 	[ pthread_rwlock_t rwlock=PTHREAD_RWLOCK_INITIALIZER;],
dnl 	[ pthread_rw=yes ] , 
dnl 	[ pthread_rw=no ] )
dnl 
dnl if [[ x"$pthread_rw" = xno ]] ; then
dnl 
dnl 	AC_TRY_COMPILE ([
dnl #define _BSD_SOURCE
dnl #define _XOPEN_SOURCE 500
dnl #include <sys/types.h>
dnl #include <threads.h>
dnl ],
dnl [ pthread_rwlock_t rwlock=PTHREAD_RWLOCK_INITIALIZER;],
dnl [ pthread_rw=yes ] , [ pthread_rw=no ])
dnl 
dnl 	if test x"$pthread_rw" = xyes ; then
dnl 		opts="-D_BSD_SOURCE -D_XOPEN_SOURCE=500"
dnl 		AC_MSG_RESULT([pthread detected options    : $opts]);
dnl 	else
dnl 		AC_MSG_RESULT([pthread detected options    : none]);
dnl 	fi
dnl fi
dnl 
dnl PTHREAD_CFLAGS="$opts"
dnl AC_SUBST(PTHREAD_CFLAGS)
dnl ])

AC_DEFUN(AC_OPENSSL_OCSP,
[ AC_RUN_IFELSE( [
#include <openssl/ocsp.h>
int main(void)
{
	OCSP_CERTID *cid = NULL;
	return(0);
}], [ AC_DEFINE(HAVE_OCSP) ], [ocsp_error=1])

if [[ ocsp_error = 1 ]] ; then
	AC_MSG_RESULT([checking for OpenSSL OCSP support ... no]);
	AC_MSG_ERROR(
[*** OCSP support]
[*** missing support for ocsp, please update OpenSSL version]
[*** to 0.9.7 (or SNAPs). More info on http://www.openssl.org]
)
else
	AC_MSG_RESULT([OpenSSL OCSP support    : yes]);
fi])

AC_DEFUN(AC_OPENSSL_VERSION,
[ AC_EGREP_HEADER( [\#define\sOPENSSL_VERSION_NUMBER\s0x],
	[ $openssl_prefix/include/opensslv.h ],
	[ openssl_ver="0.9.8+"], 
    	[ openssl_ver="0.9.7"]
);

if [[ openssl_ver = "0.9.8+" ]] ; then
	AC_DEFINE(OPENSSL_VER_00908000)
else
	AC_DEFINE(OPENSSL_VER_00907000)
fi
        AC_MSG_RESULT([OpenSSL Detected Version: $openssl_ver]);
])

