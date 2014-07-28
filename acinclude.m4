dnl Check for extra support libraries and options 
AC_DEFUN(AC_CHECK_C_OPTION,
[ 
old_cflags=$CFLAGS
CFLAGS="$CFLAGS $1"

AC_MSG_CHECKING([checking for $1 support]);

AC_RUN_IFELSE( [
#include <stdlib.h>
int main(void)
{
        return(0);
}], [ _supported=yes ], [ _supported=no])

if [[ $_supported = no ]] ; then
        AC_MSG_RESULT([not supported]);
	CFLAGS=$old_cflags
else
        AC_MSG_RESULT([yes]);
fi])
