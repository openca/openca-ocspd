## OpenCA OCSPD Makefile - by Massimiliano Pala
## (c) 2005-2013 by OpenCA Labs and Massimiliano Pala
## All Rights Reserved

TOP = ..
-include $(TOP)/global-vars

sbin_PROGRAMS = ocspd

ocspd_SOURCES = \
	ocspd.c \
	core.c \
	threads.c \
	request.c \
	response.c \
	config.c \
	crl.c 

EXTRA_DIST = \
	includes/*.h

ocspd_CPPFLAGS = -I. $(LIBPKI_CFLAGS)
ocspd_LDADD = $(LIBPKI_LDLIBS)

