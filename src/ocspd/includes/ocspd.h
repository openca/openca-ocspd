/*
 * OCSP responder
 * by Massimiliano Pala (madwolf@openca.org)
 * OpenCA project 2001
 *
 * Copyright (c) 2001-2004 The OpenCA Project.  All rights reserved.
 * OpenCA Licensed Software.
 *
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#ifdef USER
#define OCSPD_DEF_USER		USER
#else
#define OCSPD_DEF_USER		"ocspd"
#endif
#ifdef GROUP
#define OCSPD_DEF_GROUP		GROUP
#else
#define OCSPD_DEF_GROUP		"daemon"
#endif
#ifdef CONFIG
#define OCSPD_DEF_CONFIG	CONFIG
#else
#define OCSPD_DEF_CONFIG	"/etc/ocspd.xml"
#endif

#define OCSPD_DEF_PIDFILE	"/var/run/ocspd.pid"

