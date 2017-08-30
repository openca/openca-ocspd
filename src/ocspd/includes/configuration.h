/*
 * OCSP responder
 * by Massimiliano Pala (madwolf@openca.org)
 * OpenCA project 2001
 *
 * Copyright (c) 2001 The OpenCA Project.  All rights reserved.
 *
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

/* Functions prototypes*/

#ifndef _OCSPD_CONFIGURATION
#define _OCSPD_CONFIGURATION

#include "general.h"

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#include <openssl/ts.h>
#endif

OCSPD_CONFIG * OCSPD_load_config( char *configfile );

int OCSPD_build_ca_list ( OCSPD_CONFIG *handler,
				PKI_CONFIG_STACK *ca_conf_sk);

int OCSPD_load_crl ( CA_LIST_ENTRY *ca, OCSPD_CONFIG *conf );

int ocspd_reload_all_ca ( OCSPD_CONFIG *conf );

int ocspd_load_ca_section ( OCSPD_CONFIG *conf, char *dbms_section );

STACK_OF(X509_REVOKED) *ocspd_build_crl_entries_list ( CA_LIST_ENTRY *ca,
				PKI_X509_CRL *crl );

CA_LIST_ENTRY * CA_LIST_ENTRY_new ( void );

void CA_LIST_ENTRY_free ( CA_LIST_ENTRY *ca );

CA_LIST_ENTRY * OCSPD_ca_entry_new ( OCSPD_CONFIG *handler,
				PKI_X509_CERT *x, PKI_CONFIG *cnf );

STACK_OF(CA_ENTRY_CERTID) * CA_ENTRY_CERTID_new_sk ( PKI_X509_CERT *cert,
				STACK_OF(EVP_MD) *mds );

void CA_ENTRY_CERTID_free ( CA_ENTRY_CERTID *cid );

#endif
