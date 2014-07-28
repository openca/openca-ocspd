/*
 * OCSP responder - Massimiliano Pala (madwolf@openca.org)
 * Copyright (c) 2001-2009 by Massimiliano Pala and OpenCA Labs.
 * All rights reserved.
 *
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

/* Functions */

PKI_X509_OCSP_RESP *make_ocsp_response( PKI_X509_OCSP_REQ *req, 
						OCSPD_CONFIG *conf );

int ocspd_resp_send_socket(int connfd, PKI_X509_OCSP_RESP *resp, 
						OCSPD_CONFIG *conf);

/* ------------------------- Find Functions ---------------------------- */

X509_REVOKED *OCSPD_REVOKED_find (CA_LIST_ENTRY *ca, ASN1_INTEGER *serial);
CA_LIST_ENTRY *OCSPD_CA_ENTRY_find ( OCSPD_CONFIG *conf, OCSP_CERTID *cid );
