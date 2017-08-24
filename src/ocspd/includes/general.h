/* OpenCA OCSP responder
* (c) 2000-2006 by Massimiliano Pala and OpenCA Group
* All Rights Reserved
*
* ===================================================================
* Released under OpenCA LICENSE
*/

#ifndef HEADER_OPENCA_OCSPD_GENERAL_H
#define HEADER_OPENCA_OCSPD_GENERAL_H

#if defined(__clang__) || defined (__GNUC__)
# define ATTRIBUTE_NO_SANITIZE_ADDRESS __attribute__((no_sanitize_address))
#else
# define ATTRIBUTE_NO_SANITIZE_ADDRESS
#endif

#include <libpki/pki.h>

#include <strings.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>

#include <pthread.h>

#define HTTP_GET		1
#define HTTP_POST_METHOD	"POST"
#define HTTP_GET_METHOD		"GET"

#define OCSP_REQ_TYPE		"application/ocsp-request"
#define OCSP_RESP_TYPE		"application/ocsp-response"

#define BASE_SECTION    	"ocspd"
#define CONFIG_FILE 		"ocspd.xml"

#define ENV_OCSPD_USER		"user"
#define ENV_OCSPD_GROUP		"group"

#define OCSP_REQ_CONTENT_TYPE	"application/ocsp-request"
#define OCSP_RESP_CONTENT_TYPE	"application/ocsp-response"

#define APP_PASS_LEN    1024

#define OCSP_DEFAULT_HTTP_PROTO		"1.1"

#define CRL_DEF_CHECK_INTERVAL	15

#define CRL_OK			1
#define	CRL_NOT_YET_VALID	2
#define	CRL_EXPIRED		3
#define	CRL_ERROR_NEXT_UPDATE	4
#define	CRL_ERROR_LAST_UPDATE	5
#define CRL_ERROR_UNKNOWN	10

#define OCSPD_SRV_OK	0
#define OCSPD_SRV_ERR	-1

typedef struct crl_data
	{
		/* CRL access method OCSP_CRL_METHOD_... */
		/* Filename */
		URL *url;

		X509_CRL *crl;
	} CRL_DATA;

typedef struct x509_crl_entry 
	{
		long reason;

		/* Serial Number of the entry */
		ASN1_INTEGER *serial;

		/* Revocation Time */
		ASN1_TIME *rev_time;

		/* Invalidity time, if reason in KeyTime or
		 * CAKeyTime  */
		ASN1_GENERALIZEDTIME *invalidity_time;

		/* Hold Instruction, if present */
		ASN1_OBJECT *hold_instr;

	} X509_CRL_ENTRY;

typedef struct ca_entry_certid
	{

		/* This is just the structure which we want to
		   memcmp - the len is needed as we don't know the
		   exact length of the passed hash (it is the upper
		   limit for the memcmp() */

		// The Hash Algorithm that was used
		X509_ALGOR *hashAlgorithm;

		// Identifier for the CA
		ASN1_OCTET_STRING *keyHash;
		ASN1_OCTET_STRING *nameHash;

		// Holds the indication for the current status of the CRL
		int crl_status;

	} CA_ENTRY_CERTID;

#define sk_CA_ENTRY_CERTID_new_null() SKM_sk_new_null(CA_ENTRY_CERTID)
#define sk_CA_ENTRY_CERTID_push(st, val) SKM_sk_push(CA_ENTRY_CERTID, (st), (val))
#define sk_CA_ENTRY_CERTID_pop(st) SKM_sk_pop(CA_ENTRY_CERTID, (st))
#define sk_CA_ENTRY_CERTID_value(st, i) SKM_sk_value(CA_ENTRY_CERTID, (st), (i))
#define sk_CA_ENTRY_CERTID_num(st) SKM_sk_num(CA_ENTRY_CERTID, (st))
#define sk_CA_ENTRY_CERTID_sort(st) SKM_sk_sort(CA_ENTRY_CERTID, (st))
#define sk_CA_ENTRY_CERTID_find(st) SKM_sk_find(CA_ENTRY_CERTID, (st))

/* List of available CAs */
typedef struct ca_list_st {
	/* CA Identifier - Name from config file */
	char *ca_id;

	/* CA Status - If compromised > 0 respond all revoked */
	int compromised;

	/* CA certificate */
	PKI_X509_CERT *ca_cert;

	/* Cert Identifier */
	CA_ENTRY_CERTID *cid;

	/* CA certificate URL */
	URL *ca_url;

	/* CRL URL */
	URL *crl_url;

	/* CRL data */
	PKI_X509_CRL *crl;

	/* Pointer to the list of CRLs entries */
	STACK_OF(X509_REVOKED) *crl_list;

	/* X509 nextUpdate and lastUpdate */
	PKI_TIME *nextUpdate;
	PKI_TIME *lastUpdate;

	/* Options for auto reloading of CRL upon expiration */
	int crl_status;

	/* Number of entries present in the list */
	unsigned long entries_num;

	/* TOKEN to be used with this CA - if null, the default
         * one will be used */
	PKI_X509_CERT *server_cert;

	char *token_name;
	char *token_config_dir;
	PKI_TOKEN *token;
	
	/* Responder Identifier Type */
	int response_id_type;

} CA_LIST_ENTRY;

typedef struct {
	pthread_t thread_tid;
	long thread_count;
} Thread;

typedef struct {
	int iget;
	int iput;

	int connfd;
	int listenfd;
	int nthreads;

	int *clifd;

	Thread *threads_list;
} OPENCA_GENCFG;

typedef struct ocspd_config {

	/* Configuration file name */
	char *cnf_filename;
	char *ca_config_dir;
	char *pidfile;

	/* CONF strucutre pointer */
	PKI_CONFIG * conf;

	/* Verbose Flag */
	int verbose;
	int debug;
	int testmode;

	/* Default Response's validity time */
	int nmin;
	int ndays;
	int set_nextUpdate;

	int flags;

	// CRL_DATA crl_data;

	/* User and Group the processes will run as */
	char *user;
	char *group;
	char *chroot_dir;

	/* Digest to be used */
	PKI_DIGEST_ALG *digest;
	PKI_DIGEST_ALG *sigDigest;

	/* OCSP responder default token */
	char *token_name;
	char *token_config_dir;
	PKI_TOKEN *token;

	/* CAs entry list */
	PKI_STACK *ca_list;

	/* CRL validity period checking */
	int crl_check_validity;
	int crl_auto_reload;
	int crl_reload_expired;

	int current_crl_reload;
	int current_crl_check;
	int alarm_decrement;

	/* DataBase Related */
	URL *db_url;
	int db_persistant;

	/* Network related */
	ssize_t max_req_size;
	unsigned int max_timeout_secs;
	char * http_proto;
	char * base_uri;
	URL  * bindUrl;

	int *clifd;
	int connfd;
	int listenfd;

	int nthreads;
	Thread *threads_list;

	PKI_MUTEX mutexes[3];
	PKI_COND  condVars[2];

	// PKI_RWLOCK config_lock;
	PKI_RWLOCK crl_lock;

} OCSPD_CONFIG;

#define CTRL_MUTEX      0
#define CLIFD_MUTEX     1
#define SRVFD_MUTEX     2

#define CLIFD_COND      0
#define SRVFD_COND      1

#define CRL_REASON_UNSPECIFIED				0
#define CRL_REASON_KEY_COMPROMISE			1
#define CRL_REASON_CA_COMPROMISE			2
#define CRL_REASON_AFFILIATION_CHANGED		3
#define CRL_REASON_SUPERSEDED				4
#define CRL_REASON_CESSATION_OF_OPERATION	5
#define CRL_REASON_CERTIFICATE_HOLD			6
#define CRL_REASON_REMOVE_FROM_CRL			8
#define CRL_REASON_HOLD_INSTRUCTION			9
#define CRL_REASON_KEY_TIME					10
#define CRL_REASON_CA_KEY_TIME				11

#define SHARED_MEM_BLOCK_SIZE				8192

#include "ocspd.h"
#include "core.h"
#include "configuration.h"
#include "config.h"
#include "response.h"
#include "request.h"
#include "crl.h"

#define HTTP_POST		0
#endif
