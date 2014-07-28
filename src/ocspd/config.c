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

#include "general.h"

/* External imported variables */
extern OCSPD_CONFIG * ocspd_conf;

/* Functions */
OCSPD_CONFIG * OCSPD_load_config( char *configfile ) {
	OCSPD_CONFIG *h = NULL;
	PKI_CONFIG *cnf = NULL;
	PKI_CONFIG_STACK *ca_config_stack = NULL;

	char *tmp_s = NULL;
	char *tmp_s2 = NULL;

	int i;

	/* Check for the environment variable PRQP_CONF */
	if (configfile == NULL) configfile = getenv("OCSPD_CONF");

	/* If not, check for the default CONFIG_FILE */
	if (configfile == NULL) configfile = CONFIG_FILE;

	if( !configfile ) {
		/* No config file is available */
		PKI_log(PKI_LOG_ERR, "No config file provided!");
		return (NULL);
	}

	/* Load the config file */
	if(( cnf = PKI_CONFIG_load ( configfile )) == NULL ) {
		PKI_log( PKI_LOG_ERR, "Can not load config file [%s]!",
			configfile );
		return (NULL);
	}
	if(( h = (OCSPD_CONFIG *)PKI_Malloc(sizeof(OCSPD_CONFIG))) == NULL) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		goto err;
	}

	/* Set the group and user string to NULL */
	h->user = NULL;
	h->group = NULL;

	/* Set the PRQPD verbose status */
	h->verbose   = 0;
	h->debug     = 0;
	h->nthreads  = 5;
	h->http_proto = "1.0";
	h->max_timeout_secs = 5;

	h->crl_auto_reload = 3600;
	h->crl_reload_expired = 1;
	h->crl_check_validity = 600;

	/* Copy the config filename so that it could be re-loaded on SIGHUP */
	h->cnf_filename = strdup( configfile );

	/* Initialize the COND variables and MUTEXES */
	for( i = 0; i < sizeof ( h->mutexes ) / sizeof( PKI_MUTEX ); i++ )
	{
		PKI_MUTEX_init ( &h->mutexes[i] );
	}

	for( i = 0; i < sizeof ( h->condVars ) / sizeof( PKI_COND ); i++)
	{
		PKI_COND_init ( &h->condVars[i] );
	}

	PKI_RWLOCK_init ( &h->crl_lock );

	/* Token Initialization */
	if (( tmp_s = PKI_CONFIG_get_value( cnf, "/serverConfig/general/pkiConfigDir")) == NULL)
	{
		PKI_log_err("Missing pkiConfigDir in configuration!");
		return NULL;
	}
	else 
	{
		if ((tmp_s2 = PKI_CONFIG_get_value( cnf, "/serverConfig/general/token" )) != NULL)
		{
			h->token_name = strdup( tmp_s2 );
			h->token_config_dir = strdup ( tmp_s );

			if ((h->token = PKI_TOKEN_new_null()) == NULL)
			{
				PKI_log( PKI_LOG_ERR, "Memory error for new token");
				exit(1);
			}

			PKI_Free(tmp_s2);
		}
		else
		{
			PKI_log_err("No General Token provided in configuration.");

			PKI_Free(tmp_s);
			return NULL;
		}

		PKI_Free(tmp_s);
	}

	/* Thread configuration */
	if((tmp_s = PKI_CONFIG_get_value(cnf, "/serverConfig/general/spawnThreads")) != NULL)
	{
		int t = 0;
		if((t = atoi( tmp_s )) > 0 ) h->nthreads = t;

		PKI_Free(tmp_s);
	}

	if((tmp_s = PKI_CONFIG_get_value( cnf, "/serverConfig/general/caConfigDir")) != NULL)
	{
		h->ca_config_dir = strdup(tmp_s);

		ca_config_stack = PKI_CONFIG_load_dir(h->ca_config_dir, NULL);
		if (ca_config_stack == NULL)
		{
			PKI_log( PKI_LOG_ERR, "Can't load caConfigDir (%s)", h->ca_config_dir);
			PKI_Free(tmp_s);

			goto err;
		}

		PKI_Free(tmp_s);
	}
	else
	{
		PKI_log( PKI_LOG_ERR, "/serverConfig/general/caConfigDir needed in conf!\n");
		goto err;
	}

	/* Pid File */
	if((tmp_s = PKI_CONFIG_get_value( cnf, "/serverConfig/general/pidFile")) != NULL )
	{
		h->pidfile = strdup(tmp_s);

		PKI_Free(tmp_s);
	}

	/* AutoReload timeout */
	if((tmp_s = PKI_CONFIG_get_value( cnf, 
		"/serverConfig/general/crlAutoReload")) != NULL)
	{
		h->crl_auto_reload = atoi(tmp_s);

		if( h->crl_auto_reload <= 0 )
		{
			h->crl_auto_reload = 0;
			PKI_log(PKI_LOG_INFO, "Auto Reload Disabled");
		}

		PKI_Free(tmp_s);
	}

	/* CRL validity check timeout */
	if((tmp_s = PKI_CONFIG_get_value( cnf, 
			"/serverConfig/general/crlCheckValidity")) != NULL )
	{
		h->crl_check_validity = atoi(tmp_s);
		if ( h->crl_check_validity <= 0 )
		{
			h->crl_check_validity = 0;
			PKI_log(PKI_LOG_INFO, "CRL check validity disabled");
		}

		PKI_Free(tmp_s);
	}

	/* AutoReload timeout */
	if ((tmp_s = PKI_CONFIG_get_value( cnf, 
				"/serverConfig/general/crlReloadExpired")) != NULL )
	{
		if (strncmp_nocase(tmp_s, "n", 1) == 0)
		{
			h->crl_reload_expired = 0;
			PKI_log(PKI_LOG_INFO, "Expired CRLs Reload Disabled");
		}

		PKI_Free(tmp_s);
	}

	/* Server Privileges */
	if ((tmp_s = PKI_CONFIG_get_value(cnf, "/serverConfig/security/user")) != NULL)
	{
		h->user = strdup(tmp_s);
		PKI_Free(tmp_s);
	}

	if ((tmp_s = PKI_CONFIG_get_value( cnf, "/serverConfig/security/group" )) != NULL)
	{
		h->group = strdup(tmp_s);
		PKI_Free(tmp_s);
	}

	if ((tmp_s = PKI_CONFIG_get_value( cnf, "/serverConfig/security/chrootDir" )) != NULL )
	{
		h->chroot_dir = strdup(tmp_s);
		PKI_Free(tmp_s);
	}

	/* Bind Address */
	if((tmp_s = PKI_CONFIG_get_value( cnf, "/serverConfig/network/bindAddress" )) == NULL)
	{
		// If not bindAddress, let's use the universal one
		tmp_s = strdup("http://0.0.0.0:2560");
	}

	if ((h->bindUrl = URL_new( tmp_s )) == NULL)
	{
		PKI_log( PKI_LOG_ERR, "Can't parse bindAddress (%s)", tmp_s );
		PKI_Free(tmp_s);

		goto err;
	}

	// We need to free the tmp_s
	PKI_Free(tmp_s);

	/* HTTP Version */
	if((tmp_s = PKI_CONFIG_get_value( cnf, "/serverConfig/network/httpProtocol")) != NULL)
	{
		h->http_proto = strdup(tmp_s);
		PKI_Free(tmp_s);
	}

	/* Timeout for incoming connections */
	if((tmp_s = PKI_CONFIG_get_value( cnf, "/serverConfig/network/timeOut")) != NULL )
	{
		long t = 0;

		if ((t = atol( tmp_s )) > 0) h->max_timeout_secs = (unsigned int) t;
		PKI_Free(tmp_s);
	}

	/* Maximum Request Size */
	if((tmp_s = PKI_CONFIG_get_value( cnf,
				"/serverConfig/response/maxReqSize" )) != NULL ) {
		int t = 0;

		if((t = atoi( tmp_s )) > 0 ) {
			h->max_req_size = t;
		}
		PKI_Free(tmp_s);
	}


	// Default
	h->digest = PKI_DIGEST_ALG_SHA1;

	/* Digest Algorithm to be used */
	if ((tmp_s = PKI_CONFIG_get_value(cnf, "/serverConfig/response/digestAlgorithm" )) != NULL)
	{
		h->digest = PKI_DIGEST_ALG_get_by_name( tmp_s );

		if (!h->digest) 
		{
			PKI_log_err("Can not parse response digest algorithm: %s", tmp_s);
			exit(1);
		}
		else PKI_log_debug("Selected response digest algorithm: %s", tmp_s);

		PKI_Free(tmp_s);
	}

	/* Signing Digest Algorithm to be used */
	if((tmp_s = PKI_CONFIG_get_value( cnf,
			"/serverConfig/response/signatureDigestAlgorithm" )) == NULL)
	{
		PKI_log_debug("No specific signature digest algorithm selected.");
		h->sigDigest = NULL;
	}
	else
	{
		h->sigDigest = PKI_DIGEST_ALG_get_by_name( tmp_s );

		if (!h->sigDigest) 
		{
			PKI_log_err("Can not parse signing digest algorithm: %s", tmp_s);
			exit(1);
		}
		else PKI_log_debug("Selected signature digest algorithm: %s", tmp_s);

		PKI_Free(tmp_s);
	}

	/* Digest Algorithm to be used */
	if ((tmp_s = PKI_CONFIG_get_value(cnf, "/serverConfig/response/addResponseKeyID")) != NULL)
	{
		if (strncmp_nocase(tmp_s, "n", 1) == 0) 
		{
			h->add_response_keyid = 1;
		}

		PKI_Free(tmp_s);
	}

	/* Now Parse the PRQP Response Section */
	if ((tmp_s = PKI_CONFIG_get_value( cnf, "/serverConfig/response/validity/days" )) != NULL)
	{
		h->ndays = atoi(tmp_s);
		PKI_Free(tmp_s);
	}

	if ((tmp_s = PKI_CONFIG_get_value( cnf, "/serverConfig/response/validity/mins" )) != NULL)
	{
		h->nmin = atoi(tmp_s);
		PKI_Free(tmp_s);
	}

	h->set_nextUpdate = h->ndays * 3600 + h->nmin * 60;

	/* Database Options */
	if ((tmp_s = PKI_CONFIG_get_value( cnf, "/serverConfig/general/dbUrl")) != NULL)
	{
		if ((h->db_url = URL_new ( tmp_s )) == NULL)
		{
			PKI_log_err ( "Database Url not parsable (%s)", tmp_s );
			PKI_Free(tmp_s);
			goto err;
		}

		PKI_Free(tmp_s);
	}

	/* Database Persistant */
	if ((tmp_s = PKI_CONFIG_get_value( cnf, "/serverConfig/general/dbPersistant")) != NULL)
	{
		if (strncmp_nocase ( "n", tmp_s, 1 ) == 0 )
			h->db_persistant = 0;
		else 
			h->db_persistant = 1;

		PKI_Free(tmp_s);
	}

	/* Now we should load the CA configuration files and generate the
	   CERT_ID for the different CAs */
	if ((OCSPD_build_ca_list( h, ca_config_stack )) == PKI_ERR )
	{
		PKI_log(PKI_LOG_ERR, "Can not build CA list!");
		if (ca_config_stack) PKI_STACK_CONFIG_free ( ca_config_stack );
		goto err;
	}

	if (ca_config_stack) PKI_STACK_CONFIG_free ( ca_config_stack );

	return ( h );

err:
	if( ca_config_stack ) PKI_STACK_CONFIG_free ( ca_config_stack );
	if( cnf ) PKI_CONFIG_free ( cnf );
	if( h ) PKI_Free ( h );

	return( NULL );
}


int OCSPD_build_ca_list ( OCSPD_CONFIG *handler,
			PKI_CONFIG_STACK *ca_conf_sk) {

	int i = 0;
	PKI_STACK *ca_list = NULL;

	PKI_log_debug("Building CA List");

	if ( !ca_conf_sk ) {
		PKI_log( PKI_LOG_ERR, "No stack of ca configs!");
		return ( PKI_ERR );
	}

	if((ca_list = PKI_STACK_new((void (*))CA_LIST_ENTRY_free)) == NULL ) {
		PKI_log_err ( "Memory Error");
	return ( PKI_ERR );
	}

	for (i = 0; i < PKI_STACK_CONFIG_elements( ca_conf_sk ); i++)
	{
		char *tmp_s = NULL;
		URL *tmp_url = NULL;
		PKI_X509_CERT *tmp_cert = NULL;

		CA_LIST_ENTRY *ca = NULL;
		PKI_CONFIG *cnf = NULL;

		/* Get the current Configureation file */
		cnf = PKI_STACK_CONFIG_get_num( ca_conf_sk, i );
		if (!cnf) continue;

		/* Get the CA cert from the cfg file itself */
		if((tmp_s = PKI_CONFIG_get_value( cnf, "/caConfig/caCertValue" )) == NULL )
		{
			/* Get the CA parsed url */
			if((tmp_url = URL_new( PKI_CONFIG_get_value( cnf, "/caConfig/caCertUrl" ))) == NULL )
			{
				/* Error, can not parse url data */
				PKI_log( PKI_LOG_ERR, "Can not parse CA cert url (%s)", 
					PKI_CONFIG_get_value(cnf, "/caConfig/caCertUrl"));

				continue;
			}

			if((tmp_cert = PKI_X509_CERT_get_url(tmp_url, NULL, NULL ))== NULL)
			{
				PKI_log_err("Can not get CA cert from (%s)", tmp_url);
				URL_free (tmp_url);

				continue;
			}
		}
		else
		{
			PKI_X509_CERT_STACK *cc_sk = NULL;
			PKI_MEM *mm = NULL;

			if((mm = PKI_MEM_new_null()) == NULL )
			{
				PKI_Free(tmp_s);
				continue;
			}

			PKI_MEM_add ( mm, tmp_s, strlen(tmp_s));

			if((cc_sk=PKI_X509_CERT_STACK_get_mem(mm, NULL)) == NULL )
			{
				PKI_log_err ( "Can not parse cert from /caConfig/caCertValue");
				PKI_Free(tmp_s);

				continue;
			}

			if ((tmp_cert = PKI_STACK_X509_CERT_pop( cc_sk )) == NULL )
			{
				PKI_log_err ( "No elements on stack from /caConfig/caCertValue");

				PKI_STACK_X509_CERT_free_all(cc_sk);
				PKI_Free(tmp_s);

				continue;
			}

			PKI_STACK_X509_CERT_free ( cc_sk );
			PKI_Free(tmp_s);
		}

		/* OCSPD create the CA entry */
		if ((ca = CA_LIST_ENTRY_new()) == NULL )
		{
			PKI_log_err ( "CA List structure init error");

			/* remember to do THIS!!!! */
			if( tmp_url ) URL_free ( tmp_url );
			if( tmp_cert ) PKI_X509_CERT_free ( tmp_cert );

			continue;
		}

		ca->ca_cert = tmp_cert;
		tmp_cert = NULL;

		ca->ca_url = tmp_url;
		tmp_url = NULL;

		ca->ca_id = PKI_CONFIG_get_value( cnf, "/caConfig/name" );
		ca->cid = CA_ENTRY_CERTID_new ( ca->ca_cert, handler->digest );

		/* Get the CRL URL and the CRL itself */
		if((tmp_s = PKI_CONFIG_get_value(cnf, "/caConfig/crlUrl")) == NULL)
		{
			PKI_STACK *cdp_sk = NULL;

			/* Now let's get it from PRQP */

			/* Now from the Certificate */
			
			if((cdp_sk = PKI_X509_CERT_get_cdp (ca->ca_cert)) ==NULL)
			{
				// No source for the CRL Distribution Point
				PKI_log_err ( "ERROR::Can not find the CDP for %s, skipping CA", ca->ca_id );

				CA_LIST_ENTRY_free ( ca );
				continue;
			}

			while ((tmp_s = PKI_STACK_pop ( cdp_sk )) != NULL)
			{
				if ((ca->crl_url = URL_new ( tmp_s )) == NULL )
				{
					PKI_log_err( "URL %s not in the right format!");
					CA_LIST_ENTRY_free ( ca );
					continue;
				}
				else if( tmp_s ) PKI_Free ( tmp_s );

				break;
			}
		}
		else
		{
			PKI_log_debug("Got CRL Url -> %s", tmp_s );

			if((ca->crl_url = URL_new ( tmp_s )) == NULL )
			{
				PKI_log_err ("Error Parsing CRL URL [%s] for CA [%s]", ca->ca_id, tmp_s);

				CA_LIST_ENTRY_free ( ca );
				PKI_Free(tmp_s);

				continue;
			}

			PKI_Free(tmp_s);
		}

		if(OCSPD_load_crl ( ca, handler ) == PKI_ERR )
		{
			PKI_log_err ( "Can not get CRL for %s", ca->ca_id);
			CA_LIST_ENTRY_free ( ca );

			continue;
		}

		/* If the Server has a Token to be used with this CA, let's
                   load it */
		if((tmp_s = PKI_CONFIG_get_value ( cnf, "/caConfig/serverToken" )) == NULL)
		{
			/* No token in config, let's see if a specific cert
			   is configured */
			ca->token = NULL;

			if((tmp_s = PKI_CONFIG_get_value ( cnf, "/caConfig/serverCertUrl" )) == NULL )
			{
				/* No cert is configured, we will use the defaults */
				ca->server_cert = NULL;
			}
			else
			{
				/* The Server's cert URL is found, let's load the certificate */
				if ((tmp_cert = PKI_X509_CERT_get ( tmp_s, NULL, NULL )) == NULL )
				{
					PKI_log_err("Can not get server's cert from %s!", tmp_s );

					CA_LIST_ENTRY_free ( ca );
					PKI_Free(tmp_s);

					continue;
				}
				else
				{
					ca->server_cert = tmp_cert;
				}

				PKI_Free(tmp_s);
			}
		}
		else
		{
			/* A Token for this CA is found - we do not load
 			   it to avoid problems with Thread Initialization */
			ca->server_cert = NULL;
			ca->token_name = tmp_s;
			ca->token = PKI_TOKEN_new_null();

			if ((tmp_s = PKI_CONFIG_get_value ( cnf, "/caConfig/pkiConfigDir" )) != NULL)
				ca->token_config_dir = strdup( tmp_s );
			else
				ca->token_config_dir = strdup(handler->token_config_dir);
		}

		if((tmp_s = PKI_CONFIG_get_value ( cnf, "/caConfig/caCompromised" )) == NULL)
			ca->compromised = 0;
		else
			ca->compromised = atoi(tmp_s);

		// Now let's add the CA_LIST_ENTRY to the list of configured CAs
		PKI_STACK_push ( ca_list, ca );

		PKI_Free(tmp_s);
	}

	handler->ca_list = ca_list;

	return ( PKI_OK );
}


int OCSPD_load_crl ( CA_LIST_ENTRY *ca, OCSPD_CONFIG *conf ) {

	int ret = 0;

	if( !ca ) return PKI_ERR;

	if( !ca->crl_url ) {
		PKI_log_err ("CRL URL is empty (%s)!", ca->ca_id );
		return PKI_ERR;
	}

	if ( ca->crl ) PKI_X509_CRL_free ( ca->crl );

	if (( ca->crl = PKI_X509_CRL_get_url ( ca->crl_url, 
						NULL, NULL )) == NULL ) {
		PKI_log_err ("Failed loading CRL for %s", ca->ca_id );
		return PKI_ERR;
	}

	/* Let's check the CRL against the CA certificate */
	if( (ret = check_crl( ca->crl, ca->ca_cert, conf )) < 1 ) {
		PKI_log_err( "CRL/CA check error [ %s:%d ]",
						ca->ca_id, ret );
		return PKI_ERR;
	}

	/* Now we copy the lastUpdate and nextUpdate fields */
	if( ca->crl ) {
		ca->lastUpdate = PKI_TIME_dup(
			PKI_X509_CRL_get_data (ca->crl, 
				PKI_X509_DATA_LASTUPDATE));

		ca->nextUpdate = PKI_TIME_dup (
			PKI_X509_CRL_get_data (ca->crl,
				PKI_X509_DATA_NEXTUPDATE ));
	}

	if((ca->crl_status = check_crl_validity(ca, conf )) == CRL_OK ) {
		if(conf->verbose) PKI_log( PKI_LOG_INFO, "CRL for %s is Valid", 
				ca->ca_id );
	} else {
		PKI_log_err ( "CRL for %s has ERRORS (%d)", ca->ca_id, 
						ca->crl_status );
	}

	/* Let's get the CRLs entries, if any */
	if( ocspd_build_crl_entries_list ( ca, ca->crl ) == NULL ) { 
		PKI_log(PKI_LOG_ALWAYS, "No CRL Entries for %s", ca->ca_id );
	};

	if(conf->verbose) PKI_log( PKI_LOG_ALWAYS, "CRL loaded for %s", ca->ca_id );

	return PKI_OK;
}

int ocspd_reload_all_ca ( OCSPD_CONFIG *conf ) {

	int i=0;
	CA_LIST_ENTRY *ca = NULL;

	for( i = 0; i < PKI_STACK_elements( conf->ca_list); i++) {

		ca = PKI_STACK_get_num( conf->ca_list, i );

		/* Let's free the CA certs list, if present */
		/*
		if( ca->cert ) {
			sk_X509_pop_free(ca->cert, X509_free );
		}
		*/

		if (ca->ca_url ) {
			if ( ca->ca_cert) PKI_X509_CERT_free ( ca->ca_cert );

			/* Get the CA certificate */
			ca->ca_cert = PKI_X509_CERT_get_url ( ca->ca_url,
							NULL, NULL );
		}

		/*
		if(!ca->cert || !sk_X509_num(ca->cert)) {
			syslog(LOG_ERR, "Error loading CA URL data.");
			continue;
		} else {
			if(conf->verbose)
				syslog( LOG_INFO,
					"CA CERT for %s loaded successfully.",
					ca->ca_id );
		}
		*/
		if( !ca->ca_cert ) {
			if( ca->ca_url && ca->ca_url->url_s ) {
			   PKI_log_err ( "Can not load CA cert from %s",
				ca->ca_url->url_s);
			} else {
				PKI_log_err ( "Can not load CA cert!");
				continue;
			}
		} else {
			PKI_log( PKI_LOG_INFO, " CA cert for %s loaded ok",
					ca->ca_id );
		}

		if((ca->cid = CA_ENTRY_CERTID_new ( ca->ca_cert,
						conf->digest)) == NULL ) {
			PKI_log_err( "CA List structure init error (CERTID).");
			continue;
		}

	}

	return 1;
}

STACK_OF(X509_REVOKED) *ocspd_build_crl_entries_list ( CA_LIST_ENTRY *ca, PKI_X509_CRL *crl )
{
	long rev_num = 0;

	STACK_OF(X509_REVOKED) *ret = NULL;
	PKI_X509_CRL_VALUE *crl_val = NULL;

	if ( !ca || !crl || !crl->value ) 
	{
		return NULL;
	}

	crl_val = crl->value;

	ret = X509_CRL_get_REVOKED(crl_val);
	rev_num = sk_X509_REVOKED_num(ret);

	// if( ocspd_conf->verbose )
	PKI_log( PKI_LOG_INFO, "INFO::CRL::%ld Entries [ %s ]", rev_num, ca->ca_id );

	ca->crl_list = ret;
	ca->entries_num = (unsigned long) rev_num;

	if ((rev_num > -1 ) && 
		(ca->crl_list == NULL))
	{
		PKI_ERROR( PKI_ERR_MEMORY_ALLOC, NULL );
		return NULL;
	}

	sk_X509_REVOKED_sort(ca->crl_list);

	return (ca->crl_list);
}

/* --------------------------- CA_LIST_ENTRY ------------------------- */

CA_LIST_ENTRY * CA_LIST_ENTRY_new ( void ) {
	CA_LIST_ENTRY * ca = NULL;

	if((ca = (CA_LIST_ENTRY *) 
			PKI_Malloc ( sizeof (CA_LIST_ENTRY))) == NULL) {
		PKI_ERROR( PKI_ERR_MEMORY_ALLOC, NULL );

		return ( NULL );
	}

	return ( ca );
}

void CA_LIST_ENTRY_free ( CA_LIST_ENTRY *ca ) {

	if ( !ca ) return;

	if ( ca->ca_id )
	{
		PKI_log(PKI_LOG_INFO, "MEM::Freeing %s CA config", ca->ca_id );
		PKI_Free ( ca->ca_id );
	}

	if ( ca->ca_cert ) PKI_X509_CERT_free ( ca->ca_cert );
	if ( ca->cid ) CA_ENTRY_CERTID_free ( ca->cid );
	if ( ca->ca_url ) URL_free ( ca->ca_url );
	if ( ca->crl_url ) URL_free ( ca->crl_url );

	if ( ca->crl_list )
	{
		X509_REVOKED *r = NULL;

		while ((r = sk_X509_REVOKED_pop ( ca->crl_list )) != NULL) 
		{
			X509_REVOKED_free ( r );
		}
	}

	if ( ca->nextUpdate ) PKI_TIME_free ( ca->nextUpdate );
	if ( ca->lastUpdate ) PKI_TIME_free ( ca->lastUpdate );

	if ( ca->token_name ) PKI_Free ( ca->token_name );
	if ( ca->token ) PKI_TOKEN_free ( ca->token );

	PKI_Free ( ca );

	return;
}

CA_LIST_ENTRY * OCSPD_ca_entry_new ( OCSPD_CONFIG *handler,
				PKI_X509_CERT *x, PKI_CONFIG *cnf ) {

	CA_LIST_ENTRY *ret = NULL;

	if (!handler || !x || !cnf) return NULL;

	if (( ret = PKI_Malloc ( sizeof( CA_LIST_ENTRY ) )) == NULL ) return NULL;

	/* Let's get the CA_ENTRY_CERTID */
	if ((ret->cid = CA_ENTRY_CERTID_new ( x, handler->digest )) == NULL)
	{
		CA_LIST_ENTRY_free ( ret );
		return NULL;
	}

	return ret;

}

/* ---------------------------- CA_ENTRY_CERTID ------------------------- */

CA_ENTRY_CERTID * CA_ENTRY_CERTID_new ( PKI_X509_CERT *cert, 
					PKI_DIGEST_ALG * digestAlg ) {

	CA_ENTRY_CERTID *ret = NULL;

	PKI_STRING *keyString = NULL;
	PKI_DIGEST *keyDigest = NULL;

	PKI_X509_NAME *iName = NULL;
	PKI_DIGEST *nameDigest = NULL;

	PKI_log_debug("Building CA_ENTRY_CERTID");

	/* Check for needed info */
	if ( !cert || !cert->value ) return NULL;

	/* Use SHA1 as default digest algorithm */
	if ( !digestAlg ) digestAlg = PKI_DIGEST_ALG_SHA1;

	// Allocate Memory for the CA_ENTRY_CERTID
	if((ret = PKI_Malloc(sizeof(CA_ENTRY_CERTID))) == NULL) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		goto err;
	}

	/* Retrieves the subject name from the certificate */
	if ((iName = PKI_X509_CERT_get_data(cert, PKI_X509_DATA_SUBJECT)) == NULL)
	{
		PKI_log_err("Can not get certificate's subject");
		goto err;
	};

	// Let's build the HASH of the Name
	if((nameDigest = PKI_X509_NAME_get_digest(iName, digestAlg)) == NULL) {
		PKI_log_err("Can not get digest string from certificate's subject");
		goto err;
	};

	// Assign the new OCTET string tothe nameHash field
	if (( ret->nameHash = PKI_STRING_new ( PKI_STRING_OCTET,
			(char *) nameDigest->digest, (ssize_t) nameDigest->size )) == NULL ) {
		PKI_log_err("Can not assign nameHash to CERTID");
		goto err;
	};
	
	// Let's get the key bitstring from the certificate
	if (( keyString = PKI_X509_CERT_get_data( cert, 
				PKI_X509_DATA_PUBKEY_BITSTRING)) == NULL ) {
		PKI_log_err("Can not get certificate's pubkey bitstring");
		goto err;

	} else {
		// We build the keyDigest from the keyString
		if((keyDigest = PKI_STRING_get_digest (keyString, 
				digestAlg)) == NULL ) {
			PKI_log_err("Can not create new keyDigest from keyString");
			goto err;
		};
	};

	if((ret->keyHash = PKI_STRING_new ( PKI_STRING_OCTET,
				(char *) keyDigest->digest, (ssize_t) keyDigest->size )) == NULL ) {
		PKI_log_err("Can not assign keyHash to CERTID");
		goto err;
	};

	/* Set the Digest Algorithm used */
	if((ret->hashAlgorithm = PKI_ALGORITHM_new_digest( digestAlg )) == NULL ) {
		if( ret ) CA_ENTRY_CERTID_free ( ret );
		PKI_log_err("ERROR, can not create a new hashAlgorithm!");
		return NULL;
	};

	if ( nameDigest ) PKI_DIGEST_free ( nameDigest );
	if ( keyDigest  ) PKI_DIGEST_free ( keyDigest );

	return ret;

err:
	if ( nameDigest ) PKI_DIGEST_free ( nameDigest );
	if ( keyDigest  ) PKI_DIGEST_free ( keyDigest );

	if ( ret ) CA_ENTRY_CERTID_free ( ret );

	return ( NULL );
}


void CA_ENTRY_CERTID_free ( CA_ENTRY_CERTID *cid ) {

	if ( !cid ) return;

	if ( cid->keyHash ) {
		PKI_STRING_free ( cid->keyHash );
	}

	if ( cid->nameHash ) {
		PKI_STRING_free ( cid->nameHash );
	}

	PKI_Free ( cid );

	return;
}

