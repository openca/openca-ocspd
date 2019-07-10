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
OCSPD_CONFIG * OCSPD_load_config(char *configfile)
{
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

	// Sets the default
	h->responder_id_type = PKI_X509_OCSP_RESPID_TYPE_BY_KEYID;

	// Responder Id Type
	if ((tmp_s = PKI_CONFIG_get_value(cnf, "/serverConfig/response/responderIdType")) != NULL)
	{
		if (strncmp_nocase(tmp_s, "keyid", 5) == 0) 
		{
			h->responder_id_type = PKI_X509_OCSP_RESPID_TYPE_BY_KEYID;
		}
		else if (strncmp_nocase(tmp_s, "name", 4) == 0)
		{
			h->responder_id_type = PKI_X509_OCSP_RESPID_TYPE_BY_NAME;
		}
		else
		{
			PKI_log_err("Can not parse responderIdType: %s (allowed 'keyid' or 'name')", tmp_s);
			exit(1);
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

		char * tmp_id = NULL;

		// Get the current Configureation file
		cnf = PKI_STACK_CONFIG_get_num(ca_conf_sk, i);
		if (!cnf) continue;

		// Get the name of the CA config
		if (tmp_id) PKI_Free(tmp_id);
		if ((tmp_id = PKI_CONFIG_get_value( cnf, "/caConfig/name" )) == NULL) {
			tmp_id = strdup("<ca-config-no-name-set>");
		}

		// Some Useful Info
		PKI_log(PKI_LOG_ALWAYS, "Processing Configuration for [CA: %s]", tmp_id);

		/* Get the CA cert from the cfg file itself */
		if ((tmp_s = PKI_CONFIG_get_value(cnf, "/caConfig/caCertValue")) == NULL)
		{
			char *subTmp_s = NULL;

			/* Gets the URL for the CA cert */
			if ((subTmp_s = PKI_CONFIG_get_value(cnf,"/caConfig/caCertUrl")) == NULL) {

				// Error, no URL for the CA certificate
				PKI_log_err("Can not get /caConfig/caCertUrl");

				// Free the memory
				PKI_Free(tmp_s);
				PKI_Free(tmp_id);

				// Proceed to the entry
				continue;
			}

			// Get the CA parsed url
			if((tmp_url = URL_new(subTmp_s)) == NULL )
			{
				// Error, can not parse url data
				PKI_log_err("Can not parse CA cert url [CA: %s, URL: %s]", 
					tmp_id, PKI_CONFIG_get_value(cnf, "/caConfig/caCertUrl"));

				// Free the memory
				PKI_Free(tmp_s);
				PKI_Free(tmp_id);
				PKI_Free(subTmp_s);

				// Proceed to the entry
				continue;
			}

			// Free the memory
			PKI_Free(subTmp_s);
			subTmp_s = NULL;

			// Retrieves the CA cert
			if ((tmp_cert = PKI_X509_CERT_get_url(tmp_url, -1, NULL, NULL ))== NULL)
			{
				// Error, can not get the CA certificate from the
				// provided URL in the configuration
				PKI_log_err("Can not get CA cert [CA: %s, URL: %s]", 
						tmp_url->url_s, tmp_id);

				// Free the memory
				PKI_Free(tmp_s);
				PKI_Free(tmp_id);
				URL_free (tmp_url);

				// Proceed to the next entry
				continue;
			}

		} else {

			PKI_X509_CERT_STACK *cc_sk = NULL;
			PKI_MEM *mm = NULL;

			// Allocates a new PKI_MEM strcuture
			if((mm = PKI_MEM_new_data(strlen(tmp_s),
					(unsigned char *)tmp_s)) == NULL) {

				// Reports the Error
				PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);

				// Free Memory
				PKI_Free(tmp_s);
				PKI_Free(tmp_id);

				// Proceed to the next entry
				continue;
			}

			// Parses and get the stack of X509_CERT from the PKI_MEM data
			if ((cc_sk = PKI_X509_CERT_STACK_get_mem(mm, -1, NULL)) == NULL) {

				// Error, can not get the stack of certs from the CA cert value
				PKI_log_err("Can not parse cert from /caConfig/caCertValue [CA: %s]",
						tmp_id);

				// Free the Memory
				PKI_Free(tmp_s);
				PKI_Free(tmp_id);

				// Proceed to the next entry
				continue;
			}

			// Gets the certificate from the stack (although there should be
			// only one, the interface allows for multiple to be stored there
			// concatenated, we just get the first one)
			if ((tmp_cert = PKI_STACK_X509_CERT_pop( cc_sk )) == NULL) {
				// Error, can not get the CA cert from the stack
				PKI_log_err("No elements on stack from /caConfig/caCertValue [CA: %s]",
						tmp_id);

				// Free the remaining elements (if any) and data structures
				PKI_STACK_X509_CERT_free_all(cc_sk);

				// Free the memory
				PKI_Free(tmp_s);
				PKI_Free(tmp_id);

				// Continue to the next element
				continue;
			}

			// Free the memory
			PKI_STACK_X509_CERT_free_all(cc_sk);
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

		// Assigns the ownership of the CA Cert to the CA Entry
		ca->ca_cert = tmp_cert;
		tmp_cert = NULL;

		// Assignes the ownership of the CA URL to the CA Entry
		ca->ca_url = tmp_url;
		tmp_url = NULL;

		// Copies the CA Identifier to the CA Entry
		ca->ca_id = tmp_id;

		// Generates a new CERTID entry
		ca->cid = CA_ENTRY_CERTID_new(ca->ca_cert, handler->digest);

		/* Get the CRL URL and the CRL itself */
		if ((tmp_s = PKI_CONFIG_get_value(cnf, "/caConfig/crlUrl")) == NULL)
		{
			PKI_STACK *cdp_sk = NULL;

			/* Now let's get it from PRQP */

			/* Now from the Certificate */
			
			if ((cdp_sk = PKI_X509_CERT_get_cdp (ca->ca_cert)) == NULL) {

				// No source for the CRL Distribution Point
				PKI_log_err("No URL for CRLs Download, disabling CA [CA: %s]",
						ca->ca_id );

				// Free Memory
				CA_LIST_ENTRY_free ( ca );

				// Continue
				continue;
			}

			// Cycles through the stack of CDP retrieved
			while ((tmp_s = PKI_STACK_pop ( cdp_sk )) != NULL)
			{
				// If we can not parse the URL, it skips it
				if ((ca->crl_url = URL_new ( tmp_s )) == NULL) {

					// Error, Can not parse the URL
					PKI_log_err( "CDP URL not in the right format [CA: %s, URL: %s",
						ca->ca_id, (tmp_s != NULL ? tmp_s : "<null>"));

					// Free Memory
					PKI_Free(tmp_s);
					CA_LIST_ENTRY_free(ca);

					// Continue
					continue;

				}

				// Frees the Memory
				if( tmp_s ) PKI_Free ( tmp_s );

				// Exits from the cycle (we just record the first one)
				break;
			}

		} else {

			// Some logging info
			PKI_log_debug("CRL Downloading Process Started [CA: %s, URL: %s]", 
					ca->ca_id, tmp_s );

			// Gets the data from the CRL URL
			if ((ca->crl_url = URL_new(tmp_s)) == NULL) {

				// Error, can not get a new URL
				PKI_log_err("Cannot parse CRL's URL [CA: %s, URL: %s]",
						ca->ca_id, tmp_s);

				// Free Memory
				CA_LIST_ENTRY_free ( ca );
				PKI_Free(tmp_s);

				// Take it from the top
				continue;
			}

			// Free Memory
			PKI_Free(tmp_s);
			tmp_s = NULL; // Safety
		}

		// Loads the CRL from the parsed URL
		// Failure loading the CRL might not be a fatal error,
		// we let the OCSP continue since the loading error
		// might be temporary
		if (PKI_OK != OCSPD_load_crl(ca, handler)) {

			// Error Output
			PKI_log_err("Can not load CRL [CA: %s]", ca->ca_id);

			// Free Memory
			CA_LIST_ENTRY_free ( ca );

			// Continue
			continue;

      // TODO: Provide options to set SSL configuration for
      // outgoing connections
      /*
      if (ca->crl_url->ssl == 1) {

        int idx = 0;
          // Index

        PKI_SSL * ssl = NULL;
          // PKI_SSL structure for creds

        PKI_X509_CERT_STACK *sk = NULL;
          // Stack of Trused Certificates

        // Allocates the PKI_CRED structure
        if ((ca->creds = PKI_CRED_new()) == NULL) {
          PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
          return -1;
        }

        // Allocates the PKI_SSL structure
        if ((ssl = PKI_SSL_new(NULL)) == NULL) {
          PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);

          CA_LIST_ENTRY_free(ca);
          continue;
        }

        if ((sk = PKI_X509_CERT_STACK_get(trusted_certs, NULL, NULL)) == 0) {
          PKI_log_err("Can't load Trusted Certs from %s", trusted_certs);
        }

                          if (PKI_SSL_set_trusted(ssl, sk) != PKI_OK) {
          PKI_log_err("Can't set the Trusted Certs for TLS connections.");
        }

        // Set the verify options for TLS
        PKI_SSL_set_verify(ssl, PKI_SSL_VERIFY_NONE);

        // Sets the Cipher
        PKI_SSL_set_cipher(ssl, );

        // Sets the SSL flags
        PKI_SSL_set_flags(ssl, );

        // Set the SSL object for the credentials
        PKI_CRED_set_ssl(ca->creds, ssl);

      }
      */
		}

		// If the Server has a Token to be used with this CA, let's
		// load it
		if ((tmp_s = PKI_CONFIG_get_value(cnf, "/caConfig/serverToken")) == NULL) {

			// No token in config, let's see if a specific cert
			// is configured
			ca->token = NULL;

			if ((tmp_s = PKI_CONFIG_get_value(cnf, "/caConfig/serverCertUrl")) == NULL) {

				// No cert is configured, we will use the defaults
				ca->server_cert = NULL;
			}
			else
			{
				// The Server's cert URL is found, let's load the certificate
				if ((tmp_cert = PKI_X509_CERT_get(tmp_s, -1, NULL, NULL)) == NULL) {

					// Error, can not get the certificate from the URL
					PKI_log_err("Can not get server's cert [CA: %s, URL: %s]",
							ca->ca_id, tmp_s );

					// Free Memory
					CA_LIST_ENTRY_free ( ca );
					PKI_Free(tmp_s);

					// Next Entry please...
					continue;

				} else {

					// Transfer ownership of the cert to the CA Entry
					ca->server_cert = tmp_cert;
				}

				// Free Memory
				PKI_Free(tmp_s);
				tmp_s = NULL; // Safety
			}

		} else {

			// A Token for this CA is found - we do not load
 			// it to avoid problems with Thread Initialization
			ca->server_cert = NULL;
			ca->token_name = tmp_s;
			ca->token = PKI_TOKEN_new_null();

			// Gets the configuration directory
			if ((tmp_s = PKI_CONFIG_get_value(cnf,
						"/caConfig/pkiConfigDir")) != NULL) {

				// Save the directory in the CA Entry
				ca->token_config_dir = strdup(tmp_s);

				// Free the Memory
				PKI_Free(tmp_s);

			} else {

				// No config directory was given, let's duplicate the
				// handler's one
				ca->token_config_dir = strdup(handler->token_config_dir);
			}
		}

		// Checks if the CA is marked as compromised
		if ((tmp_s = PKI_CONFIG_get_value(cnf, 
					"/caConfig/caCompromised")) != NULL) {

			// CA is marked as Compromised
			ca->compromised = atoi(tmp_s);

			// Free the memory
			PKI_Free(tmp_s);

		} else {

			// CA is NOT marked as compromised
			ca->compromised = 0;
		}

		// Now let's add the CA_LIST_ENTRY to the list of configured CAs
		PKI_STACK_push ( ca_list, ca );

	}

	// Saves the CA Entries list in the main Handler
	handler->ca_list = ca_list;

	// All Done
	return PKI_OK;
}


int OCSPD_load_crl ( CA_LIST_ENTRY *ca, OCSPD_CONFIG *conf ) {

	int ret = 0;

	// Input Checks
	if (!ca) return PKI_ERR;

	// Checks we have a good URL to process
	if (!ca->crl_url) {
		PKI_log_err ("Can not load CRL because its URL is empty [CA: %s]",
			ca->ca_id );
		return PKI_ERR;
	}

	// Free any existing CRLs
	if (ca->crl) PKI_X509_CRL_free(ca->crl);

	// Load the new CRL
	if (( ca->crl = PKI_X509_CRL_get_url(ca->crl_url, 
					     -1, NULL, NULL )) == NULL) {

		// Error, can not get the CRL from the URL
		PKI_log_err("Failed loading CRL for [CA: %s, URL: %s]",
				ca->ca_id, ca->crl_url->url_s );

		// Failed
		return PKI_ERR;
	} else {
		
		// Some debugging Information
		PKI_log_debug("CRL loaded successfully [URL: %s]", ca->crl_url->url_s);
	}

	// Let's check the CRL against the CA certificate
	if( (ret = check_crl(ca->crl, ca->ca_cert, conf)) < 1 ) {

		// Error, the check for the CRL failed
		PKI_log_err( "CRL/CA check error [CA: %s, Code: %d ]",
						ca->ca_id, ret );

		// Failed
		return PKI_ERR;

	} else {

		// Some debugging Information
		PKI_log_debug("CRL Signature verified successfully [URL: %s]",
			ca->crl_url->url_s);
	}

	// Now we copy the lastUpdate and nextUpdate fields
	ca->lastUpdate = PKI_TIME_dup(
		PKI_X509_CRL_get_data (ca->crl, 
			PKI_X509_DATA_LASTUPDATE));

	ca->nextUpdate = PKI_TIME_dup (
		PKI_X509_CRL_get_data (ca->crl,
			PKI_X509_DATA_NEXTUPDATE ));

	if ((ca->crl_status = check_crl_validity(ca, conf)) == CRL_OK) {
		// Some debugging info
		PKI_log(PKI_LOG_INFO, "CRL Validity check PASSED [CA: %s]", 
				ca->ca_id);
	} else {
		// Error, can not verify the CRL validity
		PKI_log_err ( "CRL Validity check FAILED [CA: %s, Code: %d]", ca->ca_id, 
						ca->crl_status );
	}

	// Let's get the CRLs entries, if any
	if (ocspd_build_crl_entries_list(ca, ca->crl) == NULL) { 

		// Info, reports the fact that there are no entries in the CRL
		PKI_log(PKI_LOG_ALWAYS, "CRL has 0 (Zero) Entries [CA: %s]", ca->ca_id );
	} else {

		// Info, reports the number of entries in the CRL
		PKI_log(PKI_LOG_ALWAYS, "CRL has %d  Entries [CA: %s]",
                                ca->entries_num, ca->ca_id);
	}

	// Some Info
	PKI_log(PKI_LOG_ALWAYS, "CRL loaded and activated successfully [CA: %s]",
			ca->ca_id );

	// Success
	return PKI_OK;
}

int ocspd_reload_all_ca ( OCSPD_CONFIG *conf ) {

	int i=0;
	CA_LIST_ENTRY *ca = NULL;

	// Goes through all the configured CA Entries
	for( i = 0; i < PKI_STACK_elements(conf->ca_list); i++) {

		// Gets the Entry in the CA list
		ca = PKI_STACK_get_num(conf->ca_list, i);

		// If this CA cert was from a URL, let's reload it
		if (ca->ca_url) {

			// Free the old CA Certificate
			if (ca->ca_cert) PKI_X509_CERT_free(ca->ca_cert);

			// Get the CA certificate
			if ((ca->ca_cert = PKI_X509_CERT_get_url(ca->ca_url,
							         -1, NULL, NULL )) == NULL) {

				// Can not get the CA Cert from the URL
				PKI_log_err("Can not load CA cert [CA: %s, URL: %s]",
						ca->ca_id, ca->ca_url->url_s);

				// Next Entry
				continue;
			}

		} else {

			// Missing the CA certificate's URL
			PKI_log_err("Can not load CA cert [CA: %s]",
					ca->ca_id);

			// Next Entry
			continue;
		}

		// Some Logging Info
		PKI_log(PKI_LOG_INFO, "CA Certificate loaded successfully [CA: %s]",
					ca->ca_id );

		// Free existing memory
		if (ca->cid) CA_ENTRY_CERTID_free(ca->cid);
		ca->cid = NULL;

		// Generates anew CA Entry
		if ((ca->cid = CA_ENTRY_CERTID_new(ca->ca_cert,
						conf->digest)) == NULL ) {
			PKI_log_err( "CA List structure init error (Can not create a new CERTID) [CA: %s]",
				ca->ca_id);
			continue;
		}

	}

	// Success
	return 1;
}

STACK_OF(X509_REVOKED) *ocspd_build_crl_entries_list(CA_LIST_ENTRY *ca, 
	                                                 PKI_X509_CRL *crl) {

	long rev_num = 0;

	STACK_OF(X509_REVOKED) *ret = NULL;
	PKI_X509_CRL_VALUE *crl_val = NULL;

	// Input Checks
	if (!ca || !crl || !crl->value) {
		// Input Error
		PKI_ERROR(PKI_ERR_PARAM_NULL, NULL);
		// Error
		return NULL;
	}

	// Gets the reference to the internal CRL value
	crl_val = crl->value;

	// Gets the reference to the revoked stack
	ret = X509_CRL_get_REVOKED(crl_val);

	// Gets the number of revoked entries in the CRL
	rev_num = sk_X509_REVOKED_num(ret);

	// Some debugging info
	PKI_log_debug("CRL Entries are %ld [CA: %s]", 
		(rev_num > 0 ? rev_num : 0), ca->ca_id );

	// Saves the returned reference in the CA Entry
	ca->entries_num = (unsigned long) rev_num;
	ca->crl_list = ret;

	// Checks that we have entries if the number of
	// X509_REVOKED is non-negative
	if ((rev_num > -1) && (ca->crl_list == NULL)) {
		// Some internal memory error
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		// Error
		return NULL;
	}

	// Sorts the X509_REVOKED list (faster lookup)
	sk_X509_REVOKED_sort(ca->crl_list);

	// All Done
	return ca->crl_list;
}

/* --------------------------- CA_LIST_ENTRY ------------------------- */

CA_LIST_ENTRY * CA_LIST_ENTRY_new ( void ) {

	CA_LIST_ENTRY * ca = NULL;
		// The Return Structure

	// Allocates the memory for the Data Structure (CA_LIST_ENTRY)
	if ((ca = (CA_LIST_ENTRY *) 
			PKI_Malloc(sizeof (CA_LIST_ENTRY))) == NULL) {
		// Error, can not allocate memory
		PKI_ERROR( PKI_ERR_MEMORY_ALLOC, NULL );
		// Failure
		return NULL;
	}

	// Data Structure Initialization
	ca->cid        = NULL;
	ca->ca_url     = NULL;
	ca->ca_cert    = NULL;
	ca->crl_url    = NULL;
	ca->crl_list   = NULL;
	ca->nextUpdate = NULL;
	ca->lastUpdate = NULL;
	ca->token_name = NULL;
	ca->token      = NULL;

	// Initial Value
	ca->crl_status = PKI_OK;

	// Return the newly allocate structure
	return ca;
}

void CA_LIST_ENTRY_free ( CA_LIST_ENTRY *ca ) {

	// Input checks
	if (!ca) return;

	// Free CA related memory
	if (ca->ca_id) PKI_Free (ca->ca_id);
	if (ca->ca_cert) PKI_X509_CERT_free(ca->ca_cert);
	if (ca->cid) CA_ENTRY_CERTID_free(ca->cid);
	if (ca->creds) PKI_CRED_free(ca->creds);

	// Free Server's Token
	if (ca->token) PKI_TOKEN_free(ca->token);
	if (ca->token_name) PKI_Free(ca->token_name);
	if (ca->server_cert) PKI_X509_CERT_free(ca->server_cert);

	// Free URLs
	if (ca->ca_url) URL_free(ca->ca_url);
	if (ca->crl_url) URL_free(ca->crl_url);

	// Free CRL and Revocation Data
	if (ca->crl) PKI_X509_CRL_free(ca->crl);
	if (ca->nextUpdate) PKI_TIME_free(ca->nextUpdate);
	if (ca->lastUpdate) PKI_TIME_free(ca->lastUpdate);

	// Free the main structure
	PKI_Free ( ca );

	// All Done
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

	const PKI_STRING *keyString = NULL;
	PKI_DIGEST *keyDigest = NULL;

	const PKI_X509_NAME *iName = NULL;
	PKI_DIGEST *nameDigest = NULL;

	// Check for needed info
	if (!cert || !cert->value) return NULL;

	// Use SHA1 as default digest algorithm
	if (!digestAlg) digestAlg = PKI_DIGEST_ALG_SHA1;

	// Allocate Memory for the CA_ENTRY_CERTID
	if((ret = PKI_Malloc(sizeof(CA_ENTRY_CERTID))) == NULL) {

		// Error, can not allocate memory
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		goto err;
	}

	// Retrieves the subject name from the certificate
	if ((iName = PKI_X509_CERT_get_data(cert, PKI_X509_DATA_SUBJECT)) == NULL)
	{
		// Error, can not parse the certificate
		PKI_log_err("Can not get certificate's subject");
		goto err;
	}

	// Let's build the HASH of the Name
	if((nameDigest = PKI_X509_NAME_get_digest((PKI_X509_NAME *)iName, digestAlg)) == NULL) {

		// Error, Can not get the digest of the name
		PKI_log_err("Can not get digest string from certificate's subject");
		goto err;
	}

	// Assign the new OCTET string tothe nameHash field
	if ((ret->nameHash = PKI_STRING_new(PKI_STRING_OCTET,
			(char *) nameDigest->digest, (ssize_t) nameDigest->size)) == NULL) {

		// Error, can not transfer ownership of the nameHash
		PKI_log_err("Can not assign nameHash to CERTID");
		goto err;
	}
	
	// Let's get the key bitstring from the certificate
	if ((keyString = PKI_X509_CERT_get_data(cert, 
				PKI_X509_DATA_PUBKEY_BITSTRING)) == NULL) {

		// Error, can not parse the certificate
		PKI_log_err("Can not get certificate's pubkey bitstring");
		goto err;

	} else {

		// We build the keyDigest from the keyString
		if ((keyDigest = PKI_STRING_get_digest((PKI_STRING *)keyString, digestAlg)) == NULL) {

			// Error, can not get digest for the key
			PKI_log_err("Can not create new keyDigest from keyString");
			goto err;
		}
	}

	// Assign the keyHash to the returned structure
	if((ret->keyHash = PKI_STRING_new(PKI_STRING_OCTET,
				(char *) keyDigest->digest, (ssize_t) keyDigest->size)) == NULL) {

		// Error, can not transfer ownership of the keyHash
		PKI_log_err("Can not assign keyHash to CERTID");

		// Failure
		goto err;
	}

	// Set the Digest Algorithm used
	if ((ret->hashAlgorithm = PKI_X509_ALGOR_VALUE_new_digest(digestAlg)) == NULL) {

		// Can not retrieve a new digest algorithm reference
		PKI_log_err("Can not create a new hashAlgorithm for the CA CERTID");

		// Free memory
		if( ret ) CA_ENTRY_CERTID_free ( ret );
		
		// Failure
		goto err;
	}

	// Free the allocated Memory
	if (nameDigest) PKI_DIGEST_free(nameDigest);
	if (keyDigest) PKI_DIGEST_free(keyDigest);

	// All Done
	return ret;

err:

	// Free the allocated Memory
	if (nameDigest) PKI_DIGEST_free(nameDigest);
	if (keyDigest) PKI_DIGEST_free(keyDigest);
	if (ret) CA_ENTRY_CERTID_free (ret);

	// Failed
	return NULL;
}


void CA_ENTRY_CERTID_free(CA_ENTRY_CERTID *cid) {

	// Input Checks
	if ( !cid ) return;

	// Free Internal Memory
	if (cid->keyHash) PKI_STRING_free(cid->keyHash);
	if (cid->nameHash) PKI_STRING_free(cid->nameHash);

	// Free the memory for the data structure
	PKI_Free(cid);

	// Done
	return;
}

