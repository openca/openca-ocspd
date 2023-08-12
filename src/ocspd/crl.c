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

// #define _XOPEN_SOURCE 500
// #include <unistd.h>

/* External imported variables */
extern OCSPD_CONFIG * ocspd_conf;
// extern pthread_rwlock_t crl_lock;
// extern pthread_cond_t crl_cond;

int ocspd_load_ca_crl(CA_LIST_ENTRY *caEntry, OCSPD_CONFIG *conf) {

	// Input checks
	if (!caEntry || !conf || !caEntry->crl_url) {

		// If we do not have a URL, let's report the error
		if (!caEntry->crl_url) PKI_log_err(
			"Missing URL for where to access the CRL URL [CA: %s]",
			caEntry->ca_id);
		return (-1);
	}

	// Acquires the CRL lock
	PKI_RWLOCK_write_lock(&conf->crl_lock);

	// Free current CRL memory
	if (caEntry->crl) PKI_X509_CRL_free(caEntry->crl);
	caEntry->crl = NULL; // Safety

	// Free the list (it seems it is static from OpenSSL and
	// does not need to be freed explicitly (check sk_X509_REVOKED_free)
	// (check the x509/x509.h:606 X509_CRL_get_REVOKED() definition)
	caEntry->crl_list = NULL;

	// We now re-load the CRL
	if( (caEntry->crl = PKI_X509_CRL_get_url(caEntry->crl_url,
	                                          PKI_DATA_FORMAT_UNKNOWN, NULL, NULL)) == NULL ) {
		PKI_log_err("Can not reload CRL [CA: %s, URL: %s]", 
						caEntry->ca_id, caEntry->crl_url->url_s);
		PKI_RWLOCK_release_write(&conf->crl_lock);
		return(-1);
	}

	// Debugging Info
	PKI_log(PKI_LOG_INFO, "CRL successfully reloaded [CA: %s, URL: %s]",
			caEntry->ca_id, caEntry->crl_url->url_s );

	// Let's get the CRLs entries, if any
	if (ocspd_build_crl_entries_list(caEntry, caEntry->crl) == NULL) { 
		PKI_log(PKI_LOG_INFO, "CRL has 0 (Zero) Entries [CA: %s, URL: %s]",
				caEntry->ca_id, caEntry->crl_url->url_s );
	} else {
		PKI_log(PKI_LOG_INFO, "CRL has %d  Entries [CA: %s, URL: %s]",
                                caEntry->entries_num, caEntry->ca_id, caEntry->crl_url->url_s);
	}

	// If previous values are there, then we clear them up
	if (caEntry->lastUpdate) ASN1_TIME_free(caEntry->lastUpdate);
	if (caEntry->nextUpdate) ASN1_TIME_free(caEntry->nextUpdate);

	// Get new values from the recently loaded CRL
	caEntry->lastUpdate = PKI_TIME_dup(
		PKI_X509_CRL_get_data(caEntry->crl, PKI_X509_DATA_LASTUPDATE ));
	caEntry->nextUpdate = PKI_TIME_dup (
		PKI_X509_CRL_get_data(caEntry->crl, PKI_X509_DATA_NEXTUPDATE ));

	// Releases the lock
	PKI_RWLOCK_release_write(&conf->crl_lock);

	/* Now check the CRL validity */
	caEntry->crl_status = check_crl_validity(caEntry, conf);

	// Now check the CRL validity
	if ((caEntry->crl_status = check_crl_validity(caEntry, conf)) == CRL_OK) {
		PKI_log(PKI_LOG_INFO, 
				"CRL reloaded and verified [CA: %s, Status: OK]",
				caEntry->ca_id);
	} else {
		PKI_log_err("CRL Status not verified [CA: %s, Status: %d]",
				caEntry->ca_id, caEntry->crl_status);
		return -1;
	}

	return 0;
}


int ocspd_reload_crls ( OCSPD_CONFIG *conf ) {

	int i = 0, err = 0;

	CA_LIST_ENTRY *a = NULL;

	PKI_log(PKI_LOG_ALWAYS, "Auto CRL Reload Initiated [Total CAs: %ld]",
			PKI_STACK_elements (conf->ca_list));

	for (i = 0; i < PKI_STACK_elements(conf->ca_list); i++) {

		// Gets the CA config element
		a = PKI_STACK_get_num ( conf->ca_list, i );

		// Some Info
		PKI_log(PKI_LOG_INFO, "Reloading CRL for CA [Num: %d (of %d), CA: %s]",
					i, PKI_STACK_elements(conf->ca_list), a->ca_id );

		// Loads the CRL for the specific CA
		if (ocspd_load_ca_crl(a, conf) < 0 ) {

			// Logs the error
			PKI_log_err("Can not reload CRL for CA [Num: %d (of %d), CA: %s]", 
					i, PKI_STACK_elements(conf->ca_list), a->ca_id );

			// Updates the Error Counter
			err++;

			// Proceed to the next entry
			continue;
		}
	}

	// Some Debugging Info
	PKI_log(PKI_LOG_ALWAYS, "Auto CRL Reload Terminated "
			"[Success: %d, Errors: %d]", i - err, err );

	return(1);
}

int check_crl(PKI_X509_CRL  * x_crl,
	      PKI_X509_CERT * x_cacert,
	      OCSPD_CONFIG  * conf) {

	const PKI_X509_KEYPAIR_VALUE *pkey = NULL;
		// Public Key Value to verify the CRL with

	PKI_X509_KEYPAIR *k = NULL;
		// Public Key X509 Structure to verify the CRL with

	int ret = -1;
		// Return Code

	char * x_subj = NULL;
		// CA Cert Subject

	// Required Input Checks
	if (!conf) return (-1);

	// Acquires the READ lock over the CRL
	PKI_RWLOCK_read_lock ( &conf->crl_lock );

	// Checks for the required values to be there
	if (!x_crl || !x_crl->value || !x_cacert || !x_cacert->value) {

		// Reports if the CRL is missing
		if(!x_crl || !x_crl->value) PKI_log_err("CRL missing");

		// Reports if the CA Certificate is missing
		if(!x_cacert || !x_cacert->value) PKI_log_err("CA cert missing");

		// Releases the READ lock
		PKI_RWLOCK_release_read(&conf->crl_lock);

		// Failed to check the CRL
		return -1;
	}

#ifdef PKI_X509_DATA_PUBKEY
	// Gets the Public Key of the CA Certificate
	if ((pkey = PKI_X509_CERT_get_data(x_cacert, 
									   PKI_X509_DATA_PUBKEY)) == NULL ) { 
#else
	// Gets the Public Key of the CA Certificate
	if ((pkey = PKI_X509_CERT_get_data(x_cacert, 
									   PKI_X509_DATA_X509_PUBKEY)) == NULL ) { 
#endif

		// Reports the error
		PKI_log_err("Can not parse PubKey from CA Cert");

		// Releases the READ lock
		PKI_RWLOCK_release_read(&conf->crl_lock);

		// Failed to check the CRL
		return(-3);
	}

	// Builds the X509 KEYPAIR structure from the
	// CA key's value extracted from the CA's cert
	if ((k = PKI_X509_new_value(PKI_DATATYPE_X509_KEYPAIR, 
							(void *)pkey, NULL)) == NULL ) {

		// Error while creating the X509_KEYPAIR structure
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);

		// Releases the READ lock
		PKI_RWLOCK_release_read ( &conf->crl_lock );

		// Failed to check the CRL
		return -4;
	}
	
	// Some debugging info
	PKI_log_debug("Got the public key from the CA cert [Scheme: %s, Key Size: %d]",
		     PKI_SCHEME_ID_get_parsed(PKI_X509_KEYPAIR_get_scheme(k)),
		     PKI_X509_KEYPAIR_get_size(k));

	// Gets the parsed SubjectName of the CA Cert
	if ((x_subj = PKI_X509_CERT_get_parsed(x_cacert, PKI_X509_DATA_SUBJECT)) == NULL) 
		x_subj = strdup("<not set>");

	// Verifies and provides some logging
	if ((ret = PKI_X509_verify(x_crl, k)) == PKI_OK) {

		// CRL correctly verified
		PKI_log(PKI_LOG_INFO, "CRL signature is verified "
			"[Code: %d, CA Subject: %s]", ret, x_subj);

	} else {

		// CRL could not be verified, report the issue
		PKI_log_err("CRL signature is NOT verified "
			"[Code: %d, CA Subject: %s]!", ret, x_subj);
	}

	// Free the RW lock on the CRL
	PKI_RWLOCK_release_read ( &conf->crl_lock );

	// Make sure we do not free the internal value
	k->value = NULL;

	// Free the outer shell for the key
	PKI_X509_KEYPAIR_free(k);

	// Free the Memory
	PKI_Free(x_subj);

	// All Done
	return ret;
}

int check_crl_validity ( CA_LIST_ENTRY *ca, OCSPD_CONFIG *conf ) {

	int i = -1, ret = PKI_OK;

	// Allocates the Lock for CRL access
	PKI_RWLOCK_read_lock ( &conf->crl_lock );

	// Checks for the passed 'ca' parameter
	if (!ca || !ca->crl) {

		// Reports the Error
		PKI_log_err ("Error in CA internal config status [CA: %s]", ca->ca_id );
		
		// Releases the lock
		PKI_RWLOCK_release_read ( &conf->crl_lock );

		// All Done
		return CRL_ERROR_LAST_UPDATE;
	}

	// If no lastUpdate is available or it is in the future
	// let's return the lastUpdate error
	if (ca->lastUpdate == NULL || 
			(i = X509_cmp_time(ca->lastUpdate, NULL)) >= 0) {

		if (i == 0) {
			// Here the lastUpdate is in the future
			PKI_log_err("CRL Validity Check FAILED [CA: %s, Error: Not Valid Yet, Code: %d]", 
				ca->ca_id, CRL_NOT_YET_VALID);

			// Updates the CRL internal status
			ret = CRL_NOT_YET_VALID;

		} else {
			// Here we do not have a lastUpdate
			PKI_log_err( "CRL Validity Check FAILED (Missing lastUpdate) "
					"[CA: %s, Error: no lastUpdate Field, Code: %d]", 
				ca->ca_id, CRL_ERROR_LAST_UPDATE );

			// Updates the CRL internal status
			ret = CRL_ERROR_LAST_UPDATE;
		}
	}

	// Compares the nextUpdate time with now (NULL)
	if (ca->nextUpdate != NULL && 
			(i = X509_cmp_time(ca->nextUpdate, NULL)) <= 0) {
                                                                                  
		if (i == 0) {
			// nextUpdate Error
			PKI_log_err ("CRL Validity Check FAILED (Missing nextUpdate) "
					"[CA: %s, Error: no nextUpdate Field, Code: %d]",
				ca->ca_id, CRL_ERROR_NEXT_UPDATE );

			// Updates the CRL internal status
			ret = CRL_ERROR_NEXT_UPDATE;

		} else {
			char * time_s = NULL;

			// Gets the parsed representation of the nextUpdate
			time_s = PKI_TIME_get_parsed((const PKI_TIME *)ca->nextUpdate);

			// CRL is expired Error
			PKI_log_err ("CRL Validity Check FAILED [CA: %s, Error: CRL Expired on %s, Code: %d]",
				ca->ca_id, time_s, CRL_EXPIRED );

			// Updates the CRL internal status
			ret = CRL_EXPIRED;

			// Free allocated Memory
			PKI_Free(time_s);
		}
	}

	// Releases the lock
	PKI_RWLOCK_release_read(&conf->crl_lock);

	// Provides some debugging
	if (ret == PKI_OK) {
		PKI_log_debug("CRL Validity Check Success [CA: %s]", ca->ca_id);
	}

	// All Done
	return ret;
}

const char * get_crl_status_info ( int status ) {

	const char * unknown = "CRL status is unknown";

	switch( status ) {
		case CRL_OK:
			return("CRL is VALID");
			break;

		case CRL_ERROR_LAST_UPDATE:
			return("ERROR in LAST UPDATE field");
			break;

		case CRL_NOT_YET_VALID:
			return("WARNING, CRL is NOT YET valid");
			break;

		case CRL_ERROR_NEXT_UPDATE:
			return("ERROR in NEXT UPDATE field");
			break;

		case CRL_EXPIRED:
			return("CRL is EXPIRED");
			break;

		default:
			return unknown;
	}

	return unknown;
}

void auto_crl_check ( int sig ) {

	CA_LIST_ENTRY *ca = NULL;
	int i, ret;

	// If Auto CRL Check is enable, let's start
	if( ocspd_conf->crl_auto_reload ) {

		// Debugging Info
		PKI_log_debug("Auto CRL Check Process started");

		ocspd_conf->current_crl_reload += 
					ocspd_conf->alarm_decrement;

		if( ocspd_conf->current_crl_reload >=
					ocspd_conf->crl_auto_reload ) {

			ocspd_conf->current_crl_reload = 0;

			// Here we de-allocate the CRL entries and
			// reload the CRL
			if (ocspd_reload_crls(ocspd_conf) == 0) {

				// Can not reload CRLs
				PKI_log_err("Error reloading CRLs");

			}

			// Restart the Alarm
			alarm((unsigned int) ocspd_conf->alarm_decrement);

			// All Done
			return;
		}
	}

	// Cycles through all the configured CAs
	for( i=0; i < PKI_STACK_elements (ocspd_conf->ca_list); i++ ) {

		// Retrieves the CA configuration
		if((ca = PKI_STACK_get_num (ocspd_conf->ca_list, i)) == NULL) {
			// If nothing is returned, let's get to the next element
			// (should never happen)
			continue;
		}

		// Some Info for the logs
		PKI_log(PKI_LOG_INFO, "Auto CRL checking [CA %d: %s]",
			i, ca->ca_id ? ca->ca_id : "<name not set in config>");

		// Checks the CRL validity
		ret = check_crl_validity(ca, ocspd_conf);

		// Compares the returned value with the one that was
		// previously set in the CA's entry
		if (ca->crl_status != ret) {

			// Some logging information
			PKI_log(PKI_LOG_ALWAYS,"Auto CRL Detected CRL status change [CA %d: %s]",
				i, ca->ca_id ? ca->ca_id : "<name not set in config>");

			// Updates the CA's entry
			ca->crl_status = ret;

			// Let's load the CA's CRL
			ocspd_load_ca_crl (ca, ocspd_conf);

			// Next Entry
			continue;

		} else {

			// Some Info for the logs
			PKI_log(PKI_LOG_INFO,"No CRL status change [CA %d: %s]",
				i, ca->ca_id ? ca->ca_id : "<name not set in config>");
		}
	}

	// Some Debugging Information
	PKI_log_debug("Auto CRL Check Process completed");

	// Reset the Alarm
	alarm((unsigned int) ocspd_conf->alarm_decrement);

	// All Done
	return;
}

void force_crl_reload ( int sig ) {
	PKI_log( LOG_INFO, "Forced CRL reloading detected");
	ocspd_reload_crls ( ocspd_conf );

	return;
}
