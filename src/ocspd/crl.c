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

int ocspd_load_ca_crl ( CA_LIST_ENTRY *a, OCSPD_CONFIG *conf ) {

	// Input checks
	if (!a || !conf) return(-1);

	// Debugging information
	if( conf->debug ) PKI_log_debug( "ACQUIRING WRITE LOCK -- BEGIN CRL RELOAD");
	
	// Acquires the CRL lock
	PKI_RWLOCK_write_lock ( &conf->crl_lock );

	// Debugging information
	if( conf->debug ) PKI_log_debug( "INFO::LOCK ACQUIRED (CRL RELOAD)");

	// Free current CRL memory
	if( a->crl ) PKI_X509_CRL_free ( a->crl );

	// Safety
	a->crl = NULL;
	a->crl_list = NULL;

	if( a->crl_url == NULL ) {
		 PKI_log_err ( "Missing CRL URL for CA %s", a->ca_id );
		return(-1);
	}

	/* We now re-load the CRL */
	if( (a->crl = PKI_X509_CRL_get_url( a->crl_url, NULL, NULL)) == NULL ) {
		PKI_log_err ("Can not reload CRL [ %s ] for CA [%s]", 
						a->crl_url->addr, a->ca_id);
		PKI_RWLOCK_release_write ( &conf->crl_lock );
		return(-1);
	}

	if( conf->verbose )
		PKI_log( PKI_LOG_INFO, "INFO::CRL successfully reloaded [ %s ]",
			a->ca_id );

	/* Let's get the CRLs entries, if any */
	if( ocspd_build_crl_entries_list ( a, a->crl ) == NULL ) { 
		if( conf->verbose )
			PKI_log(PKI_LOG_INFO, "INFO::No Entries for CRL [ %s ]",
				a->ca_id );
	};

	if(conf->verbose)
		PKI_log( PKI_LOG_INFO, "INFO::CRL loaded successfully [ %s ]", 
								a->ca_id );

	/* If previous values are there, then we clear them up */
	if ( a->lastUpdate ) ASN1_TIME_free(a->lastUpdate);
	if ( a->nextUpdate ) ASN1_TIME_free(a->nextUpdate);

	/* Get new values from the recently loaded CRL */
	a->lastUpdate = M_ASN1_TIME_dup (
		PKI_X509_CRL_get_data ( a->crl, PKI_X509_DATA_LASTUPDATE ));
	a->nextUpdate = M_ASN1_TIME_dup (
		PKI_X509_CRL_get_data ( a->crl, PKI_X509_DATA_NEXTUPDATE ));

	if(conf->debug) PKI_log_debug("RELEASING LOCK (CRL RELOAD)");
	PKI_RWLOCK_release_write ( &conf->crl_lock );
	// pthread_rwlock_unlock ( &crl_lock );
	if(conf->debug) PKI_log_debug ( "LOCK RELEASED --END--");

	/* Now check the CRL validity */
	a->crl_status = check_crl_validity( a, conf );

	if( a->crl_status == CRL_OK ) {
		PKI_log(PKI_LOG_ALWAYS, "%s's CRL reloaded (OK)", a->ca_id);
	}

	return(0);
}


int ocspd_reload_crls ( OCSPD_CONFIG *conf ) {

	int i, err;

	CA_LIST_ENTRY *a = NULL;

	if( conf->verbose )
		PKI_log( PKI_LOG_INFO, "INFO::CRL Reload %ld CAs",
			PKI_STACK_elements (conf->ca_list));

	err = 0;
	for( i=0; i < PKI_STACK_elements (conf->ca_list); i++ ) {
		a = PKI_STACK_get_num ( conf->ca_list, i );

		if( conf->verbose )
			PKI_log(PKI_LOG_INFO, "INFO::Reloading CRL for CA [%s]",
							a->ca_id );

		if( ocspd_load_ca_crl(a, conf) < 0 ) {
			PKI_log_err("Reload CRL for CA [%s]", a->ca_id );
			err++;
			continue;
		}
	}

	PKI_log(PKI_LOG_INFO, "CRL Reloaded (%d ok, %d err)",
		i - err, err );

	return(1);
}

int check_crl ( PKI_X509_CRL *x_crl, PKI_X509_CERT *x_cacert,
		OCSPD_CONFIG *conf ) {

	const PKI_X509_KEYPAIR_VALUE *pkey = NULL;
	PKI_X509_KEYPAIR *k = NULL;

	int ret = -1;

	if (!conf) return (-1);

	PKI_RWLOCK_read_lock ( &conf->crl_lock );
	if( !x_crl || !x_crl->value || !x_cacert || !x_cacert->value ) {
		if( conf->verbose ) {
			if(!x_crl || !x_crl->value) 
					PKI_log_err ("CRL missing");
			if(!x_cacert || !x_cacert->value) 
					PKI_log_err("CA cert missing");
		}
		PKI_RWLOCK_release_read ( &conf->crl_lock );
		return(-1);
	}

	/* Gets the Public Key of the CA Certificate */
	if((pkey = PKI_X509_CERT_get_data( x_cacert, 
				PKI_X509_DATA_PUBKEY )) == NULL ) { 
		PKI_log_err( "Can not parse PubKey from CA Cert");
		PKI_RWLOCK_release_read ( &conf->crl_lock );
		return(-3);
	}

	if ((k = PKI_X509_new_value(PKI_DATATYPE_X509_KEYPAIR, (void *)pkey, NULL))
							== NULL ) {
		PKI_log_err ("Memory Error!");
		PKI_RWLOCK_release_read ( &conf->crl_lock );
		return(-3);
	}
	
	if ( PKI_X509_verify ( x_crl, k ) == PKI_OK ) {
		PKI_log_debug("CRL signature is verified!");
		ret = PKI_OK;
	} else {
		ret = PKI_ERR;
	}

	k->value = NULL;
	PKI_X509_KEYPAIR_free ( k );

	PKI_RWLOCK_release_read ( &conf->crl_lock );

	if ( ret > 0 ) {
		PKI_log(PKI_LOG_INFO, "CRL matching CA cert ok [ %d ]",
				ret);
	}

	return ret;
}

int check_crl_validity ( CA_LIST_ENTRY *ca, OCSPD_CONFIG *conf ) {
	int i;

	PKI_RWLOCK_read_lock ( &conf->crl_lock );
	// pthread_rwlock_rdlock( &crl_lock );

	if( (!ca) || (!ca->crl) || (!(ca->lastUpdate)) ) {
		PKI_log_err ("CRL::[%s]::Verify error (memory alloc)", 
								ca->ca_id );
		PKI_RWLOCK_release_read ( &conf->crl_lock );
		// pthread_rwlock_unlock( &crl_lock );
		return(CRL_ERROR_LAST_UPDATE);
	}

	i=X509_cmp_time(ca->lastUpdate, NULL);
	if (i == 0) {
		PKI_log_err( "CRL [%s] LAST UPDATE error (code %d)", 
			ca->ca_id, CRL_ERROR_LAST_UPDATE );

		PKI_RWLOCK_release_read ( &conf->crl_lock );
		ca->crl_status = CRL_ERROR_LAST_UPDATE;
		
		return(CRL_ERROR_LAST_UPDATE);
	} else if (i > 0) {
		PKI_log_err("WARING::CRL [%s] NOT YET valid (code %d)", 
				ca->ca_id, CRL_NOT_YET_VALID);
		ca->crl_status = CRL_NOT_YET_VALID;
		PKI_RWLOCK_release_read ( &conf->crl_lock );
		
		return(CRL_NOT_YET_VALID);
	}
                                                                                
	if (!conf->crl_reload_expired) {
		if(ca->nextUpdate) {
			i=X509_cmp_time(ca->nextUpdate, NULL);
                                                                                  
			if (i == 0) {
				PKI_RWLOCK_release_read ( &conf->crl_lock );
				
				PKI_log_err ("CRL [%s] NEXT UPDATE error (code %d)", 
						ca->ca_id, CRL_ERROR_NEXT_UPDATE );
				ca->crl_status = CRL_ERROR_NEXT_UPDATE;
				
				return(CRL_ERROR_NEXT_UPDATE);
			} else if (i < 0) {
				PKI_RWLOCK_release_read ( &conf->crl_lock );
				
				PKI_log_err ("CRL [%s] IS EXPIRED (code %d)",
						ca->ca_id, CRL_EXPIRED );
				ca->crl_status = CRL_EXPIRED;
				return(CRL_EXPIRED);
			}
		} else {
			PKI_log_err ("CRL [%s] has no nextUpdate!", ca->ca_id );
		}
	}

	PKI_RWLOCK_release_read ( &conf->crl_lock );

	return (CRL_OK);
}

char * get_crl_status_info ( int status ) {

	switch( status ) {
		case CRL_OK:
			return("CRL is VALID");
			break;
			;;
		case CRL_ERROR_LAST_UPDATE:
			return("ERROR in LAST UPDATE field");
			break;
			;;
		case CRL_NOT_YET_VALID:
			return("WARNING, CRL is NOT YET valid");
			break;
			;;
		case CRL_ERROR_NEXT_UPDATE:
			return("ERROR in NEXT UPDATE field");
			break;
			;;
		case CRL_EXPIRED:
			return("CRL is EXPIRED");
			break;
			;;
	}
	return("CRL status is UNKNOWN");
}

void auto_crl_check ( int sig ) {

	CA_LIST_ENTRY *ca = NULL;
	int i, ret;

	if( ocspd_conf->verbose == 1 ) {
		PKI_log(PKI_LOG_INFO, "auto_crl_check() started");
	}

	if( ocspd_conf->crl_auto_reload ) {
		ocspd_conf->current_crl_reload += 
					ocspd_conf->alarm_decrement;

		if( ocspd_conf->current_crl_reload >=
					ocspd_conf->crl_auto_reload ) {

			ocspd_conf->current_crl_reload = 0;

			/* Here we de-allocate the CRL entries and
			   reload the CRL */
			if( ocspd_reload_crls( ocspd_conf ) == 0 ) {
				PKI_log_err("Error reloading CRLs");
			} else {
				if( ocspd_conf->verbose )
					PKI_log(PKI_LOG_INFO, "CRLs reloaded.");
			}

			alarm( (unsigned int) ocspd_conf->alarm_decrement );

			return;
		}
	}

	if( ocspd_conf->verbose == 1 ) {
		PKI_log(PKI_LOG_INFO, "auto_crl_check() continuing");
	}

	for( i=0; i < PKI_STACK_elements (ocspd_conf->ca_list); i++ ) {

		if((ca = PKI_STACK_get_num (ocspd_conf->ca_list, i)) == NULL) {
			continue;
		}

		if( ocspd_conf->verbose && ca->ca_id )
			PKI_log(PKI_LOG_INFO, "Auto CRL checking [%s]", ca->ca_id);


		ret = check_crl_validity ( ca, ocspd_conf );

		if( ca->crl_status != ret ) {
			if(ocspd_conf->verbose) 
				PKI_log(PKI_LOG_INFO,"Detected CRL status change");
			ca->crl_status = ret;

			ocspd_load_ca_crl (ca, ocspd_conf);

			continue;
		} else {
			if( ocspd_conf->verbose && ca->ca_id ) 
				PKI_log(PKI_LOG_INFO,"No CRL status change for [%s]",
					ca->ca_id);
		}
		// syslog( LOG_INFO, "Forcing CRL Reloading for [%s]",
		// 	ca->ca_id ? ca->ca_id : "No Name" );
		// ocspd_load_ca_crl (ca, ocspd_conf);
	}

	/*
	if( ocspd_conf->crl_check_validity ) {
		if( verbose )
			syslog(LOG_INFO, "Checking again CRL in %d secs",
				ocspd_conf->crl_check_validity );

		alarm( ocspd_conf->crl_check_validity );
	}
	*/

	if( ocspd_conf->verbose == 1 ) {
		PKI_log(LOG_INFO, "auto_crl_check() completed");
	}

	alarm( (unsigned int) ocspd_conf->alarm_decrement );

	return;
}

void force_crl_reload ( int sig ) {
	PKI_log( LOG_INFO, "Forced CRL reloading detected");
	ocspd_reload_crls ( ocspd_conf );

	return;
};
