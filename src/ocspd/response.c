/* src/ocsp_response.c
 * ============================================================
 * OCSP Responder
 * (c) 2001-2006 by Massimiliano Pala and OpenCA Group
 *     OpenCA License software
 * ============================================================
 */
 
#include "general.h"

pthread_mutex_t sign_mutex = PTHREAD_MUTEX_INITIALIZER;

PKI_X509_OCSP_RESP *make_ocsp_response(PKI_X509_OCSP_REQ *req, OCSPD_CONFIG *conf )
{
	OCSP_CERTID *cid = NULL;

	PKI_X509_OCSP_RESP *resp = NULL;
	PKI_X509_OCSP_REQ_VALUE *req_val = NULL;

	PKI_TOKEN *tk = NULL;
	PKI_X509_CERT *cert = NULL;
	PKI_X509_CERT *cacert = NULL;

	int i, id_count;

	int use_server_cert = 0;
	int use_server_cacert = 0;

	PKI_TIME *thisupd = NULL;
	PKI_TIME *nextupd = NULL;

	if((resp = PKI_X509_OCSP_RESP_new()) == NULL )
	{
		PKI_log_err ( "Memory Error" );
		goto end;
	}

	if ((req_val = PKI_X509_get_value ( req )) == NULL)
	{
		PKI_log_err ( "Memory Error" );
		goto end;
	}

	id_count = OCSP_request_onereq_count( req_val );

	if (id_count <= 0)
	{
		unsigned long error_num = HSM_get_errno(conf->token ? conf->token->hsm : NULL);

		PKI_log_err("[Thread] ERROR::Request has no onereq (Crypto Error is %ld::%s)",
			errno, HSM_get_errdesc(error_num, conf->token ? conf->token->hsm : NULL));

		PKI_X509_OCSP_RESP_set_status (resp, PKI_X509_OCSP_RESP_STATUS_MALFORMEDREQUEST);

		goto end;
	}

	/* Let's set the default token for signing */
	tk = conf->token;

	// Next update (if specified in the config)
	if (conf->set_nextUpdate)
		nextupd = PKI_TIME_new((conf->nmin * 60 ) + (conf->ndays * 86400));

	/* Examine each certificate id in the request */
	for (i = 0; i < id_count; i++)
	{
		OCSP_ONEREQ *one = NULL;
		ASN1_INTEGER *serial = NULL;
		CA_LIST_ENTRY *ca = NULL;
		X509_REVOKED *entry = NULL;

		one = OCSP_request_onereq_get0(req_val, i);
		cid = OCSP_onereq_get0_id(one);

		/* Get basic request info */
		OCSP_id_get0_info(NULL, NULL, NULL, &serial, cid);

		if (conf->verbose)
		{
			char *s = PKI_INTEGER_get_parsed ( serial );
			PKI_log( PKI_LOG_INFO, "request for certificate serial %s", s);
			if( s ) PKI_Free ( s );
		}

		/* Is this request about our CA? */
		if ((ca = OCSPD_CA_ENTRY_find( conf, cid )) == NULL)
		{
			if (conf->verbose)
			{
				char *s = PKI_INTEGER_get_parsed ( serial );
				PKI_log( PKI_LOG_INFO, "request for non reckognized CA [serial %s]", s );
				if( s ) PKI_Free ( s );
			}

			PKI_X509_OCSP_RESP_add ( resp, cid, PKI_OCSP_CERTSTATUS_UNKNOWN,
					NULL, NULL, nextupd, 0, NULL );

			/* Maybe we could add the serviceLocator extension
 			   we can use the PRQP to find out the server address */

			continue;
		}

		/* If the CA has a specific token, let's use that */
		if (ca->token != NULL)
		{
			tk = ca->token;
			if (conf->debug)
			{
				PKI_log_debug( "Using the specific token for the found CA (%s)",
					ca->token_name);
			}
		}
		else
		{
			/* If no specific token but a different server_cert
 			 * is to be used, let's report it in debug mode */
			if (ca->server_cert)
			{
				cert = ca->server_cert;

				use_server_cert = 1;

				if (ca->ca_cert)
				{
					use_server_cacert = 1;
					cacert = ca->ca_cert;
				}

				if (conf->debug)
				{
					char *subject = PKI_X509_CERT_get_parsed(cert, PKI_X509_DATA_SUBJECT);
					char *issuer = PKI_X509_CERT_get_parsed(cert, PKI_X509_DATA_ISSUER);
					char *serial = PKI_X509_CERT_get_parsed(cert, PKI_X509_DATA_SERIAL);

					PKI_log_debug("Using CA-Specific Config specified cert:", subject);
					PKI_log_debug("- Serial: %s", serial ? serial : "n/a");
					PKI_log_debug("- Subject: %s", subject ? subject : "n/a");
					PKI_log_debug("- Issuer: %s", issuer ? issuer : "n/a");

					if (serial) PKI_Free(serial);
					if (subject) PKI_Free(subject);
					if (issuer) PKI_Free(issuer);
				}
			}
		}

		/* This case returns the same response for any request in case the
		 * CA was compromised - all certificates are to be considered now
		 * not valid
		 */
		if (ca->compromised > 0)
		{
			PKI_X509_OCSP_RESP_add ( resp, cid, PKI_OCSP_CERTSTATUS_REVOKED,
				NULL, NULL, nextupd, CRL_REASON_CA_COMPROMISE, NULL);

			continue;
		}

		/* Here we check for the case where the CRL status is not ok, so
		 * we ask the client to try later, hopefully when we have a valid
		 * CRL to provide the response with
		 */
		if (ca->crl_status != CRL_OK)
		{
			PKI_X509_OCSP_RESP_set_status(resp, PKI_X509_OCSP_RESP_STATUS_TRYLATER);

			if (conf->debug || conf->verbose)
			{
				PKI_log_err ("SENT TRYLATER (%s)", get_crl_status_info (ca->crl_status));
			}
			goto end;
		}

		/* Get the entry from the CRL data, if NULL then the
		   certificate is not revoked */
		entry = OCSPD_REVOKED_find( ca, serial );

		/* Sets thisUpdate field to the value of the loaded CRL */
		// thisupd = M_ASN1_TIME_dup(ca->lastUpdate);
		// thisupd = PKI_TIME_dup(ca->lastUpdate);
		thisupd = PKI_TIME_new( 0 );

		if (entry)
		{
			long reason = -1;
			void *ext = NULL;

			/* If extensions are found, process them */
			if (entry->extensions)
			{
				ASN1_ENUMERATED *asn = NULL;

				if( (asn = X509_REVOKED_get_ext_d2i( entry, NID_crl_reason,NULL,NULL )) != NULL )
				{
					reason = ASN1_ENUMERATED_get( asn );
					ASN1_ENUMERATED_free( asn );
				}

				/* Check and add the invalidity date */
				ext = X509_REVOKED_get_ext_d2i( entry, NID_invalidity_date, NULL, NULL );
			}

			if((PKI_X509_OCSP_RESP_add ( resp, cid, PKI_OCSP_CERTSTATUS_REVOKED,
					entry->revocationDate, thisupd, nextupd, reason, ext )) == PKI_ERR )
			{
				PKI_log_err ("Can not generate OCSP response");
			}

			if( reason == CRL_REASON_CERTIFICATE_HOLD ) {
				/* TODO: We might want to add the CrlID
 				   extension to the response */
			}

			if (conf->verbose)
			{
				char * s = PKI_INTEGER_get_parsed ( serial );

				PKI_log(PKI_LOG_INFO, "Status for %s is REVOKED", s );
				PKI_Free ( s );
			}
		}
		else if (ca == NULL )
		{
			if (conf->verbose)
			{
				char * s = PKI_INTEGER_get_parsed ( serial );
				PKI_log( PKI_LOG_INFO, "status unknown for %ld (unknown CA)", s );
				PKI_Free ( s );
			}

			PKI_X509_OCSP_RESP_add ( resp, cid, PKI_OCSP_CERTSTATUS_UNKNOWN, 
				NULL, thisupd, nextupd, 0, NULL );
		}
		else
		{
			if (conf->verbose)
			{
				char *s = PKI_INTEGER_get_parsed ( serial );
				PKI_log( PKI_LOG_INFO, "status VALID for %s",s);
				PKI_Free ( s );
			}
			
			PKI_X509_OCSP_RESP_add ( resp, cid, PKI_OCSP_CERTSTATUS_GOOD,
				NULL, thisupd, nextupd, 0, NULL );
		}
	}

	// Let's copy the NONCE from the request
	if(PKI_X509_OCSP_RESP_copy_nonce( resp, req ) == PKI_ERR ) {
		PKI_log_err ("Can not copy NONCE from request to response");
	}

	// If no cert is provided but we have the token, let's get it from
	// the token
	if (!cert && tk) cert = PKI_TOKEN_get_cert ( tk );

	if (tk == NULL)
	{
		if (conf->debug) PKI_log_debug ( "CA Token is empty");
		if (conf->token == NULL) PKI_log_debug ("Default Token is empty!");
	}

	/* It seems that this function is not thread safe!!! */
	if (tk != NULL)
	{
		if (cert == NULL)
		{
			PKI_log_err ("OCSP certificate is empty!");
			if (resp) PKI_X509_OCSP_RESP_free (resp);
			resp = NULL;

			goto end;
		}

		/* It seems that CISCO devices require the SHA1 algorithm to be
 		 * used. Make sure you use that in the configuration for the digest
 		 */
		PKI_DIGEST_ALG *sign_dgst = NULL;

		if (conf->sigDigest) sign_dgst = conf->sigDigest;
		else sign_dgst = PKI_ALGOR_get_digest(tk->algor);

		if (conf->debug)
		{
			if (sign_dgst)
				PKI_log_debug("Digest Algorithm For Signature: %s", PKI_DIGEST_ALG_get_parsed(sign_dgst));
			else
				PKI_log_err("Can not parse the Digest Algorithm for Signatures!");
		}

		/* Sign the response only if we have a valid pkey pointer! */
		int sig_rv = PKI_OK;
		if (use_server_cert)
		{
			if (use_server_cacert)
			{
				sig_rv = PKI_X509_OCSP_RESP_sign(resp, tk->keypair, cert, cacert,
					tk->otherCerts, sign_dgst);
			}
			else
			{
				sig_rv = PKI_X509_OCSP_RESP_sign(resp, tk->keypair, cert, tk->cacert,
					tk->otherCerts, sign_dgst);
			}
		}
		else 
		{
			sig_rv = PKI_X509_OCSP_RESP_sign_tk(resp, tk, sign_dgst);
		}

		if (sig_rv != PKI_OK)
		{
			PKI_log_err("Failed while signing [%s]", PKI_ERROR_crypto_get_errdesc());
			if (resp) PKI_X509_OCSP_RESP_free(resp);
			resp = NULL;

			goto end;
		}

		/* Test Mode: Issues WRONG signatures by flipping the first
 		 * bit in the signature. Use it ONLY for testing OCSP clients
 		 * verify capabilities! */

		if (conf->testmode)
		{
			PKI_STRING *signature = NULL;

			PKI_log(PKI_LOG_ALWAYS, 
				"WARNING: TestMode (Wrong Signatures): Fipping first bit in Signature");

			// Get The Signature
			signature = PKI_X509_OCSP_RESP_get_data(resp, PKI_X509_DATA_SIGNATURE);
			if(signature)
			{	
				PKI_X509_OCSP_RESP_VALUE *resp_val = NULL;
  			PKI_OCSP_RESP *r = NULL;
				OCSP_BASICRESP *bsrp = NULL;
				
				int i = 0;

				PKI_log_debug("Test Mode: Signature Found!");

				// Flip The First n-Bit of the Signature (n=1)
				for (i=0; i < 1; i++ )
				{
					if(ASN1_BIT_STRING_get_bit(signature, i))
    			{
    				ASN1_BIT_STRING_set_bit(signature, i, 0);
    			}
    			else
    			{
        		ASN1_BIT_STRING_set_bit(signature, i, 1);
    			}
				}

				r = resp->value;

				// Now we need to re-encode the basicresp
		  	resp_val = r->resp;
				bsrp = r->bs;

				if (resp_val->responseBytes)
					OCSP_RESPBYTES_free(resp_val->responseBytes);

				if (!(resp_val->responseBytes = OCSP_RESPBYTES_new()))
				{
					PKI_log_err("Memory Error, aborting signature!");
 					return PKI_ERR;
				}

				resp_val->responseBytes->responseType = OBJ_nid2obj(NID_id_pkix_OCSP_basic);

				if (bsrp)
				{
					/* Now add the encoded data to the request bytes */
					if (!ASN1_item_pack(bsrp, ASN1_ITEM_rptr(OCSP_BASICRESP),
													&resp_val->responseBytes->response))
					{
						PKI_log_err("ERROR while encoding OCSP RESP");
						return ( PKI_ERR );
					}
				}
			}
			else
			{
				if (conf->debug) PKI_log_debug("Test Mode: Signature Not Found!");
			}
		}
	}

	if( conf->debug ) PKI_log_debug ("Response signed ok!");

	/*
	if ( conf->debug ) {
		PKI_MEM *mem = NULL;
		mem = PKI_X509_OCSP_RESP_put_mem ( resp, PKI_DATA_FORMAT_ASN1,
				NULL, NULL, NULL );

		PKI_log_debug("RESP converted -> %d", mem->size );

		URL_put_data ( "/tmp/ocsp-req-2.der", mem, NULL,
			NULL, 0, 0, NULL );

		PKI_X509_OCSP_REQ_put(req, PKI_DATA_FORMAT_ASN1,
				"/tmp/ocsp-req.der", NULL, NULL, NULL );
		PKI_X509_OCSP_RESP_put(resp, PKI_DATA_FORMAT_ASN1,
				"/tmp/ocsp-resp.der", NULL, NULL, NULL );
	}
	*/

end:

	if(thisupd) PKI_TIME_free ( thisupd );
	if(nextupd) PKI_TIME_free ( nextupd );

	return resp;
}

int ocspd_resp_send_socket(int connfd, PKI_X509_OCSP_RESP *r, 
						OCSPD_CONFIG *conf) {

	PKI_TIME *date = NULL;
	PKI_TIME *expire = NULL;
	PKI_MEM  *mem = NULL;

	char buf[1024];
	char *tmp_parsed_date = NULL;
	char *tmp_parsed_expire = NULL;

	char http_resp[] =
		"HTTP/1.0 200 OK\r\n"
		"Content-Type: application/ocsp-response\r\n"
 		"Content-Transfer-Encoding: Binary\r\n";

	if ( connfd <= 0 )
	{
		PKI_log_err("Socket fd is 0!");
		return 0;
	}

	if ((mem = PKI_X509_OCSP_REQ_put_mem(r, PKI_DATA_FORMAT_ASN1, 
					NULL, NULL, NULL )) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return ( 0 );
	}

	// Gets the time for the expire
	if (conf->set_nextUpdate) expire = PKI_TIME_new ((conf->nmin*60) + (conf->ndays * 86400));
	else expire = PKI_TIME_new( 0 );
	if (expire)
	{
		tmp_parsed_expire = PKI_TIME_get_parsed(expire);
		PKI_TIME_free(expire);
		expire = NULL;
	}

	// Gets current date and time
	if ((date = PKI_TIME_new(0)) != NULL)
	{
		tmp_parsed_date = PKI_TIME_get_parsed(date);
		PKI_TIME_free(date);
		date = NULL;
	}

	// Depending on what we have, we print out the appropriate header
	if (tmp_parsed_date && tmp_parsed_expire)
	{
#if ( LIBPKI_OS_BITS == LIBPKI_OS32)
		snprintf(buf, sizeof(buf), "%sContent-Length: %d\r\nDate: %s\r\nExpires: %s\r\n\r\n",
			http_resp, mem->size, tmp_parsed_date, tmp_parsed_expire);
#else
		snprintf(buf, sizeof(buf), "%sContent-Length: %ld\r\nDate: %s\r\nExpires: %s\r\n\r\n",
			http_resp, mem->size, tmp_parsed_date, tmp_parsed_expire);
#endif
	}
	else if (tmp_parsed_date)
	{
#if ( LIBPKI_OS_BITS == LIBPKI_OS32)
		snprintf(buf, sizeof(buf), "%sContent-Length: %d\r\nDate: %s\r\n\r\n",
			http_resp, mem->size, tmp_parsed_date);
#else
		snprintf(buf, sizeof(buf), "%sContent-Length: %ld\r\nDate: %s\r\n\r\n",
			http_resp, mem->size, tmp_parsed_date);
#endif
	}
	else if (tmp_parsed_expire)
	{
#if ( LIBPKI_OS_BITS == LIBPKI_OS32)
		snprintf(buf, sizeof(buf), "%sContent-Length: %d\r\nExpires: %s\r\n\r\n",
			http_resp, mem->size, tmp_parsed_expire);
#else
		snprintf(buf, sizeof(buf), "%sContent-Length: %ld\r\nExpires: %s\r\n\r\n",
			http_resp, mem->size, tmp_parsed_expire);
#endif
	}
	else
	{
#if ( LIBPKI_OS_BITS == LIBPKI_OS32 )
		snprintf(buf, sizeof(buf), "%sContent-Length: %d\r\n\r\n", http_resp, mem->size);
#else
		snprintf(buf, sizeof(buf), "%sContent-Length: %ld\r\n\r\n", http_resp, mem->size);
#endif
	}

	// Writes the headers to the Network
	PKI_NET_write(connfd, buf, strlen(buf));

	// Writes the OCSP response
	PKI_NET_write (connfd, mem->data, mem->size );

	// Flushes the buffers
	fflush(NULL);

	if (conf->debug) 
	{
		PKI_log_debug("OCSP Response Bytes = %d, HTTP Header Bytes = %d", mem->size, strlen(buf));

		// Enable this section if you need to debug responses deeper
		/*
		URL_put_data ("file:///var/tmp/ocsp-resp.der", mem, NULL, NULL, 0, 0, NULL);
		PKI_log_debug("OCSP Response Written to /var/tmp/ocsp-resp.der (%d)", mem->size);

		PKI_MEM *t = PKI_MEM_new_data(strlen(buf), buf);
		if (t)
		{
			PKI_MEM_add(t, mem->data, mem->size);
			URL_put_data ("file:///var/tmp/http-ocsp-resp.txt", t, NULL, NULL, 0, 0, NULL);
			PKI_log_debug("HTTP Response Written to /var/tmp/http-ocsp-resp.txt (%d)", t->size);
		}
		*/
	}

	// Frees the memory
	if (mem) PKI_MEM_free(mem);
	if (tmp_parsed_expire) PKI_Free(tmp_parsed_expire);
	if (tmp_parsed_date) PKI_Free(tmp_parsed_date);

	return PKI_OK;
}

CA_LIST_ENTRY *OCSPD_CA_ENTRY_find(OCSPD_CONFIG *conf, OCSP_CERTID *cid)
{
	// STACK_OF(CA_ENTRY_CERTID) *a = NULL;

	int i = 0, ret = PKI_OK;

	OCSP_CERTID *b = NULL;
	CA_LIST_ENTRY *ca = NULL;
	CA_ENTRY_CERTID *tmp = NULL;

	b = cid;

	if (conf == NULL || conf->ca_list == NULL ) 
	{
		PKI_log_err("ERROR: missing conf and/or ca_list");
		return NULL;
	}

	int elements = PKI_STACK_elements(conf->ca_list);
	for ( i = 0; i < elements; i++ )
	{
		ca = (CA_LIST_ENTRY *) PKI_STACK_get_num(conf->ca_list, i);

		tmp = ca->cid;

		/* Check for hashes */
		if((ret = ASN1_OCTET_STRING_cmp(tmp->nameHash, b->issuerNameHash)) != 0 )
		{
			if (conf->debug) 
			{
				PKI_log_debug("CRL::CA [%s] nameHash mismatch (%d)", 
					ca->ca_id, ret);
				continue;
			}
		}
		else if( conf->debug ) 
		{
			PKI_log_debug("CRL::CA [%s] nameHash OK", ca->ca_id);
		}

		if ((ret = ASN1_OCTET_STRING_cmp(tmp->keyHash, b->issuerKeyHash)) != 0)
		{
			if (conf->debug)
			{
				PKI_log_debug("CRL::CA [%s] issuerKeyHash mismatch (%d)",
				 	ca->ca_id, ret);
				continue;
			}
		}
		else if (conf->debug) 
		{
			PKI_log_debug("CRL::CA [%s] issuerKeyHash OK", ca->ca_id);
		}

		/* If here we have found it! */
		if (!ret) return ( ca );
	}

	/* Here we have not found any suitable CA */
	return(NULL);
}

X509_REVOKED *OCSPD_REVOKED_find (CA_LIST_ENTRY *ca, ASN1_INTEGER *serial) {

	X509_REVOKED *r = NULL;

	int curr = 0;
	int start = 0;
	int cont = 1;
	int end, cmp_val;
	int found = 0;

	/* If no entries are in the list, return directly */
	if( !(ca) || !(ca->crl) || !(ca->crl_list)) return (r);
 
	/* Set the end point to the last one */
	end = sk_X509_REVOKED_num(ca->crl_list) - 1;
	if( end < 0 ) return (r);

	while( cont == 1 ) {
		/* We have not found the entry */
		if( end < start ) break;

		/* Calculate the middle between start and end */
		curr = (int) ((end - start) / 2) + start;

		/* Get the entry from the stack */
		r = sk_X509_REVOKED_value(ca->crl_list, curr);

		/* Compare the two serials */
		cmp_val = ASN1_INTEGER_cmp(r->serialNumber, serial);

		if( cmp_val > 0 ) {
			end = curr - 1;
			continue;
		} else if ( cmp_val < 0 ) {
			start = curr + 1;
			continue;
		} else {
			/* Entry Found ! */
			cont = 0;
			found = 1;
			break;
		}
	}
	if( found )
		return (r);
	else
		return(NULL);

}

