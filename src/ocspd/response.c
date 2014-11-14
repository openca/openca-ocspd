/* src/ocsp_response.c
 * ============================================================
 * OCSP Responder
 * (c) 2001-2006 by Massimiliano Pala and OpenCA Group
 *     OpenCA License software
 * ============================================================
 */
 
#include "general.h"

pthread_mutex_t sign_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef enum {
	OCSPD_INFO_UNKNOWN_STATUS     = 0,
	OCSPD_INFO_VALID_CERT         = 1,
	OCSPD_INFO_NON_RECOGNIZED_CA  = 2,
	OCSPD_INFO_NON_VALID_CRL      = 3,
	OCSPD_INFO_REVOKED            = 4
} OCSPD_INFO_TYPE;

static const char *statusInfo[] = {
		"unknown certificate status",
		"valid certificate status",
		"request for non recognized CA",
		"unknown status due to invalid CRL status",
		"certificate revoked",
		NULL
};

int sign_ocsp_response(PKI_X509_OCSP_RESP *resp, OCSPD_CONFIG *conf, PKI_X509_CERT *signCert, PKI_X509_CERT *caCert, PKI_TOKEN *tk)
{
	PKI_DIGEST_ALG * sign_dgst = NULL;
	PKI_OCSP_RESP  * r = NULL;

	int sig_rv = PKI_OK;

	// Input Checks
	if (!resp || !conf) return PKI_ERR;
	
	// Checks the internal value
	r = PKI_X509_get_value(resp);
	if (!r || !r->resp) return PKI_ERR;

	// Checks if the response can be signed, if not, let's return
	// OK since there is no actions to be addressed
	if (!r->bs) return PKI_OK;

	// Let's get the default token for signing
	if (tk == NULL)
	{
		if ((tk = conf->token) == NULL)
		{
			PKI_log_err("CA Token is empty, can not sign response!");
			return PKI_ERR;
		}
	}

	// Sign the response only if we have a valid pkey pointer!
	if (PKI_TOKEN_get_keypair(tk) == NULL)
	{
		PKI_log_err("Can not sign responses - no valid keyPair was configured");
		return PKI_ERR;
	}

	// If no cert is provided but we have the token, let's get it from
	// the token. If no cert is in the token, let's abort signing
	if (signCert == NULL && (signCert = PKI_TOKEN_get_cert(tk)) == NULL)
		PKI_log(PKI_LOG_WARNING, "No signing certificate for OCSP response signing");

	if (caCert == NULL && ((caCert = PKI_TOKEN_get_cacert(tk)) == NULL))
		PKI_log(PKI_LOG_WARNING, "No CA certificate for OCSP response signing");

	// It seems that CISCO devices require the SHA1 algorithm to be
 	// used. Make sure you use that in the configuration for the digest
	if (conf->sigDigest)
		sign_dgst = conf->sigDigest;
	else
		sign_dgst = PKI_ALGOR_get_digest(tk->algor);

	// Some debugging information
	if (conf->debug)
	{
		if (sign_dgst)
			PKI_log_debug("Digest Algorithm For Signature: %s", PKI_DIGEST_ALG_get_parsed(sign_dgst));
		else
			PKI_log_err("Can not parse the Digest Algorithm for Signatures!");

		if (PKI_X509_CERT_check_pubkey(signCert, tk->keypair))
			PKI_log_err("The PublicKey in the certificate and the private keypair do not match!");

		if (signCert)
		{
			char *subject = PKI_X509_CERT_get_parsed(signCert, PKI_X509_DATA_SUBJECT);
			char *issuer = PKI_X509_CERT_get_parsed(signCert, PKI_X509_DATA_ISSUER);
			char *serial = PKI_X509_CERT_get_parsed(signCert, PKI_X509_DATA_SERIAL);

			PKI_log_debug("Signing Certificate:");
			PKI_log_debug("- Serial .....: %s", serial  ? serial  : "n/a");
			PKI_log_debug("- Subject ....: %s", subject ? subject : "n/a");
			PKI_log_debug("- Issuer .....: %s", issuer  ? issuer  : "n/a");

			if (subject) PKI_Free(subject);
			if (serial ) PKI_Free(serial );
			if (issuer ) PKI_Free(issuer );
		}
	}

	// Now generate the signature for the response
	sig_rv = PKI_X509_OCSP_RESP_sign(resp, tk->keypair, signCert, caCert, tk->otherCerts, sign_dgst);

	// Checks the return code and report the error (if any)
	if (sig_rv != PKI_OK)
	{
		PKI_log_err("Failed while signing [%s]", PKI_ERROR_crypto_get_errdesc());
		return PKI_ERR;
	}

	if (conf->debug)
		PKI_log_debug ("Response signed successfully");

	// Test Mode: Issues WRONG signatures by flipping the first
 	// bit in the signature. Use it ONLY for testing OCSP clients
 	// verify capabilities!
	if (conf->testmode)
	{
		PKI_STRING *signature = NULL;

		PKI_log(PKI_LOG_ALWAYS,
			"WARNING: TestMode (Wrong Signatures): Flipping first bit in Signature");

		// Get The Signature
		signature = PKI_X509_OCSP_RESP_get_data(resp, PKI_X509_DATA_SIGNATURE);
		if (signature)
		{
			PKI_X509_OCSP_RESP_VALUE *resp_val = NULL;
  			PKI_OCSP_RESP *r = NULL;
			OCSP_BASICRESP *bsrp = NULL;

			int i = 0;

			// Flip The First n-Bit of the Signature (n=1)
			for (i=0; i < 1; i++ )
			{
				if(ASN1_BIT_STRING_get_bit(signature, i))
    				ASN1_BIT_STRING_set_bit(signature, i, 0);
    			else
    				ASN1_BIT_STRING_set_bit(signature, i, 1);
			}

			r = resp->value;

			// Now we need to re-encode the basicresp
		  	resp_val = r->resp;
			bsrp = r->bs;

			if (resp_val->responseBytes)
				OCSP_RESPBYTES_free(resp_val->responseBytes);

			if (!(resp_val->responseBytes = OCSP_RESPBYTES_new()))
			{
				PKI_log_err("Memory Error, aborting signature mangling!");
 				return PKI_ERR;
			}

			// Sets the OCSP basic bit
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

	// Success
	return PKI_OK;
}

PKI_X509_OCSP_RESP *make_error_response(PKI_X509_OCSP_RESP_STATUS status)
{
	PKI_X509_OCSP_RESP *resp = NULL;

	if ((resp = PKI_X509_OCSP_RESP_new()) != NULL)
	{
		// Sets the MALFORMED status for the response
		PKI_X509_OCSP_RESP_set_status(resp, status);
	}

	return resp;
}

PKI_X509_OCSP_RESP *make_ocsp_response(PKI_X509_OCSP_REQ *req, OCSPD_CONFIG *conf )
{
	OCSP_CERTID *cid = NULL;

	PKI_X509_OCSP_RESP *resp = NULL;
	PKI_X509_OCSP_REQ_VALUE *req_val = NULL;

	PKI_TOKEN *tk = NULL;

	PKI_X509_CERT *signCert = NULL;
	PKI_X509_CERT *caCert = NULL;

	int i, id_count;
	int signResponse;

	int use_server_cert = 0;
	int use_server_cacert = 0;

	PKI_TIME *thisupd = NULL;
	PKI_TIME *nextupd = NULL;

	char *parsedSerial = NULL;

	// Set the signature bit to 0 (enable only for non-error responses)
	signResponse = 0;

	// Checks if we have a valid request, if not, we just send back
	// a response for a malformed request
	if (req == NULL || (req_val = PKI_X509_get_value(req)) == NULL)
	{
		// Gets the response for a MALFORMED request
		resp = make_error_response(PKI_X509_OCSP_RESP_STATUS_MALFORMEDREQUEST);

		// Let's go to the end
		goto end;
	}

	// Let's get the number of requests in the OCSP req
	if ((id_count = OCSP_request_onereq_count(req_val)) <= 0)
	{
		unsigned long error_num = HSM_get_errno(conf->token ? conf->token->hsm : NULL);

		PKI_log_err("Request has no internal OneReq (Crypto Error is %ld::%s)",
			errno, HSM_get_errdesc(error_num, conf->token ? conf->token->hsm : NULL));

		// Let's generate the appropriate error response
		resp = make_error_response(PKI_X509_OCSP_RESP_STATUS_MALFORMEDREQUEST);
		goto end;
	}

	// Now allocates the memory for the response
	if((resp = PKI_X509_OCSP_RESP_new()) == NULL )
	{
		PKI_log_err("Memory Error: can not allocate a new OCSP response");

		// Let's generate the appropriate error response
		resp = make_error_response(PKI_X509_OCSP_RESP_STATUS_INTERNALERROR);
		goto end;
	}

	/* Let's set the default token for signing */
	tk = conf->token;

	// Next update (if specified in the configuration)
	if (conf->set_nextUpdate)
		nextupd = PKI_TIME_new((conf->nmin * 60 ) + (conf->ndays * 86400));

	// Gets the reference to the "now" time
	thisupd = PKI_TIME_new(0);

	/* Examine each certificate id in the request */
	for (i = 0; i < id_count; i++)
	{
		PKI_INTEGER   *serial = NULL;
		CA_LIST_ENTRY *ca     = NULL;
		X509_REVOKED  *entry  = NULL;

		/* Get basic request info */
		if (((cid = PKI_X509_OCSP_REQ_get_cid(req, i)) == NULL) ||
				((serial = PKI_X509_OCSP_REQ_get_serial(req, i)) == NULL))
		{
			// NO cid found, let's generate a response for a malformed request
			if (resp) PKI_X509_OCSP_RESP_free(resp);
			resp = make_error_response(PKI_X509_OCSP_RESP_STATUS_MALFORMEDREQUEST);

			goto end;
		}

		// Some debugging information
		if (conf->verbose || conf->debug)
		{
			if (parsedSerial) PKI_Free(parsedSerial);
			parsedSerial = PKI_INTEGER_get_parsed(serial);

			if (conf->debug)
				PKI_log( PKI_LOG_INFO, "Request for certificate serial %s", parsedSerial);
		}

		/* Is this request about our CA? */
		if ((ca = OCSPD_CA_ENTRY_find(conf, cid)) == NULL)
		{
			if (conf->verbose)
				PKI_log(PKI_LOG_INFO, "%s [serial %s]",
					statusInfo[OCSPD_INFO_NON_RECOGNIZED_CA], parsedSerial);

			// Adds the single response to the response container
			PKI_X509_OCSP_RESP_add(resp, cid, PKI_OCSP_CERTSTATUS_UNKNOWN,
					NULL, NULL, nextupd, 0, NULL);

			// TODO: Maybe we could add the serviceLocator extension
 			//       we can use the PRQP to find out the server address

			continue;
		}

		/* If the CA has a specific token, let's use that */
		if (ca->token != NULL)
		{
			tk = ca->token;

			if (conf->debug)
				PKI_log_debug( "Using the specific token for the found CA (%s)",
					ca->token_name);
		}
		else
		{
			// If no specific token but a different server_cert
 			// is to be used, let's report it in debug mode
			if (ca->server_cert)
			{
				signCert = ca->server_cert;

				if (ca->ca_cert)
					caCert = ca->ca_cert;
				else
					caCert = NULL;
			}
			else signCert = NULL;
		}

		// Here we check for the case where the CRL status is not ok, so
		// we ask the client to try later, hopefully when we have a valid
		// CRL to provide the response with
		if (ca->crl_status != CRL_OK)
		{
			// Check the status of the CRL, if it is not valid, we return a TRY_LATER
			// or INTERNAL_ERROR responses
			switch(ca->crl_status)
			{
				case CRL_ERROR_NEXT_UPDATE:
					// This situation does not provide any security risk, we can proceed
					// as normal with the response building
					break;

				case CRL_ERROR_LAST_UPDATE:
					// Here we do not have when the information was valid from, this is
					// considered to be an internal error - let's report it to the client
					if (resp) PKI_X509_OCSP_RESP_free(resp);
					resp = make_error_response(PKI_X509_OCSP_RESP_STATUS_INTERNALERROR);
					if (conf->debug)
						PKI_log_debug("sending INTERNAL ERROR (%s)", 
							get_crl_status_info(ca->crl_status));
					goto end;
					break;

				case CRL_NOT_YET_VALID:
				case CRL_EXPIRED:
					// Since the CRL is not valid, we do not have a reliable source of
					// information for the revocation status. The client should retry
					// later when the information will be available
					if (resp) PKI_X509_OCSP_RESP_free(resp);
					resp = make_error_response(PKI_X509_OCSP_RESP_STATUS_TRYLATER);
					if (conf->debug)
						PKI_log_debug("sending TRYLATER (%s)", 
							get_crl_status_info(ca->crl_status));
					goto end;
					break;

				default:
					// In this case we have an un-identified error, let's log it and
					// report an internal error to the client
					PKI_X509_OCSP_RESP_add(resp, cid, PKI_OCSP_CERTSTATUS_UNKNOWN,
						NULL, NULL, nextupd, CRL_REASON_UNSPECIFIED, NULL);
					if (conf->debug)
						PKI_log_debug("setting CERTSTATUS UNKNOWN for serial %s (%s)", 
							parsedSerial, get_crl_status_info(ca->crl_status));
					continue;
			}
		}

		// This case returns the same response for any request in case the
		// CA was compromised - all certificates are to be considered now
		// not valid
		if (ca->compromised > 0)
		{
			PKI_X509_OCSP_RESP_add ( resp, cid, PKI_OCSP_CERTSTATUS_REVOKED,
				NULL, NULL, nextupd, CRL_REASON_CA_COMPROMISE, NULL);

			continue;
		}

		// Get the entry from the CRL data, if NULL then the
		// certificate is not revoked
		if ((entry = OCSPD_REVOKED_find( ca, serial )) != NULL)
		{
			long reason = -1;
			void *ext = NULL;

			// If extensions are found, process them
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

			if ((PKI_X509_OCSP_RESP_add(resp, cid, PKI_OCSP_CERTSTATUS_REVOKED,
					entry->revocationDate, thisupd, nextupd, reason, ext )) == PKI_ERR)
			{
				PKI_log_err ("Can not add a simple resp into the OCSP response");

				// Let's free the current response (since there is an internal error,
				// we do not want to generate partially valid responses)
				PKI_X509_OCSP_RESP_free(resp);

				// Generates the error response
				resp = make_error_response(PKI_X509_OCSP_RESP_STATUS_INTERNALERROR);

				// Skip the processing and return this new response
				goto end;
			}

			if( reason == CRL_REASON_CERTIFICATE_HOLD ) {
				// TODO: We might want to add the CrlID extension to the response
			}

			if (conf->verbose)
				PKI_log(PKI_LOG_INFO, "%s [serial %s]",
					statusInfo[OCSPD_INFO_REVOKED], parsedSerial);
		}
		else if (ca == NULL )
		{
			if (conf->verbose)
				PKI_log(PKI_LOG_INFO, "%s [serial %s]",
						statusInfo[OCSPD_INFO_NON_RECOGNIZED_CA], parsedSerial);

			PKI_X509_OCSP_RESP_add ( resp, cid, PKI_OCSP_CERTSTATUS_UNKNOWN, 
				NULL, thisupd, nextupd, CRL_REASON_UNSPECIFIED, NULL );
		}
		else
		{
			if (conf->verbose)
				PKI_log(PKI_LOG_INFO, "%s [serial %s]",
					statusInfo[OCSPD_INFO_VALID_CERT], parsedSerial);

			PKI_X509_OCSP_RESP_add ( resp, cid, PKI_OCSP_CERTSTATUS_GOOD,
				NULL, thisupd, nextupd, 0, NULL );
		}
	}

	// Let's copy the NONCE from the request
	if (PKI_X509_OCSP_REQ_has_nonce(req))
	{
		if (PKI_X509_OCSP_RESP_copy_nonce(resp, req) == PKI_ERR)
		{
			PKI_log_err ("Can not copy NONCE from request to response");

			// Free the current response
			PKI_X509_OCSP_RESP_free(resp);

			// Generates the error response
			resp = make_error_response(PKI_X509_OCSP_RESP_STATUS_INTERNALERROR);

			goto end;
		}
	}

	// Now, if we reach here, no error responses were generated, so we can
	// safely set the signature bit to true (sign the response)
	signResponse = 1;

end:

	// Now we need to sign the response
	if (resp != NULL && signResponse == 1)
	{
		if (sign_ocsp_response(resp, conf, signCert, caCert, tk) != PKI_OK)
		{
			// Free the current response, and generate the appropriate error
			PKI_X509_OCSP_RESP_free(resp);
			resp = make_error_response(PKI_X509_OCSP_RESP_STATUS_INTERNALERROR);
		}
	}

	// Free the memory for the parsed serial (debug or verbose modes only)
	if (parsedSerial) PKI_Free(parsedSerial);

	// Free the time information
	if (thisupd) PKI_TIME_free(thisupd);
	if (nextupd) PKI_TIME_free(nextupd);

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

	int buf_size = 0;

	char http_resp[] =
		"HTTP/1.0 200 OK\r\n"
		"Content-Type: application/ocsp-response\r\n"
 		"Content-Transfer-Encoding: Binary\r\n";

	if ( connfd <= 0 )
	{
		PKI_log_err("Socket fd is 0!");
		return PKI_ERR;
	}

	if ((mem = PKI_X509_OCSP_RESP_put_mem(r, PKI_DATA_FORMAT_ASN1,
					NULL, NULL, NULL )) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return PKI_ERR;
	}

	// Gets the time for the expire
	if (conf->set_nextUpdate)
		expire = PKI_TIME_new ((conf->nmin*60) + (conf->ndays * 86400));
	else
		expire = PKI_TIME_new( 0 );

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
		buf_size = snprintf(buf, sizeof(buf), "%sContent-Length: %d\r\nDate: %s\r\nExpires: %s\r\n\r\n",
			http_resp, mem->size, tmp_parsed_date, tmp_parsed_expire);
#else
		buf_size = snprintf(buf, sizeof(buf), "%sContent-Length: %ld\r\nDate: %s\r\nExpires: %s\r\n\r\n",
			http_resp, mem->size, tmp_parsed_date, tmp_parsed_expire);
#endif
	}
	else if (tmp_parsed_date)
	{
#if ( LIBPKI_OS_BITS == LIBPKI_OS32)
		buf_size = snprintf(buf, sizeof(buf), "%sContent-Length: %d\r\nDate: %s\r\n\r\n",
			http_resp, mem->size, tmp_parsed_date);
#else
		buf_size = snprintf(buf, sizeof(buf), "%sContent-Length: %ld\r\nDate: %s\r\n\r\n",
			http_resp, mem->size, tmp_parsed_date);
#endif
	}
	else if (tmp_parsed_expire)
	{
#if ( LIBPKI_OS_BITS == LIBPKI_OS32)
		buf_size = snprintf(buf, sizeof(buf), "%sContent-Length: %d\r\nExpires: %s\r\n\r\n",
			http_resp, mem->size, tmp_parsed_expire);
#else
		buf_size = snprintf(buf, sizeof(buf), "%sContent-Length: %ld\r\nExpires: %s\r\n\r\n",
			http_resp, mem->size, tmp_parsed_expire);
#endif
	}
	else
	{
#if ( LIBPKI_OS_BITS == LIBPKI_OS32 )
		buf_size = snprintf(buf, sizeof(buf), "%sContent-Length: %d\r\n\r\n", http_resp, mem->size);
#else
		buf_size = snprintf(buf, sizeof(buf), "%sContent-Length: %ld\r\n\r\n", http_resp, mem->size);
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
		PKI_log_debug("OCSP Response Bytes = %d, HTTP Header Bytes = %d", mem->size, buf_size);

		// Enable this section if you need to debug responses deeper
		/*
		URL_put_data ("file:///ocsp-resp.der", mem, NULL, NULL, 0, 0, NULL);
		PKI_log_debug("OCSP Response Written to ocsp-resp.der (%d)", mem->size);

		PKI_MEM *t = PKI_MEM_new_data(strlen(buf), (unsigned char *)buf);
		if (t)
		{
			PKI_MEM_add(t, (char *) mem->data, mem->size);
			URL_put_data ("file:///http-ocsp-resp.txt", t, NULL, NULL, 0, 0, NULL);
			PKI_log_debug("HTTP Response Written to http-ocsp-resp.txt (%d)", t->size);
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
			}
			continue;
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
			}
			continue;

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

