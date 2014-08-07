/* file: src/ocspd/ocsp_request.c
 *
 * OpenCA OCSPD - Massimiliano Pala <madwolf@openca.org>
 * Copyright (c) 2001-2009 by Massimiliano Pala and OpenCA Labs
 * All Rights Reserved
 */

#include "general.h"

#define  OCSPD_DEF_MAX_SIZE 	65535
#define  OCSPD_DEF_MAX_READ	1024

#define  METHOD_UNKNOWN		0
#define  METHOD_GET		1
#define  METHOD_POST		2

#define  MAX_USEC		1000
#define  WAIT_USEC		50

extern OCSPD_CONFIG *ocspd_conf;

PKI_X509_OCSP_REQ * ocspd_req_get_socket ( int connfd, OCSPD_CONFIG *ocspd_conf) 
{
	PKI_X509_OCSP_REQ 	*req = NULL;
	PKI_X509_OCSP_REQ_VALUE *req_val = NULL;

	PKI_IO			*mem = NULL;
	PKI_MEM			*pathmem = NULL;

	PKI_SOCKET		sock;

	size_t maxsize  = 0;
	maxsize = (size_t) ocspd_conf->max_req_size;

	PKI_HTTP *http_msg = NULL;

	if ( connfd <= 0 ) return NULL;

	// Initialize the sock structure
	sock.ssl = NULL;
	PKI_SOCKET_set_fd ( &sock, connfd );

	http_msg = PKI_HTTP_get_message(&sock, (int) ocspd_conf->max_timeout_secs, maxsize);
	if (http_msg == NULL)
	{
		PKI_log_err ("Network Error while reading Request!");
		return NULL;
	}

	/* If method is METHOD_GET we shall de-urlify the buffer and get the
	   right begin (keep in mind there might be a path set in the config */

	if( http_msg->method == PKI_HTTP_METHOD_GET )
	{
		char *req_pnt = NULL;

		if (http_msg->path == NULL)
		{
			PKI_log_err("Malformed GET request");
			goto err;
		}
		
		req_pnt = http_msg->path;
		while(strchr(req_pnt, '/') != NULL)
		{
			req_pnt = strchr(req_pnt, '/') + 1;
		}

		pathmem = PKI_MEM_new_data(strlen(req_pnt), (unsigned char *) req_pnt);
		if (pathmem == NULL)
		{
			PKI_log_err("Memory Allocation Error!");
			goto err;
		}

		if (PKI_MEM_decode(pathmem, PKI_DATA_FORMAT_URL, 0) != PKI_OK)
		{
			PKI_log_err("Memory Allocation Error!");
			PKI_MEM_free(pathmem);
			goto err;
		}

		if (PKI_MEM_decode(pathmem, PKI_DATA_FORMAT_B64, 0) != PKI_OK)
		{
			PKI_log_err ("Error decoding B64 Mem");
			PKI_MEM_free (pathmem);
			goto err;
		}

		// Generates a new mem bio from the pathmem
		if((mem = BIO_new_mem_buf(pathmem->data, (int) pathmem->size)) == NULL)
		{
			PKI_log_err("Memory Allocation Error");
			PKI_MEM_free(pathmem);
			goto err;
		}

		// Transfer data ownership and release the pathmem
		pathmem->data = NULL;
		pathmem->size = 0;

		// Tries to decode the binary (der) encoded request
		if ((req_val = d2i_OCSP_REQ_bio(mem, NULL)) == NULL)
		{
			PKI_log_err("Can not parse REQ");
			BIO_free(mem);
			PKI_MEM_free(pathmem);
			goto err;
		}

		// Let's free the mem
		BIO_free(mem);

		PKI_MEM_free(pathmem);
	} 
	else if (http_msg->method == PKI_HTTP_METHOD_POST)
	{
		mem = BIO_new_mem_buf(http_msg->body->data, (int) http_msg->body->size);
		if (mem == NULL)
		{
			PKI_log_err( "Memory Allocation Error");
			goto err;
		}
		else
		{
			if ((req_val = d2i_OCSP_REQ_bio(mem, NULL)) == NULL)
			{
				PKI_log_err("Can not parse REQ");
			}
			BIO_free (mem);
		}
	} 
	else
	{
		PKI_log_err ( "HTTP Method not supported");
		goto err;
	}

	if ( !req_val ) goto err;

	req = PKI_X509_new_value(PKI_DATATYPE_X509_OCSP_REQ, req_val, NULL);
	if (req == NULL)
	{
		PKI_log_err ("Can not generate a new X509_OCSP_REQ");
		goto err;
	}

	if ( http_msg ) PKI_HTTP_free ( http_msg );

	return (req);

err:
	if (req) PKI_X509_OCSP_REQ_free(req);

	if (http_msg) PKI_HTTP_free(http_msg);

	return NULL;
}

