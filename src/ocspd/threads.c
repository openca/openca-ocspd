
#include "general.h"

extern OCSPD_CONFIG *ocspd_conf;

/* Thread Function Prototype */
void * thread_main ( void *arg );


int thread_make ( int i )
{
	PKI_THREAD *th_id = NULL;
	int * id = NULL;

	// Basic Memory Check
	if (!ocspd_conf || !ocspd_conf->threads_list) return -1;

	// Gets the right pointer where to store the new thread identifier
	th_id = &ocspd_conf->threads_list[i].thread_tid;
	if ((id = (int *) PKI_Malloc(sizeof(int))) == NULL)
	{
		PKI_log_err("Memory allocation error!");
		return -1;
	}

	// Assign the thread id
	*id = i;

	// Let's generate the new thread
	// if ((ret = PKI_THREAD_create(th_id, NULL, thread_main, (void *) &i)) != PKI_OK)
	if ((th_id = PKI_THREAD_new(thread_main, (void *) id)) == NULL)
	{
		PKI_log_err("ERROR::OPENCA_SRV_ERR_THREAD_CREATE");
		return(-1);
	}

	// Copy the value of the thread structure
	memcpy(&ocspd_conf->threads_list[i].thread_tid, th_id, sizeof(PKI_THREAD));

	// Frees the memory associated with the original structure
	PKI_Free(th_id);

	// Returns ok
	return OCSPD_SRV_OK;
}

void * thread_main ( void *arg )
{
	int connfd    = -1;
	int thread_nr = -1;
	int *arg_int  = NULL;

	PKI_X509_OCSP_REQ  *req = NULL;
	PKI_X509_OCSP_RESP *resp = NULL;

	if (arg)
	{
		arg_int = (int *) arg;
		thread_nr = *arg_int;

		PKI_Free(arg);
	}
	else
	{
		thread_nr = -1;
	}

	if ( ocspd_conf->verbose )
		PKI_log(PKI_LOG_INFO, "New Thread Started [%d]", thread_nr);

	// PThread specific SIGPIPE handling
	sigset_t sigpipe_mask;
	sigset_t saved_mask;

	// Let's initialize the sigpipe mask
	sigemptyset(&sigpipe_mask);

	// Let's add the SIGPIPE to the mask
	sigaddset(&sigpipe_mask, SIGPIPE);

	// Prevent the server to die in case of a write to a prematurely closed socket
	if (pthread_sigmask(SIG_BLOCK, &sigpipe_mask, &saved_mask) == -1)
	{
	  PKI_log_err("Can not block SIGPIPE signal!");
	  exit(1);
	}

	for ( ; ; )
	{
		/* Before calling the cond_wait we need to own the mutex */
		PKI_MUTEX_acquire ( &ocspd_conf->mutexes[CLIFD_MUTEX] );
		while(ocspd_conf->connfd <= 2)
		{
			PKI_COND_wait ( &ocspd_conf->condVars[CLIFD_COND],
				&ocspd_conf->mutexes[CLIFD_MUTEX] );
		}

		// Let's copy the socket descriptor
		connfd = ocspd_conf->connfd;

		// Reset the global value
		ocspd_conf->connfd = -1;

		// Let's now release the mutex to allow for the server to listen
		// for the next connection
		PKI_MUTEX_release ( &ocspd_conf->mutexes[CLIFD_MUTEX] );

		// Communicate to the main thread to listen for the next connection
		PKI_MUTEX_acquire ( &ocspd_conf->mutexes[SRVFD_MUTEX] );
		PKI_COND_signal ( &ocspd_conf->condVars[SRVFD_COND] );
		PKI_MUTEX_release ( &ocspd_conf->mutexes[SRVFD_MUTEX] );

		// Retrieves the request from the socket
		req = ocspd_req_get_socket(connfd, ocspd_conf);

		// Now let's build the response
		resp = make_ocsp_response(req, ocspd_conf);

		// If we do not have a response, we were not able to generate one
		// from the received request, let's send a generic error.
		if (resp == NULL)
		{
			// Error info
			PKI_log_err("Can not generate the OCSP response (internal error)");

			// Generate the error response
			resp = PKI_X509_OCSP_RESP_new();
			if (resp != NULL)
			{
				PKI_X509_OCSP_RESP_set_status(resp,
					PKI_X509_OCSP_RESP_STATUS_MALFORMEDREQUEST );
			}
		}

		// If we have a response, let's send it over the wire and free
		// the associated memory
		if (resp != NULL)
		{
			// Send the response over the wire
			ocspd_resp_send_socket( connfd, resp, ocspd_conf );

			// Frees the response memory
			PKI_X509_OCSP_RESP_free (resp);
		}

		// Free the memory associated with the request
		if (req != NULL) PKI_X509_OCSP_REQ_free (req);

		// Finally close the current socket
		PKI_NET_close(connfd);
	}
}
