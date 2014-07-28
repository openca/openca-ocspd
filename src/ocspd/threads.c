
#include "general.h"

extern OCSPD_CONFIG *ocspd_conf;

/* Thread Function Prototype */
void * thread_main ( void *arg );


int thread_make ( int i )
{
	// Thread *th_ptr = NULL;
	int ret;

	// th_ptr = &(ocspd_conf->threads_list[i]);
	if( (ret=pthread_create( &ocspd_conf->threads_list[i].thread_tid, 
			NULL, thread_main, (void *) &i )) ) {

		PKI_log_err("ERROR::OPENCA_SRV_ERR_THREAD_CREATE");
		return(ret);
	}

	return(OCSPD_SRV_OK);
}

void * thread_main ( void *arg ) {
	int connfd = -1;
	int *arg_int = NULL;

	PKI_X509_OCSP_REQ  *req = NULL;
	PKI_X509_OCSP_RESP *resp = NULL;

	int thread_nr = -1;

	struct sigaction sa;

	arg_int = (int *) arg;
	thread_nr = *arg_int;

	if ( ocspd_conf->verbose ) {
		PKI_log(PKI_LOG_INFO, "OPENCA_SRV_INFO_TREAD::new thread "
			"created [%d]", thread_nr);
	}

	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;

	if (sigaction(SIGPIPE, &sa, NULL) == -1) {
		perror("Error during handling the death processes");
		exit(1);
	}

	if (sigaction(SIGPIPE, &sa, NULL) == -1) {
		PKI_log( PKI_LOG_ERR, "Error during handling the death processes");
		exit(1);
	}

	for ( ; ; ) {

		/* Before calling the cond_wait we need to own the mutex */
		PKI_MUTEX_acquire ( &ocspd_conf->mutexes[CLIFD_MUTEX] );

		while( ocspd_conf->connfd <= 2 ) {
			PKI_COND_wait ( &ocspd_conf->condVars[CLIFD_COND],
                &ocspd_conf->mutexes[CLIFD_MUTEX] );
		}

		connfd = ocspd_conf->connfd;

		PKI_log_debug("Thread [%d] - got fd %d", thread_nr, connfd);

		ocspd_conf->connfd = -1;
		PKI_MUTEX_release ( &ocspd_conf->mutexes[CLIFD_MUTEX] );
		PKI_MUTEX_acquire ( &ocspd_conf->mutexes[SRVFD_MUTEX] );
		PKI_COND_signal ( &ocspd_conf->condVars[SRVFD_COND] );
		PKI_MUTEX_release ( &ocspd_conf->mutexes[SRVFD_MUTEX] );

		if((req = ocspd_req_get_socket(connfd, ocspd_conf)) == NULL ) {
			PKI_log_err("Can not parse REQ");
			goto err;
		}

		PKI_log_debug("[Thread::%d] Got resp from socket", thread_nr );

		if((resp = make_ocsp_response(req, ocspd_conf)) == NULL){
                        PKI_log_err ("Can not generate response!" );
                        goto err;
		}

		PKI_log_debug("[Thread::%d] Built resp from socket", thread_nr);

		goto end;

err:
		PKI_log_debug("[Thread::%d] - An error occurred!", thread_nr);

		if ( !resp ) {
			if(( resp = PKI_X509_OCSP_RESP_new ()) != NULL ) {
				PKI_X509_OCSP_RESP_set_status ( resp, 
					PKI_X509_OCSP_RESP_STATUS_MALFORMEDREQUEST );
			}
		}

end:

		if ( resp != NULL ) {
			ocspd_resp_send_socket( connfd, resp, ocspd_conf );
			PKI_X509_OCSP_RESP_free (resp);
			resp = NULL;
		}

		if( req ) {
			PKI_X509_OCSP_REQ_free (req);
		}

		PKI_NET_close ( connfd );
	}
}
