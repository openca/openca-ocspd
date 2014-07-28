/* ===========================================================
 * OpenCA OCSPD Server - src/core.c
 * (c) 2001-2008 by Massimiliano Pala and OpenCA Labs
 * All Rights Reserved
 * ===========================================================
 * OpenCA Licensed Software
 * ===========================================================
 */

/*
#include <strings.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
*/

#include "general.h"
#include "threads.h"
#include "crl.h"

extern void auto_crl_check( int );
extern OCSPD_CONFIG *ocspd_conf;

/* Local Functions */
void handle_sigabrt ( int i );

/* Function Bodies */

int start_threaded_server ( OCSPD_CONFIG * ocspd_conf )
{
	int i = 0;
	int rv = 0;

	struct sockaddr_in cliaddr;
	socklen_t cliaddrlen;

	struct sigaction sa;

	/* Just print a nice log message when exits */
	atexit(close_server);

	if( ocspd_conf->token ) {

		if( PKI_TOKEN_init ( ocspd_conf->token, 
				ocspd_conf->token_config_dir, ocspd_conf->token_name)
								== PKI_ERR ) {
			PKI_log_err( "Can not load default token (%s/%s)",
				ocspd_conf->cnf_filename, ocspd_conf->token_name );
			exit(1);
		}

		PKI_TOKEN_cred_set_cb ( ocspd_conf->token, NULL, NULL);

		if ( PKI_TOKEN_login ( ocspd_conf->token ) != PKI_OK ) {
			PKI_log_debug("Can not login into token!");
			exit(1);
		}

		rv = PKI_TOKEN_check(ocspd_conf->token);
		if (rv & (PKI_TOKEN_STATUS_KEYPAIR_ERR |
							PKI_TOKEN_STATUS_CERT_ERR |
							PKI_TOKEN_STATUS_CACERT_ERR))
		{
			if (rv & PKI_TOKEN_STATUS_KEYPAIR_ERR) PKI_ERROR(PKI_ERR_TOKEN_KEYPAIR_LOAD, NULL);
			if (rv & PKI_TOKEN_STATUS_CERT_ERR) PKI_ERROR(PKI_ERR_TOKEN_CERT_LOAD, NULL);
			if (rv & PKI_TOKEN_STATUS_CACERT_ERR) PKI_ERROR(PKI_ERR_TOKEN_CACERT_LOAD, NULL);

			PKI_log_err("Token Configuration Fatal Error (%d)", rv);
			exit(rv);
		}
	}

	/* Init all the tokens configured for the single CA entries */
	for( i=0; i < PKI_STACK_elements(ocspd_conf->ca_list);i++){
		CA_LIST_ENTRY *ca = NULL;

		if((ca = PKI_STACK_get_num( ocspd_conf->ca_list, i )) == NULL){
			continue;
		}

		if ( ca->token_name == NULL ) {
			continue;
		}

		if((ca->token = PKI_TOKEN_new_null()) == NULL ) {
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
			exit (1);
		}

		PKI_TOKEN_cred_set_cb ( ocspd_conf->token, NULL, NULL);

		rv = PKI_TOKEN_init(ca->token, ca->token_config_dir, ca->token_name);
		if (rv != PKI_OK)
		{
			PKI_ERROR(rv, NULL);
			PKI_log_err ( "Can not load token %s for CA %s (%s)",
				ca->token_name, ca->ca_id, ca->token_config_dir );
			exit (rv);
		}

		rv = PKI_TOKEN_login(ca->token);
		if (rv != PKI_OK)
		{
			PKI_log_err("Can not login into token (%s)!", ca->ca_id);
			exit(rv);
		}

		rv = PKI_TOKEN_check(ca->token);
		if ( rv & (PKI_TOKEN_STATUS_KEYPAIR_ERR |
							 PKI_TOKEN_STATUS_CERT_ERR |
							 PKI_TOKEN_STATUS_CACERT_ERR))
		{
			if (rv & PKI_TOKEN_STATUS_KEYPAIR_ERR) PKI_ERROR(PKI_TOKEN_STATUS_KEYPAIR_ERR, NULL);
			if (rv & PKI_TOKEN_STATUS_CERT_ERR) PKI_ERROR(PKI_TOKEN_STATUS_CERT_ERR, NULL);
			if (rv & PKI_TOKEN_STATUS_CACERT_ERR) PKI_ERROR(PKI_TOKEN_STATUS_CACERT_ERR, NULL);

			PKI_log_err ( "Token Configuration Fatal Error (%d) for ca %s", rv, ca->ca_id);
			exit(rv);
		}
	}

	if((ocspd_conf->listenfd = PKI_NET_listen (ocspd_conf->bindUrl->addr,
					ocspd_conf->bindUrl->port, PKI_NET_SOCK_STREAM )) == PKI_ERR ) {
		PKI_log_err ("Can not bind to [%s],[%d]",
			ocspd_conf->bindUrl->addr, ocspd_conf->bindUrl->port);
		exit(101);
	}

	/* Now Chroot the application */
	if( (ocspd_conf->chroot_dir ) && (set_chroot( ocspd_conf ) < 1) ) {
		PKI_log_err ("Can not chroot, exiting!");
		exit(204);
	}

	/* Set privileges */
	if( set_privileges( ocspd_conf ) < 1 ) {
		if( ocspd_conf->chroot_dir != NULL ) {
			PKI_log(PKI_LOG_ALWAYS, "SECURITY:: Can not drop privileges! [203]");
			PKI_log(PKI_LOG_ALWAYS, "SECURITY:: Continuing because chrooted");
		} else {
			PKI_log(PKI_LOG_ALWAYS, "SECURITY:: Can not drop privileges! [203]");
			PKI_log(PKI_LOG_ALWAYS, "SECURITY:: Check User/Group in config file!");
			exit(203);
		}
	}

	if((ocspd_conf->threads_list = calloc ( (size_t) ocspd_conf->nthreads, 
					sizeof(Thread))) == NULL ) {
		PKI_log_err ("Memory allocation failed");
	};

	for( i = 0; i < ocspd_conf->nthreads; i++ ) {
		if(thread_make(i) != 0 ) {
			PKI_log_err ("Can not create thread (%d)\n", i );
			exit(80);
		}
	}

	/* Register the alarm handler */
	set_alrm_handler();

	/* Just print a nice log message when killed */
	signal(SIGTERM, handle_sigterm );
	signal(SIGABRT, handle_sigabrt );

	/* Setting the SIGHUP in order to reload the CRLs */
	// sa.sa_handler = auto_crl_check;
	sa.sa_handler = force_crl_reload;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;

	if (sigaction(SIGHUP, &sa, NULL) == -1) {
		PKI_log_err("Error during setting sig_handler");
		exit(1);
	}

	cliaddrlen = sizeof( cliaddr );
	for ( ; ; ) 
	{
		PKI_log_debug( "CORE::Waiting on connect" );

		PKI_MUTEX_acquire ( &ocspd_conf->mutexes[CLIFD_MUTEX] );

		if ((ocspd_conf->connfd = PKI_NET_accept(ocspd_conf->listenfd, 0)) == -1)
		{
			char err_str[512];
			PKI_log_err("Network Error [%d::%s]", errno,
				strerror_r(errno, err_str, sizeof(err_str)));
			PKI_MUTEX_release ( &ocspd_conf->mutexes[CLIFD_MUTEX] );
			continue;
		}

		if (ocspd_conf->verbose)
		{
			if (getpeername(ocspd_conf->connfd, (struct sockaddr*)&cliaddr, &cliaddrlen) == -1)
			{
				char err_str[512];
				PKI_log_err("Network Error [%d::%s] in getpeername", errno,
					strerror_r(errno, err_str, sizeof(err_str)));
			}

			PKI_log(PKI_LOG_INFO, "CORE::Connection from [%s]\n", 
	 			inet_ntoa(cliaddr.sin_addr) );
		}

		PKI_COND_broadcast ( &ocspd_conf->condVars[CLIFD_COND] );
		PKI_MUTEX_release ( &ocspd_conf->mutexes[CLIFD_MUTEX] );
		PKI_MUTEX_acquire ( &ocspd_conf->mutexes[SRVFD_MUTEX] );

		while( ocspd_conf->connfd > 2 ) {
			PKI_COND_wait ( &ocspd_conf->condVars[SRVFD_COND],
				&ocspd_conf->mutexes[SRVFD_MUTEX] );
		}
		PKI_MUTEX_release ( &ocspd_conf->mutexes[SRVFD_MUTEX] );
	}
	return(0);
}

int set_alrm_handler( void ) {

	/* Now on the parent process we setup the auto_checking
	   functions */
	struct sigaction sa;

	if( ocspd_conf->crl_auto_reload ||
			ocspd_conf->crl_check_validity ) {

		int auto_rel, val_check;

		/* Help variable, for readability reasons */
		auto_rel = ocspd_conf->crl_auto_reload;
		val_check = ocspd_conf->crl_check_validity;

		/* This returns the min of the two values if it
		   is not 0, otherwise return the other */
		ocspd_conf->alarm_decrement = 
			(( auto_rel > val_check ) ? 
				(val_check ? val_check : auto_rel) : 
					(auto_rel ? auto_rel : val_check ));

		sa.sa_handler = auto_crl_check;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = SA_RESTART;

		if (sigaction(SIGALRM, &sa, NULL) == -1) {
			PKI_log_err("Error handling the death processes");
			exit(1);
		}

	 	/* signal( SIGALRM, auto_crl_check ); */
	 	alarm ( (unsigned int) ocspd_conf->alarm_decrement );
	} else {
		signal( SIGALRM, SIG_IGN);
	}

	return 1;
}

void handle_sighup ( int i ) {

	PKI_log( PKI_LOG_WARNING, "SIGHUP::Reloading CRLs, Master!");
	ocspd_reload_crls( ocspd_conf );
	return;
}

void handle_sigterm ( int i ) {
	if( ocspd_conf->verbose ) {
		PKI_log (PKI_LOG_INFO,"SIGTERM::Received TERM signal");
	}
	exit(0);
	return;
}

void handle_sigabrt ( int i ) {

	PKI_log_err("SIGABRT::received - should not happen,");
	PKI_log_err("SIGABRT::please enable strict locking.");
	PKI_log_err("ERROR::SIGABRT::Fatal Error, aborting server!");

	return;
}

void close_server ( void ) {
	PKI_log (PKI_LOG_NOTICE, "Exiting, Glad to serve you, Master!");
	return;
}

int set_privileges( OCSPD_CONFIG *conf ) {

	struct passwd *pw = NULL;
	struct group *gr = NULL;

	if( (gr = getgrnam( conf->group ) ) == NULL ) {
		PKI_log_err("Cannot find group %s", conf->group);
		return 0;
	}
	
	if( (pw = getpwnam( conf->user ) ) == NULL ) {
		PKI_log_err ("Cannot find user %s", conf->user);
		return 0;
	}

	if (setgid (gr->gr_gid) == -1) {
		PKI_log_err ("Error setting group %d (%s)", 
			gr->gr_gid, conf->group);
		return 0;
	}

	if (setuid (pw->pw_uid) == -1) {
		PKI_log_err("Error setting user %d (%s)", 
						pw->pw_uid, conf->user );
		return 0;
	}

	return 1;
}

int set_chroot( OCSPD_CONFIG *conf ) {

	if( (!conf) || (!conf->chroot_dir))
		return(1);

	/* Now chroot the running process before starting the server */
	if( chdir ( conf->chroot_dir ) != 0 ) {
		/* Error in changing to working directory */
		PKI_log_err ("SECURITY::CHROOT::ERROR [%s]", strerror(errno));
		perror(NULL);
		return(0);
	}

	if( chroot( conf->chroot_dir ) != 0 ) {
		/* Error chrooting the process */
		PKI_log_err ("SECURITY::CHROOT::ERROR [%s]", strerror(errno));
		perror(NULL);
		return(0);
	}

	PKI_log(PKI_LOG_INFO,"SECURITY::CHROOT::Completed [%s]",
		conf->chroot_dir );

	/* Ok, chdir and chroot! */
	return(1);
}
