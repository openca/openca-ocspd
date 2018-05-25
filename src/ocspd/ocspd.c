/* file: src/ocspd/ocspd.c
 * ==================================================================
 * OCSP responder - Massimiliano Pala (madwolf@openca.org)
 * Copyright (c) 2001-2014 The OpenCA Labs.
 * All rights reserved.
 * ==================================================================
 */

#include "general.h"

static char *ocspd_warning = 
"\n"
"OpenCA's OCSP Responder - v%s\n"
"(c) 2002-2014 by Massimiliano Pala and OpenCA Project\n"
"    OpenCA licensed software\n"
"\n";

static char *ocspd_usage[] = {
"OCSPD - OpenCA OCSP responder daemon\n",
"(c) 2002-2014 by Massimiliano Pala and OpenCA Project\n",
"\n",
"   USAGE: ocspd args\n",
"\n",
" -c file         - The configuration file\n",
" -d              - Daemon, detach from current console\n",
" -r dir          - Directory where to jail the running process (chroot)\n",
" -k pwd          - Password protecting the private key (if any)\n",
" -debug          - Debug mode (exit after the first request)\n",
" -testmode       - Use test mode (wrong signatures w/ 1st bit flipped\n",
" -stdout         - Route all logging messages to stdout\n",
" -v              - Talk alot while doing things\n",
NULL
};

/* Staic variables */
char *prgname = "ocspd";
char *version = VERSION;

OCSPD_CONFIG *ocspd_conf = NULL;

/* Local functions prototypes */
int  writePid(int pid, char *pidfile);
void my_exit(int cod, char *txt);
void mask_signals();

/* Main */
int main ( int argc, char *argv[] ) {

	int log_level = PKI_LOG_NOTICE;
	int log_type  = PKI_LOG_TYPE_SYSLOG;

	int verbose   = 0;
	int debug     = 0;
	int testmode  = 0;

	int daemon = 0;
	int badops = 0;
	int ret = 0;

	char *configfile = NULL;
	char **pp = NULL;

	int i = 0;
	pid_t pid = 0;
	pid_t ppid = 0;

	/* Let's init LibPKI */
	PKI_init_all();

	argv++;
	argc--;

	while (argc >= 1) 
	{
		if (strcmp(*argv,"-c") == 0) 
		{
			if (--argc < 1) goto bad;
			configfile= *(++argv);
		} else if (strcmp(*argv,"-v") == 0) {
			log_level=PKI_LOG_INFO;
			verbose = 1;
		} else if (strcmp(*argv,"-debug") == 0) {
			debug=1;
		} else if (strcmp(*argv,"-testmode") == 0) {
			testmode=1;
		} else if (strcmp(*argv,"-d") == 0) {
			daemon=1;
		} else if (strcmp(*argv,"-stdout") == 0) {
			log_type=PKI_LOG_TYPE_STDOUT;
		} else {
			badops = 1;
		};

		argc--;
		argv++;
	}

bad:
	if (badops) 
	{
		for (pp = ocspd_usage; pp && *pp; pp++)
		{
			fprintf(stderr, "%s", *pp);
		}
		goto err;
	}

	if( daemon == 0 ) {
		fprintf(stderr, ocspd_warning, VERSION);
	}

	if(( PKI_log_init (log_type, log_level, NULL,
			debug, NULL )) == PKI_ERR ) {
		fprintf(stderr, "OCSPD, can not initiating logs! Aborting!\n\n");
		exit(1);
	}

	PKI_log(PKI_LOG_ALWAYS, "OpenCA OCSPD v%s - starting.", VERSION );

	if(( ocspd_conf = OCSPD_load_config( configfile )) == NULL ) {
		my_exit(1, "ERROR::can not load config file!\n");
	}

	if( debug ) ocspd_conf->debug = 1;
	if( verbose ) ocspd_conf->verbose = 1;
	if( testmode ) 
	{
		PKI_log(PKI_LOG_ALWAYS, "WARNING: Test Mode Used, All Signatures "
			"will be INVALID (first bit flipped)");
		ocspd_conf->testmode = 1;
	};


	/*****************************************************************/
	/* Main spawn and signal routines */

	if (verbose)
		PKI_log(PKI_LOG_INFO,"Configuration loaded and parsed");

	if( daemon ) {
		pid = fork();
		if( pid == 0 ) {
			/* Main process, we have to save the pid to the
			 * pidfile and then exit */
			writePid( getpid(), ocspd_conf->pidfile );
		} else if ( pid > 0 ) {
			/* Nop */
			goto end;
		} else {
			PKI_log_err("Error While spawning child %d", i );
			goto err;
		}
	} else {
		ppid = getpid();
		writePid( ppid, ocspd_conf->pidfile );
	}

	// Mask un-wanted signals
	mask_signals();

	// Let's now start the threaded server
	start_threaded_server( ocspd_conf );

	goto end;


err:
	ret = -1;
	my_exit( -1, "ERROR:General error, please check the logs");

end:

	return ret;
}

int writePid ( int pid, char *pidfile ) {
	FILE *fd;

	if( !pidfile ) {
		PKI_log_err ("No Pidfile specified, using %s",
					OCSPD_DEF_PIDFILE );
		pidfile = OCSPD_DEF_PIDFILE;
	}

	if( (fd = fopen( pidfile, "w" )) <= 0 ) {
		PKI_log_err ("Cannot open pidfile (%s - %s)", 
			pidfile, strerror(errno) );
		return(0);
	}

	fprintf( fd, "%d", (int) getpid());
	fclose( fd );

	return(1);
}

void mask_signals()
{
	struct sigaction sa;

	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;

	if (sigaction(SIGPIPE, &sa, 0) == -1)
	{
		PKI_log(PKI_LOG_ERR, "Can not mask SIGPIPE, aborting!\n\n");
		exit(1);
	}
}

void my_exit(int cod, char *txt) {
	PKI_log(PKI_LOG_ERR, "%s - %s (exit with %d)\n\n", prgname, txt, cod );
	exit(cod);
}
