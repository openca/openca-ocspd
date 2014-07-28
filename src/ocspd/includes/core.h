#include <sys/socket.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <string.h>

#include <pthread.h>

#ifndef __OPENCA_CORE_H
#define __OPENCA_CORE_H

#include "general.h"
#include "request.h"

int start_threaded_server ( OCSPD_CONFIG * ocspd_conf );

int set_alrm_handler( void );
void close_server ( void );
void handle_sigterm ( int i );
void handle_sighup ( int i );

int set_privileges( OCSPD_CONFIG *conf );
int set_chroot( OCSPD_CONFIG *conf );

#endif
