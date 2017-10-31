/*
 * OCSP responder
 * by Massimiliano Pala (madwolf@openca.org)
 * OpenCA Labs project 2001-2017
 *
 * Copyright (c) 2001-2017 The OpenCA Project.  All rights reserved.
 *
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

/* Functions prototypes*/

#ifndef OCSPD_CACHE_H
#define OCSPD_CACHE_H

typedef struct ocspd_cache_entry_st {
	// Serial Number of the Certificate
	ASN1_INTEGER		* serialNumber;
	// Cached Response
	PKI_OCSP_RESP		* response;
	// Time until the response is valid
	time_t			   expires;
	// Mutex to be acquired before updating the entry
	PKI_MUTEX		   mutext;
} OCSPD_CACHE_ENTRY;

typedef struct ocspd_cache_st {

	// Lock for the [data] access
	PKI_RWLOCK		   lock;

	// Condition Variable and Mutex (TBD)
	PKI_COND		   cond_var;
	PKI_MUTEX		   mutext;

	// Size of the [data] pointers array
	size_t			   size;

	// Pointers array
	OCSPD_CACHE_ENTRY	** idx;
} OCSPD_CACHE;

// Allocates a new caching buffer
OCSPD_CACHE * OCSPD_CACHE_new(size_t num_of_entries);

// Frees all the memory associated with the cache structure
void OCSPD_CACHE_free(OCSPD_CACHE * oc);

// Returns the number of the entry in the hash table
int OCSPD_CACHE_entry_idx(OCSPD_CACHE_ENTRY *e);

// Adds the entry to the cache (no copy)
int OCSPD_CACHE_add0_entry(OCSPD_CACHE * oc, OCSPD_CACHE_ENTRY *e);

// Returns the entry for the serial number
OCSPD_CACHE_ENTRY * OCSPD_CACHE_get0_entry(OCSPD_CACHE * oc, ASN1_INTEGER *serialNumber);

#endif
