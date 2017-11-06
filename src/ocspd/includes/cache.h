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

	// Lock for the [data] access
	PKI_RWLOCK		   lock;

	// Collision code lookup: next entry
	struct ocspd_cache_entry_st next;

	// Collision code lookup: prev entry
	struct ocspd_cache_entry_st prev;

} OCSPD_CACHE_ENTRY;

#define OCSPD_CACHE_TABLE_SIZE	65535

typedef struct ocspd_cache_st {

	// Lock for the [data] access
	PKI_RWLOCK		   lock;

	// Pointers array
	OCSPD_CACHE_ENTRY	*idx[OCSPD_CACHE_TABLE_SIZE];

} OCSPD_CACHE;


// Frees all memory associated with a cache entry
void OCSPD_CACHE_ENTRY_free(OCSPD_CACHE_ENTRY *e);

// Returns the number of the entry in the hash table
int OCSPD_CACHE_entry_idx(OCSPD_CACHE_ENTRY *e);

// Allocates a new caching buffer
OCSPD_CACHE * OCSPD_CACHE_new(size_t num_of_entries);

// Frees all the memory associated with the cache structure
void OCSPD_CACHE_free(OCSPD_CACHE * oc);

// Allocates a new caching entry
OCSPD_CACHE_ENTRY * OCSPD_CACHE_ENTRY_new(void);

// Adds the entry to the cache (no copy)
int OCSPD_CACHE_add0_entry(OCSPD_CACHE * oc, OCSPD_CACHE_ENTRY *e);

// Returns the entry for the serial number
OCSPD_CACHE_ENTRY * OCSPD_CACHE_get0_entry(OCSPD_CACHE * oc, ASN1_INTEGER *serialNumber);

#endif
