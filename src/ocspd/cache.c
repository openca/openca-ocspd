/* src/ocspd/cache.c */

#include "general.h"

	ASN1_INTEGER		* serialNumber;

	// Cached Response
	PKI_OCSP_RESP		* response;

	// Time until the response is valid
	time_t			   expires;

	// Lock for the [data] access
	PKI_RWLOCK		   lock;

	// Collision code lookup: next entry
	struct ocspd_cache_entry_st * next;

	// Collision code lookup: prev entry
	struct ocspd_cache_entry_st * prev;

// Allocates a new caching entry
OCSPD_CACHE_ENTRY * OCSPD_CACHE_ENTRY_new(void) {

	OCSPD_CACHE_ENTRY * e = NULL;

	// Allocates the required memory
	if ((e = PKI_Malloc(sizeof(OCSPD_CACHE_ENTRY))) == NULL) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		return NULL;
	}

	// Initializes the RWLock
	PKI_RWLOCK_init(&e->lock);

	// Makes sure we null pointers
	e->serialNumber = NULL;
	e->response = NULL;
	e->expires = 0;

	// Queue for collisions
	e->next = NULL;
	e->prev = NULL;

	// All Done
	return e;
}

// Frees all memory associated with a cache entry
void OCSPD_CACHE_ENTRY_free(OCSPD_CACHE_ENTRY *e) {

	OCSPD_CACHE_ENTRY *pnt = NULL;

	// Arguments Checking
	if (e == NULL) return;

	// Makes sure we have the write lock on the data
	// structure
	PKI_RWLOCK_write_lock(&e->lock);

	// Free all internal pointers
	if (e->serialNumber) ASN1_INTEGER_free(e->serialNumber);
	if (e->response) PKI_OCSP_RESP_free(e->response);

	// The assumption is that the e->next and e->prev
	// are handled outside the memory management function,
	// no action for those two here

	// Releases the lock
	PKI_RWLOCK_release_write(&e->lock);

	// Free the associated memory
	PKI_Free(e);

	// All Done
	return;
}

OCSPD_CACHE * OCSPD_CACHE_new(size_t size) {

	OCSPD_CACHE * oc = NULL;

	// Input checks
	if (size <= 0) size = 1000;

	// Allocates the memory
	if ((oc = PKI_Malloc(sizeof(OCSPD_CACHE))) == NULL) {
		PKI_log_err("Can not allocate cache memory");
		return NULL;
	}
	
	// Initializes the lock
	PKI_RWLOCK_init(&oc->lock);

	// Return the initialized data structure
	return oc;

}

void OCSPD_CACHE_free(OCSPD_CACHE * oc) {

	size_t cycle = 0;
		// Index for table entries

	// Input check
	if (!oc) return;

	// Make sure we have a write lock over the cache
	// database
	PKI_RWLOCK_write_lock(&oc->lock);

	while(cycle < OCSPD_CACHE_TABLE_SIZE) {

		OCSPD_CACHE_ENTRY * next;
			// Pointer for memoizing the next entry

		OCSPD_CACHE_ENTRY * e;
			// Container for the entry

		// If we do not have an entry here, let's move
		// to the next pointer
		if ((e = oc->idx[cycle]) == NULL)
			continue;

		// Let's follow the path until all 'next' are
		// cleared up
		while (e != NULL) {

			OCSPD_CACHE_ENTRY * tmp;

			// Make sure we can free the entry
			PKI_RWLOCK_write_lock(&e->lock);

			// Check if there is another next
			tmp = next->next;

			// Releases the lock
			PKI_RWLOCK_release_write(&e->lock);

			// Free the memory associated with the
			// current entry
			OCSPD_CACHE_ENTRY_free(next);

			// Assign the pointer to point to the next
			// entry (if any)
			next = tmp;
		}

		// Increment the cycle
		cycle++;
	}

	// Remove the linked entry
	PKI_RWLOCK_release_write(&oc->lock);

	// Destroys the lock
	PKI_RWLOCK_destroy(&oc->lock);

	// Free the data structure
	PKI_Free(oc);
}

int OCSPD_CACHE_entry_idx(ASN1_INTEGER *serialNumber) {

	// Calculates the Digest and uses the first 16bytes
	// of the value of the HASH of the serialNumber to
	// build the index of the cache value. Since we want
	// to maximize speed here
	PKI_DIGEST *x_dgst = NULL;

	return 0;
}

int OCSPD_CACHE_set_entry(OCSPD_CACHE * cache, OCSPD_CACHE_ENTRY *entry) {
	return -1;
}

OCSPD_CACHE_ENTRY * OCSPD_CACHE_get0_entry(OCSPD_CACHE * cache, ASN1_INTEGER *serialNumber) {
	return NULL;
}

