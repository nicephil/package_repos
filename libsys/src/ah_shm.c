/*************************************************************************
* @file ah_shm.c
* @brief Shared memory APIs
*
*************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>

#include "ah_types.h"
#include "ah_lib.h"
#include "ah_shm.h"

typedef struct {
	uint32_t counter;
	uint8_t  bytes[128 - 4];
} ah_shm_header_t;

#define SHM_BASE_OFFSET sizeof(ah_shm_header_t)


/**
 * @brief create shared memory with specified key, possibly synchronizing with a semaphore
 *
 * @param shmid pointer to where to store created shared memory id (ah_shn_t)
 * @param key unique key value to use to share this memory with other processes
 * @param size The size of the memory segment to create
 * @param sem_id Semaphore id if you want to use a semaphore
 */
void *ah_shm_create(ah_shm_t *shmid, ah_shm_key_t key, size_t size)
{
	int shm_id;
	char *shm_addr = NULL;

	/* try get shared memory ID with specified key */
	shm_id = shmget(key, size + sizeof(ah_shm_header_t), IPC_CREAT | 0666);
	/* Check whether shared memory created */
	if (shm_id == -1) {
		ah_fatal("Error creating shared memory %x of size %u (error %d)", key, size, errno);
	}
	/* attach shared memory to process
	 * NOTE: creating a shared memory segment also zeroes it, so we don't need to
	 *       do that separately
	 */
	shm_addr = shmat(shm_id, NULL, 0);
	if (shm_addr == (char *) - 1L) {
		ah_fatal("Error mapping shared memory %x of size %u (error %d)", key, size, errno);
	}
	if (shmid != NULL) {
		*shmid = shm_id;
	}

	ah_log_old(AH_LOG_INFO, "Fetch shared memory %x of size %u, address at %p", key, size, shm_addr);

	__sync_fetch_and_add(&((ah_shm_header_t *)shm_addr)->counter, 1);

	return shm_addr + SHM_BASE_OFFSET;
}

void ah_shm_destroy(ah_shm_t shmid, void *in_addr)
{
	char *addr = ((char *)in_addr) - SHM_BASE_OFFSET;
	int  val = __sync_add_and_fetch(&((ah_shm_header_t *)addr)->counter, -1);
	// Yes - there's a small race condition here.  I (mjq) don't believe that it's a big
	// enough probability to actually try to deal with, given the way shared memory is used in
	// our system - it's not being dynamically created and destroyed to where someone might be
	// creating it just as we're destroying it.....
	// The __sync__ adds are so that two people creating at the same time don't mess up the counter.
	//
	if (shmdt(addr) == 0) {
		if (val == 0) {
			if (shmctl(shmid, IPC_RMID, NULL) < 0) {
				ah_fatal_debug("Error destroying shared memory at %p (error %d)", addr, errno);
			}
		}
	} else {
		ah_fatal_debug("Error detaching shared memory at %p (error %d)", addr, errno);
	}
}
