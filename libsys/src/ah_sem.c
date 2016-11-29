/*************************************************************************
* @file ah_sem.c
* @brief Semaphore APIs
*
*************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>

#include <ah_types.h>
#include <ah_sem.h>
#include <ah_lib.h> // for ah_fatal, ah_log

ah_sem_t ah_sem_create(ah_sem_key_t key, int count)
{
	ah_sem_t sem_id;
	struct sembuf sbuf;

retry:
	sem_id = semget(key, 0, 0);
	if (sem_id == AH_INVALID_SEM_ID) {
		if (errno == ENOENT) {
			sem_id = semget(key, 1, IPC_CREAT | AH_SEM_MODE | IPC_EXCL);
			if (sem_id == AH_INVALID_SEM_ID) {
				if (errno == EEXIST) {
					goto retry;
				}
				ah_fatal("Could not create semaphore for key %x", key);
			}
			ah_log_old(AH_LOG_INFO, "Semaphore id %x created for key %x", key);
			sbuf.sem_num = 0;
			sbuf.sem_op = count;
			sbuf.sem_flg = 0;
			if (semop(sem_id, &sbuf, 1) != 0) {
				ah_fatal("semop failed for key %x with error %d", errno);
			}
		} else {
			ah_fatal("Fetch of semaphore %x failed with error %d", key, errno);
		}
	}
	return sem_id;
}

/**
 * @brief Wait for a semaphore, but return if an EINTR occurs.
 * @param sem_id the semaphore id
 * @return true if we got the semaphore, false if we were interrupted.
 */
boolean ah_sem_wait_interrupt(ah_sem_t sem_id)
{
	struct sembuf  sem_op;

	sem_op.sem_num = 0;
	sem_op.sem_op = -1;
	sem_op.sem_flg = SEM_UNDO;

	if (semop(sem_id, &sem_op, 1) < 0) {
		if (errno != EAGAIN && errno != EINTR) {
			ah_fatal("Wait on semaphore %x failed with error %d", sem_id, errno);
		}
		return FALSE;
	}
	return TRUE;
}

/**
 * @brief Wait for a semaphore
 * @param sem_id the semaphore id
 */
void ah_sem_wait(ah_sem_t sem_id)
{
	struct sembuf  sem_op;

	sem_op.sem_num = 0;
	sem_op.sem_op = -1;
	sem_op.sem_flg = SEM_UNDO;

	while (semop(sem_id, &sem_op, 1) < 0) {
		if (errno != EAGAIN && errno != EINTR) {
			ah_fatal("Wait on semaphore %x failed with error %d", sem_id, errno);
		}
	}
}

/**
 * @brief Signal the semaphore (i.e. wake up waiters)
 * @param sem_id the semaphore id
 * @return 0 if signal execute, -1 if an error occurred.
 */
void ah_sem_signal(ah_sem_t sem_id)
{
	struct sembuf  sem_op;
	sem_op.sem_num = 0;
	sem_op.sem_op = 1;
	sem_op.sem_flg = SEM_UNDO;

	while (semop(sem_id, &sem_op, 1) < 0) {
		if (errno != EAGAIN && errno != EINTR) {
			ah_fatal("Semaphore %x signalling failed with error %d", sem_id, errno);
		}
	}
}

/**
 * @brief Destroy the semaphore.
 * @param sem_id the semaphore id to destroy
 */
void ah_sem_destroy(ah_sem_t sem_id)
{
	if (semctl(sem_id, IPC_RMID, 0) == -1) {
		ah_fatal_debug("Semaphore %x could not be destroyed - error %d", sem_id, errno);
	}
}
