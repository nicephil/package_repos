/*************************************************************************
* @file ah_sem.h.
* @brief Semaphore APIs
*
*************************************************************************/
#ifndef AH_SEM_H
#define AH_SEM_H

#include "ah_types.h"

#define AH_SEM_MODE  0666

#define AH_INVALID_SEM_ID ((ah_sem_t)(-1))

typedef int ah_sem_t;
typedef int ah_sem_key_t;

ah_sem_t ah_sem_create(ah_sem_key_t key, int count);
void ah_sem_wait(ah_sem_t sem_id);
void ah_sem_signal(ah_sem_t sem_id);
void ah_sem_destroy(ah_sem_t sem_id);

#endif /* AH_SRM_H */
