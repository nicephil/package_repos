/*************************************************************************
* @file ah_atomics.h
* @brief Atomic APIs
*
*
*************************************************************************/

#ifndef _AH_ATOMICS_H_
#define _AH_ATOMICS_H_

// These are done as macros to keep from proliferating a number
// of functions for each different type that "x" could be
// "x" must be an lvalue.

#define ah_atomic_bitset(x, bit) \
	do { \
		typeof(x) prev; \
		do { \
			prev = (x); \
		} while (!__sync_bool_compare_and_swap(&(x), prev, prev | (bit))); \
	} while (0)

#define ah_atomic_bitclear(x, bit) \
	do { \
		typeof(x) prev; \
		do { \
			prev = (x); \
		} while (!__sync_bool_compare_and_swap(&(x), prev, prev & ~(bit))); \
	} while (0)

// These macros return the value AFTER the operation.

#define ah_atomic_inc(x) __sync_add_and_fetch(&(x), 1)
#define ah_atomic_dec(x) __sync_add_and_fetch(&(x), -1)
#define ah_atomic_add(x, a)  __sync_add_and_fetch(&(x), (a))
#define ah_atomic_cas(ptr, is, tobe) __sync_bool_compare_and_swap(ptr, is, tobe)

#endif /* _AH_ATOMICS_H_ */
