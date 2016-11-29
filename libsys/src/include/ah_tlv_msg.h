#ifndef _AH_TLV_MSG_H
#define _AH_TLV_MSG_H

#include "ah_types.h"
#include "ah_mpi.h"

typedef struct {
	ushort      type;/* Type identifier */
	ushort      len; /* Length of the data, in bytes */
	uint      sess;/* Session number */
	uchar      val[0]; /* array starting address of data buffer */
} ah_tlv_t;

#define ah_get_tlv_value(t, type) ( (type*)((t)->val) )
/* recommend use following macro to extract tlv parms */
#define TLV_T(p)         ( (p)->type )
#define TLV_L(p)         ( (p)->len )
#define TLV_S(p)         ( (p)->sess)
#define TLV_V(p,type)    ( (type*)((p)->val) )

/* The smallest number that is multiple of 4s and bigger than l */
/* Assume l to be an usigned short */
static inline uint ALIGNED_LEN(uint l)
{
	return ((l + 0x3) & 0xfffffffc);
}


/* 4-rounded offset from the head of a AH_TLV, given the len of the data */
/* Should move this to makefile */
#define _WORD_ALIGN 1

#ifdef  _WORD_ALIGN
static inline uint AH_TLVSIZE(uint len)
{
	len = ALIGNED_LEN(sizeof(ah_tlv_t) + len);
	return len;
}

#else
#define AH_TLVSIZE(len) (sizeof(ah_tlv_t)+(len))
#endif

typedef struct {
	uint      alloc_len; /* size of the currently pre-allocated buffer (in multiple of 1024) */
	uint      used_len; /* size of the actual payload, including size of ah_tlv_hdr_t */
	uint      num_blks;/* number of tlv blocks */
	uchar      tlv_blks[0]; /* array starting address of data buffer (data is AH_TLV blocks) */
} ah_tlv_hdr_t;

#define ah_get_tlv_num(tlvh) ( (tlvh)->num_blks )

#define ah_tlv_set_value(tlv, l, v)\
	do {\
		memcpy((tlv)->val, v, (l)>(tlv)->len?(l):(tlv)->len);\
	} while(0)

#define ah_tlv_buf(tlvh)\
	((ah_tlv_t *)((tlvh)->tlv_blks))


/* AH_TLV iterator functions, allowing caller to loop thru a buffer of AH_TLVs. */
typedef struct {
	ah_tlv_t *tlv;
	short n;
	int i;
} ah_tlv_iterator_t;

static inline ah_tlv_t *AH_NEXT_TLV(ah_tlv_t *tlv)
{
	return (ah_tlv_t *)(((uchar *)tlv) + AH_TLVSIZE((tlv)->len));
}


static inline ah_tlv_t *ah_first_tlv(ah_tlv_iterator_t *it, ah_tlv_t *first, int ntlvs)
{
	it->tlv = first;
	it->n = ntlvs;
	it->i = 0;
	return it->tlv;
}

static inline int ah_more_tlv(ah_tlv_iterator_t *it)
{
	return (it->i < it->n);
}

static inline ah_tlv_t *ah_next_tlv(ah_tlv_iterator_t *it)
{
	it->tlv = AH_NEXT_TLV(it->tlv);
	it->i++;
	return it->tlv;
}

static inline uint ah_calc_tlv_bytes(ah_tlv_t *t, int n)
{
	uint      sz = sizeof(ah_tlv_hdr_t);
	while (n-- > 0) {
		int s = AH_TLVSIZE(t->len);
		sz += s;
		t = (ah_tlv_t *)(((uchar *)t) + s);
	}
	return sz;
}

static inline ah_tlv_t *ah_get_nth_tlv(ah_tlv_hdr_t *hdr, int n)
{
	ah_tlv_iterator_t it;
	ah_tlv_t *p;
	for (p = ah_first_tlv(&it, ah_tlv_buf(hdr), n);
		 ah_more_tlv(&it);
		 p = ah_next_tlv(&it));
	return p;
}

/*
   Example:
   ah_tlv_t *ptr
   ah_tlv_hdr_t *tlvhdr = ah_mpi_buf(mpihdr);
   ah_tlv_iterator_t it;
   for (ptr = ah_first_tlv(tlvhdr, &it); ah_more_tlv(&it); ptr = ah_next_tlv(&it)) {
        // work with ptr  ...
   }
*/


/*
 * Add one TLV cell to the payload of msg.
 * If v==NULL, the added TLV cell will be zeroized. Otherwise v will be mem copied to the value field.
 * This function returns a pointer to the newly added TLV
 */
extern ah_tlv_t *ah_mpi_add_tlv(ah_tlv_hdr_t **_tlvh, ushort t, ushort l, void *v);



#endif
