#ifndef AH_ALARM_H
#define AH_ALARM_H

#include "ah_trap.h"

struct ah_trap_data_with_id_s {
	long trap_type;
	long       trap_type_id;
	boolean  clear;
	boolean  send2hm_now;
	uint16_t    data_len;
	char      data[0];
} __attribute__((packed));
typedef struct ah_trap_data_with_id_s ah_trap_data_with_id_t;


/* when rcv this id, the capwap will not store the msg into db */
#define AH_MSG_TRAP_NOT_STORE_ID   -1

enum {
	AH_MSG_TRAP_SET,
	AH_MSG_TRAP_CLEAR,
};

#define AH_MSG_TRAP_DB                                "/tmp/db/capwap_trap.db"
#define __MASK(x)                                     ((1UL << (x))-1)

#define AH_MSG_TRAP_FALURE_TYPE_CAUSE_BITS            8
#define AH_MSG_TRAP_FALURE_TYPE_OBJ_NAME_BITS         8
#define AH_MSG_TRAP_FAILURE_TYPE_OBJ_NAME_SHIFT       0
#define AH_MSG_TRAP_FAILURE_TYPE_CAUSE_SHIFT          (AH_MSG_TRAP_FAILURE_TYPE_OBJ_NAME_SHIFT + AH_MSG_TRAP_FALURE_TYPE_OBJ_NAME_BITS)

#define AH_MSG_TRAP_FAILURE_TYPE_OBJ_NAME_MASK        (__MASK(AH_MSG_TRAP_FALURE_TYPE_OBJ_NAME_BITS) << AH_MSG_TRAP_FAILURE_TYPE_OBJ_NAME_SHIFT)
#define AH_MSG_TRAP_FAILURE_TYPE_CAUSE_MASK           (__MASK(AH_MSG_TRAP_FALURE_TYPE_CAUSE_BITS) << AH_MSG_TRAP_FAILURE_TYPE_CAUSE_SHIFT)

/* Define trap type here, which is used to exchange between
 * HiveOS and HM, the value is define by HM */

#define AH_CAPWAP_DELAY_TRAP (108)
/*
 * TRAP TYPE IDX, Globally unique value
 *
 * The higher 16 bits of ID should same with the trap type,
 * and change the lower 16 bits to seperate the sub-type
 *
 */
enum {
	AH_MSG_TRAP_FAILUER_TYPE_ID_START = AH_FAILURE_TRAP_TYPE << 16,
	/* FAILURE TRAP sub-TYPE */
	AH_MSG_TRAP_FAILUER_TYPE_ID_END = ((AH_FAILURE_TRAP_TYPE << 16) + __MASK(16)),

	AH_INTERFERENCE_ALERT_TRAP_TYPE_ID_START = AH_INTERFERENCE_ALERT_TRAP_TYPE << 16,
	/* INTERFERENCE TRAP sub-TYPE */
	AH_INTERFERENCE_ALERT_TRAP_TYPE_ID_END = ((AH_INTERFERENCE_ALERT_TRAP_TYPE << 16) +  __MASK(16)),

	AH_MSG_TRAP_GENERIC_ALARM_ID_START = AH_MSG_TRAP_GENERIC_ALARM << 16,
	/* GENERAIC ALARM sub-TYPE */
	AH_MSG_TRAP_GENERIC_ALARM_ID_END = ((AH_MSG_TRAP_GENERIC_ALARM << 16) + __MASK(16)),

	AH_MSG_TRAP_LDAP_ALARM_ID_START = LDAP_ALARM_TRAP_TYPE << 16,
	/* LDAP ALARM sub-TYPE */
	AH_MSG_TRAP_LDAP_ALARM_ID_END = ((LDAP_ALARM_TRAP_TYPE << 16) + __MASK(16)),

};


enum failure_trap_obj_name_e {
	HARDWARE_RADIO = 0,
	DEVICE_ENVIRONMENT_TEMPERATURE,
	DEVICE_ENVIRONMENT_WATCHDOG,
};
#endif /* AH_ALARM_H*/
