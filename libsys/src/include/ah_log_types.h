/**
 * @file ah_log_types.h
 * @brief header file of ah syslog level declaration
 *
 * Copyright (c) 2016 Aerohive Networks, Inc. All rights reserved.
 *
 * This software and all information contained herein is confidential and
 * proprietary to Aerohive Networks, and is protected by copyright and
 * other applicable laws in the United States and other jurisdictions. You
 * may not use, modify, reproduce, distribute, or disclose this software
 * without the express written permission of Aerohive Networks.
 *
 */

#ifndef __AH_LOG_TYPES_H__ 
#define __AH_LOG_TYPES_H__

/* Log level */
typedef enum {
	AH_LOG_EMERG = 0,
	AH_LOG_ALERT,
	AH_LOG_CRIT,
	AH_LOG_ERR,
	AH_LOG_WARNING,
	AH_LOG_NOTICE,
	AH_LOG_INFO,
	AH_LOG_DEBUG,
	AH_MAX_LOG_LEVELS
} ah_log_level_t;


#endif /* __AH_LOG_TYPES_H__ */

