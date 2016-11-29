#ifndef _AH_DEVICE_H_
#define _AH_DEVICE_H_

#define AH_RED_IF_NAME              "red0"
#define AH_AGG_IF_NAME              "agg0"
#define AH_DEF_PRIMARY_IFP_NAME     "eth0"
#define AH_TUNNEL0_IF_NAME          "tunnel0"
#define AH_TUNNEL1_IF_NAME          "tunnel1"

/* add your device major below */
#define AH_FE_DEV_MAJOR         240
#define AH_MPI_DEV_MAJOR        241
#define AH_BOARD_DEV_MAJOR      242
#define AH_SYS_DEV_MAJOR        243
#define AH_MT_DEV_MAJOR     244
#define AH_SEC_DEV_MAJOR        245

/* add your device name below */
#define AH_FE_DEV_NAME          "/dev/fe"
#define AH_MPI_DEV_NAME         "/dev/mpi"
#define AH_BOARD0_DEV_NAME      "/dev/board0"
#define AH_SYS_DEV_NAME         "/dev/ah_sys"
#define AH_MT_DEV_NAME      "/dev/ah_mt"
#define AH_SEC_DEV_NAME         "/dev/ah_sec"
#endif /* _AH_DEVICE_H_ */

