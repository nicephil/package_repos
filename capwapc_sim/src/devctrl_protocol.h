#ifndef __DEVCTRL_PROTOCOL_H__
#define __DEVCTRL_PROTOCOL_H__

#define DEVCTRL_BLOCK_HEADER_LEN    20
typedef struct devctrl_block{
#define COOKIE_LENGTH   8    
    unsigned char version;
    char cookie[COOKIE_LENGTH];
    unsigned short type;
    unsigned char compressed;
    unsigned int orig_len;
    unsigned int len;
    char *data;
} devctrl_block_s;

#define DEVINFO_FIX_LEN     36    
typedef struct device_info{
    char mac[6];
    char iptype;
    int  ip;
    int  netmask;
    int  gateway;
    int  uptime;
    char snlen;
    char *sn;
    char namelen;
    char *name;
    unsigned short mtu;
    char verlen;
    char *version;
    int  cfg_version;
    int  cfg_code;
} device_info_s;

typedef struct devctrl_fraglist {
    int id;
    int order;
    CWList list;
} devctrl_fraglist_s;

CWBool parse_devctrlreq_msg(CWProtocolMessage *Msg, devctrl_block_s *Controlinfo) ;
CWBool assemble_devctrlresp_elem(CWProtocolMessage *msgPtr, devctrl_block_s *Controlblock);
CWBool assemble_devctrlresp_msg(CWProtocolMessage **messagesPtr, int *fragmentsNumPtr, 
    int PMTU, int seqNum, CWProtocolResultCode resultCode);
CWBool assemble_devctrlresp_frag(CWProtocolMessage **completeMsgPtr, 
    int *fragmentsNumPtr, int PMTU, int seqNum, int msgTypeValue, 
    CWProtocolMessage *msgElems, int is_crypted);
CWBool parse_devctrlreq_frag(char *buf, int readBytes, CWProtocolMessage *reassembledMsg, CWBool *dataFlagPtr);
CWBool assemble_vendor_devinfo(char **info, int *len);
CWBool WTPEventRequest_devctrlresp(int type, int value);
#endif
