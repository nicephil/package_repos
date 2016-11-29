#ifndef _AH_NET_H_
#define _AH_NET_H_

/*----------------------------------------------------------------------------*/
/* this file contain the common aerohive data structures used in the src code */
/*----------------------------------------------------------------------------*/
#include "ah_netconst.h"
#include "ah_config.h"

/*
 * ----------------------------------------------------------------------
 * well-known ah structures
 * ----------------------------------------------------------------------
 */
/*
 * mac-addr type
 */
typedef union ah_mac_ {
	uint8_t   am_bp[6];         /* 6 uint8_t value */
	uint16_t  am_sp[3];         /* 3 uint16_t value */
	struct  {                 /* 1 uint32_t value and 1 uint16_t value */
		uint32_t am_wv_;
		uint16_t am_sv_;
	} __attribute__((packed)) am_c_;
#define am_wv am_c_.am_wv_
#define am_sv am_c_.am_sv_
} ah_mac_t;
#define is_ah_mac_equal(m1,m2) ( ((ah_mac_t*)(m1))->am_sv == ((ah_mac_t*)(m2))->am_sv && \
								 ((ah_mac_t*)(m1))->am_wv == ((ah_mac_t*)(m2))->am_wv    )
#define is_ah_mac_gt(m1, m2) (memcmp((char *)m1, (char *)m2, MACADDR_LEN) > 0)
#define is_ah_mac_zero(m)      ( ((ah_mac_t*)(m))->am_sv == 0x0 && ((ah_mac_t*)(m))->am_wv == 0x0 )
#define set_ah_mac_zero(m)     do { ((ah_mac_t*)(m))->am_wv = 0x0; ((ah_mac_t*)(m))->am_sv = 0x0; } while(0)
#define is_ah_mac_ff(m)        ( ((ah_mac_t*)(m))->am_sv == 0xffff && ((ah_mac_t*)(m))->am_wv == 0xffffffff )
#define set_ah_mac_ff(m)       do { ((ah_mac_t*)(m))->am_wv = 0xffffffff; ((ah_mac_t*)(m))->am_sv = 0xffff; } while(0)
#define is_ah_mac_bcast(m)     ((m)->am_bp[0] & 1)
#define is_ah_mac_gt_or_eq(m1, m2) (memcmp((char *)m1, (char *)m2, MACADDR_LEN) >= 0)
#define AH_MACADDR_EQ(a1,a2)            (memcmp(a1,a2,MACADDR_LEN) == 0)
#define AH_MACADDR_COPY(dst,src)        memcpy(dst,src,MACADDR_LEN)

int ah_mac_hash_idx(ah_mac_t *_mac, int sz);

#ifndef __KERNEL__
/* copy from ah_mac_tbl.h
 */
struct _ah_mac_internal_ {
	uint   addr_int;
	ushort addr_short;
} __attribute__((__packed__));

#define mac_addr_int(_mac1) (htonl(((struct _ah_mac_internal_ *)_mac1)->addr_int))
#define mac_addr_short(_mac1) (htons(((struct _ah_mac_internal_ *)_mac1)->addr_short))
#endif
/*
 * ethernet hdr type
 */
typedef struct ah_eth_ {
	char     da[MACADDR_LEN]; /* dst mac */
	char     sa[MACADDR_LEN]; /* src mac */
	uint16_t ether_type;      /* ether type */
} __attribute__((__packed__)) ah_eth_t;

/*
 * LLC hdr type, we take the standard LLC , append a 2 byte crc-16 cksum
 */
typedef struct ah_llc_ {
	uint8_t dsap;       /* null DSAP address */
	uint8_t ssap;       /* null SSAP address, CR=Response */
	uint8_t ctrl;       /* we use 1-byte ctrl */
#ifndef LLC_SNAP_DSAP
#define LLC_SNAP_DSAP 0xaa   /* we are use SNAP to demux, so pls fill the standard LLC SNAP value */
#endif
#ifndef LLC_SNAP_SSAP
#define LLC_SNAP_SSAP 0xaa
#endif
#ifndef LLC_SNAP_CTRL
#define LLC_SNAP_CTRL 0x03
#endif
	uint8_t oui[3];     /* snap */
	/*
	 * The folllowing OUI (00:19:77) is the first ever OUI for Aerohive,
	 * For purpose of backward compatibility, it also
	 * serves as  the magic number in AMRP to identify control
	 * flows between Aerohive devices.
	 * In case of new OUIs been deployed, no need to change the
	 * magic number in AMRP control flows.
	 * One only need to update the functions/macros/code which
	 * are to check-and-verify OUI information read from hardware.
	 */
#define AH_OUI_0 AH_OEM_OUI_0     /* oui number got 8/06 */
#define AH_OUI_1 AH_OEM_OUI_1
#define AH_OUI_2 AH_OEM_OUI_2
#define AH_OUI_NUM 3
	uint16_t  proto;
#define AH_NDP            0x0001 /* depreciate after amrp2 */
#define AH_AMRP            0x0002 /* depreciate after amrp2 */
#define AH_RMP            0x0003
#define AH_PROBE        0x0004
#define AH_L3PORTAL     0x0005
#define AH_IDPIND    0x0006        /* IDP in-network detection packet (l2 LLC broadcast), should be flooded to other interfaces */
#define AH_AMRP_ETH       0x0007        /* amrp2 eth side ctrl traffic */
#define AH_AMRP_WIFI_NDP  0x0008        /* amrp2 1-hop wifi, no route lookup, set nhop from dst directly */
#define AH_AMRP_WIFI_MESH 0x0009        /* amrp2 x-hop wifi, need FE route lookup to get nhop */
#define AH_HIVE_BROADCAST 0x000a    /* broadcast the packet to entire hive */
#define AH_AMRP_ETH_1HOP_HACK 0x000b    /* this is a hack, the pkt is broadcast from AP to Switch, one hop only to
                     * annouce direct attached APs on the switch, note AH_AMRP_ETH has a hopcount
                     * of 1 too.
                     */

#define AH_LLC_PROTO2NAME(p) ( \
							   ((p) == AH_NDP)?"NDP": \
							   ((p) == AH_AMRP)?"AMRP": \
							   ((p) == AH_RMP)?"RM": \
							   ((p) == AH_PROBE)?"PROBE": \
							   ((p) == AH_L3PORTAL)?"L3PORTAL": \
							   ((p) == AH_IDPIND)?"IDPIND": \
							   ((p) == AH_AMRP_ETH)?"AMRP_ETH": \
							   ((p) == AH_AMRP_WIFI_NDP)?"AMRP_WIFI_NDP": \
							   ((p) == AH_AMRP_WIFI_MESH)?"AMRP_WIFI_MESH": \
							   ((p) == AH_HIVE_BROADCAST)?"HIVE_BROADCAST": \
							   ((p) == AH_AMRP_ETH_1HOP_HACK)?"AMRP_ETH_1HOP": \
							   "N/A" )

	uint16_t  crc;
	uint8_t   enc_flag; /* encyption flag */
	uint8_t   unused;   /* padding */
	uint16_t  mic;      /* crc for plain text payload */
	uint32_t  seq;      /* sequence number */
	uint16_t vlan;
} __attribute__((__packed__)) ah_llc_t;

extern ah_llc_t ah_dummy_llc;
#define is_ah_llc(llc) is_ah_mac_equal(llc, &ah_dummy_llc)
#define is_ah_llc_old(llc) ((llc)->dsap   == LLC_SNAP_DSAP && \
							(llc)->ssap   == LLC_SNAP_SSAP && \
							(llc)->ctrl   == LLC_SNAP_CTRL && \
							(llc)->oui[0] == AH_OUI_0      && \
							(llc)->oui[1] == AH_OUI_1      && \
							(llc)->oui[2] == AH_OUI_2 )

/*
 * General helper function to find the index in the OUI list
 * that matches the mac from "start" byte to "end" byte.
 * If not found, return -1;
 */
static inline int ah_match_mac_oui_bytes(unsigned char *mac, int start, int end)
{
	int i, j;
	int find = -1;
	/* Sanity check */
	if (start < 0 || start > 2 || end < 0 || end > 2 || start > end) {
		return -1;
	}
	for (i = 0; i < AH_OUI_NUM ; i ++) {
		for (j = start; j <= end; j ++) {
			if (!ah_is_mac_oui_onebyte(mac, i, j)) {
				break;
			}
		}
		if (j > end) {
			find = i;
			break;
		}
	}
	return find;
}

/*
 * The first byte of OUI will be used as flaging bits for special purpose
 * in the mesh, e.g., group bits for multicast frames in mesh.
 * The remaining bytes in OUI will be used as the tag, and can be utilized
 * to find the OUI index by this tag, and restore the first byte if desired.
 * This is the basic idea of "MAC NAT" in mesh in our design.
 */
static inline int ah_find_oui_idx_by_tag(unsigned char *mac)
{
	return ah_match_mac_oui_bytes(mac, 1, 2);
}

static inline void ah_revert_mac_to_oui(unsigned char *mac)
{
	int oui_idx;
	oui_idx = ah_find_oui_idx_by_tag(mac);
	if (oui_idx != -1) {
		/* is it possible that oui_idx is -1, i.e., not found in oui list? */
		ah_set_mac_oui_onebyte(mac, oui_idx, 0);
	}
}

/* Aerohive internal mesh frame format:
 * used between backhaul interface and forwarding engine
 * ------------------------------
 * |                            |
 * |    ah_int_mesh_hdr_t (36B) |
 * |                            |
 * |----------------------------|
 * |    Original Ether type (2B)|
 * |----------------------------|
 * |    AH_HDRTYPE_INT_MESH(1B) |
 * |----------------------------|
 * |    length            (1B)  |
 * |----------------------------|
 * |    Ethernet DA   (6B)      |
 * |----------------------------|
 * |    Ethernet SA   (6B)      |
 * |----------------------------|
 * |    AH_ETHERTYPE_MESH (2B)  |
 * |----------------------------|
 * |    payload                 |
 * |                            |
 * |                            |
 * |                            |
 * |                            |
 * |----------------------------|
 */

/*
 * Aerohive proprietary ethernet tag
 */
#define AH_ETHERTYPE_MESH       0xFEAE /* this ah magic valiue */
#define AH_ETHERTYPE_PAE        0x888e /* this is standard value */
#define AH_ETHERTYPE_PREAUTH    0x88c7 /* this is for pre-auth */
#define AH_ETHERTYPE_IP        0x0800 /* this is for screen */
#define AH_ETHERTYPE_ARP       0x0806 /* this is for screen */
#define AH_ETHERTYPE_LLDP    0x88cc
#define AH_ETHERTYPE_BRCM   0x886c

#ifdef __KERNEL__
// the following for optimization
#define eq_8bytes(ptr1, ptr2) (*(uint64_t *)(ptr1) == *(uint64_t*)(ptr2))
extern ah_llc_t ah_dummy_cdp_llc;
#define is_ah_cdp_llc(llc) eq_8bytes(llc, &ah_dummy_cdp_llc)
#else
#define is_ah_cdp_llc(llc)             \
	(   (LLC_SNAP_DSAP == (llc)->dsap) \
		&& (LLC_SNAP_SSAP == (llc)->ssap) \
		&& (LLC_SNAP_CTRL == (llc)->ctrl) \
		&& (0x00 == (llc)->oui[0])        \
		&& (0x00 == (llc)->oui[1])        \
		&& (0x0c == (llc)->oui[2])        \
		&& (0x2000 == ntohs((llc)->proto))  )
#endif

typedef struct {
	uint16_t   ether_type;    /* Ethertype */
	uint8_t    type;    /* Header type */
#define AH_HDRTYPE_INT_MESH    0x01
	uint8_t    len;        /* Header length */
} __attribute__((__packed__)) ah_eth_tag_t;

#define AH_ETH_TAG_LEN \
	sizeof(ah_eth_tag_t)
#define AH_GET_TAG_ETHERTYPE(pTag) \
	(((ah_eth_tag_t *)(pTag))->ether_type)
#define AH_SET_TAG_ETHERTYPE(pTag, type) \
	do {((ah_eth_tag_t *)(pTag))->ether_type = type;} while (0)
#define AH_GET_TAG_TYPE(pTag) \
	(((ah_eth_tag_t *)(pTag))->type)
#define AH_SET_TAG_TYPE(pTag, htype) \
	do {((ah_eth_tag_t *)(pTag))->type = htype;} while (0)
#define AH_GET_TAG_LEN(pTag) \
	(((ah_eth_tag_t *)(pTag))->len)
#define AH_SET_TAG_LEN(pTag, hlen) \
	do {((ah_eth_tag_t *)(pTag))->len = hlen;} while (0)

typedef struct {
	uint8_t    mseq[2];
	uint8_t    ttl[1];
#define AH_MESH_TTL        16
	uint8_t pad[1];
} __attribute__((__packed__)) ah_meshfc_t;

#define AH_MESHFC_LEN    sizeof(ah_meshfc_t)

#define is_orig_ah_pae_pkt(ptr)  (*(unsigned short *)(((char *)ptr) - AH_ETH_TAG_LEN) == __constant_htons(AH_ETHERTYPE_PAE))
/* Internal mesh header structure */
typedef struct {
	uint8_t     fc[2];
	uint8_t     dur[2];
	uint8_t    addr1[MACADDR_LEN];
	uint8_t    addr2[MACADDR_LEN];
	uint8_t    addr3[MACADDR_LEN];
	uint8_t    seq[2];
	uint8_t    addr4[MACADDR_LEN];
	uint8_t qos[2];
	ah_meshfc_t    mfc;
} __attribute__((__packed__)) ah_int_mesh_hdr_t;

#define AH_INT_MESH_HDR_LEN        sizeof(ah_int_mesh_hdr_t)
#define AH_INT_MESH_HDR_TOTAL_LEN    (AH_INT_MESH_HDR_LEN + AH_ETH_TAG_LEN)

/* External 802.11s see-mesh header structure without qos */
typedef struct {
	uint8_t   fc[2];
	uint8_t   dur[2];
	uint8_t   addr1[MACADDR_LEN];
	uint8_t   addr2[MACADDR_LEN];
	uint8_t   addr3[MACADDR_LEN];
	uint8_t   seq[2];
	uint8_t   addr4[MACADDR_LEN];
	ah_meshfc_t    mfc;
} __attribute__((__packed__)) ah_seemesh_hdr_t;


/* External 802.11s see-mesh header structure with qos */
typedef struct {
	uint8_t   fc[2];
	uint8_t   dur[2];
	uint8_t   addr1[MACADDR_LEN];
	uint8_t   addr2[MACADDR_LEN];
	uint8_t   addr3[MACADDR_LEN];
	uint8_t   seq[2];
	uint8_t   addr4[MACADDR_LEN];
	uint8_t   qos[2];
	ah_meshfc_t    mfc;
} __attribute__((__packed__)) ah_qos_seemesh_hdr_t;

/* Default VLAN ID */
#define AH_DEFAULT_VLAN_ID      1

/* Minimum VLAN ID */
#define AH_MIN_VLAN_ID          1

#define AH_MAX_VLAN_BITMAP              512
#define ah_vlan_bitmap_set(b, v)        ((b)[(v)/8] |= (1<<(8-(v)%8-1)))
#define ah_vlan_bitmap_clr(b, v)        ((b)[(v)/8] &= ~(1<<(8-(v)%8-1)))
#define ah_vlan_bitmap_query(b, v)      ((b)[(v)/8] & (1<<(8-(v)%8-1)))

/* Maximum VLAN ID */
#define AH_MAX_VLAN_ID          4094

/* VLAN tag/802.1p priority tag format */
typedef struct {
#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN          0x8100
#endif
	uint16_t  ether_type;             /* Ethertype - 0x8100 */

#define AH_VLAN_PRI_MASK        0xE000
#define AH_VLAN_CFI_MASK        0x1000
#define AH_VLAN_VID_MASK        0x0FFF
#define AH_VLAN_PRI_SHIFT       13
#define AH_VLAN_CFI_SHIFT       12
	uint16_t  tci;                    /* Tag Control Infomation */
} __attribute__((__packed__)) ah_vlan_tag_t;

#define AH_VLAN_TAG_SIZE \
	sizeof(ah_vlan_tag_t)

/* VLAN tag information conveyed through skb->cb */
/* The data format in skb->cb is host endian */
typedef struct {
#define AH_VLAN_COOKIE_MAGIC    0x564c414e
	uint32_t        magic;          /* VLAN magic cookie = 0x564c414e */
	ah_vlan_tag_t   tag;
} __attribute__((__packed__)) ah_vlan_cb_t;

#define AH_VLAN_TCI(pTag) \
	(((ah_vlan_tag_t *)(pTag))->tci)
#define AH_GET_VLAN_PRI(pTag) \
	((AH_VLAN_TCI(pTag) & AH_VLAN_PRI_MASK) >> AH_VLAN_PRI_SHIFT)
#define AH_SET_VLAN_PRI(pTag, pri) \
	do { \
		AH_VLAN_TCI(pTag) &= ~AH_VLAN_PRI_MASK; \
		AH_VLAN_TCI(pTag) |= (((pri) << AH_VLAN_PRI_SHIFT) & AH_VLAN_PRI_MASK); \
	} while (0)
#define AH_GET_VLAN_VID(pTag) \
	(AH_VLAN_TCI(pTag) & AH_VLAN_VID_MASK)

#define AH_SET_VLAN_VID(pTag, vid) \
	do { \
		AH_VLAN_TCI(pTag) &= ~AH_VLAN_VID_MASK; \
		AH_VLAN_TCI(pTag) |= ((vid) & AH_VLAN_VID_MASK); \
	} while (0)
#define AH_GET_VLAN_CFI(pTag) \
	((AH_VLAN_TCI(pTag) & AH_VLAN_CFI_MASK) >> AH_VLAN_CFI_SHIFT)
#define AH_SET_VLAN_CFI(pTag, cfi) \
	do { \
		AH_VLAN_TCI(pTag) &= ~AH_VLAN_CFI_MASK; \
		AH_VLAN_TCI(pTag) |= (((cfi) << AH_VLAN_CFI_SHIFT) & AH_VLAN_CFI_MASK); \
	} while (0)
#define AH_GET_TCI_VID(tci) \
	((tci) & AH_VLAN_VID_MASK)
#define AH_SET_TCI_VID(tci, vid) \
	do { \
		tci &=  ~AH_VLAN_VID_MASK; \
		tci |= ((vid) & AH_VLAN_VID_MASK); \
	} while (0)
#define AH_GET_TCI_PRI(tci) \
	(((tci) & AH_VLAN_PRI_MASK) >> AH_VLAN_PRI_SHIFT)
#define AH_SET_TCI_PRI(tci, pri) \
	do { \
		tci &= ~AH_VLAN_PRI_MASK; \
		tci |= (((pri) << AH_VLAN_PRI_SHIFT) & AH_VLAN_PRI_MASK); \
	} while (0)


/*
 * switch cb, conveyed in skb->ah_sw_cb, not skb->cb
*/
typedef struct ah_sw_cb_s {

	uint32_t     flags;      /* flags*/
#define AH_SW_CB_FLAG_CTRL_PKT_TYPE_SET     0x00000001    // Whether control packet type is filled, only valid if AH_SW_CB_IS_CONTROL_PACKET are set
#if (AH_IS_SWITCH)        /* switch platform */
#define AH_SW_CB_FLAG_RX_PORT_SET           0x00000002   // Whether underlying NIC driver successfully determine through which port this packet is received.
#define AH_SW_CB_FLAG_TX_PORT_SET           0x00000004    // Whether upper layer already decided which port the packet should be sent to. If not set driver will ask switch hardware to make forwarding decision for this packet.
#else                    /* non-switch platform */
#define AH_SW_CB_FLAG_RX_IFINDEX_SET        0x00000002    //the ifindex of ingress net_device
#define AH_SW_CB_FLAG_TX_IFINDEX_SET        0x00000004    //the ifindex of egress net_device
#endif                    /* AH_IS_SWITCH */
#define AH_SW_CB_FLAG_VLAN_SET              0x00000008    //Whether VLAN info set.

#define AH_SW_CB_FLAG_DATA_PKT_TYPE_SET     0x00000010  //contrary to AH_SW_CB_FLAG_CTRL_PKT_TYPE_SET, means this packet is a data packet.

	/* This flag is ONLY used for switch platforms, not nonswitch platforms. */
#define AH_SW_CB_FLAG_VLAN_SET_IN_ORIG_PACKET    0x00000020    //Whether VLAN tag exist in original packet.

#define AH_SW_CB_FLAG_TX_NOT_BY_FORCE    0x00000040    //see: AH_SW_TAG_FLAG_TX_NOT_BY_FORCE in "ah_sw_tag_t"


	/* internal flag, do not use it directly, such radio devNum or switch devNum */
#define AH_SW_CB_FLAG_RX_DEV_SET        0x10000000
#define AH_SW_CB_FLAG_TX_DEV_SET        0x20000000
#define AH_SW_CB_FLAG_TX_FROM_SW_SOCK    0x40000000    //transmitted by ah_sw_sock
	//meanwhile, __tx_sw_sock_owner tells transmitter "ah_sw_sock", like "skb->sk"

	uint32_t     ctrl_pkt_type;      //see 'AH_CTRL_PKT_TYPE'


#if (AH_IS_SWITCH)        /* switch platform */
	uint32_t     rx_port;            //logical port for ingress port, only valid when AH_SW_CB_IS_RX_PORT_SET
	//  --- ""SWD internal logcil index""

	uint32_t     tx_port;            // logical port for egress port, only valid when AH_SW_CB_IS_TX_PORT_SET
	//  --- ""SWD internal logcil index""
#else                    /* non-switch platform */
	uint32_t     rx_ifindex;
	uint32_t     tx_ifindex;
#endif                    /* AH_IS_SWITCH */


	uint16_t
	vid;           //VLAN info, only valid if AH_SW_CB_IS_VLAN_SET, duplicated with skb->cb VLAN, but if these 2 is not the same, skb->cb take preference.
	uint8_t     up;
	uint8_t     cfi;
	// --- These 2 are only for debug.
	uint32_t     __rx_dev;           //logical dev for ingress, only valid when AH_SW_CB_IS_RX_DEV_SET
	uint32_t     __tx_dev;           //logical dev for egress, only valid when AH_SW_CB_IS_TX_DEV_SET

	ulong        __tx_sw_sock_owner; //kernel "task_struct" of ah_sw_sock.
} ah_sw_cb_t;


/*
 *        ah_sw_cb->ctrl_pkt_type
 *
 * In traditional implementation, it is FE which parses the packet data and determine what kind of packet it is.
 *
 * In future implementation, we plan to offload this work to NIC driver (ethernet / radio):
 *
 *        If NIC support classify packet in HW-level, such as Marvell xCat with its DSA cpu code, then we offload to HW ( with proper translation).
 *
 *        Otherwise, FE sees it not set, it do its tranditional parsing and classification work, but FE also need to set FLAG_CODE.
 *
 *
 * In ingress path, ah_packet_code is used to quickly determine packet type without parsing.
 *
 * In egress path, ah_packet_code might be used to determine egress QoS policy ( need to more design and implemented).
 *
 *
 * This idea is from MVL-specific cpu code.
 *
 * See:
 *        MVL_CPUCODE
 *
 *
 * Anyway, for now, any NIC driver (if possible) should set this skb->ah_packet_code in its RX routine.
 *
 *        --- no uniform function defined, each NIC driver-specific.
 */
enum AH_CTRL_PKT_TYPE {

	AH_CTRL_PKT_TYPE_UNKNOWN = 0,

	AH_CTRL_PKT_TYPE_STP,

	/*
	 * FE doesn't see ARP as control packet, comment it for now.
	 */
//    AH_CTRL_PKT_TYPE_ARP,

	AH_CTRL_PKT_TYPE_LACP,

	AH_CTRL_PKT_TYPE_GVRP,

	AH_CTRL_PKT_TYPE_GMRP,

	AH_CTRL_PKT_TYPE_8021X,

	AH_CTRL_PKT_TYPE_LLDP,

	AH_CTRL_PKT_TYPE_IPV4_IGMP,

	AH_CTRL_PKT_TYPE_AH_AMRP,    /* aerohive AMRP packets */

	AH_CTRL_PKT_TYPE_CDP,

	AH_CTRL_PKT_TYPE_MDNS,

	AH_CTRL_PKT_TYPE_MAX,
};

#define AH_CTRL_PKT_TYPE2NAME(p) ( \
								   ((p) == AH_CTRL_PKT_TYPE_STP)?"BPDU": \
								   ((p) == AH_CTRL_PKT_TYPE_LACP)?"LACP": \
								   ((p) == AH_CTRL_PKT_TYPE_GVRP)?"GVRP": \
								   ((p) == AH_CTRL_PKT_TYPE_GMRP)?"GMRP": \
								   ((p) == AH_CTRL_PKT_TYPE_8021X)?"EAP": \
								   ((p) == AH_CTRL_PKT_TYPE_LLDP)?"LLDP": \
								   ((p) == AH_CTRL_PKT_TYPE_IPV4_IGMP)?"IGMP": \
								   ((p) == AH_CTRL_PKT_TYPE_AH_AMRP)?"AMRP": \
								   ((p) == AH_CTRL_PKT_TYPE_CDP)? "CDP": \
								   ((p) == AH_CTRL_PKT_TYPE_MDNS)? "MDNS": \
								   "N/A" )

/*************************************************************************
 * rx air time normalization
 *************************************************************************/
/* Rx rate information conveyed through skb->wifi_cb */
/* The data format in skb->wifi_cb is host endian */
typedef struct {
#define AH_RXRATE_COOKIE_MAGIC    0x52415445
	uint32_t          magic;          /* Rx Rate magic cookie = 0x52415445 */
	uint16_t          rate_type;      /* One of ah_ieee80211_rate_t */
	uint16_t          rate_factor;    /* rate factor = 54 */
	uint32_t          rate;           /* actual rx rate in unit of Kbps */
	int16_t           noise_floor;    /* rx noise floor in dBm */
	int8_t            rssi;           /* rx RSSI */
	int8_t            ratecode;       /* rx rate code */
} __attribute__((__packed__)) ah_rxrate_cb_t;

typedef struct {
	uint32_t          rx_airtime;        /* rx airtime */
	uint32_t          tx_airtime;        /* tx airtime */
} __attribute__((__packed__)) ah_airtime_cb_t;

typedef struct {
	void          *buf;
} __attribute__((__packed__)) ah_ctx_buf_cb_t;

typedef struct {
	ah_rxrate_cb_t  rxrate_cb;      /* 16 bytes */
	ah_airtime_cb_t airtime_cb;     /* 8 bytes */
	ah_ctx_buf_cb_t ctx_buf_cb;     /* 8 bytes */

} __attribute__((__packed__)) ah_wifi_cb_t;

typedef enum {
	AH_IEEE80211_RATE_G = 0,        /* 11g client */
	AH_IEEE80211_RATE_GB,           /* 11g client in mixed b/g environment */
	AH_IEEE80211_RATE_B,            /* 11b client */
	AH_IEEE80211_RATE_A,            /* 11a client */
	AH_IEEE80211_RATE_TG,           /* turbo g client */
	AH_IEEE80211_RATE_TA,           /* turbo a client */
	AH_IEEE80211_RATE_NAHT20,       /* 11naht20 client */
	AH_IEEE80211_RATE_NGHT20,       /* 11nght20 client */
	AH_IEEE80211_RATE_NAHT40,       /* 11naht40 client */
	AH_IEEE80211_RATE_NGHT40,      /* 11nght40 client */
	AH_IEEE80211_RATE_NAHT40_HGI,   /* 11naht40 short guard interval client */
	AH_IEEE80211_RATE_NGHT40_HGI,   /* 11nght40 short guard interval client */
	AH_IEEE80211_RATE_VHT20,
	AH_IEEE80211_RATE_VHT40,
	AH_IEEE80211_RATE_VHT80,
	AH_IEEE80211_RATE_VHT160,
	AH_IEEE80211_MAX_RATE_TYPES
} ah_ieee80211_rate_t;

#define AH_IEEE80211_RATE_IS_G(_rate) \
	((_rate) == AH_IEEE80211_RATE_G || (_rate) == AH_IEEE80211_RATE_NGHT20 || (_rate) == AH_IEEE80211_RATE_NGHT40)

#define AH_IS_VALID_IEEE80211_RATE(rate_type) \
	(((rate_type) >= 0) && ((rate_type) < AH_IEEE80211_MAX_RATE_TYPES))

/* rate factor base */
#define AH_RATE_FACTOR_BASE     10
#define AH_LEN_TO_RXRATE_LEN(len, rate_factor) \
	(((len) * (rate_factor)) >> AH_RATE_FACTOR_BASE)

/* convert skb->wifi_cb to rxrate cb */
#define AH_CB_TO_RXRATE_CB(_cb) \
	(&(((ah_wifi_cb_t *)(_cb))->rxrate_cb))

#define AH_SKB_TO_RXRATE_CB(_skb) \
	(&(((ah_wifi_cb_t *)((_skb)->wifi_cb))->rxrate_cb))

#define AH_SKB_TO_AIRTIME_CB(_skb) \
	(&(((ah_wifi_cb_t *)((_skb)->wifi_cb))->airtime_cb))

#define AH_IS_RXRATE_CB_PRESENT(_cb) \
	(AH_CB_TO_RXRATE_CB(_cb)->magic == AH_RXRATE_COOKIE_MAGIC)

#define AH_INIT_RXRATE_CB(_cb) \
	do { \
		memset(AH_CB_TO_RXRATE_CB(_cb), 0, sizeof(ah_rxrate_cb_t));\
		AH_CB_TO_RXRATE_CB(_cb)->magic = AH_RXRATE_COOKIE_MAGIC; \
	} while (0)

#define AH_GET_RXRATE_TYPE(_cb) \
	(AH_CB_TO_RXRATE_CB(_cb)->rate_type)

#define AH_SET_RXRATE_TYPE(_cb, _rate_type) \
	do { \
		AH_CB_TO_RXRATE_CB(_cb)->rate_type = (_rate_type); \
	} while (0)

#define AH_GET_RXRATE_FACTOR(_cb) \
	(AH_CB_TO_RXRATE_CB(_cb)->rate_factor)

#define AH_SET_RXRATE_FACTOR(_cb, _rate_factor) \
	do { \
		AH_CB_TO_RXRATE_CB(_cb)->rate_factor = (_rate_factor); \
	} while (0)

#define AH_GET_RXRATE(_cb) \
	(AH_CB_TO_RXRATE_CB(_cb)->rate)

#define AH_SET_RXRATE(_cb, _rate) \
	do { \
		AH_CB_TO_RXRATE_CB(_cb)->rate = (_rate); \
	} while (0)

#define AH_GET_RXRSSI(_cb) \
	(AH_CB_TO_RXRATE_CB(_cb)->rssi)

#define AH_SET_RXRSSI(_cb, _rssi) \
	do { \
		AH_CB_TO_RXRATE_CB(_cb)->rssi = (_rssi); \
	} while (0)

#define AH_GET_RXNF(_cb) \
	(AH_CB_TO_RXRATE_CB(_cb)->noise_floor)

#define AH_SET_RXNF(_cb, _nf) \
	do { \
		AH_CB_TO_RXRATE_CB(_cb)->noise_floor = (_nf); \
	} while (0)

#define AH_GET_RXRATECODE(_cb) \
	(AH_CB_TO_RXRATE_CB(_cb)->ratecode);

#define AH_SET_RXRATECODE(_cb, _ratecode) \
	do { \
		AH_CB_TO_RXRATE_CB(_cb)->ratecode = (_ratecode); \
	} while (0)

#define AH_SET_RX_AIRTIME(_skb, _airtime) \
	do { \
		AH_SKB_TO_AIRTIME_CB(_skb)->rx_airtime = (_airtime);  \
	} while (0)

#define AH_GET_RX_AIRTIME(_skb) \
	(AH_SKB_TO_AIRTIME_CB(_skb)->rx_airtime)

#define AH_SET_TX_AIRTIME(_skb, _airtime) \
	do { \
		AH_SKB_TO_AIRTIME_CB(_skb)->tx_airtime = (_airtime);  \
	} while (0)

#define AH_GET_TX_AIRTIME(_skb) \
	(AH_SKB_TO_AIRTIME_CB(_skb)->tx_airtime)

#define AH_CLEAR_RXRATE_CB(_cb) \
	memset(AH_CB_TO_RXRATE_CB(_cb), 0, sizeof(ah_rxrate_cb_t))

#define AH_SET_CTX_BUF_CB(_cb, _buf) \
	(((ah_wifi_cb_t *)(_cb))->ctx_buf_cb.buf = (_buf))

#define AH_GET_CTX_BUF_CB(_cb) \
	(((ah_wifi_cb_t *)(_cb))->ctx_buf_cb.buf)


/*************************************************************************
 * End of rx air time normalization
 *************************************************************************/

/* Convert RSSI to dbm: only true for Atheros chip set */
#define AH_RSSI_TO_DBM(_rssi) \
	((int)(_rssi) - 95)
/* Convert dbm to RSSI: only true for Atheros chip set */
#define AH_DBM_TO_RSSI(_dbm) \
	((int)(_dbm) + 95)

#if defined(AH_SUPPORT_LCS)
/* LCS Convert RSSI to dbm */
#define AH_LCS_RSSI_TO_DBM(_rssi, _noise_floor) \
	((int)(_rssi) + (_noise_floor))
/* LCS Convert dbm to RSSI */
#define AH_LCS_DBM_TO_RSSI(_dbm, _noise_floor) \
	((int)(_dbm) - (_noise_floor))
#endif



/*
 * return a '\0' tailed string for default Hive-Virtual-Interface
 */
static inline char *default_hvi_name(void)
{
	return "mgt0";
}

// These should move to ah_device.h
//
#ifdef AH_RADIO_BCM /* BCM */

#define AH_IF_RADIO_PREFIX         "wifi"
#define AH_IF_VAP_PREFIX_0         "wifi0."
#define AH_IF_VAP_PREFIX_1         "wifi1."
#define AH_IF_RADIO_DEV_0          "wifi0"
#define AH_IF_RADIO_DEV_1          "wifi1"

#define AH_IF_RADIO_0              "wifi0"
#define AH_IF_RADIO_1              "wifi1"

#define AH_IF_VAP_0                "wifi0.1"
#define AH_IF_VAP_1                "wifi1.1"

#ifdef AH_SUPPORT_WPA_SUPP_WIFI
#define AH_IF_VAP_0_2           "wifi0.2"
#define AH_IF_VAP_1_2           "wifi1.2"
#endif

#define AH_RADIO_IFNAME    "wifi%d"

#else /* ATH */
#define AH_IF_RADIO_PREFIX         "wifi"
#define AH_IF_VAP_PREFIX_0         "wifi0."
#define AH_IF_VAP_PREFIX_1         "wifi1."
#define AH_IF_RADIO_DEV_0          "wifi0"
#define AH_IF_RADIO_DEV_1          "wifi1"

#define AH_IF_RADIO_0              "wifi0"
#define AH_IF_RADIO_1              "wifi1"

#define AH_IF_VAP_0                "wifi0.1"
#define AH_IF_VAP_1                "wifi1.1"

#ifdef AH_SUPPORT_WPA_SUPP_WIFI
#define AH_IF_VAP_0_2           "wifi0.2"
#define AH_IF_VAP_1_2           "wifi1.2"
#endif

#define AH_IF_RADIO_PREFIX_QCA         "wifi"
#endif

#define AH_IF_MGT0                 default_hvi_name()

#ifdef AH_VPN_ENABLE
#define AH_IF_TUNNEL               "tunnel"
#endif
#define AH_IF_ETH0_PREFIX          "eth"
#define AH_IF_ETH0                 "eth0"
#define AH_IF_ETH1                 "eth1"
#ifdef AH_SUPPORT_INTERFACE_EMU
#define AH_IF_ETH2                 "eth2"
#define AH_IF_ETH3                 "eth3"
#define AH_IF_ETH4                 "eth4"
#endif


#define AH_IF_FASTETHERNET0        "eth0"
#define AH_IF_FASTETHERNET1        "eth1"
#ifdef AH_SUPPORT_INTERFACE_EMU
#define AH_IF_FASTETHERNET2        "eth2"
#define AH_IF_FASTETHERNET3        "eth3"
#define AH_IF_FASTETHERNET4        "eth4"
#endif

#define AH_IF_FASTETHERNET_PREFIX  "eth"
#define AH_IF_GIGAETHERNET_PREFIX  "eth"
#define AH_IF_GIGAETHERNET_HM_PREFIX "eth"
#define AH_IF_NETIF_PREFIX         "eth"


#define AH_IF_MANAGEMENT           "mgt"
#define AH_IF_MANAGEMENT_0         "mgt0."
#define AH_IF_MANAGEMENT0          "mgt0"
#define AH_IF_RED0                 "red0"
#define AH_IF_AGG0                 "agg0"
#define AH_IF_PPP0                 "ppp0"
#ifdef AH_SUPPORT_USBNET
#define AH_IF_USB_PREFIX           "usb"
#define AH_IF_USB0                 "usb0"
#endif
#define AH_IF_BGD_PREFIX           "bgd0."
#define AH_IF_USBNET_PREFIX        "usbnet"
#define AH_IF_USBNET0              "usbnet0"
#define AH_IF_LAN_PREFIX           "vlan"



/* ip is in network order */
#define AH_IN_MULTICAST(ip) (((ip) & htonl(0xf0000000)) == htonl(0xe0000000))

#define AH_IPV4_LINK_LOCAL_SUBNET 0xA9FE0000 // 169.254.0.0
#define AH_IPV4_LINK_LOCAL_MASK   0xFFFF0000 // slash 16
/* ip is big endian format */
#define AH_IS_LINK_LOCAL_ADDR(ip)               \
	(((ip) & AH_IPV4_LINK_LOCAL_MASK) == AH_IPV4_LINK_LOCAL_SUBNET)

/* RFC 1918 "Address Allocation for Private Internets" defines the IPv4
 * private address space as the following:
 *
 * 10.0.0.0 - 10.255.255.255 (10/8 prefix)
 * 172.16.0.0.0 - 172.31.255.255 (172.16/12 prefix)
 * 192.168.0.0 - 192.168.255.255 (192.168/16 prefix)
 */
#define AH_IS_IPV4_PRIVATE_ADDRESS(a) \
	((((unsigned char *)(a))[0] == 10) || \
	 ((((unsigned char *)(a))[0] == 172) && \
	  (((unsigned char *)(a))[1] >= 16) && \
	  (((unsigned char *)(a))[1] < 32)) || \
	 ((((unsigned char *)(a))[0] == 192) && \
	  (((unsigned char *)(a))[1] == 168)))

#endif /* _AH_NET_H_ */
