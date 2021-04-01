/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2021 Oxide Computer Company
 */
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/atomic.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/cpuvar.h>
#include <sys/pci.h>
#include <sys/sysmacros.h>
#include <sys/mac.h>
#include <sys/mac_ether.h>
#include <sys/mac_provider.h>
#include <sys/pattr.h>
#include <sys/strsun.h>
#include <sys/ethernet.h>
#include <sys/vlan.h>
#include <sys/utsname.h>
#include "ena_hw.h"

#ifndef _ENA_H
#define _ENA_H

/*
 * AWS ENA Ethernet Driver
 */

#ifdef __cplusplus
extern "C" {
#endif

#define ENA_MODULE_NAME	"ena"

#define ENA_MODULE_VER_MAJOR	1
#define ENA_MODULE_VER_MINOR	0
#define ENA_MODULE_VER_SUBMINOR	0

#define	ENA_REG_NUMBER	1

#define	ENA_POLL_NULL	-1

#define	ENA_RX_BUF_IPHDR_ALIGNMENT	2

/* TODO linux set to 32, setting to 16 for debugging */
#define	ENA_ADMINQ_DEPTH		16
#define	ENA_AENQ_NUM_DESCS		16

/*
 * Property macros.
 */
#define	ENA_PROP_RXQ_NUM_DESCS	"rx_queue_num_descs"
#define	ENA_PROP_TXQ_NUM_DESCS	"tx_queue_num_descs"

#define ENA_PROP_MIN_RXQ_NUM_DESCS	64
#define ENA_PROP_MIN_TXQ_NUM_DESCS	64

#define	ENA_DMA_BIT_MASK(x)	((1ULL << (x)) - 1ULL)
#define	ENA_DMA_VERIFY_ADDR(ena, phys_addr)				\
	VERIFY3U(ENA_DMA_BIT_MASK((ena)->ena_dma_width) & (phys_addr), \
	    ==, (phys_addr))

typedef struct ena_dma_buf {
	caddr_t			edb_va;
	size_t			edb_len;
	 /*
	  * The length given by DMA engine, kept around for debugging
	  * purposes.
	  */
	size_t			edb_real_len;
	size_t			edb_used_len;
	ddi_acc_handle_t	edb_acc_hdl;
	ddi_dma_handle_t	edb_dma_hdl;
	const ddi_dma_cookie_t	*edb_cookie;
} ena_dma_buf_t;

/*
 * We always sync the entire range, and therefore expect success.
 */
#ifdef DEBUG
#define	ENA_DMA_SYNC(buf, flag) ASSERT0(ddi_dma_sync((buf).edb_dma_hdl, 0, 0, \
                                   (flag)))
#else  /* DEBUG */
#define	ENA_DMA_SYNC(buf, flag) ((void)ddi_dma_sync((buf).edb_dma_hdl, 0, 0, \
                                   (flag)))
#endif

typedef struct ena_aenq_grpstr {
	enahw_aenq_groups_t	eag_type;
	const char		*eag_str;
} ena_aenq_grpstr_t;

typedef struct ena_aenq_synstr {
	enahw_aenq_syndrome_t	eas_type;
	const char		*eas_str;
} ena_aenq_synstr_t;

typedef void (*ena_aenq_hdlr_t)(void *data, enahw_aenq_desc_t *desc);

typedef struct ena_aenq {
	enahw_aenq_desc_t	*eaenq_descs;
	ena_dma_buf_t		eaenq_dma;
	ena_aenq_hdlr_t		eaenq_hdlrs[ENAHW_AENQ_GROUP_NUM];
	uint16_t		eaenq_num_descs;
	uint16_t		eaenq_head;
	uint8_t			eaenq_phase;
} ena_aenq_t;

/*
 * TODO document/rename all
 *
 * TODO it seems that the common/Linux code uses separate types for
 * the various submission/completion queues (admin, I/O, etc). It
 * would be nice if there was a shared CQ/SQ type.
 *
 * ena_com_admin_sq
 */
typedef struct ena_admin_sq {
	enahw_cmd_desc_t	*eas_entries;
	ena_dma_buf_t		eas_dma;
	uint32_t		*eas_dbaddr; /* alias db_addr */
	uint16_t		eas_head; /* TODO not really used? */
	uint16_t		eas_tail;
	uint8_t			eas_phase;
} ena_admin_sq_t;

/*
 * TODO doc
 *
 * ena_com_admin_cq
 */
typedef struct ena_admin_cq {
	enahw_resp_desc_t	*eac_entries;
	ena_dma_buf_t		eac_dma;
	uint16_t		eac_head;
	uint8_t			eac_phase;
} ena_admin_cq_t;

/*
 * TODO doc
 * TODO mutex?
 *
 * ena_com_admin_queue
 */
typedef struct ena_adminq {
	uint16_t		ea_qlen;
	boolean_t		ea_poll_mode;
	uint16_t		ea_cmd_idx;
	uint16_t		ea_pending_cmds;

	ena_admin_sq_t		ea_sq;
	ena_admin_cq_t		ea_cq;

	struct ena_adminq_stats {
		uint64_t cmds_fail;
		uint64_t cmds_submitted;
		uint64_t cmds_success;
		uint64_t queue_full;
	} ea_stats;
} ena_adminq_t;

/*
 * Attach Sequencing
 * -----------------
 *
 * Most drivers implement their attach/detach/cleanup functions as a
 * long stream of function calls used to allocate and initialize
 * resources in an order determined by the device's programming manual
 * combined with any requirements imposed by the kernel and its
 * relevant modules. These functions can become quite long, making it
 * hard to see the order in which steps are taken, and even harder to
 * tell if detach/cleanup undoes them in the correct order, or even if
 * it undoes them at all! The only sure way to understand the flow is
 * to take good notes while closely inspecting each line of code in
 * the attach/deatch callbacks. Even armed with good notes, it's easy
 * for attach and detach to get out of sync.
 *
 * Some more recent drivers have improved on this situation by using a
 * bit vector to track the sequence of events in attach/detach. Each
 * bit is declared in an enum, in the same order it is expected attach
 * would run, and thus detach would run in the exact opposite order.
 * This has three main benefits:
 *
 *    1. it makes it easier to determine sequence order at a
 *       glance,
 *
 *    2. it gives a better idea of what state the device is in during
 *       debugging (the sequence bit vector is kept with the instance
 *       state), and
 *
 *    3. the deatch function can verify that all sequence bits are
 *       cleared, indicating that everything done in attach is
 *       successfully undone.
 *
 * These are great improvements. However, the attach/detach functions
 * can still become unruly, and there is still no guarantee that the
 * detach is done in opposite order of attach (this is not always
 * strictly required, but is probably the best way to write deatch).
 * There is still a lot of boilerplate and chances for programmer
 * error.
 *
 * The ena driver takes the sequence idea even further, creating a
 * descriptor table of the attach sequence (ena_attach_tbl). This
 * table is used by attach/detach to generically, declaratively, and
 * progromatically enforce the precise sequence order and verify that
 * anything that is done is undone. This provides several benefits:
 *
 *    o Correct order is enforced implicitly by the descriptor table.
 *      It is impossible for the detach sequence to run in any other
 *      order other than opposite that of attach.
 *
 *    o It is obvious what the precise attach sequence is. While the
 *      enum helps a lot with this it doesn't prevent programmer
 *      error. With the sequence defined as a declarative table it
 *      makes it easy for the programmer to see the order and know
 *      it's followed exactly.
 *
 *    o It is impossible to modify the attach sequence without also
 *      specifying a callback for its dual in the deatch sequence.
 *
 *    o Common and repitive code like error checking, logging, and bit
 *      vector modification is eliminated and centralized, again
 *      reducing the chance of programmer error.
 */
typedef enum ena_attach_seq {
	ENA_ATTACH_FMA = 1,	/* FMA init */
	ENA_ATTACH_PCI,		/* PCI config space */
	ENA_ATTACH_REGS,	/* BAR mapping */
	ENA_ATTACH_DEV_INIT,	/* ENA device initialization */
	ENA_ATTACH_READ_CONF,	/* Read driver conf file */
	ENA_ATTACH_INTR_ALLOC,	/* interrupt handles allocated */
	ENA_ATTACH_INTR_HDLRS,	/* intr handlers set */
	ENA_ATTACH_TXQS_ALLOC,	/* Tx Queues allocated */
	ENA_ATTACH_RXQS_ALLOC,	/* Tx Queues allocated */
	ENA_ATTACH_MAC_REGISTER,/* registered with mac */
	ENA_ATTACH_INTRS_ENABLE,/* interrupts are enabled */
	ENA_ATTACH_END
} ena_attach_seq_t;

#define	ENA_ATTACH_SEQ_FIRST	(ENA_ATTACH_FMA)
#define	ENA_ATTACH_NUM_ENTRIES	(ENA_ATTACH_END - 1)

/*
 * TODO might want to change ena_attach_fn to return int for cases
 * where failing calls have specific error messages
 */
struct ena;
typedef boolean_t (*ena_attach_fn_t)(struct ena *);
typedef int (*ena_cleanup_fn_t)(struct ena *);

typedef struct ena_attach_desc {
	ena_attach_seq_t ead_seq;
	const char *ead_name;
	ena_attach_fn_t ead_attach_fn;
	boolean_t ead_attach_hard_fail;
	ena_cleanup_fn_t ead_cleanup_fn;
	boolean_t ead_cleanup_hard_fail;
} ena_attach_desc_t;

/*
 * Start of Tx structures.
 *
 * TODO linux cache line aligned this, should I worry about that?
 */
typedef struct ena_io_sq {
	uint16_t eis_qlen;
	uint16_t eis_qidx;
	uint8_t	eis_desc_sz;	/* Will vary depending on Tx/Rx. */
	/*
	 * For now, in order to share SQ structure across Tx/Rx, we
	 * use a generic pointer for the descs. It will point to
	 * either enahw_tx_desc_t or enahw_rx_desc_t.
	 */
	void *eis_descs;

	boolean_t eis_is_tx;

} ena_io_sq_t;

typedef enum {
	ENA_TCB_NONE,
	ENA_TCB_COPY
} ena_tcb_type_t;

/*
 * The TCB is used to track information relating to the Tx of a
 * packet. At the moment we only support pure copy Tx.
 */
typedef struct ena_tx_control_block {
	mblk_t		*etcb_mp;
	ena_tcb_type_t	etcb_type;
	ena_dma_buf_t	etcb_dma;
} ena_tx_control_block_t;

/* TODO finer grained states under host alloc? */
typedef enum ena_txq_state {
	ENA_TXQ_STATE_NONE		= 0,
	ENA_TXQ_STATE_HOST_ALLOC	= 1 << 0,
	ENA_TXQ_STATE_CQ_CREATED	= 1 << 1,
	ENA_TXQ_STATE_SQ_CREATED	= 1 << 2,
	ENA_TXQ_STATE_READY		= 1 << 3, /* TxQ ready and waiting */
	ENA_TXQ_STATE_RUNNING		= 1 << 4, /* intrs enabled */
	ENA_TXQ_STATE_BLOCKED		= 1 << 5, /* out of descs */
} ena_txq_state_t;

/* TODO doc
 *
 * One txq per Tx SQ+CQ.
 *
 * TODO create/use locks, document lock usage.
 */
typedef struct ena_txq {
	/*
	 * Everything not labeled WO (Write Once) is protected by this
	 * lock.
	 */
	kmutex_t		et_lock;

	struct ena		*et_ena; /* WO */
	mac_ring_handle_t	et_mrh;	 /* WO */
	uint64_t		et_m_gen_num;
	ena_txq_state_t		et_state; /* TODO use atomics */
	uint16_t		et_intr_vector; /* TODO i40e uses uint32_t? */

	/* ena_io_sq_t et_sq; */

	enahw_tx_desc_t		*et_sq_descs; /* desc space */
	ena_dma_buf_t		et_sq_dma;
	uint16_t		et_sq_num_descs;   /* total descs */
	uint16_t		et_sq_avail_descs; /* available descs */
	uint16_t		et_sq_tail_idx;  /* next free desc idx */
	uint16_t		et_sq_phase; /* phase of desc: 0/1 */
	uint16_t		et_sq_hw_index;
	uint32_t		*et_sq_db_addr; /* doorbell address */

	ena_tx_control_block_t	*et_tcbs;    /* TCBs, 1:1 mapping with descs */

	enahw_tx_cdesc_t	*et_cq_descs;
	ena_dma_buf_t		et_cq_dma;
	uint16_t		et_cq_num_descs;
	uint16_t		et_cq_head_idx;
	uint16_t		et_cq_phase;
	uint16_t		et_cq_hw_index;
	uint32_t		*et_cq_unmask_addr; /* unmask interrupt */
	uint32_t		*et_cq_head_db_addr; /* head doorbell */
	uint32_t		*et_cq_numa_addr;    /* numa node */

	kmutex_t		et_stats_lock;
	struct ena_txq_stats_t {
		kstat_named_t	etxs_hck_meoifail;
		kstat_named_t	etxs_blocked;
		kstat_named_t	etxs_recycled_descs;

		kstat_named_t	etxs_bytes;
		kstat_named_t	etxs_packets;
	} et_stats;
} ena_txq_t;

typedef enum ena_rxq_state {
	ENA_RXQ_STATE_NONE		= 0,
	ENA_RXQ_STATE_HOST_ALLOC	= 1 << 0,
	ENA_RXQ_STATE_CQ_CREATED	= 1 << 1,
	ENA_RXQ_STATE_SQ_CREATED	= 1 << 2,
	ENA_RXQ_STATE_READY		= 1 << 3, /* RxQ ready and waiting */
	ENA_RXQ_STATE_RUNNING		= 1 << 4, /* intrs enabled */
	ENA_RXQ_STATE_BLOCKED		= 1 << 5, /* out of descs */
} ena_rxq_state_t;

typedef struct ena_rx_ctrl_block {
	mblk_t		*ercb_mp;
	ena_dma_buf_t	ercb_dma;
	uint8_t		ercb_offset;
	uint16_t	ercb_length;
} ena_rx_ctrl_block_t;

typedef enum {
	ENA_RXQ_MODE_POLLING	= 1,
	ENA_RXQ_MODE_INTR	= 2,
} ena_rxq_mode_t;

typedef struct ena_rxq {
	kmutex_t		er_lock;

	struct ena		*er_ena; /* WO */
	mac_ring_handle_t	er_mrh;
	uint64_t		er_m_gen_num;
	ena_rxq_state_t		er_state;
	uint16_t		er_intr_vector;
	ena_rxq_mode_t		er_mode;

	/* TODO figure out descriptor array */
	enahw_rx_desc_t		*er_sq_descs;
	ena_dma_buf_t		er_sq_dma;
	uint16_t		er_sq_num_descs;
	uint16_t		er_sq_avail_descs; /* available descs */
	uint16_t		er_sq_tail_idx;  /* next free desc idx */
	uint16_t		er_sq_phase; /* phase of desc: 0/1 */
	uint16_t		er_sq_hw_index;
	uint32_t		*er_sq_db_addr; /* doorbell address */

	enahw_rx_cdesc_t	*er_cq_descs;
	ena_dma_buf_t		er_cq_dma;
	uint16_t		er_cq_num_descs;
	uint16_t		er_cq_head_idx;
	uint16_t		er_cq_phase;
	uint16_t		er_cq_hw_index;
	uint32_t		*er_cq_unmask_addr;
	uint32_t		*er_cq_head_db_addr;
	uint32_t		*er_cq_numa_addr;

	ena_rx_ctrl_block_t	*er_rcbs;

	kmutex_t		er_stats_lock;
	struct ena_rxq_stats_t {
		kstat_named_t	erxs_packets;
		kstat_named_t	erxs_intr_packets;
		kstat_named_t	erxs_poll_packets;

		kstat_named_t	erxs_bytes;
		kstat_named_t	erxs_intr_bytes;
		kstat_named_t	erxs_poll_bytes;
	} er_stats;

} ena_rxq_t;

typedef enum ena_state {
	ENA_STATE_PRIMORDIAL	= 1 << 0,
	ENA_STATE_RUNNING	= 1 << 1,
} ena_state_t;

typedef struct ena_basic_stats {
	uint64_t	ebs_tx_bytes;
	uint64_t	ebs_tx_pkts;
	uint64_t	ebs_tx_drops;

	uint64_t	ebs_rx_bytes;
	uint64_t	ebs_rx_pkts;
	uint64_t	ebs_rx_drops;
} ena_basic_stats_t;

/*
 * This structure contains the per-instance (PF of VF) state of the
 * device.
 */
typedef struct ena {
	dev_info_t		*ena_dip;
	int			ena_instance;

	/*
	 * Global lock, used to synchronize administration changes to
	 * the ena_t. This lock should not be held in the datapath.
	 */
	kmutex_t		ena_lock;
	ena_attach_seq_t	ena_attach_seq;
	ena_state_t		ena_state;

	/*
	 * PCI config space and BAR handle.
	 */
	ddi_acc_handle_t	ena_pci_hdl;
	off_t			ena_reg_size;
	caddr_t			ena_reg_base; /* alias reg_bar */
	ddi_device_acc_attr_t	ena_reg_attr;
	ddi_acc_handle_t	ena_reg_hdl;

	/*
	 * Vendor information.
	 */
	uint16_t		ena_pci_vid;
	uint16_t		ena_pci_did;
	uint8_t			ena_pci_rev;
	uint16_t		ena_pci_svid;
	uint16_t		ena_pci_sdid;

	/*
	 * FMA state
	 */
	int			ena_fm_caps;

	/*
	 * Interrupts
	 */
	uint16_t		ena_num_intrs;
	ddi_intr_handle_t	*ena_intr_handles;
	size_t			ena_intr_handles_sz;
	int			ena_intr_caps;
	uint_t			ena_intr_pri;

	mac_handle_t		ena_mh;

	size_t			ena_page_sz;

	/*
	 * The MTU and data layer frame sizes.
	 */
	uint32_t		ena_mtu;
	uint32_t		ena_max_frame_hdr;
	uint32_t		ena_max_frame_total;

	/* The size (in bytes) of the Rx/Tx data buffers. */
	uint32_t		ena_tx_buf_sz;
	uint32_t		ena_rx_buf_sz;

	/* The number of descriptors per Rx/Tx queue. */
	uint16_t		ena_rxq_num_descs;
	uint16_t		ena_txq_num_descs;

	/* The Rx/Tx data queues (rings). */
	ena_rxq_t		*ena_rxqs;
	uint16_t		ena_num_rxqs;
	ena_txq_t		*ena_txqs;
	uint16_t		ena_num_txqs;

	/* These statistics are device-wide. */
	ena_basic_stats_t	ena_basic_stats;

	/*
	 * Device information controlled by common code.
	 */
	/* struct ena_com_dev	ena_com_dev; */

	ena_adminq_t		ena_aq;
	ena_aenq_t		ena_aenq;
	ena_dma_buf_t		ena_host_info;

	/*
	 * Hardware info
	 */
	uint32_t		ena_supported_features;
	uint8_t			ena_dma_width;
	boolean_t		ena_link_up;
	boolean_t		ena_link_autoneg;
	boolean_t		ena_link_full_duplex;
	link_duplex_t		ena_link_duplex;
	uint64_t		ena_link_speed_mbits;
	enahw_link_speeds_t	ena_link_speeds;
	link_state_t		ena_link_state;

	uint32_t		ena_tx_max_sq_num;
	uint32_t		ena_tx_max_sq_num_descs;
	uint32_t		ena_tx_max_cq_num;
	uint32_t		ena_tx_max_cq_num_descs;
	uint16_t		ena_tx_max_desc_per_pkt;
	uint32_t		ena_tx_max_hdr_len;

	uint32_t		ena_rx_max_sq_num;
	uint32_t		ena_rx_max_sq_num_descs;
	uint32_t		ena_rx_max_cq_num;
	uint32_t		ena_rx_max_cq_num_descs;
	uint16_t		ena_rx_max_desc_per_pkt;

	/* This is calculated from the Rx/Tx queue nums. */
	uint16_t		ena_max_io_queues;

	boolean_t		ena_rx_l3_ipv4_csum;
	boolean_t		ena_rx_l4_ipv4_full_csum;

	uint32_t		ena_max_mtu;
	uint8_t			ena_mac_addr[ETHERADDRL];
} ena_t;

/*
 * The driver soft state holds ena_t instances.
 */
void *ena_state;

/*
 * Logging functions.
 */
extern void ena_err(const ena_t *, const char *, ...);
extern void ena_log(const ena_t *, const char *, ...);
extern void ena_dbg(const ena_t *, const char *, ...);
extern void ena_xxx(const ena_t *, const char *, ...);

extern uint32_t ena_hw_bar_read32(const ena_t *, const uint16_t);
extern uint32_t ena_hw_abs_read32(const ena_t *, uint32_t *);
extern void ena_hw_bar_write32(const ena_t *, const uint16_t, const uint32_t);
extern void ena_hw_abs_write32(const ena_t *, uint32_t *, const uint32_t);
extern void ena_hw_update_reg_cache(const ena_t *);

/*
 * DMA
 */
extern void ena_dma_adminq_attr(ena_t *, ddi_dma_attr_t *, size_t);
extern void ena_dma_io_attr(ena_t *ena, ddi_dma_attr_t *attrp, size_t);
extern void ena_dma_acc_attr(ena_t *, ddi_device_acc_attr_t *);
extern void ena_dma_io_acc_attr(ena_t *, ddi_device_acc_attr_t *);
extern boolean_t ena_dma_alloc(ena_t *, ena_dma_buf_t *, ddi_dma_attr_t *,
    ddi_device_acc_attr_t *, size_t, boolean_t);
extern void ena_dma_free(ena_dma_buf_t *);
extern void ena_set_dma_addr(const ena_t *, const uint64_t, enahw_addr_t *);
extern void ena_set_dma_addr_values(const ena_t *, const uint64_t, uint32_t *,
    uint16_t *);

/*
 * Interrupts
 */
extern boolean_t ena_intr_add_handlers(ena_t *);
extern int ena_intr_remove_handlers(ena_t *);
extern void ena_tx_intr_work(ena_txq_t *);
extern void ena_rx_intr_work(ena_rxq_t *);
extern void ena_aenq_work(ena_t *);
extern int ena_intrs_disable(ena_t *);
extern boolean_t ena_intrs_enable(ena_t *);

/*
 * MAC
 */
extern boolean_t ena_mac_register(ena_t *);
extern int ena_mac_unregister(ena_t *);
extern void ena_ring_tx_stop(mac_ring_driver_t);
extern int ena_ring_tx_start(mac_ring_driver_t, uint64_t);
extern mblk_t *ena_ring_tx(void *, mblk_t *);
extern void ena_ring_rx_stop(mac_ring_driver_t);
extern int ena_ring_rx_start(mac_ring_driver_t rh, uint64_t gen_num);
extern int ena_m_stat(void *, uint_t, uint64_t *);
extern mblk_t *ena_ring_rx_poll(void *, int);
extern int ena_ring_rx_stat(mac_ring_driver_t, uint_t, uint64_t *);
extern int ena_ring_tx_stat(mac_ring_driver_t, uint_t, uint64_t *);

/*
 * Admin API
 */
extern int ena_admin_submit_cmd(ena_t *, enahw_cmd_desc_t *);
extern int ena_admin_read_resp(ena_t *, enahw_resp_desc_t *);
extern int ena_free_host_info(ena_t *);
extern boolean_t ena_init_host_info(ena_t *);
extern int ena_create_cq(ena_t *, uint16_t, uint64_t, boolean_t, uint32_t,
    uint16_t *, uint32_t **, uint32_t **, uint32_t **);
extern int ena_destroy_cq(ena_t *, uint16_t);
extern int ena_create_sq(ena_t *, uint16_t, uint64_t, boolean_t, uint16_t,
    uint16_t *, uint32_t **);
extern int ena_destroy_sq(ena_t *, uint16_t, boolean_t);
extern int ena_set_feature(ena_t *, enahw_cmd_desc_t *,
    enahw_resp_desc_t *, const enahw_feature_id_t, const uint8_t);
extern int ena_get_feature(ena_t *, enahw_resp_desc_t *,
    const enahw_feature_id_t, const uint8_t);
extern boolean_t ena_setup_aenq(ena_t *);
extern void ena_admin_get_basic_stats(ena_t *);

extern void ena_link_status_update(ena_t *);

extern ena_aenq_grpstr_t ena_groups_str[];
extern ena_aenq_synstr_t ena_syndrome_str[];

#endif	/* _ENA_H */
