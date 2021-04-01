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

/*
 * This file declares all constants and structures dealing with the
 * physical ENA device. It is based on the ena_com code of the public
 * Linux and FreeBSD drivers.
 */
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/debug.h>
#include <sys/ethernet.h>

#include "ena_linux.h"

#ifndef _ENA_HW_H
#define _ENA_HW_H

/*
 * Generate a 32-bit bitmask where the bits between high (inclusive)
 * and low (inclusive) are set to 1.
 */
#define	GENMASK(h, l)	(((~0U) - (1U << (l)) + 1) & (~0U >> (32 - 1 - (h))))

/*
 * Generate a 64-bit bitmask where bit b is set to 1.
 */
#define	BIT(b)	(1UL << (b))

#define	ENAHW_DMA_ADMINQ_ALIGNMENT	8

/*
 * BAR0 register offsets.
 *
 * Any register not defined in the common code was marked as a gap,
 * using the hex address of the register as suffix. The idea is to
 * make it clear where the gaps are and allow the
 * ena_hw_update_reg_cache() function to display any bits stored in
 * these gaps in case they turn out to be interesting later.
 */
#define	ENAHW_REG_VERSION		0x0
#define ENAHW_REG_CONTROLLER_VERSION	0x4
#define ENAHW_REG_CAPS			0x8
#define ENAHW_REG_CAPS_EXT		0xc
#define ENAHW_REG_ASQ_BASE_LO		0x10
#define ENAHW_REG_ASQ_BASE_HI		0x14
#define ENAHW_REG_ASQ_CAPS		0x18
#define	ENAHW_REG_GAP_1C		0x1c
#define ENAHW_REG_ACQ_BASE_LO		0x20
#define ENAHW_REG_ACQ_BASE_HI		0x24
#define ENAHW_REG_ACQ_CAPS		0x28
#define ENAHW_REG_ASQ_DB		0x2c
#define ENAHW_REG_ACQ_TAIL		0x30
#define ENAHW_REG_AENQ_CAPS		0x34
#define ENAHW_REG_AENQ_BASE_LO		0x38
#define ENAHW_REG_AENQ_BASE_HI		0x3c
#define ENAHW_REG_AENQ_HEAD_DB		0x40
#define ENAHW_REG_AENQ_TAIL		0x44
#define	ENAHW_REG_GAP_48		0x48
#define ENAHW_REG_INTERRUPT_MASK	0x4c
#define	ENAHW_REG_GAP_50		0x50
#define ENAHW_REG_DEV_CTL		0x54
#define ENAHW_REG_DEV_STS		0x58
#define ENAHW_REG_MMIO_REG_READ		0x5c
#define ENAHW_REG_MMIO_RESP_LO		0x60
#define ENAHW_REG_MMIO_RESP_HI		0x64
#define ENAHW_REG_RSS_IND_ENTRY_UPDATE	0x68
#define ENAHW_NUM_REGS		((ENAHW_REG_RSS_IND_ENTRY_UPDATE / 4) + 1)

/* Version (Register 0x0) */
#define	ENAHW_VERSION_MINOR_VERSION_MASK	0xff
#define	ENAHW_VERSION_MAJOR_VERSION_SHIFT	8
#define	ENAHW_VERSION_MAJOR_VERSION_MASK	0xff00

/* Device Caps (Register 0x8) */
#define ENAHW_CAPS_CONTIGUOUS_QUEUE_REQUIRED_MASK        0x1
#define ENAHW_CAPS_RESET_TIMEOUT_SHIFT                   1
#define ENAHW_CAPS_RESET_TIMEOUT_MASK                    0x3e
#define ENAHW_CAPS_RESET_TIMEOUT(v)		    \
	((v) & ENAHW_CAPS_RESET_TIMEOUT_MASK) >>    \
	ENAHW_CAPS_RESET_TIMEOUT_SHIFT
#define ENAHW_CAPS_DMA_ADDR_WIDTH_SHIFT                  8
#define ENAHW_CAPS_DMA_ADDR_WIDTH_MASK                   0xff00
#define ENAHW_CAPS_DMA_ADDR_WIDTH(v)		     \
	((v) & ENAHW_CAPS_DMA_ADDR_WIDTH_MASK) >>    \
	ENAHW_CAPS_DMA_ADDR_WIDTH_SHIFT
#define ENAHW_CAPS_ADMIN_CMD_TO_SHIFT                    16
#define ENAHW_CAPS_ADMIN_CMD_TO_MASK                     0xf0000

enum enahw_reset_reason_types {
	ENAHW_RESET_NORMAL                       = 0,
	ENAHW_RESET_KEEP_ALIVE_TO                = 1,
	ENAHW_RESET_ADMIN_TO                     = 2,
	ENAHW_RESET_MISS_TX_CMPL                 = 3,
	ENAHW_RESET_INV_RX_REQ_ID                = 4,
	ENAHW_RESET_INV_TX_REQ_ID                = 5,
	ENAHW_RESET_TOO_MANY_RX_DESCS            = 6,
	ENAHW_RESET_INIT_ERR                     = 7,
	ENAHW_RESET_DRIVER_INVALID_STATE         = 8,
	ENAHW_RESET_OS_TRIGGER                   = 9,
	ENAHW_RESET_OS_NETDEV_WD                 = 10,
	ENAHW_RESET_SHUTDOWN                     = 11,
	ENAHW_RESET_USER_TRIGGER                 = 12,
	ENAHW_RESET_GENERIC                      = 13,
	ENAHW_RESET_MISS_INTERRUPT               = 14,
	ENAHW_RESET_LAST,
};

/*
 * Admin Submission Queue Caps (Register 0x18)
 */
#define	ENAHW_ASQ_CAPS_DEPTH_MASK		0xffff
#define	ENAHW_ASQ_CAPS_ENTRY_SIZE_SHIFT		16
#define	ENAHW_ASQ_CAPS_ENTRY_SIZE_MASK		0xffff0000

#define	ENAHW_ASQ_CAPS_DEPTH(x)	((x) & ENAHW_ASQ_CAPS_DEPTH_MASK)

#define	ENAHW_ASQ_CAPS_ENTRY_SIZE(x)			\
	(((x) << ENAHW_ASQ_CAPS_ENTRY_SIZE_SHIFT) &	\
	    ENAHW_ASQ_CAPS_ENTRY_SIZE_MASK)

/*
 * Admin Completion Queue Caps (Register 0x28)
 */
#define	ENAHW_ACQ_CAPS_DEPTH_MASK	0xffff
#define	ENAHW_ACQ_CAPS_ENTRY_SIZE_SHIFT	16
#define	ENAHW_ACQ_CAPS_ENTRY_SIZE_MASK	0xffff0000

#define	ENAHW_ACQ_CAPS_DEPTH(x)	((x) & ENAHW_ACQ_CAPS_DEPTH_MASK)

#define	ENAHW_ACQ_CAPS_ENTRY_SIZE(x)			\
	(((x) << ENAHW_ACQ_CAPS_ENTRY_SIZE_SHIFT) &	\
	    ENAHW_ACQ_CAPS_ENTRY_SIZE_MASK)

/*
 * Admin Event Notification Queue Caps (Register 0x34)
 */
#define	ENAHW_AENQ_CAPS_DEPTH_MASK		0xffff
#define	ENAHW_AENQ_CAPS_ENTRY_SIZE_SHIFT	16
#define	ENAHW_AENQ_CAPS_ENTRY_SIZE_MASK		0xffff0000

#define	ENAHW_AENQ_CAPS_DEPTH(x) ((x) & ENAHW_AENQ_CAPS_DEPTH_MASK)

#define	ENAHW_AENQ_CAPS_ENTRY_SIZE(x)		     \
	(((x) << ENAHW_AENQ_CAPS_ENTRY_SIZE_SHIFT) & \
	    ENAHW_AENQ_CAPS_ENTRY_SIZE_MASK)

/*
 * Interrupt Mask (Register 0x4c)
 */
#define	ENAHW_INTR_UNMASK	0x0
#define	ENAHW_INTR_MASK		0x1

/*
 * Device Control (Register 0x54)
 */
#define	ENAHW_DEV_CTL_DEV_RESET_MASK		0x1
#define	ENAHW_DEV_CTL_AQ_RESTART_SHIFT		1
#define	ENAHW_DEV_CTL_AQ_RESTART_MASK		0x2
#define	ENAHW_DEV_CTL_QUIESCENT_SHIFT		2
#define	ENAHW_DEV_CTL_QUIESCENT_MASK		0x4
#define	ENAHW_DEV_CTL_IO_RESUME_SHIFT		3
#define	ENAHW_DEV_CTL_IO_RESUME_MASK		0x8
#define	ENAHW_DEV_CTL_RESET_REASON_SHIFT	28
#define	ENAHW_DEV_CTL_RESET_REASON_MASK		0xf0000000

/*
 * Device Status (Register 0x58)
 */
#define	ENAHW_DEV_STS_READY_MASK			0x1
#define	ENAHW_DEV_STS_AQ_RESTART_IN_PROGRESS_SHIFT	1
#define	ENAHW_DEV_STS_AQ_RESTART_IN_PROGRESS_MASK	0x2
#define	ENAHW_DEV_STS_AQ_RESTART_FINISHED_SHIFT		2
#define	ENAHW_DEV_STS_AQ_RESTART_FINISHED_MASK		0x4
#define	ENAHW_DEV_STS_RESET_IN_PROGRESS_SHIFT		3
#define	ENAHW_DEV_STS_RESET_IN_PROGRESS_MASK		0x8
#define	ENAHW_DEV_STS_RESET_FINISHED_SHIFT		4
#define	ENAHW_DEV_STS_RESET_FINISHED_MASK		0x10
#define	ENAHW_DEV_STS_FATAL_ERROR_SHIFT			5
#define	ENAHW_DEV_STS_FATAL_ERROR_MASK			0x20
#define	ENAHW_DEV_STS_QUIESCENT_STATE_IN_PROGRESS_SHIFT	6
#define	ENAHW_DEV_STS_QUIESCENT_STATE_IN_PROGRESS_MASK	0x40
#define	ENAHW_DEV_STS_QUIESCENT_STATE_ACHIEVED_SHIFT	7
#define	ENAHW_DEV_STS_QUIESCENT_STATE_ACHIEVED_MASK	0x80

/*
 * Admin Queue
 */

/* common: ena_admin_aenq_common_desc */
typedef struct enahw_aenq_desc {
	uint16_t	ead_group;
	uint16_t	ead_syndrome;
	uint8_t		ead_flags;
	uint8_t		ead_rsvd1[3];
	uint32_t	ead_ts_low;
	uint32_t	ead_ts_high;

	union {
		uint32_t	raw[12];

		struct {
			uint32_t flags;
		} link_change;

		struct {
			uint32_t rx_drops_low;
			uint32_t rx_drops_high;
			uint32_t tx_drops_low;
			uint32_t tx_drops_high;
		} keep_alive;
	} ead_payload;
} enahw_aenq_desc_t;

CTASSERT(sizeof (enahw_aenq_desc_t) == 64);

#define	ENAHW_AENQ_DESC_PHASE_MASK	BIT(0)

#define	ENAHW_AENQ_DESC_PHASE(desc)		\
	((desc)->ead_flags & ENAHW_AENQ_DESC_PHASE_MASK)

#define	ENAHW_AENQ_LINK_CHANGE_LINK_STATUS_MASK	BIT(0)

/*
 * Asynchronous Event Notification Queue groups.
 *
 * common: ena_admin_aenq_group
 */
typedef enum enahw_aenq_groups {
	ENAHW_AENQ_GROUP_LINK_CHANGE		= 0,
	ENAHW_AENQ_GROUP_FATAL_ERROR		= 1,
	ENAHW_AENQ_GROUP_WARNING		= 2,
	ENAHW_AENQ_GROUP_NOTIFICATION		= 3,
	ENAHW_AENQ_GROUP_KEEP_ALIVE		= 4,
	ENAHW_AENQ_GROUP_NUM			= 5,
} enahw_aenq_groups_t;

/*
 * The reason for ENAHW_AENQ_GROUP_NOFIFICATION.
 *
 * common: ena_admin_aenq_notification_syndrome
 */
typedef enum enahw_aenq_syndrome {
	ENAHW_AENQ_SYNDROME_SUSPEND		= 0,
	ENAHW_AENQ_SYNDROME_RESUME		= 1,
	ENAHW_AENQ_SYNDROME_UPDATE_HINTS	= 2,
	ENAHW_AENQ_SYNDROME_NUM			= 3,
} enahw_aenq_syndrome_t;

/*
 * ENA devices use a 48-bit memory space.
 *
 * common: ena_common_mem_addr
 */
typedef struct enahw_addr {
	uint32_t	ea_low;
	uint16_t	ea_high;
	uint16_t	ea_rsvd; /* MBZ */
} enahw_addr_t;

/* common: ena_admin_ctrl_buff_info */
struct enahw_ctrl_buff {
	uint32_t	ecb_length;
	enahw_addr_t	ecb_addr;
};

/* common: ena_admin_get_set_feature_common_desc */
struct enahw_feat_common {
	/*
	 * 1:0 Select which value you want.
	 *
	 *     0x1 = Current value.
	 *     0x3 = Default value.
	 *
	 *     Note: Linux seems to set this to 0 to get the value,
	 *     not sure if that's a bug or just another way to get the
	 *     current value.
	 *
	 * 7:3 Reserved.
	 */
	uint8_t	efc_flags;

	/* An id from enahw_feature_id_t. */
	uint8_t	efc_id;

	/*
	 * Each feature is versioned, allowing upgrades to the feature
	 * set without breaking backwards compatibility. The driver
	 * uses this field to specify which version it supports
	 * (starting from zero). Linux doesn't document this very well
	 * and sets this value to 0 for most features. We define a set
	 * of macros, underneath the enahw_feature_id_t type, clearly
	 * documenting the version we support for each feature.
	 */
	uint8_t	efc_version;
	uint8_t	efc_rsvd;
};

/* common: ena_admin_get_feat_cmd */
typedef struct enahw_cmd_get_feat {
	struct enahw_ctrl_buff		ecgf_ctrl_buf;
	struct enahw_feat_common	ecgf_comm;
	uint32_t			egcf_unused[11];
} enahw_cmd_get_feat_t;

/*
 * Set the MTU of the device. This value does not include the L2
 * headers or trailers, only the payload.
 *
 * common: ena_admin_set_feature_mtu_desc */
typedef struct enahw_feat_mtu {
	uint32_t efm_mtu;
} enahw_feat_mtu_t;

/* common: ena_admin_set_feature_host_attr_desc */
typedef struct enahw_feat_host_attr {
	enahw_addr_t    efha_os_addr;
	enahw_addr_t    efha_debug_addr;
	uint32_t        efha_debug_sz;
} enahw_feat_host_attr_t;

/*
 * ENAHW_FEAT_AENQ_CONFIG
 *
 * common: ena_admin_feature_aenq_desc
 */
typedef struct enahw_feat_aenq {
	/* Bitmask of AENQ groups this device supports. */
	uint32_t efa_supported_groups;

	/* Bitmask of AENQ groups currently enabled. */
	uint32_t efa_enabled_groups;
} enahw_feat_aenq_t;

/* common: ena_admin_set_feature_cmd */
typedef struct enahw_cmd_set_feat {
	struct enahw_ctrl_buff		ecsf_ctrl_buf;
	struct enahw_feat_common	ecsf_comm;

	union {
		uint32_t			ecsf_raw[11];
		enahw_feat_host_attr_t		ecsf_host_attr;
		enahw_feat_mtu_t		ecsf_mtu;
		enahw_feat_aenq_t		ecsf_aenq;
	} ecsf_feat;
} enahw_cmd_set_feat_t;

/*
 * Used to populate the host information buffer which the Nitro
 * hypervisor supposedly uses for display, debugging, and possibly
 * other purposes.
 *
 * common: ena_admin_host_info
 */
typedef struct enahw_host_info {
	uint32_t	ehi_os_type;
	uint8_t		ehi_os_dist_str[128];
	uint32_t	ehi_os_dist;
	uint8_t		ehi_kernel_ver_str[32];
	uint32_t	ehi_kernel_ver;
	uint32_t	ehi_driver_ver;
	/*
	 * XXX The driver uses this bitstring to declare which network
	 * stack features it has enabled. Given that Linux and FreeBSD
	 * don't use the same values here it would seem this bitstring
	 * is only used for informational purposes. For that reason we
	 * currently leave this zeroed.
	 */
	uint32_t	ehi_supported_net_features[2];
	uint16_t	ehi_ena_spec_version;
	uint16_t	ehi_bdf;
	uint16_t	ehi_num_cpus;
	uint16_t	ehi_rsvd;
	uint32_t	ehi_driver_supported_features;
} enahw_host_info_t;

#define ENAHW_HOST_INFO_MAJOR_MASK				GENMASK(7, 0)
#define ENAHW_HOST_INFO_MINOR_SHIFT				8
#define ENAHW_HOST_INFO_MINOR_MASK				GENMASK(15, 8)
#define ENAHW_HOST_INFO_SUB_MINOR_SHIFT				16
#define ENAHW_HOST_INFO_SUB_MINOR_MASK				GENMASK(23, 16)
#define ENAHW_HOST_INFO_MODULE_TYPE_SHIFT			24
#define ENAHW_HOST_INFO_MODULE_TYPE_MASK			GENMASK(31, 24)
#define ENAHW_HOST_INFO_FUNCTION_MASK				GENMASK(2, 0)
#define ENAHW_HOST_INFO_DEVICE_SHIFT				3
#define ENAHW_HOST_INFO_DEVICE_MASK				GENMASK(7, 3)
#define ENAHW_HOST_INFO_BUS_SHIFT				8
#define ENAHW_HOST_INFO_BUS_MASK				GENMASK(15, 8)
#define ENAHW_HOST_INFO_MUTABLE_RSS_TABLE_SIZE_MASK		BIT(0)
#define ENAHW_HOST_INFO_RX_OFFSET_SHIFT				1
#define ENAHW_HOST_INFO_RX_OFFSET_MASK				BIT(1)
#define ENAHW_HOST_INFO_INTERRUPT_MODERATION_SHIFT		2
#define ENAHW_HOST_INFO_INTERRUPT_MODERATION_MASK		BIT(2)
#define ENAHW_HOST_INFO_RX_BUF_MIRRORING_SHIFT			3
#define ENAHW_HOST_INFO_RX_BUF_MIRRORING_MASK			BIT(3)
#define ENAHW_HOST_INFO_RSS_CONFIGURABLE_FUNCTION_KEY_SHIFT	4
#define ENAHW_HOST_INFO_RSS_CONFIGURABLE_FUNCTION_KEY_MASK	BIT(4)

/*
 * The Linux driver doesn't document what the specification version
 * number controls or the contract around version changes. The best we
 * can do is use the same version that they use and port version
 * changes as they come (the last one was in 2018).
 *
 * common: ENA_COMMON_SPEC_VERSION
 */
#define	ENAHW_SPEC_VERSION_MAJOR	2
#define	ENAHW_SPEC_VERSION_MINOR	0

/* common: ena_admin_os_type */
enum enahw_os_type {
	ENAHW_OS_LINUX		= 1,
	ENAHW_OS_WIN		= 2,
	ENAHW_OS_DPDK		= 3,
	ENAHW_OS_FREEBSD	= 4,
	ENAHW_OS_IPXE		= 5,
	ENAHW_OS_ESXI		= 6,
	ENAHW_OS_GROUPS_NUM	= 6,
};

/*
 * Create Completion Queue
 *
 * A completion queue is where the device writes responses to admin
 * commands and send/recv requests.
 */
typedef struct enahw_cmd_create_cq {
	/*
	 * 7-6	reserved
	 *
	 * 5	interrupt mode: when set the device sends an interrupt
	 *      for each completion, otherwise the driver must poll
	 *      the queue.
	 *
	 * 4-0	reserved
	 */
	uint8_t		ecq_caps_1;

	/*
	 * 7-5	reserved
	 *
	 * 4-0	CQ entry size (in words): the size of a single CQ entry
	 *      in multiples of 32-bit words. Valid values are 4 or 8.
	 */
	uint8_t		ecq_caps_2;

	/* The number of CQ entries, must be a power of 2. */
	uint16_t	ecq_num_descs;

	/* The MSI-X vector assigned to this CQ. */
	uint32_t	ecq_msix_vector;

	/*
	 * The CQ's physical base address. The CQ memory must be
	 * physically contiguous.
	 */
	enahw_addr_t	ecq_addr;
} enahw_cmd_create_cq_t;

#define	ENAHW_CMD_CREATE_CQ_INTERRUPT_MODE_ENABLED_SHIFT	5
#define	ENAHW_CMD_CREATE_CQ_INTERRUPT_MODE_ENABLED_MASK		(BIT(5))
#define	ENAHW_CMD_CREATE_CQ_DESC_SIZE_WORDS_MASK		(GENMASK(4, 0))

#define	ENAHW_CMD_CREATE_CQ_INTERRUPT_MODE_ENABLE(cmd)	\
	((cmd)->ecq_caps_1 |= ENAHW_CMD_CREATE_CQ_INTERRUPT_MODE_ENABLED_MASK)

#define	ENAHW_CMD_CREATE_CQ_DESC_SIZE_WORDS(cmd, val)		\
	(((cmd)->ecq_caps_2) |=					\
	    ((val) & ENAHW_CMD_CREATE_CQ_DESC_SIZE_WORDS_MASK))

/*
 * Destroy Completion Queue
 *
 * common: ena_admin_aq_destroy_cq_cmd
 */
typedef struct enahw_cmd_destroy_cq {
	uint16_t	edcq_idx;
	uint16_t	edcq_rsvd;
} enahw_cmd_destroy_cq_t;

/*
 * common: ena_admin_aq_create_sq_cmd
 */
typedef struct enahw_cmd_create_sq {
	/*
	 * 7-5	direction: 0x1 = Tx, 0x2 = Rx
	 * 4-0	reserved
	 */
	uint8_t		ecsq_dir;
	uint8_t		ecsq_rsvd1;

	/*
	 * 7	reserved
	 *
	 * 6-4	completion policy: How are completion events generated.
	 *
	 *    0x0: Generate a completion event for each SQ descriptor.
	 *
	 *    0x1: Generation a completion event upon request in SQ
	 *         descriptor.
	 *
	 *    0x2: Queue head pointer in host memory is updated per SQ
	 *         descriptor request.
	 *
	 *    0x3: Queue head pointer in host memory is updated for
	 *         each SQ descriptor.
	 *
	 * 3-0	placement policy: Where the descriptor ring and
	 *                        headers reside.
	 *
	 *    0x1: Descriptor ring and headers live in host memory.
	 *
	 *    0x3: Descriptor ring and headers live in device memory,
	 *         also known as low latency queue (LLQ).
	 */
	uint8_t		ecsq_caps_2;

	/*
	 * 7-1	reserved
	 *
	 * 0	physically contiguous: When set indicates the descriptor
	 *                             ring memory is physically contiguous.
         */
	uint8_t		ecsq_caps_3;

	/*
	 * The index of the associated Completion Queue (CQ). The CQ
	 * must be created before the SQ.
	 */
	uint16_t	ecsq_cq_idx;

	/* The number of descriptors in this SQ. */
	uint16_t	ecsq_num_descs;

	/*
	 * The base physical address of the SQ. This should not be set
	 * for LLQ. Must be page aligned.
	 */
	enahw_addr_t	ecsq_base;

	/*
	 * The physical address of the head write-back pointer. Valid
	 * only when the completion policy is set to one of the head
	 * write-back modes (0x2 or 0x3). Must be cacheline size
	 * aligned.
	 */
	enahw_addr_t	ecsq_head_wb;
	uint32_t	ecsq_rsvdw2;
	uint32_t	ecsq_rsvdw3;
} enahw_cmd_create_sq_t;

typedef enum enahw_sq_direction {
	ENAHW_SQ_DIRECTION_TX = 1,
	ENAHW_SQ_DIRECTION_RX = 2,
} enahw_sq_direction_t;

typedef enum enahw_placement_policy {
	/* Descriptors and headers are in host memory. */
	ENAHW_PLACEMENT_POLICY_HOST = 1,

	/*
	 * Descriptors and headers are in device memory (a.k.a Low
	 * Latency Queue).
	 */
	ENAHW_PLACEMENT_POLICY_DEV = 3,
} enahw_placement_policy_t;

/*
 * DESC: Write a CQ entry for each SQ descriptor.
 *
 * DESC_ON_DEMAND: Write a CQ entry when requested by the SQ descriptor.
 *
 * HEAD_ON_DEMAND: Update head pointer when requested by the SQ
 *                 descriptor.
 *
 * HEAD: Update head pointer for each SQ descriptor.
 *
 * */
typedef enum enahw_completion_policy_type {
	ENAHW_COMPLETION_POLICY_DESC		= 0,
	ENAHW_COMPLETION_POLICY_DESC_ON_DEMAND	= 1,
	ENAHW_COMPLETION_POLICY_HEAD_ON_DEMAND	= 2,
	ENAHW_COMPLETION_POLICY_HEAD		= 3,
} enahw_completion_policy_type_t;

#define	ENAHW_CMD_CREATE_SQ_DIR_SHIFT			5
#define	ENAHW_CMD_CREATE_SQ_DIR_MASK			GENMASK(7, 5)
#define	ENAHW_CMD_CREATE_SQ_PLACEMENT_POLICY_MASK	GENMASK(3, 0)
#define	ENAHW_CMD_CREATE_SQ_COMPLETION_POLICY_SHIFT	4
#define	ENAHW_CMD_CREATE_SQ_COMPLETION_POLICY_MASK	GENMASK(6, 4)
#define	ENAHW_CMD_CREATE_SQ_PHYSMEM_CONTIG_MASK		BIT(0)

#define ENAHW_CMD_CREATE_SQ_DIR(cmd, val)				\
	(((cmd)->ecsq_dir) |= (((val) << ENAHW_CMD_CREATE_SQ_DIR_SHIFT) & \
	    ENAHW_CMD_CREATE_SQ_DIR_MASK))

#define	ENAHW_CMD_CREATE_SQ_PLACEMENT_POLICY(cmd, val)		\
	(((cmd)->ecsq_caps_2) |=				\
	    ((val) & ENAHW_CMD_CREATE_SQ_PLACEMENT_POLICY_MASK))

#define	ENAHW_CMD_CREATE_SQ_COMPLETION_POLICY(cmd, val)			\
	(((cmd)->ecsq_caps_2) |=					\
	    (((val) << ENAHW_CMD_CREATE_SQ_COMPLETION_POLICY_SHIFT) &	\
		ENAHW_CMD_CREATE_SQ_COMPLETION_POLICY_MASK))

#define	ENAHW_CMD_CREATE_SQ_PHYSMEM_CONTIG(cmd)				\
	((cmd)->ecsq_caps_3 |= ENAHW_CMD_CREATE_SQ_PHYSMEM_CONTIG_MASK)

typedef struct enahw_cmd_destroy_sq {
	uint16_t	edsq_idx;
	uint8_t		edsq_dir; /* Tx/Rx */
	uint8_t		edsq_rsvd;
} enahw_cmd_destroy_sq_t;

#define	ENAHW_CMD_DESTROY_SQ_DIR_SHIFT	5
#define	ENAHW_CMD_DESTROY_SQ_DIR_MASK	GENMASK(7, 5)

#define ENAHW_CMD_DESTROY_SQ_DIR(cmd, val)				\
	(((cmd)->edsq_dir) |= (((val) << ENAHW_CMD_DESTROY_SQ_DIR_SHIFT) & \
	    ENAHW_CMD_DESTROY_SQ_DIR_MASK))

/* common: ena_admin_aq_get_stats_cmd */
typedef struct enahw_cmd_get_stats {
	struct enahw_ctrl_buff	ecgs_ctrl_buf;
	uint8_t			ecgs_type;
	uint8_t			ecgs_scope;
	uint16_t		ecgs_rsvd;
	uint16_t		ecgs_queue_idx;
	uint16_t		ecgs_device_id;
} enahw_cmd_get_stats_t;

typedef enum enahw_get_stats_type {
	ENAHW_GET_STATS_TYPE_BASIC	= 0,
	ENAHW_GET_STATS_TYPE_EXTENDED	= 1,
	/* extra HW stats for specific network interface */
	ENAHW_GET_STATS_TYPE_ENI	= 2,
} enahw_get_stats_type_t;

typedef enum enahw_get_stats_scope {
	ENAHW_GET_STATS_SCOPE_QUEUE	= 0,
	ENAHW_GET_STATS_SCOPE_ETH	= 1,
} enahw_get_stats_scope_t;

/* common: ena_admin_aq_entry */
typedef struct enahw_cmd_desc {
	uint16_t	ecd_idx;
	uint8_t		ecd_opcode;
	uint8_t		ecd_flags;

	union {
		uint32_t			ecd_raw[15];
		enahw_cmd_get_feat_t		ecd_get_feat;
		enahw_cmd_set_feat_t		ecd_set_feat;
		enahw_cmd_create_cq_t		ecd_create_cq;
		enahw_cmd_destroy_cq_t		ecd_destroy_cq;
		enahw_cmd_create_sq_t		ecd_create_sq;
		enahw_cmd_destroy_sq_t		ecd_destroy_sq;
		enahw_cmd_get_stats_t		ecd_get_stats;
	} ecd_cmd;

} enahw_cmd_desc_t;

/* Let's make sure the compiler is not mucking about with padding. */
CTASSERT(64 == sizeof (enahw_cmd_desc_t));
CTASSERT(sizeof (struct ena_admin_aq_entry) == sizeof (enahw_cmd_desc_t));
/* CTASSERT(offsetof (struct enahw_cmd_desc, ecd_payload.create_cq.cq_caps_1) == */
/*     offsetof (struct ena_admin_aq_create_cq_cmd, cq_caps_1)); */
/* CTASSERT(32 == */
/*     offsetof (struct ena_admin_aq_create_cq_cmd, cq_caps_1)); */

/*
 * Top level commands that may be sent to the Admin Queue.
 *
 * common: ena_admin_aq_opcode
 */
enum ena_cmd_opcode {
	ENAHW_CMD_CREATE_SQ	= 1,
	ENAHW_CMD_DESTROY_SQ	= 2,
	ENAHW_CMD_CREATE_CQ	= 3,
	ENAHW_CMD_DESTROY_CQ	= 4,
	ENAHW_CMD_GET_FEATURE	= 8,
	ENAHW_CMD_SET_FEATURE	= 9,
	ENAHW_CMD_GET_STATS	= 11,
};

/* common: ENA_ADMIN_AQ_COMMON_DESC */
#define	ENAHW_CMD_ID_MASK	GENMASK(11, 0)
#define	ENAHW_CMD_PHASE_MASK	BIT(0)

/*
 * Subcommands for ENA_ADMIN_{GET,SET}_FEATURE.
 *
 * common: ena_admin_aq_feature_id
 */
typedef enum enahw_feature_id {
	ENAHW_FEAT_DEVICE_ATTRIBUTES		= 1,
	ENAHW_FEAT_MAX_QUEUES_NUM		= 2,
	ENAHW_FEAT_HW_HINTS			= 3,
	ENAHW_FEAT_LLQ				= 4,
	ENAHW_FEAT_EXTRA_PROPERTIES_STRINGS	= 5,
	ENAHW_FEAT_EXTRA_PROPERTIES_FLAGS	= 6,
	ENAHW_FEAT_MAX_QUEUES_EXT		= 7,
	ENAHW_FEAT_RSS_HASH_FUNCTION		= 10,
	ENAHW_FEAT_STATELESS_OFFLOAD_CONFIG	= 11,
	ENAHW_FEAT_RSS_INDIRECTION_TABLE_CONFIG	= 12,
	ENAHW_FEAT_MTU				= 14,
	ENAHW_FEAT_RSS_HASH_INPUT		= 18,
	ENAHW_FEAT_INTERRUPT_MODERATION		= 20,
	ENAHW_FEAT_AENQ_CONFIG			= 26,
	ENAHW_FEAT_LINK_CONFIG			= 27,
	ENAHW_FEAT_HOST_ATTR_CONFIG		= 28,
	ENAHW_FEAT_NUM				= 32,
} enahw_feature_id_t;

/*
 * The following macros define the maximum version we support for each
 * feature. These are the feature versions we use to communicate with
 * the feature command. Linux has these values spread throughout the
 * code at the various callsites of ena_com_get_feature(). We choose
 * to centralize our feature versions to make it easier to audit.
 */
#define	ENAHW_FEAT_DEVICE_ATTRIBUTES_VER		0
#define	ENAHW_FEAT_MAX_QUEUES_NUM_VER			0
#define	ENAHW_FEAT_HW_HINTS_VER				0
#define	ENAHW_FEAT_LLQ_VER				0
#define	ENAHW_FEAT_EXTRA_PROPERTIES_STRINGS_VER		0
#define	ENAHW_FEAT_EXTRA_PROPERTIES_FLAGS_VER		0
#define	ENAHW_FEAT_MAX_QUEUES_EXT_VER			1
#define	ENAHW_FEAT_RSS_HASH_FUNCTION_VER		0
#define	ENAHW_FEAT_STATELESS_OFFLOAD_CONFIG_VER		0
#define	ENAHW_FEAT_RSS_INDIRECTION_TABLE_CONFIG_VER	0
#define ENAHW_FEAT_MTU_VER				0
#define	ENAHW_FEAT_RSS_HASH_INPUT_VER			0
#define	ENAHW_FEAT_INTERRUPT_MODERATION_VER		0
#define	ENAHW_FEAT_AENQ_CONFIG_VER			0
#define	ENAHW_FEAT_LINK_CONFIG_VER			0
#define	ENAHW_FEAT_HOST_ATTR_CONFIG_VER			0

/* common: ena_admin_link_types */
typedef enum enahw_link_speeds {
	ENAHW_LINK_SPEED_1G		= 0x1,
	ENAHW_LINK_SPEED_2_HALF_G	= 0x2,
	ENAHW_LINK_SPEED_5G		= 0x4,
	ENAHW_LINK_SPEED_10G		= 0x8,
	ENAHW_LINK_SPEED_25G		= 0x10,
	ENAHW_LINK_SPEED_40G		= 0x20,
	ENAHW_LINK_SPEED_50G		= 0x40,
	ENAHW_LINK_SPEED_100G		= 0x80,
	ENAHW_LINK_SPEED_200G		= 0x100,
	ENAHW_LINK_SPEED_400G		= 0x200,
} enahw_link_speeds_t;

/*
 * Command Response descriptors
 * ----------------------------
 */


/*
 * ENAHW_FEAT_DEVICE_ATTRIBUTES
 *
 * common: ena_admin_device_attr_feature_desc
 */
typedef struct enahw_feat_dev_attr {
	uint32_t efda_impl_id;
	uint32_t efda_device_version;

	/*
	 * Bitmap representing supported get/set feature subcommands
	 * (enahw_feature_id).
	 */
	uint32_t efda_supported_features;
	uint32_t efda_rsvd1;

	/* Number of bits used for physical/vritual address. */
	uint32_t efda_phys_addr_width;
	uint32_t efda_virt_addr_with;

	/* The unicast MAC address in network byte order. */
	uint8_t efda_mac_addr[6];
	uint8_t efda_rsvd2[2];
	uint32_t efda_max_mtu;
} enahw_feat_dev_attr_t;

/*
 * ENAHW_FEAT_MAX_QUEUES_NUM
 *
 * common: ena_admin_queue_feature_desc
 */
typedef struct enahw_feat_max_queue {
	uint32_t efmq_max_sq_num;
	uint32_t efmq_max_sq_depth;
	uint32_t efmq_max_cq_num;
	uint32_t efmq_max_cq_depth;
	uint32_t efmq_max_legacy_llq_num;
	uint32_t efmq_max_legacy_llq_depth;
	uint32_t efmq_max_header_size;

	/*
	 * The maximum number of descriptors a single Tx packet may
	 * span. This includes the meta descriptor.
	 */
	uint16_t efmq_max_packet_tx_descs;

	/*
	 * The maximum number of descriptors a single Rx packet may span.
	 */
	uint16_t efmq_max_packet_rx_descs;
} enahw_feat_max_queue_t;

/*
 * ENAHW_FEAT_MAX_QUEUES_EXT
 *
 * common: ena_admin_queue_ext_feature_desc
 */
typedef struct enahw_feat_max_queue_ext {
	uint8_t efmqe_version;
	uint8_t	efmqe_rsvd[3];

	uint32_t efmqe_max_tx_sq_num;
	uint32_t efmqe_max_tx_cq_num;
	uint32_t efmqe_max_rx_sq_num;
	uint32_t efmqe_max_rx_cq_num;
	uint32_t efmqe_max_tx_sq_depth;
	uint32_t efmqe_max_tx_cq_depth;
	uint32_t efmqe_max_rx_sq_depth;
	uint32_t efmqe_max_rx_cq_depth;
	uint32_t efmqe_max_tx_header_size;

	/*
	 * The maximum number of descriptors a single Tx packet may
	 * span. This includes the meta descriptor.
	 */
	uint16_t efmqe_max_per_packet_tx_descs;

	/*
	 * The maximum number of descriptors a single Rx packet may span.
	 */
	uint16_t efmqe_max_per_packet_rx_descs;
} enahw_feat_max_queue_ext_t;

/*
 * ENA_ADMIN_LINK_CONFIG
 *
 * common: ena_admin_get_feature_link_desc
 */
typedef struct enahw_feat_link_conf {
	/* Link speed in Mb/s. */
	uint32_t eflc_speed;

	/* Bit field of enum enahw_link_t types. */
	uint32_t eflc_supported;

	/*
	 * 31-2:	reserved
	 * 1:		duplex - Full Duplex
	 * 0:		autoneg
	 */
	uint32_t eflc_flags;
} enahw_feat_link_conf_t;

#define	ENAHW_FEAT_LINK_CONF_AUTONEG_MASK	BIT(0)
#define	ENAHW_FEAT_LINK_CONF_DUPLEX_SHIFT	1
#define	ENAHW_FEAT_LINK_CONF_DUPLEX_MASK	BIT(1)

#define	ENAHW_FEAT_LINK_CONF_AUTONEG(f)				\
	((f)->eflc_flags & ENAHW_FEAT_LINK_CONF_AUTONEG_MASK)

#define	ENAHW_FEAT_LINK_CONF_FULL_DUPLEX(f)				\
	((((f)->eflc_flags & ENAHW_FEAT_LINK_CONF_DUPLEX_MASK) >>	\
	    ENAHW_FEAT_LINK_CONF_DUPLEX_SHIFT) == 1)

/*
 * ENAHW_FEAT_STATELESS_OFFLOAD_CONFIG
 *
 * common: ena_admin_feature_offload_desc
 */
typedef struct enahw_feat_offload {
	/* 0 : TX_L3_csum_ipv4
	 * 1 : TX_L4_ipv4_csum_part - The checksum field
	 *    should be initialized with pseudo header checksum
	 * 2 : TX_L4_ipv4_csum_full
	 * 3 : TX_L4_ipv6_csum_part - The checksum field
	 *    should be initialized with pseudo header checksum
	 * 4 : TX_L4_ipv6_csum_full
	 * 5 : tso_ipv4
	 * 6 : tso_ipv6
	 * 7 : tso_ecn
	 */
	u32 efo_tx;

	/* Receive side supported stateless offload
	 * 0 : RX_L3_csum_ipv4 - IPv4 checksum
	 * 1 : RX_L4_ipv4_csum - TCP/UDP/IPv4 checksum
	 * 2 : RX_L4_ipv6_csum - TCP/UDP/IPv6 checksum
	 * 3 : RX_hash - Hash calculation
	 */
	u32 efo_rx_supported;

	/* XXX Linux seems to only check rx_supported. */
	u32 efo_rx_enabled;
} enahw_feat_offload_t;

/* Feature Offloads */
#define ENAHW_FEAT_OFFLOAD_TX_L3_CSUM_IPV4_MASK		BIT(0)
#define ENAHW_FEAT_OFFLOAD_TX_L4_IPV4_CSUM_PART_SHIFT	1
#define ENAHW_FEAT_OFFLOAD_TX_L4_IPV4_CSUM_PART_MASK	BIT(1)
#define ENAHW_FEAT_OFFLOAD_TX_L4_IPV4_CSUM_FULL_SHIFT	2
#define ENAHW_FEAT_OFFLOAD_TX_L4_IPV4_CSUM_FULL_MASK	BIT(2)
#define ENAHW_FEAT_OFFLOAD_TX_L4_IPV6_CSUM_PART_SHIFT	3
#define ENAHW_FEAT_OFFLOAD_TX_L4_IPV6_CSUM_PART_MASK	BIT(3)
#define ENAHW_FEAT_OFFLOAD_TX_L4_IPV6_CSUM_FULL_SHIFT	4
#define ENAHW_FEAT_OFFLOAD_TX_L4_IPV6_CSUM_FULL_MASK	BIT(4)
#define ENAHW_FEAT_OFFLOAD_TSO_IPV4_SHIFT		5
#define ENAHW_FEAT_OFFLOAD_TSO_IPV4_MASK		BIT(5)
#define ENAHW_FEAT_OFFLOAD_TSO_IPV6_SHIFT		6
#define ENAHW_FEAT_OFFLOAD_TSO_IPV6_MASK		BIT(6)
#define ENAHW_FEAT_OFFLOAD_TSO_ECN_SHIFT		7
#define ENAHW_FEAT_OFFLOAD_TSO_ECN_MASK			BIT(7)
#define ENAHW_FEAT_OFFLOAD_RX_L3_CSUM_IPV4_MASK		BIT(0)
#define ENAHW_FEAT_OFFLOAD_RX_L4_IPV4_CSUM_SHIFT	1
#define ENAHW_FEAT_OFFLOAD_RX_L4_IPV4_CSUM_MASK		BIT(1)
#define ENAHW_FEAT_OFFLOAD_RX_L4_IPV6_CSUM_SHIFT	2
#define ENAHW_FEAT_OFFLOAD_RX_L4_IPV6_CSUM_MASK		BIT(2)
#define ENAHW_FEAT_OFFLOAD_RX_HASH_SHIFT		3
#define ENAHW_FEAT_OFFLOAD_RX_HASH_MASK			BIT(3)

#define	ENAHW_FEAT_OFFLOAD_TX_L3_CSUM_IPV4(f)				\
	(((f)->efo_rx_supported & ENAHW_FEAT_OFFLOAD_TX_L3_CSUM_IPV4_MASK) != 0)

#define	ENAHW_FEAT_OFFLOAD_TX_L4_IPV4_CSUM_FULL(f)		\
	(((f)->efo_rx_supported &				\
	    ENAHW_FEAT_OFFLOAD_TX_L4_IPV4_CSUM_FULL_MASK) != 0)

typedef union enahw_resp_get_feat {
	uint32_t			ergf_raw[14];
	enahw_feat_dev_attr_t		ergf_dev_attr;
	enahw_feat_max_queue_t		ergf_max_queue;
	enahw_feat_max_queue_ext_t	ergf_max_queue_ext;
	enahw_feat_aenq_t		ergf_aenq;
	enahw_feat_link_conf_t		ergf_link_conf;
	enahw_feat_offload_t		ergf_offload;
} enahw_resp_get_feat_u;

/*
 * common: ena_admin_acq_create_cq_resp_desc
 */
typedef struct enahw_resp_create_cq {
	uint16_t ercq_idx;

	/*
	 * Apparently the number of descriptors granted may be
	 * different than that requested.
	 */
	uint16_t ercq_actual_num_descs;
	uint32_t ercq_numa_node_reg_offset;
	uint32_t ercq_head_db_reg_offset;       /* doorbell */
	uint32_t ercq_interrupt_mask_reg_offset; /* stop intr */
} enahw_resp_create_cq_t;

/* common: ena_admin_acq_create_sq_resp_desc */
typedef struct enahw_resp_create_sq {
	uint16_t ersq_idx;
	uint16_t ersq_rsvdw1;
	uint32_t ersq_db_reg_offset;
	uint32_t ersq_llq_descs_reg_offset;
	uint32_t ersq_llq_headers_reg_offset;
} enahw_resp_create_sq_t;

/* common: ena_admin_basic_stats */
typedef struct enahw_resp_basic_stats {
	uint32_t erbs_tx_bytes_low;
	uint32_t erbs_tx_bytes_high;
	uint32_t erbs_tx_pkts_low;
	uint32_t erbs_tx_pkts_high;
	uint32_t erbs_rx_bytes_low;
	uint32_t erbs_rx_bytes_high;
	uint32_t erbs_rx_pkts_low;
	uint32_t erbs_rx_pkts_high;
	uint32_t erbs_rx_drops_low;
	uint32_t erbs_rx_drops_high;
	uint32_t erbs_tx_drops_low;
	uint32_t erbs_tx_drops_high;
} enahw_resp_basic_stats_t;

/*
 * common: ena_admin_acq_entry
 */
typedef struct enahw_resp_desc {
	/* The index of the completed command. */
	uint16_t	erd_cmd_idx;

	/* The status of the command (enahw_cmd_status). */
	uint8_t		erd_status;

	/*
	 * 7-1	Reserved
	 * 0	Phase
	 */
	uint8_t		erd_flags;

	/* Extended status. */
	uint16_t	erd_ext_status;

	/*
	 * The AQ entry (enahw_cmd_desc) index which has been consumed
	 * by the device and can be reused. However, this field is not
	 * used in the other drivers, and it seems to be redundant
	 * with the erd_idx field.
	 */
	uint16_t	erd_sq_head_idx;

	union {
		uint32_t			raw[14];
		enahw_resp_get_feat_u		erd_get_feat;
		enahw_resp_create_cq_t		erd_create_cq;
		/* destroy_cq: No command-specific response. */
		enahw_resp_create_sq_t		erd_create_sq;
		/* destroy_sq: No command-specific response. */
		enahw_resp_basic_stats_t	erd_basic_stats;
	} erd_resp;
} enahw_resp_desc_t;

/* Let's make sure the compiler is not mucking about with padding. */
CTASSERT(64 == sizeof (enahw_resp_desc_t));
CTASSERT(sizeof (struct ena_admin_acq_entry) == sizeof (enahw_resp_desc_t));

/* common: ENA_ADMIN_ACQ_COMMON_DESC */
#define	ENAHW_RESP_ID_MASK	GENMASK(11, 0)
#define	ENAHW_RESP_PHASE_MASK	0x1

/*
 * The response status of an Admin Queue command.
 *
 * common: ena_admin_aq_completion_status
 */
typedef enum enahw_resp_status {
	ENAHW_RESP_SUCCESS			= 0,
	ENAHW_RESP_RESOURCE_ALLOCATION_FAILURE	= 1,
	ENAHW_RESP_BAD_OPCODE			= 2,
	ENAHW_RESP_UNSUPPORTED_OPCODE		= 3,
	ENAHW_RESP_MALFORMED_REQUEST		= 4,
	/*
	 * At this place in the common code it mentions that there is
	 * "additional status" in the reponse descriptor's
	 * erd_ext_status field. As the common code never actually
	 * uses this field it's hard to know the exact meaning of the
	 * comment. My best guess is the illegal parameter error
	 * stores additional context in the erd_ext_status field. But
	 * how to interpret that additional context is anyone's guess.
	 */
	ENAHW_RESP_ILLEGAL_PARAMETER		= 5,
	ENAHW_RESP_UNKNOWN_ERROR		= 6,
	ENAHW_RESP_RESOURCE_BUSY		= 7,
} enahw_resp_status_t;

/*
 * Not really a device structure, more of a helper to debug register values.
 */
typedef struct enahw_reg_nv {
	char		*ern_name;
	uint32_t	ern_offset;
	uint32_t	ern_value;
} enahw_reg_nv_t;

/*
 * I/O macros and strcutures.
 * -------------------------
 */

/*
 * The device's L3 and L4 protocol numbers. These are specific to the
 * ENA device and not to be confused with IANA protocol numbers.
 */
typedef enum enahw_io_l3_proto {
	ENAHW_IO_L3_PROTO_UNKNOWN	= 0,
	ENAHW_IO_L3_PROTO_IPV4		= 8,
	ENAHW_IO_L3_PROTO_IPV6		= 11,
	ENAHW_IO_L3_PROTO_FCOE		= 21,
	ENAHW_IO_L3_PROTO_ROCE		= 22,
} enahw_io_l3_proto_t;

typedef enum enahw_io_l4_proto {
	ENAHW_IO_L4_PROTO_UNKNOWN		= 0,
	ENAHW_IO_L4_PROTO_TCP			= 12,
	ENAHW_IO_L4_PROTO_UDP			= 13,
	ENAHW_IO_L4_PROTO_ROUTEABLE_ROCE	= 23,
} enahw_io_l4_proto_t;

/* common: ena_eth_io_tx_desc */
typedef struct enahw_tx_data_desc {
	/*
	 * 15-0	  Buffer Length (LENGTH)
	 *
	 *     The buffer length in bytes. This should NOT include the
	 *     Ethernet FCS bytes.
	 *
	 * 21-16  Request ID High Bits [15-10] (REQ_ID_HI)
	 * 22	  Reserved Zero
	 * 23	  Metadata Flag always zero (META_DESC)
	 *
	 *	This flag indicates if the descriptor is a metadata
	 *	descriptor or not. In this case we are defining the Tx
	 *	descriptor, so it's always zero.
	 *
	 * 24	  Phase bit (PHASE)
	 * 25	  Reserved Zero
	 * 26	  First Descriptor Bit (FIRST)
	 *
	 *	Indicates this is the first descriptor for the packet.
	 *
	 * 27	  Last Descriptor Bit (LAST)
	 *
	 *	Indicates this is the last descriptor for the packet.
	 *
	 * 28	  Completion Request Bit (COMP_REQ)
	 *
	 *	Indicates if completion should be posted after packet
	 *	is transmitted. This bit is only valid on the first
	 *	descriptor.
	 *
	 * 31-29  Reserved Zero
	 */
	uint32_t etd_len_ctrl;

	/* 3-0	  L3 Protocol Number (L3_PROTO_IDX)
	 *
	 *	The L3 protocol type, one of enahw_io_l3_proto_t. This
	 *	field is required when L3_CSUM_EN or TSO_EN are set.
	 *
	 * 4	  Don't Fragment Bit (DF)
	 *
	 *	The value of IPv4 DF. This value must copy the value
	 *	found in the packet's IPv4 header.
	 *
	 * 6-5	  Reserved Zero
	 * 7	  TSO Bit (TSO_EN)
	 *
	 *	Enable TCP Segment Offload.
	 *
	 * 12-8	  L4 Protocol Number (L4_PROTO_IDX)
	 *
	 *	The L4 protocol type, one of enahw_io_l4_proto_t. This
	 *	field is required when L4_CSUM_EN or TSO_EN are
	 *	set.
	 *
	 * 13	  L3 Checksum Offload (L3_CSUM_EN)
	 *
	 *	Enable IPv4 header checksum offload.
	 *
	 * 14	  L4 Checksum Offload (L4_CSUM_EN)
	 *
	 *	Enable TCP/UDP checksum offload.
	 *
	 * 15	  Ethernet FCS Disable (ETHERNET_FCS_DIS)
	 *
	 *	Disable the device's Ethernet Frame Check sequence.
	 *
	 * 16	  Reserved Zero
	 * 17	  L4 Partial Checksum Present (L4_CSUM_PARTIAL)
	 *
	 *	When set it indicates the host has already provided
	 *	the pseudo-header checksum. Otherwise, it is up to the
	 *	device to calculate it.
	 *
	 *	When set and using TSO the host stack must remember
	 *	not to include the TCP segment length in the supplied
	 *	pseudo-header.
	 *
	 *	The host stack should provide the pseudo-header
	 *	checksum when using IPv6 with Routing Headers.
	 *
	 * 21-18  Reserved Zero
	 * 31-22  Request ID Low [9-0] (REQ_ID_LO)
	 */
	uint32_t etd_meta_ctrl;

	/* The low 32 bits of the buffer address. */
	uint32_t etd_buff_addr_lo;

	/* address high and header size
	 *
	 * 15-0	Buffer Address High [47-32] (ADDR_HI)
	 *
	 *	The upper 15 bits of the buffer address.
	 *
	 * 23-16  Reserved Zero
	 * 31-24  Header Length (HEADER_LENGTH)
	 *
	 *	In the case of LLQs this field must be set to the
	 *	number of bytes written to the header memory.
	 *
	 *	For normal queues, if the packet is TCP or UDP and
	 *	contains more than just header data, then this field
	 *	must be set to the sum of the L3 and L4 headers
	 *	(without options). Otherwise, this field should be set
	 *	to zero.
	 *
	 *	In any case, the value in this field may never excreed
	 *	the maximum header size: efmq_max_header_size.
	 */
	uint32_t etd_buff_addr_hi_hdr_sz;
} enahw_tx_data_desc_t;

#define ENAHW_TX_DESC_LENGTH_MASK                      GENMASK(15, 0)
#define ENAHW_TX_DESC_REQ_ID_HI_SHIFT                  16
#define ENAHW_TX_DESC_REQ_ID_HI_MASK                   GENMASK(21, 16)
#define ENAHW_TX_DESC_META_DESC_SHIFT                  23
#define ENAHW_TX_DESC_META_DESC_MASK                   BIT(23)
#define ENAHW_TX_DESC_PHASE_SHIFT                      24
#define ENAHW_TX_DESC_PHASE_MASK                       BIT(24)
#define ENAHW_TX_DESC_FIRST_SHIFT                      26
#define ENAHW_TX_DESC_FIRST_MASK                       BIT(26)
#define ENAHW_TX_DESC_LAST_SHIFT                       27
#define ENAHW_TX_DESC_LAST_MASK                        BIT(27)
#define ENAHW_TX_DESC_COMP_REQ_SHIFT                   28
#define ENAHW_TX_DESC_COMP_REQ_MASK                    BIT(28)
#define ENAHW_TX_DESC_L3_PROTO_IDX_MASK                GENMASK(3, 0)
#define ENAHW_TX_DESC_DF_SHIFT                         4
#define ENAHW_TX_DESC_DF_MASK                          BIT(4)
#define ENAHW_TX_DESC_TSO_EN_SHIFT                     7
#define ENAHW_TX_DESC_TSO_EN_MASK                      BIT(7)
#define ENAHW_TX_DESC_L4_PROTO_IDX_SHIFT               8
#define ENAHW_TX_DESC_L4_PROTO_IDX_MASK                GENMASK(12, 8)
#define ENAHW_TX_DESC_L3_CSUM_EN_SHIFT                 13
#define ENAHW_TX_DESC_L3_CSUM_EN_MASK                  BIT(13)
#define ENAHW_TX_DESC_L4_CSUM_EN_SHIFT                 14
#define ENAHW_TX_DESC_L4_CSUM_EN_MASK                  BIT(14)
#define ENAHW_TX_DESC_ETHERNET_FCS_DIS_SHIFT           15
#define ENAHW_TX_DESC_ETHERNET_FCS_DIS_MASK            BIT(15)
#define ENAHW_TX_DESC_L4_CSUM_PARTIAL_SHIFT            17
#define ENAHW_TX_DESC_L4_CSUM_PARTIAL_MASK             BIT(17)
#define ENAHW_TX_DESC_REQ_ID_LO_SHIFT                  22
#define ENAHW_TX_DESC_REQ_ID_LO_MASK                   GENMASK(31, 22)
#define ENAHW_TX_DESC_ADDR_HI_MASK                     GENMASK(15, 0)
#define ENAHW_TX_DESC_HEADER_LENGTH_SHIFT              24
#define ENAHW_TX_DESC_HEADER_LENGTH_MASK               GENMASK(31, 24)

#define	ENAHW_TX_DESC_LENGTH(desc, len)					\
	(((desc)->etd_len_ctrl) |= ((len) & ENAHW_TX_DESC_LENGTH_MASK))

#define	ENAHW_TX_DESC_FIRST_ON(desc)				\
	(((desc)->etd_len_ctrl) |= ENAHW_TX_DESC_FIRST_MASK)

#define	ENAHW_TX_DESC_FIRST_OFF(desc)				\
	(((desc)->etd_len_ctrl) &= ~ENAHW_TX_DESC_FIRST_MASK)

#define	ENAHW_TX_DESC_REQID_HI(desc, reqid)				\
	(((desc)->etd_len_ctrl) |=					\
	    ((((reqid) >> 10) << ENAHW_TX_DESC_REQ_ID_HI_SHIFT) &	\
		ENAHW_TX_DESC_REQ_ID_HI_MASK))

#define	ENAHW_TX_DESC_REQID_LO(desc, reqid)				\
	(((desc)->etd_meta_ctrl) |=					\
	    (((reqid) << ENAHW_TX_DESC_REQ_ID_LO_SHIFT) &		\
		ENAHW_TX_DESC_REQ_ID_LO_MASK))

#define	ENAHW_TX_DESC_PHASE(desc, phase)				\
	(((desc)->etd_len_ctrl) |= (((phase) << ENAHW_TX_DESC_PHASE_SHIFT) & \
	    ENAHW_TX_DESC_PHASE_MASK))

#define	ENAHW_TX_DESC_LAST_ON(desc)				\
	(((desc)->etd_len_ctrl) |= ENAHW_TX_DESC_LAST_MASK)

#define	ENAHW_TX_DESC_LAST_OFF(desc)				\
	(((desc)->etd_len_ctrl) &= ~ENAHW_TX_DESC_LAST_MASK)

#define	ENAHW_TX_DESC_COMP_REQ_ON(desc)				\
	(((desc)->etd_len_ctrl) |= ENAHW_TX_DESC_COMP_REQ_MASK)

#define	ENAHW_TX_DESC_COMP_REQ_OFF(desc)				\
	(((desc)->etd_len_ctrl) &= ~ENAHW_TX_DESC_COMP_REQ_MASK)

#define	ENAHW_TX_DESC_META_DESC_ON(desc)				\
	(((desc)->etd_len_ctrl) |= ENAHW_TX_DESC_META_DESC_MASK)

#define	ENAHW_TX_DESC_META_DESC_OFF(desc)				\
	(((desc)->etd_len_ctrl) &= ~ENAHW_TX_DESC_META_DESC_MASK)

#define	ENAHW_TX_DESC_ADDR_LO(desc, addr)	\
	(((desc)->etd_buff_addr_lo) = (addr))

#define	ENAHW_TX_DESC_ADDR_HI(desc, addr)				\
	(((desc)->etd_buff_addr_hi_hdr_sz) |=				\
	    (((addr) >> 32) & ENAHW_TX_DESC_ADDR_HI_MASK))

#define	ENAHW_TX_DESC_HEADER_LENGTH(desc, len)			\
	(((desc)->etd_buff_addr_hi_hdr_sz) |=			\
	    (((len) << ENAHW_TX_DESC_HEADER_LENGTH_SHIFT) &	\
		ENAHW_TX_DESC_HEADER_LENGTH_MASK))

#define	ENAHW_TX_DESC_DF_ON(desc)				\
	((desc)->etd_meta_ctrl |= ENAHW_TX_DESC_DF_MASK)

#define	ENAHW_TX_DESC_TSO_OFF(desc)				\
	(((desc)->etd_meta_ctrl) &= ~ENAHW_TX_DESC_TSO_EN_MASK)

#define	ENAHW_TX_DESC_L3_CSUM_OFF(desc)				\
	(((desc)->etd_meta_ctrl) &= ~ENAHW_TX_DESC_L3_CSUM_EN_MASK)

#define	ENAHW_TX_DESC_L4_CSUM_OFF(desc)				\
	(((desc)->etd_meta_ctrl) &= ~ENAHW_TX_DESC_L4_CSUM_EN_MASK)

#define	ENAHW_TX_DESC_L4_CSUM_PARTIAL_ON(desc)				\
	(((desc)->etd_meta_ctrl) &= ~ENAHW_TX_DESC_L4_CSUM_PARTIAL_MASK)

/* common: ena_eth_io_tx_meta_desc */
typedef struct enahw_tx_meta_desc {
	/*
	 * 9-0	  Request ID Low [9-0] (REQ_ID_LO)
	 * 13-10  Reserved Zero
	 * 14	  Extended Metadata Valid (EXT_VALID)
	 *
	 *	When set this descriptor contains valid extended
	 *	metadata. The extended metadata includes the L3/L4
	 *	length and offset fields as well as the MSS bits. This
	 *	is needed for TSO.
	 *
	 * 15	  Reserved Zero
	 * 19-16  MSS High Bits (MSS_HI)
	 * 20	  Meta Type (ETH_META_TYPE)
	 *
	 *	If enabled this is an extended metadata descriptor.
	 *	This seems redundant with EXT_VALID.
	 *
	 * 21	  Meta Store (META_STORE)
	 *
	 *	Store the extended metadata in the queue cache.
	 *
	 * 22	  Reserved Zero
	 * 23	  Metadata Flag (META_DESC) -- always one
	 * 24	  Phase (PHASE)
	 * 25	  Reserved Zero
	 * 26	  First Descriptor Bit (FIRST)
	 * 27	  Last Descriptor Bit (LAST)
	 * 28	  Completion Request Bit (COMP_REQ)
	 * 31-29  Reserved Zero
	 */
	uint32_t etmd_len_ctrl;

	/*
	 * 5-0	  Request ID High Bits [15-10] (REQ_ID_HI)
	 * 31-6	  Reserved Zero
	 */
	uint32_t etmd_word1;

	/*
	 * 7-0	  L3 Header Length (L3_HDR_LEN)
	 * 15:8	  L3 Header Offset (L3_HDR_OFF)
	 * 21:16  L4 Header Length in Words (L4_HDR_LEN_IN_WORDS)
	 *
	 *    Specifies the L4 header length in words. The device
	 *    assumes the L4 header follows directly after the L3
	 *    header and that the L4 offset is equal to L3_HDR_OFF +
	 *    L3_HDR_LEN.
	 *
	 * 31-22  MSS Low Bits (MSS_LO)
	 */
	uint32_t etmd_word2;
	uint32_t etmd_reserved;
} enahw_tx_meta_desc_t;

/* TODO: Define the various macros for the meta desc. */

typedef union enahw_tx_desc {
	enahw_tx_data_desc_t etd_data;
	enahw_tx_meta_desc_t etd_meta;
} enahw_tx_desc_t;

CTASSERT(sizeof (enahw_tx_data_desc_t) == sizeof (enahw_tx_meta_desc_t));
CTASSERT(sizeof (enahw_tx_data_desc_t) == sizeof (enahw_tx_desc_t));
CTASSERT(sizeof (enahw_tx_meta_desc_t) == sizeof (enahw_tx_desc_t));
CTASSERT(sizeof (struct ena_eth_io_tx_desc) == sizeof (enahw_tx_desc_t));
CTASSERT(sizeof (struct ena_eth_io_tx_meta_desc) == sizeof (enahw_tx_desc_t));

/* common: ena_eth_io_tx_cdesc */
typedef struct enahw_tx_cdesc {
	/*
	 * 15-0	  Request ID Bits
	 * 16	  Reserved Zero
	 */
	uint16_t etc_req_id;

	/*
	 * Presumably the status of the Tx, though the Linux driver
	 * never checks this field.
	 */
	uint8_t etc_status;

	/*
	 * 0	  Phase
	 * 7-1	  Reserved Zero
	 */
	uint8_t etc_flags;

	/*
	 * This isn't documented or used in the Linux driver, but
	 * these probably store the submission queue ID and the
	 * submission queue head index.
	 */
	uint16_t etc_sub_qid;
	uint16_t etc_sq_head_idx;
} enahw_tx_cdesc_t;

/* common: ena_eth_io_rx_desc */
typedef struct enahw_rx_desc {
	/*
	 * The length of the buffer provided by the host, in bytes.
	 * Use the value of 0 to indicate 64K.
	 */
	uint16_t erd_length;
	uint8_t erd_reserved1;

	/*
	 * 0	  Phase (PHASE)
	 * 1	  Reserved Zero
	 * 2	  First (FIRST)
	 *
	 *	Indicates this is the first descriptor for the frame.
	 *
	 * 3	  Last (LAST)
	 *
	 *	Indicates this is the last descriptor for the frame.
	 *
	 * 4	  Completion Request (COMP_REQ)
	 *
	 *	Indicates that a completion request should be generated
	 *	for this descriptor.
	 *
	 * 7-5	  Reserved Zero
	 */
	uint8_t erd_ctrl;

	/*
	 * 15-0	  Request ID
	 * 16	  Reserved 0
	 */
	uint16_t erd_req_id;
	uint16_t erd_reserved2;

	/* The physical address of the buffer provided by the host. */
	uint32_t erd_buff_addr_lo;
	uint16_t erd_buff_addr_hi;
	uint16_t erd_reserved3;
} enahw_rx_desc_t;

CTASSERT(sizeof (enahw_rx_desc_t) == sizeof (struct ena_eth_io_rx_desc));

#define	ENAHW_RX_DESC_PHASE_MASK	BIT(0)
#define	ENAHW_RX_DESC_FIRST_SHIFT	2
#define	ENAHW_RX_DESC_FIRST_MASK	BIT(2)
#define	ENAHW_RX_DESC_LAST_SHIFT	3
#define	ENAHW_RX_DESC_LAST_MASK		BIT(3)
#define	ENAHW_RX_DESC_COMP_REQ_SHIFT	4
#define	ENAHW_RX_DESC_COMP_REQ_MASK	BIT(4)

#define	ENAHW_RX_DESC_PHASE(desc, val)					\
	((desc)->erd_ctrl |= ((val) & ENAHW_RX_DESC_PHASE_MASK))

#define	ENAHW_RX_DESC_FIRST(desc)			\
	((desc)->erd_ctrl |= ENAHW_RX_DESC_FIRST_MASK)

#define	ENAHW_RX_DESC_LAST(desc)			\
	((desc)->erd_ctrl |= ENAHW_RX_DESC_LAST_MASK)

#define	ENAHW_RX_DESC_COMP_REQ(desc)			\
	((desc)->erd_ctrl |= ENAHW_RX_DESC_COMP_REQ_MASK)

/*
 * Ethernet parsing information is only valid when last == 1.
 */
typedef struct enahw_rx_cdesc {
	/*
	 * 4-0	  L3 Protocol Number (L3_PROTO)
	 *
	 *	The L3 protocol type, one of enahw_io_l3_proto_t.
	 *
	 * 6-5	  (SRC_VLAN_CNT)
	 * 7	  Reserved Zero
	 * 12-8	  L4 Protocol Number (L4_PROTO)
	 * 13	  L3 Checksum Error (L3_CSUM_ERR)
	 *
	 *	When set either the L3 checksum failed to match or the
	 *      controller didn't attempt to validate the checksum.
	 *      This bit is valid only when L3_PROTO indicates an IPv4
	 *      packet.
	 *
	 * 14	  L4 Checksum Error (L4_CSUM_ERR)
	 *
	 *	When set either the L4 checksum failed to match or the
	 *	controller didn't attempt to validate the checksum.
	 *	This bit is valid only when L4_PROTO indicates a
	 *	TCP/UDP packet, IPV4_FRAG is not set, and
	 *	L4_CSUM_CHECKED is set.
	 *
	 * 15	  IPv4 Fragmented (IPV4_FRAG)
	 * 16	  L4 Checksum Validated (L4_CSUM_CHECKED)
	 *
	 *	When set it indicates the device attempted to validate
	 *	the L4 checksum.
	 *
	 * 23-17  Reserved Zero
	 * 24	  Phase (PHASE)
	 * 25	  (L3_CSUM2)
	 *
	 *	According to the Linux source this is the "second
	 *	checksum engine result". It's never checked.
	 *
	 * 26	  First Descriptor Bit (FIRST)
	 *
	 *	Indicates the first descriptor for the frame.
	 *
	 * 27	  Last Descriptor Bit (LAST)
	 *
	 *	Indicates the last descriptor for the frame.
	 *
	 * 29-28  Reserved Zero
	 * 30	  Buffer Type (BUFFER)
	 *
	 *	When enabled indicates this is a data descriptor.
	 *	Otherwse, it is a metadata descriptor.
	 *
	 * 31 : reserved31
	 */
	uint32_t erc_status;
	uint16_t erc_length;
	uint16_t erc_req_id;

	/* 32-bit hash result */
	uint32_t erc_hash;
	uint16_t erc_sub_qid;
	uint8_t erc_offset;
	uint8_t erc_reserved;
} enahw_rx_cdesc_t;

#define	ENAHW_RX_CDESC_L3_PROTO_MASK		GENMASK(4, 0)
#define	ENAHW_RX_CDESC_SRC_VLAN_CNT_SHIFT	5
#define	ENAHW_RX_CDESC_SRC_VLAN_CNT_MASK	GENMASK(6, 5)
#define	ENAHW_RX_CDESC_L4_PROTO_SHIFT		8
#define	ENAHW_RX_CDESC_L4_PROTO_MASK		GENMASK(12, 8)
#define	ENAHW_RX_CDESC_L3_CSUM_ERR_SHIFT	13
#define	ENAHW_RX_CDESC_L3_CSUM_ERR_MASK		BIT(13)
#define	ENAHW_RX_CDESC_L4_CSUM_ERR_SHIFT	14
#define	ENAHW_RX_CDESC_L4_CSUM_ERR_MASK		BIT(14)
#define	ENAHW_RX_CDESC_IPV4_FRAG_SHIFT		15
#define	ENAHW_RX_CDESC_IPV4_FRAG_MASK		BIT(15)
#define	ENAHW_RX_CDESC_L4_CSUM_CHECKED_SHIFT	16
#define	ENAHW_RX_CDESC_L4_CSUM_CHECKED_MASK	BIT(16)
#define	ENAHW_RX_CDESC_PHASE_SHIFT		24
#define	ENAHW_RX_CDESC_PHASE_MASK		BIT(24)
#define	ENAHW_RX_CDESC_L3_CSUM2_SHIFT		25
#define	ENAHW_RX_CDESC_L3_CSUM2_MASK		BIT(25)
#define	ENAHW_RX_CDESC_FIRST_SHIFT		26
#define	ENAHW_RX_CDESC_FIRST_MASK		BIT(26)
#define	ENAHW_RX_CDESC_LAST_SHIFT		27
#define	ENAHW_RX_CDESC_LAST_MASK		BIT(27)
#define	ENAHW_RX_CDESC_BUFFER_SHIFT		30
#define	ENAHW_RX_CDESC_BUFFER_MASK		BIT(30)

#define	ENAHW_RX_CDESC_L3_PROTO(desc)				\
	((desc)->erc_status & ENAHW_RX_CDESC_L3_PROTO_MASK)

#define	ENAHW_RX_CDESC_L3_CSUM_ERR(desc)				\
	((((desc)->erc_status & ENAHW_RX_CDESC_L3_CSUM_ERR_MASK) >>	\
	    ENAHW_RX_CDESC_L3_CSUM_ERR_SHIFT) != 0)

#define	ENAHW_RX_CDESC_L4_PROTO(desc)				\
	(((desc)->erc_status & ENAHW_RX_CDESC_L4_PROTO_MASK) >>	\
	    ENAHW_RX_CDESC_L4_PROTO_SHIFT)

#define	ENAHW_RX_CDESC_L4_CSUM_CHECKED(desc)				\
	((((desc)->erc_status & ENAHW_RX_CDESC_L4_CSUM_CHECKED_MASK) >>	\
	    ENAHW_RX_CDESC_L4_CSUM_CHECKED_SHIFT) != 0)

#define	ENAHW_RX_CDESC_PHASE(desc)			 \
	(((desc)->erc_status & ENAHW_RX_CDESC_PHASE_MASK) >> \
	    ENAHW_RX_CDESC_PHASE_SHIFT)

#define	ENAHW_RX_CDESC_FIRST(desc)			 \
	((((desc)->erc_status & ENAHW_RX_CDESC_FIRST_MASK) >> \
	    ENAHW_RX_CDESC_FIRST_SHIFT) == 1)

#define	ENAHW_RX_CDESC_LAST(desc)			 \
	((((desc)->erc_status & ENAHW_RX_CDESC_LAST_MASK) >> \
	    ENAHW_RX_CDESC_LAST_SHIFT) == 1)

/*
 * Controls for the interrupt register mapped to each Rx/Tx CQ.
 */
#define	ENAHW_REG_INTR_RX_DELAY_MASK	GENMASK(14, 0)
#define	ENAHW_REG_INTR_TX_DELAY_SHIFT	15
#define	ENAHW_REG_INTR_TX_DELAY_MASK	GENMASK(29, 15)
#define	ENAHW_REG_INTR_UNMASK_SHIFT	30
#define	ENAHW_REG_INTR_UNMASK_MASK	BIT(30)

#define	ENAHW_REG_INTR_UNMASK(val)		\
	((val) |= ENAHW_REG_INTR_UNMASK_MASK)

#define	ENAHW_REG_INTR_MASK(val)		\
	((val) &= ~ENAHW_REG_INTR_UNMASK_MASK)

extern int enahw_resp_status_to_errno(enahw_resp_status_t);

#endif	/* _ENA_HW_H */
