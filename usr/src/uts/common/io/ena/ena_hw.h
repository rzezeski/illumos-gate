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
 * Copyright 2020 Oxide Computer Company
 */

/*
 * This file declares all constants and structures dealing with the
 * physical ENA device. It is based on the ena_com code of the public
 * Linux and FreeBSD drivers.
 *
 * TODO Maybe drop the hw_ prefix on structs/types. In fact, now I'm
 * thinking drop the "hw" prefixes and define the types without them.
 * Instead, the rule will be that if it's defined in this file it's
 * value or structure is determined by the hardware, and that if it
 * belongs to the hardware it MUST be defined here. Everything outside
 * of this file is software abstraction and considered fair game.
 *
 */
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/debug.h>
#include <sys/ethernet.h>

#include "ena_linux.h"

#ifndef _ENA_HW_H
#define _ENA_HW_H

/* TODO copied from Linux */
#ifndef GENMASK
#define	GENMASK(h, l)	(((~0U) - (1U << (l)) + 1) & (~0U >> (32 - 1 - (h))))
#endif

#ifndef BIT
#define	BIT(b)		(1UL << (b))
#endif

#define	ENA_DMA_ADMINQ_ALIGNMENT	8

/*
 * BAR0 register offsets.
 *
 * Any register not defined in the common code was marked as a gap,
 * using the hex address of the register as suffix. The idea is to
 * make it clear where the gaps are and allow the
 * ena_hw_update_reg_cache() function to display any bits stored in
 * these gaps in case they turn out to be interesting later.
 */
#define ENA_REG_VERSION			0x0
#define ENA_REG_CONTROLLER_VERSION	0x4
#define ENA_REG_CAPS			0x8
#define ENA_REG_CAPS_EXT		0xc
#define ENA_REG_ASQ_BASE_LO		0x10
#define ENA_REG_ASQ_BASE_HI		0x14
#define ENA_REG_ASQ_CAPS		0x18
#define	ENA_REG_GAP_1C			0x1c
#define ENA_REG_ACQ_BASE_LO		0x20
#define ENA_REG_ACQ_BASE_HI		0x24
#define ENA_REG_ACQ_CAPS		0x28
#define ENA_REG_ASQ_DB			0x2c
#define ENA_REG_ACQ_TAIL		0x30
#define ENA_REG_AENQ_CAPS		0x34
#define ENA_REG_AENQ_BASE_LO		0x38
#define ENA_REG_AENQ_BASE_HI		0x3c
#define ENA_REG_AENQ_HEAD_DB		0x40
#define ENA_REG_AENQ_TAIL		0x44
#define	ENA_REG_GAP_48			0x48
#define ENA_REG_INTR_MASK		0x4c
#define	ENA_REG_GAP_50			0x50
#define ENA_REG_DEV_CTL			0x54
#define ENA_REG_DEV_STS			0x58
#define ENA_REG_MMIO_REG_READ		0x5c
#define ENA_REG_MMIO_RESP_LO		0x60
#define ENA_REG_MMIO_RESP_HI		0x64
#define ENA_REG_RSS_IND_ENTRY_UPDATE	0x68
#define ENA_NUM_REGS			((ENA_REG_RSS_IND_ENTRY_UPDATE / 4) + 1)

/* Version (Register 0x0) */
#define ENA_VERSION_MINOR_VERSION_MASK                 0xff
#define ENA_VERSION_MAJOR_VERSION_SHIFT                8
#define ENA_VERSION_MAJOR_VERSION_MASK                 0xff00

/*
 * Device Caps (Register 0x8)
 */
#define ENA_CAPS_CONTIGUOUS_QUEUE_REQUIRED_MASK        0x1
#define ENA_CAPS_RESET_TIMEOUT_SHIFT                   1
#define ENA_CAPS_RESET_TIMEOUT_MASK                    0x3e
#define ENA_CAPS_RESET_TIMEOUT(v)		    \
	((v) & ENA_CAPS_RESET_TIMEOUT_MASK) >> \
	ENA_CAPS_RESET_TIMEOUT_SHIFT
#define ENA_CAPS_DMA_ADDR_WIDTH_SHIFT                  8
#define ENA_CAPS_DMA_ADDR_WIDTH_MASK                   0xff00
#define ENA_CAPS_DMA_ADDR_WIDTH(v)		     \
	((v) & ENA_CAPS_DMA_ADDR_WIDTH_MASK) >> \
	ENA_CAPS_DMA_ADDR_WIDTH_SHIFT
#define ENA_CAPS_ADMIN_CMD_TO_SHIFT                    16
#define ENA_CAPS_ADMIN_CMD_TO_MASK                     0xf0000

enum ena_reset_reason_types {
	ENA_RESET_NORMAL                       = 0,
	ENA_RESET_KEEP_ALIVE_TO                = 1,
	ENA_RESET_ADMIN_TO                     = 2,
	ENA_RESET_MISS_TX_CMPL                 = 3,
	ENA_RESET_INV_RX_REQ_ID                = 4,
	ENA_RESET_INV_TX_REQ_ID                = 5,
	ENA_RESET_TOO_MANY_RX_DESCS            = 6,
	ENA_RESET_INIT_ERR                     = 7,
	ENA_RESET_DRIVER_INVALID_STATE         = 8,
	ENA_RESET_OS_TRIGGER                   = 9,
	ENA_RESET_OS_NETDEV_WD                 = 10,
	ENA_RESET_SHUTDOWN                     = 11,
	ENA_RESET_USER_TRIGGER                 = 12,
	ENA_RESET_GENERIC                      = 13,
	ENA_RESET_MISS_INTERRUPT               = 14,
	ENA_RESET_LAST,
};

/*
 * Admin Submission Queue Caps (Register 0x18)
 */
#define	ENA_ASQ_CAPS_DEPTH_MASK			0xffff
#define	ENA_ASQ_CAPS_ENTRY_SIZE_SHIFT		16
#define	ENA_ASQ_CAPS_ENTRY_SIZE_MASK		0xffff0000

#define	ENA_ASQ_CAPS_DEPTH(x)	((x) & ENA_ASQ_CAPS_DEPTH_MASK)

#define	ENA_ASQ_CAPS_ENTRY_SIZE(x)		\
	(((x) << ENA_ASQ_CAPS_ENTRY_SIZE_SHIFT) & ENA_ASQ_CAPS_ENTRY_SIZE_MASK)

/*
 * Admin Completion Queue Caps (Register 0x28)
 */
#define ENA_ACQ_CAPS_DEPTH_MASK                    0xffff
#define ENA_ACQ_CAPS_ENTRY_SIZE_SHIFT              16
#define ENA_ACQ_CAPS_ENTRY_SIZE_MASK               0xffff0000

#define	ENA_ACQ_CAPS_DEPTH(x)	((x) & ENA_ACQ_CAPS_DEPTH_MASK)

#define	ENA_ACQ_CAPS_ENTRY_SIZE(x)		\
	(((x) << ENA_ACQ_CAPS_ENTRY_SIZE_SHIFT) & ENA_ACQ_CAPS_ENTRY_SIZE_MASK)

/*
 * Admin Event Notification Queue Caps (Register 0x34)
 */
#define	ENA_AENQ_CAPS_DEPTH_MASK	0xffff
#define	ENA_AENQ_CAPS_ENTRY_SIZE_SHIFT	16
#define	ENA_AENQ_CAPS_ENTRY_SIZE_MASK	0xffff0000

#define	ENA_AENQ_CAPS_DEPTH(x)	((x) & ENA_AENQ_CAPS_DEPTH_MASK)

#define	ENA_AENQ_CAPS_ENTRY_SIZE(x)		   \
	(((x) << ENA_AENQ_CAPS_ENTRY_SIZE_SHIFT) & \
	    ENA_AENQ_CAPS_ENTRY_SIZE_MASK)

/*
 * Interrupt Mask (Register 0x4c)
 */
#define	ENA_INTR_UNMASK		0x0
#define	ENA_INTR_MASK		0x1

/*
 * Device Control (Register 0x54)
 */
#define ENA_DEV_CTL_DEV_RESET_MASK                     0x1
#define ENA_DEV_CTL_AQ_RESTART_SHIFT                   1
#define ENA_DEV_CTL_AQ_RESTART_MASK                    0x2
#define ENA_DEV_CTL_QUIESCENT_SHIFT                    2
#define ENA_DEV_CTL_QUIESCENT_MASK                     0x4
#define ENA_DEV_CTL_IO_RESUME_SHIFT                    3
#define ENA_DEV_CTL_IO_RESUME_MASK                     0x8
#define ENA_DEV_CTL_RESET_REASON_SHIFT                 28
#define ENA_DEV_CTL_RESET_REASON_MASK                  0xf0000000

/*
 * Device Status (Register 0x58)
 */
#define	ENA_DEV_STS_READY_MASK				0x1
#define	ENA_DEV_STS_AQ_RESTART_IN_PROGRESS_SHIFT		1
#define	ENA_DEV_STS_AQ_RESTART_IN_PROGRESS_MASK		0x2
#define	ENA_DEV_STS_AQ_RESTART_FINISHED_SHIFT		2
#define	ENA_DEV_STS_AQ_RESTART_FINISHED_MASK		0x4
#define	ENA_DEV_STS_RESET_IN_PROGRESS_SHIFT		3
#define	ENA_DEV_STS_RESET_IN_PROGRESS_MASK			0x8
#define	ENA_DEV_STS_RESET_FINISHED_SHIFT			4
#define	ENA_DEV_STS_RESET_FINISHED_MASK			0x10
#define	ENA_DEV_STS_FATAL_ERROR_SHIFT			5
#define	ENA_DEV_STS_FATAL_ERROR_MASK			0x20
#define	ENA_DEV_STS_QUIESCENT_STATE_IN_PROGRESS_SHIFT	6
#define	ENA_DEV_STS_QUIESCENT_STATE_IN_PROGRESS_MASK	0x40
#define	ENA_DEV_STS_QUIESCENT_STATE_ACHIEVED_SHIFT		7
#define	ENA_DEV_STS_QUIESCENT_STATE_ACHIEVED_MASK		0x80

/*
 * Admin Queue
 */

/*
 * Top level commands that may be sent to the Admin Queue.
 *
 * Linux: ena_admin_aq_opcode
 */
enum ena_admin_opcode {
	ENA_ADMIN_CMD_CREATE_SQ		= 1,
	ENA_ADMIN_CMD_DESTROY_SQ	= 2,
	ENA_ADMIN_CMD_CREATE_CQ		= 3,
	ENA_ADMIN_CMD_DESTROY_CQ	= 4,
	ENA_ADMIN_CMD_GET_FEATURE	= 8,
	ENA_ADMIN_CMD_SET_FEATURE	= 9,
	ENA_ADMIN_CMD_GET_STATS		= 11,
};

/*
 * Asynchronous Event Notification Queue groups.
 *
 * Linux: ena_admin_aenq_group
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
 * Linux: ena_admin_aenq_notification_syndrome
 */
typedef enum enahw_aenq_syndrome {
	ENAHW_AENQ_SYNDROME_SUSPEND		= 0,
	ENAHW_AENQ_SYNDROME_RESUME		= 1,
	ENAHW_AENQ_SYNDROME_UPDATE_HINTS	= 2,
	ENAHW_AENQ_SYNDROME_NUM			= 3,
} enahw_aenq_syndrome_t;


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
 * The response status of an Admin Queue command.
 *
 * Linux: ena_admin_aq_completion_status
 */
typedef enum enahw_admin_cmd_status {
	ENA_ADMIN_SUCCESS			= 0,
	ENA_ADMIN_RESOURCE_ALLOCATION_FAILURE	= 1,
	ENA_ADMIN_BAD_OPCODE			= 2,
	ENA_ADMIN_UNSUPPORTED_OPCODE		= 3,
	ENA_ADMIN_MALFORMED_REQUEST		= 4,
	/*
	 * Additional status is provided in ACQ entry
	 * extended_status.
	 */
	ENA_ADMIN_ILLEGAL_PARAMETER		= 5,
	ENA_ADMIN_UNKNOWN_ERROR			= 6,
	ENA_ADMIN_RESOURCE_BUSY			= 7,
} enahw_admin_cmd_status_t;

/*
 * ENA devices use a 48-bit memory space.
 *
 * Linux: ena_common_mem_addr
 */
typedef struct enahw_addr {
	uint32_t	eha_addr_low;
	uint16_t	eha_addr_high;
	uint16_t	eha_rsvd16;
} enahw_addr_t;

/* TODO used? rename? */
#define	ENA_HW_ASQ_CD_COMMAND_ID_MASK	GENMASK(11, 0)
#define	ENA_HW_ASQ_CD_PHASE_MASK	0x1

/* typedef ena_hw_asq_entry_t ena_hw_admin_cmd_t; */

struct enahw_ctrl_buff {
	uint32_t length;
	uint32_t mem_addr_low;
	uint16_t mem_addr_high;
	uint16_t rsvdw3;
};

/* Linux: ena_admin_get_feat_cmd */
struct enahw_get_feat_cmd {
	struct enahw_ctrl_buff	ctrl_buf;

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
	uint8_t			flags;

	/* An id from enahw_feature_id_t. */
	uint8_t			id;

	/*
	 * Each feature is versioned, allowing upgrades to the feature
	 * set without breaking backwards compatibility. The driver
	 * uses this field to specify which version it supports
	 * (starting from zero). Linux doesn't document this very well
	 * and sets version to 0 for most features. We define a set of
	 * macros, underneath the enahw_feature_id_t type, clearly
	 * documenting the version we support for each feature.
	 */
	uint8_t			version;
	uint8_t			rsvd;

	uint32_t		unused[11];
};

/*
 * TODO doc
 *
 * ena_admin_set_feature_host_attr_desc
 */
struct enahw_set_feat_host_attr {
	/*
	 * Host OS info base address in OS memory. Host info is 4KB of
	 * physically contiguous memory.
	 */
	enahw_addr_t	os_addr;

	/*
	 * Host debug area base address in OS memory. Debug area must
	 * be physically contiguous.
	 */
	enahw_addr_t	debug_addr;
	uint32_t	debug_sz;
};

struct enahw_set_feat_mtu {
	/*
	 * TODO: The MTU should not include the L2 frame
	 * header/trailer bytes? (some devices do)
	 */
	uint32_t mtu;
};

struct enahw_set_aenq {
	uint32_t supported_groups;
	uint32_t enabled_groups;
};

union enahw_set_feat_u {
	uint32_t raw[11];
	struct enahw_set_feat_host_attr host_attr;
	struct enahw_set_feat_mtu mtu;
	struct enahw_set_aenq aenq;
};

struct enahw_set_feat_cmd {
	struct enahw_ctrl_buff	ctrl_buf;

	/*
	 * 1:0	select value
	 *
	 *     0x1 = current value
	 *     0x3 = default value
	 *
	 * 7:3	reserved
	 */
	uint8_t flags;

	/* TODO as appears in ena_admin_aq_feature_id */
	uint8_t id;
	uint8_t version;
	uint8_t rsvd;

	union enahw_set_feat_u egfc_cmd;
};

struct enahw_create_cq_cmd {
	uint8_t		cq_caps_1;
	uint8_t		cq_caps_2;
	uint16_t	cq_num_descs;
	uint32_t	cq_msix_vector;

	uint32_t	cq_ba_low;
	uint16_t	cq_ba_high;
	uint16_t	cq_rsvdw5;
};

/* aq_create_cq_cmd */
#define	ENA_CMD_CREATE_CQ_INTERRUPT_MODE_ENABLED_SHIFT	5
#define	ENA_CMD_CREATE_CQ_INTERRUPT_MODE_ENABLED_MASK	(BIT(5))
#define	ENA_CMD_CREATE_CQ_DESC_SIZE_WORDS_MASK		(GENMASK(4, 0))

#define	ENA_CMD_CREATE_CQ_INTERRUPT_MODE_ENABLE(cmd)	\
	((cmd).cq_caps_1 |= ENA_CMD_CREATE_CQ_INTERRUPT_MODE_ENABLED_MASK)

#define	ENA_CMD_CREATE_CQ_DESC_SIZE_WORDS(cmd, val)	\
	(((cmd).cq_caps_2) |= ((val) & ENA_CMD_CREATE_CQ_DESC_SIZE_WORDS_MASK))

struct enahw_destroy_cq_cmd {
	uint16_t	cq_idx;
	uint16_t	cq_rsvd1;
};

/* ena_admin_aq_create_sq_cmd */
struct enahw_create_sq_cmd {
	uint8_t		sq_direction;
	uint8_t		rsvdw1;
	uint8_t		sq_caps_2;
	uint8_t		sq_caps_3;
	uint16_t	sq_cq_idx;
	uint16_t	sq_num_descs;

	/*
	 * ena_common_mem_addr, this should not be used for LLQ, must
	 * be page aligned
	 */
	uint32_t	sq_ba_low;
	uint16_t	sq_ba_high;
	uint16_t	rsvdw4;

	uint32_t	sq_head_wb_low;
	uint16_t	sq_head_wb_high;
	uint16_t	rsvdw6;
	uint32_t	rsvdw7;
	uint32_t	rsvdw8;
};

typedef enum enahw_sq_direction {
	ENA_ADMIN_SQ_DIRECTION_TX = 1,
	ENA_ADMIN_SQ_DIRECTION_RX = 2,
} enahw_sq_direction_t;

typedef enum ena_placement_policy {
	/* Descriptors and headers are in host memory. */
	ENA_PLACEMENT_POLICY_HOST = 1,
	/*
	 * Descriptors and headers are in device memory (a.k.a Low
	 * Latency Queue).
	 */
	ENA_PLACEMENT_POLICY_DEV = 3,
} ena_placement_policy_t;

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
typedef enum ena_completion_policy_type {
	ENA_COMPLETION_POLICY_DESC		= 0,
	ENA_COMPLETION_POLICY_DESC_ON_DEMAND	= 1,
	ENA_COMPLETION_POLICY_HEAD_ON_DEMAND	= 2,
	ENA_COMPLETION_POLICY_HEAD		= 3,
} ena_completion_policy_type_t;

#define	ENA_CMD_CREATE_SQ_DIR_SHIFT			5
#define	ENA_CMD_CREATE_SQ_DIR_MASK			GENMASK(7, 5)
#define	ENA_CMD_CREATE_SQ_PLACEMENT_POLICY_MASK		GENMASK(3, 0)
#define	ENA_CMD_CREATE_SQ_COMPLETION_POLICY_SHIFT	4
#define	ENA_CMD_CREATE_SQ_COMPLETION_POLICY_MASK	GENMASK(6, 4)
#define	ENA_CMD_CREATE_SQ_PHYSMEM_CONTIG_MASK		BIT(0)

#define	ENA_CMD_CREATE_SQ_BA_LO(cmd, val)	\
	(((cmd).sq_ba_low = ((val) >> 32))

#define ENA_CMD_CREATE_SQ_DIR(cmd, val)					\
	(((cmd).sq_direction) |= (((val) << ENA_CMD_CREATE_SQ_DIR_SHIFT) & \
	    ENA_CMD_CREATE_SQ_DIR_MASK))

#define	ENA_CMD_CREATE_SQ_PLACEMENT_POLICY(cmd, val)	\
	(((cmd).sq_caps_2) |= ((val) & ENA_CMD_CREATE_SQ_PLACEMENT_POLICY_MASK))

#define	ENA_CMD_CREATE_SQ_COMPLETION_POLICY(cmd, val)	\
	(((cmd).sq_caps_2) |=						\
	    (((val) << ENA_CMD_CREATE_SQ_COMPLETION_POLICY_SHIFT) &	\
		ENA_CMD_CREATE_SQ_COMPLETION_POLICY_MASK))

#define	ENA_CMD_CREATE_SQ_PHYSMEM_CONTIG(cmd)			\
	((cmd).sq_caps_3 |= ENA_CMD_CREATE_SQ_PHYSMEM_CONTIG_MASK)

struct enahw_destroy_sq_cmd {
	uint16_t	sq_idx;
	uint8_t		sq_identity; /* Tx/Rx */
	uint8_t		sq_rsvd1;
};

#define	ENAHW_CMD_DESTROY_SQ_DIR_SHIFT	5
#define	ENAHW_CMD_DESTROY_SQ_DIR_MASK	GENMASK(7, 5)

#define ENAHW_CMD_DESTROY_SQ_DIR(cmd, val)				\
	(((cmd).sq_identity) |= (((val) << ENAHW_CMD_DESTROY_SQ_DIR_SHIFT) & \
	    ENAHW_CMD_DESTROY_SQ_DIR_MASK))

struct enahw_get_stats_cmd {
	struct enahw_ctrl_buff	ctrl_buf;
	uint8_t			type;
	uint8_t			scope;
	uint16_t		rsvdw1;
	uint16_t		queue_idx;
	uint16_t		device_id;
};

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

/* TODO replacement for ena_hw_asq_entry_t */
typedef struct enahw_cmd_desc {
	uint16_t	ecd_idx; /* 0,2 TODO index in SQ */
	uint8_t		ecd_opcode; /* 2,1 */
	uint8_t		ecd_flags;  /* 3,1 */

	union {
		uint32_t			raw[15]; /* 16,4 */
		struct enahw_get_feat_cmd	get_feat;
		struct enahw_set_feat_cmd	set_feat;
		struct enahw_create_cq_cmd	create_cq;
		struct enahw_destroy_cq_cmd	destroy_cq;
		struct enahw_create_sq_cmd	create_sq;
		struct enahw_destroy_sq_cmd	destroy_sq;
		struct enahw_get_stats_cmd	get_stats;
	} ecd_payload;

} enahw_cmd_desc_t;			 /* 64,4 */

/* Let's make sure the compiler is not mucking about with padding. */
CTASSERT(64 == sizeof (enahw_cmd_desc_t));
CTASSERT(sizeof (struct ena_admin_aq_entry) == sizeof (enahw_cmd_desc_t));
/* CTASSERT(offsetof (struct enahw_cmd_desc, ecd_payload.create_cq.cq_caps_1) == */
/*     offsetof (struct ena_admin_aq_create_cq_cmd, cq_caps_1)); */
/* CTASSERT(32 == */
/*     offsetof (struct ena_admin_aq_create_cq_cmd, cq_caps_1)); */

/*
 * Subcommands for ENA_ADMIN_{GET,SET}_FEATURE.
 *
 * Linux: ena_admin_aq_feature_id
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
 * feature above. Furthermore, these are the feature versions we will
 * use to communicate with the feature command. Linux has these values
 * spread throughout the code, at the various callsites of
 * ena_com_get_feature().
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
 * TODO rename these? */
#define	ENA_HW_ACQ_CD_COMMAND_ID_MASK	GENMASK(11, 0)
#define	ENA_HW_ACQ_CD_PHASE_MASK	0x1

/*
 * TODO doc
 *
 * TODO Might want to rename enahw_admin_resp_desc. Yes, we will want
 * to name cmd/resp either admin_{cmd,resp} or io_{cmd,resp} to
 * differentiate the purposes of these descs.
 */
typedef struct enahw_resp_desc {
	uint16_t	erd_cmd_idx;
	/* TODO status of the cmd? */
	uint8_t		erd_status;
	/*
	 * TODO flags of the response?
	 *
	 * 0		Phase
	 * 7:1		Reserved
	 */
	uint8_t		erd_flags;
	/* TODO extended status bits? */
	uint16_t	erd_ext_status;
	/*
	 * TODO document
	 */
	uint16_t	erd_sq_head_idx;

	union {
		uint32_t	raw[14];

		/* ENA_ADMIN_DEVICE_ATTRIBUTES */
		struct {
			uint32_t impl_id;
			uint32_t device_version;
			uint32_t supported_features;
			uint32_t rsvd3;
			uint32_t phys_addr_width;
			uint32_t virt_addr_with;
			/* unicast MAC address in network byte order */
			uint8_t mac_addr[6];
			uint8_t rsvd7[2];
			uint32_t max_mtu;
		} get_feat_dev_attr;

		/* ENA_ADMIN_MAX_QUEUES_NUM */
		struct {
			uint32_t max_sq_num;
			uint32_t max_sq_depth;
			uint32_t max_cq_num;
			uint32_t max_cq_depth;
			uint32_t max_legacy_llq_num;
			uint32_t max_legacy_llq_depth;
			uint32_t max_header_size;

			/*
			 * Maximum Descriptors number, including meta
			 * descriptor, allowed for a single Tx packet
			 */
			uint16_t max_packet_tx_descs;

			/* Maximum Descriptors number allowed for a
			 * single Rx packet */
			uint16_t max_packet_rx_descs;
		} get_feat_max_queue;

		/* ENA_ADMIN_MAX_QUEUES_EXT */
		struct {
			uint8_t version;
			uint8_t	rsvd1[3];

			uint32_t max_tx_sq_num;
			uint32_t max_tx_cq_num;
			uint32_t max_rx_sq_num;
			uint32_t max_rx_cq_num;
			uint32_t max_tx_sq_depth;
			uint32_t max_tx_cq_depth;
			uint32_t max_rx_sq_depth;
			uint32_t max_rx_cq_depth;
			uint32_t max_tx_header_size;

			/*
			 * Maximum Descriptors number, including meta
			 * descriptor, allowed for a single Tx packet.
			 */
			uint16_t max_per_packet_tx_descs;

			/*
			 * Maximum Descriptors number allowed for a
			 * single Rx packet.
			 */
			uint16_t max_per_packet_rx_descs;
		} get_feat_max_queue_ext;

		struct {
			uint32_t supported_groups;
			uint32_t enabled_groups;
		} get_feat_aenq;

		/* ENA_ADMIN_LINK_CONFIG */
		/* ena_admin_get_feature_link_desc */
		struct {
			/* Link speed in Mb. */
			uint32_t speed;

			/* Bit field of enum enahw_link_t types. */
			uint32_t supported;

			/*
			 * 0:		autoneg
			 * 1:		duplex - Full Duplex
			 * 31-2:	reserved
			 */
			uint32_t flags;
		} get_feat_link_conf;

		struct {
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
			u32 tx;

			/* Receive side supported stateless offload
			 * 0 : RX_L3_csum_ipv4 - IPv4 checksum
			 * 1 : RX_L4_ipv4_csum - TCP/UDP/IPv4 checksum
			 * 2 : RX_L4_ipv6_csum - TCP/UDP/IPv6 checksum
			 * 3 : RX_hash - Hash calculation
			 */
			u32 rx_supported;

			/* XXX Linux seems to only check rx_supported. */
			u32 rx_enabled;
		} get_feat_offload;

		struct {
			uint16_t cq_idx;
			uint16_t cq_actual_num_descs;
			uint32_t cq_numa_node_reg_offset; /* ??? */
			uint32_t cq_head_db_reg_offset;	       /* doorbell */
			uint32_t cq_interrupt_mask_reg_offset; /* stop intr */
		} create_cq;

		/* destroy_cq: No command-specific response. */

		struct {
			uint16_t sq_idx;
			uint16_t sq_rsvdw1;
			uint32_t sq_db_reg_offset;
			uint32_t sq_llq_desc_reg_offset;
			uint32_t sq_llq_header_reg_offset;
		} create_sq;

		/* destroy_sq: No command-specific response. */

		struct {
			uint32_t tx_bytes_low;
			uint32_t tx_bytes_high;
			uint32_t tx_pkts_low;
			uint32_t tx_pkts_high;
			uint32_t rx_bytes_low;
			uint32_t rx_bytes_high;
			uint32_t rx_pkts_low;
			uint32_t rx_pkts_high;
			uint32_t rx_drops_low;
			uint32_t rx_drops_high;
			uint32_t tx_drops_low;
			uint32_t tx_drops_high;
		} get_stats_basic;

	} erd_payload;
} enahw_resp_desc_t;

/* Let's make sure the compiler is not mucking about with padding. */
CTASSERT(64 == sizeof (enahw_resp_desc_t));
CTASSERT(sizeof (struct ena_admin_acq_entry) == sizeof (enahw_resp_desc_t));

#define	ENAHW_GET_FEATURE_LINK_CONF_AUTONEG_MASK	BIT(0)
#define	ENAHW_GET_FEATURE_LINK_CONF_DUPLEX_SHIFT	1
#define	ENAHW_GET_FEATURE_LINK_CONF_DUPLEX_MASK		BIT(1)

#define	ENAHW_GET_FEATURE_LINK_CONF_AUTONEG(desc)			\
	((desc).flags & ENAHW_GET_FEATURE_LINK_CONF_AUTONEG_MASK)

#define	ENAHW_GET_FEATURE_LINK_CONF_FULL_DUPLEX(desc)			\
	((((desc).flags & ENAHW_GET_FEATURE_LINK_CONF_DUPLEX_MASK) >>	\
	    ENAHW_GET_FEATURE_LINK_CONF_DUPLEX_SHIFT) == 1)

/* Feature Offloads */
#define ENAHW_GET_FEATURE_OFFLOAD_TX_L3_CSUM_IPV4_MASK BIT(0)
#define ENAHW_GET_FEATURE_OFFLOAD_TX_L4_IPV4_CSUM_PART_SHIFT 1
#define ENAHW_GET_FEATURE_OFFLOAD_TX_L4_IPV4_CSUM_PART_MASK BIT(1)
#define ENAHW_GET_FEATURE_OFFLOAD_TX_L4_IPV4_CSUM_FULL_SHIFT 2
#define ENAHW_GET_FEATURE_OFFLOAD_TX_L4_IPV4_CSUM_FULL_MASK BIT(2)
#define ENAHW_GET_FEATURE_OFFLOAD_TX_L4_IPV6_CSUM_PART_SHIFT 3
#define ENAHW_GET_FEATURE_OFFLOAD_TX_L4_IPV6_CSUM_PART_MASK BIT(3)
#define ENAHW_GET_FEATURE_OFFLOAD_TX_L4_IPV6_CSUM_FULL_SHIFT 4
#define ENAHW_GET_FEATURE_OFFLOAD_TX_L4_IPV6_CSUM_FULL_MASK BIT(4)
#define ENAHW_GET_FEATURE_OFFLOAD_TSO_IPV4_SHIFT       5
#define ENAHW_GET_FEATURE_OFFLOAD_TSO_IPV4_MASK        BIT(5)
#define ENAHW_GET_FEATURE_OFFLOAD_TSO_IPV6_SHIFT       6
#define ENAHW_GET_FEATURE_OFFLOAD_TSO_IPV6_MASK        BIT(6)
#define ENAHW_GET_FEATURE_OFFLOAD_TSO_ECN_SHIFT        7
#define ENAHW_GET_FEATURE_OFFLOAD_TSO_ECN_MASK         BIT(7)
#define ENAHW_GET_FEATURE_OFFLOAD_RX_L3_CSUM_IPV4_MASK BIT(0)
#define ENAHW_GET_FEATURE_OFFLOAD_RX_L4_IPV4_CSUM_SHIFT 1
#define ENAHW_GET_FEATURE_OFFLOAD_RX_L4_IPV4_CSUM_MASK BIT(1)
#define ENAHW_GET_FEATURE_OFFLOAD_RX_L4_IPV6_CSUM_SHIFT 2
#define ENAHW_GET_FEATURE_OFFLOAD_RX_L4_IPV6_CSUM_MASK BIT(2)
#define ENAHW_GET_FEATURE_OFFLOAD_RX_HASH_SHIFT        3
#define ENAHW_GET_FEATURE_OFFLOAD_RX_HASH_MASK         BIT(3)

#define	ENAHW_GET_FEATURE_OFFLOAD_TX_L3_CSUM_IPV4(desc)			\
	(((desc).rx_supported &						\
	    ENAHW_GET_FEATURE_OFFLOAD_TX_L3_CSUM_IPV4_MASK) != 0)

#define	ENAHW_GET_FEATURE_OFFLOAD_TX_L4_IPV4_CSUM_FULL(desc)		\
	(((desc).rx_supported &						\
	    ENAHW_GET_FEATURE_OFFLOAD_TX_L4_IPV4_CSUM_FULL_MASK) != 0)

/*
 * AENQ
 */

/*
 * TODO doc
 *
 * ena_admin_aenq_common_desc
 */
typedef struct ena_hw_aenq_comm_desc {
	uint16_t	ehacd_group;
	uint16_t	ehacd_syndrome;
	uint8_t		ehacd_flags;
	uint8_t		ehacd_rsvd1[3];
	uint32_t	ehacd_timestamp_low;
	uint32_t	ehacd_timestamp_high;
} ena_hw_aenq_comm_desc_t;

/*
 * TODO doc
 *
 * ena_admin_aenq_entry
 */
typedef struct ena_hw_aenq_entry {
	ena_hw_aenq_comm_desc_t	ehae_comm_desc;
	uint32_t		ehae_data[12];
} ena_hw_aenq_entry_t;

/*
 * TODO potentially prefix the following two with 'reg' to make it
 * clear they wer just for querying the reg space, not for data
 * flow.
 */
typedef struct ena_hw_read_resp {
	uint16_t	ehrr_id;
	uint16_t	ehrr_off;

	/*
	 * Valid when poll is cleared.
	 *
	 * TODO figure out what that means and write better doc.
	 */
	uint32_t	ehrr_val;
} ena_hw_read_resp_t;

typedef struct ena_hw_read_req {
	ena_hw_read_resp_t	*ehrr_resp;
	uint32_t		ehrr_timeout;
	uint16_t		ehrr_seq;
	boolean_t		ehrr_readless; /* TODO rename */
	/* TODO mutex? */
} ena_hw_read_req_t;

typedef struct ena_hw_reg_nv {
	char		*ehrv_name;
	uint32_t	ehrv_offset;
	uint32_t	ehrv_value;
} ena_hw_reg_nv_t;

typedef struct enahw_basic_stats {
	uint64_t	ebs_tx_bytes;
	uint64_t	ebs_tx_pkts;
	uint64_t	ebs_tx_drops;

	uint64_t	ebs_rx_bytes;
	uint64_t	ebs_rx_pkts;
	uint64_t	ebs_rx_drops;
} enahw_basic_stats_t;

typedef struct ena_hw {
	kmutex_t		eh_lock;

	ena_hw_read_req_t	eh_read_req; /* TODO old stuff? */

	uint8_t			eh_dma_width;

	uint32_t		eh_tx_max_sq_num;
	uint32_t		eh_tx_max_sq_num_descs;
	uint32_t		eh_tx_max_cq_num;
	uint32_t		eh_tx_max_cq_num_descs;
	uint16_t		eh_tx_max_desc_per_pkt;
	uint32_t		eh_tx_max_hdr_len;

	uint32_t		eh_rx_max_sq_num;
	uint32_t		eh_rx_max_sq_num_descs;
	uint32_t		eh_rx_max_cq_num;
	uint32_t		eh_rx_max_cq_num_descs;
	uint16_t		eh_rx_max_desc_per_pkt;

	boolean_t		eh_rx_l3_ipv4_csum;
	boolean_t		eh_rx_l4_ipv4_full_csum;

	/*
	 * This is calculated from the Rx/Tx queue nums.
	 */
	uint16_t		eh_max_io_queues;

	uint32_t		eh_max_mtu;
	uint8_t			eh_mac_addr[ETHERADDRL];

	/*
	 * These statistics apply to the entire device.
	 */
	enahw_basic_stats_t	eh_basic_stats;
} ena_hw_t;

/*
 * Tx descriptors and related structures.
 *
 * TODO for now this is direct copy-pasta of Linux driver.
 * TODO we probably have our own illumos constants to use.
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

typedef struct enahw_tx_data_desc {
	/* 15:0 : length - Buffer length in bytes, must
	 *    include any packet trailers that the ENA supposed
	 *    to update like End-to-End CRC, Authentication GMAC
	 *    etc. This length must not include the
	 *    'Push_Buffer' length. This length must not include
	 *    the 4-byte added in the end for 802.3 Ethernet FCS
	 * 21:16 : req_id_hi - Request ID[15:10]
	 * 22 : reserved22 - MBZ
	 * 23 : meta_desc - MBZ
	 * 24 : phase
	 * 25 : reserved1 - MBZ
	 * 26 : first - Indicates first descriptor in
	 *    transaction
	 * 27 : last - Indicates last descriptor in
	 *    transaction
	 * 28 : comp_req - Indicates whether completion
	 *    should be posted, after packet is transmitted.
	 *    Valid only for first descriptor
	 * 30:29 : reserved29 - MBZ
	 * 31 : reserved31 - MBZ
	 */
	uint32_t len_ctrl;

	/* 3:0 : l3_proto_idx - L3 protocol. This field
	 *    required when l3_csum_en,l3_csum or tso_en are set.
	 * 4 : DF - IPv4 DF, must be 0 if packet is IPv4 and
	 *    DF flags of the IPv4 header is 0. Otherwise must
	 *    be set to 1
	 * 6:5 : reserved5
	 * 7 : tso_en - Enable TSO, For TCP only.
	 * 12:8 : l4_proto_idx - L4 protocol. This field need
	 *    to be set when l4_csum_en or tso_en are set.
	 * 13 : l3_csum_en - enable IPv4 header checksum.
	 * 14 : l4_csum_en - enable TCP/UDP checksum.
	 * 15 : ethernet_fcs_dis - when set, the controller
	 *    will not append the 802.3 Ethernet Frame Check
	 *    Sequence to the packet
	 * 16 : reserved16
	 * 17 : l4_csum_partial - L4 partial checksum. when
	 *    set to 0, the ENA calculates the L4 checksum,
	 *    where the Destination Address required for the
	 *    TCP/UDP pseudo-header is taken from the actual
	 *    packet L3 header. when set to 1, the ENA doesn't
	 *    calculate the sum of the pseudo-header, instead,
	 *    the checksum field of the L4 is used instead. When
	 *    TSO enabled, the checksum of the pseudo-header
	 *    must not include the tcp length field. L4 partial
	 *    checksum should be used for IPv6 packet that
	 *    contains Routing Headers.
	 * 20:18 : reserved18 - MBZ
	 * 21 : reserved21 - MBZ
	 * 31:22 : req_id_lo - Request ID[9:0]
	 */
	uint32_t meta_ctrl;

	uint32_t buff_addr_lo;

	/* address high and header size
	 * 15:0 : addr_hi - Buffer Pointer[47:32]
	 * 23:16 : reserved16_w2
	 * 31:24 : header_length - Header length. For Low
	 *    Latency Queues, this fields indicates the number
	 *    of bytes written to the headers' memory. For
	 *    normal queues, if packet is TCP or UDP, and longer
	 *    than max_header_size, then this field should be
	 *    set to the sum of L4 header offset and L4 header
	 *    size(without options), otherwise, this field
	 *    should be set to 0. For both modes, this field
	 *    must not exceed the max_header_size.
	 *    max_header_size value is reported by the Max
	 *    Queues Feature descriptor
	 */
	uint32_t buff_addr_hi_hdr_sz;
} enahw_tx_data_desc_t;

/* tx_desc */
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
	(((desc)->len_ctrl) |= ((len) & ENAHW_TX_DESC_LENGTH_MASK))

#define	ENAHW_TX_DESC_FIRST_ON(desc)				\
	(((desc)->len_ctrl) |= ENAHW_TX_DESC_FIRST_MASK)

#define	ENAHW_TX_DESC_FIRST_OFF(desc)				\
	(((desc)->len_ctrl) &= ~ENAHW_TX_DESC_FIRST_MASK)

#define	ENAHW_TX_DESC_REQID_HI(desc, reqid)				\
	(((desc)->len_ctrl) |=						\
	    ((((reqid) >> 10) << ENAHW_TX_DESC_REQ_ID_HI_SHIFT) &	\
		ENAHW_TX_DESC_REQ_ID_HI_MASK))

#define	ENAHW_TX_DESC_REQID_LO(desc, reqid)				\
	(((desc)->meta_ctrl) |= (((reqid) << ENAHW_TX_DESC_REQ_ID_LO_SHIFT) & \
	    ENAHW_TX_DESC_REQ_ID_LO_MASK))

#define	ENAHW_TX_DESC_PHASE(desc, phase)				\
	(((desc)->len_ctrl) |= (((phase) << ENAHW_TX_DESC_PHASE_SHIFT) & \
	    ENAHW_TX_DESC_PHASE_MASK))

#define	ENAHW_TX_DESC_LAST_ON(desc)			\
	(((desc)->len_ctrl) |= ENAHW_TX_DESC_LAST_MASK)

#define	ENAHW_TX_DESC_LAST_OFF(desc)				\
	(((desc)->len_ctrl) &= ~ENAHW_TX_DESC_LAST_MASK)

#define	ENAHW_TX_DESC_COMP_REQ_ON(desc)				\
	(((desc)->len_ctrl) |= ENAHW_TX_DESC_COMP_REQ_MASK)

#define	ENAHW_TX_DESC_COMP_REQ_OFF(desc)			\
	(((desc)->len_ctrl) &= ~ENAHW_TX_DESC_COMP_REQ_MASK)

#define	ENAHW_TX_DESC_META_DESC_ON(desc)	\
	(((desc)->len_ctrl) |= ENAHW_TX_DESC_META_DESC_MASK)

#define	ENAHW_TX_DESC_META_DESC_OFF(desc)	\
	(((desc)->len_ctrl) &= ~ENAHW_TX_DESC_META_DESC_MASK)

#define	ENAHW_TX_DESC_ADDR_LO(desc, addr)	\
	(((desc)->buff_addr_lo) = (addr))

#define	ENAHW_TX_DESC_ADDR_HI(desc, addr)				\
	(((desc)->buff_addr_hi_hdr_sz) |=				\
	    (((addr) >> 32) & ENAHW_TX_DESC_ADDR_HI_MASK))

#define	ENAHW_TX_DESC_HEADER_LENGTH(desc, len)			\
	(((desc)->buff_addr_hi_hdr_sz) |=			\
	    (((len) << ENAHW_TX_DESC_HEADER_LENGTH_SHIFT) &	\
		ENAHW_TX_DESC_HEADER_LENGTH_MASK))

#define	ENAHW_TX_DESC_DF_ON(desc)				\
	((desc)->meta_ctrl |= ENAHW_TX_DESC_DF_MASK)

#define	ENAHW_TX_DESC_TSO_OFF(desc)				\
	(((desc)->meta_ctrl) &= ~ENAHW_TX_DESC_TSO_EN_MASK)

#define	ENAHW_TX_DESC_L3_CSUM_OFF(desc)				\
	(((desc)->meta_ctrl) &= ~ENAHW_TX_DESC_L3_CSUM_EN_MASK)

#define	ENAHW_TX_DESC_L4_CSUM_OFF(desc)				\
	(((desc)->meta_ctrl) &= ~ENAHW_TX_DESC_L4_CSUM_EN_MASK)

#define	ENAHW_TX_DESC_L4_CSUM_PARTIAL_ON(desc)				\
	(((desc)->meta_ctrl) &= ~ENAHW_TX_DESC_L4_CSUM_PARTIAL_MASK)

typedef struct enahw_tx_meta_desc {
	/* 9:0 : req_id_lo - Request ID[9:0]
	 * 11:10 : reserved10 - MBZ
	 * 12 : reserved12 - MBZ
	 * 13 : reserved13 - MBZ
	 * 14 : ext_valid - if set, offset fields in Word2
	 *    are valid Also MSS High in Word 0 and bits [31:24]
	 *    in Word 3
	 * 15 : reserved15
	 * 19:16 : mss_hi
	 * 20 : eth_meta_type - 0: Tx Metadata Descriptor, 1:
	 *    Extended Metadata Descriptor
	 * 21 : meta_store - Store extended metadata in queue
	 *    cache
	 * 22 : reserved22 - MBZ
	 * 23 : meta_desc - MBO
	 * 24 : phase
	 * 25 : reserved25 - MBZ
	 * 26 : first - Indicates first descriptor in
	 *    transaction
	 * 27 : last - Indicates last descriptor in
	 *    transaction
	 * 28 : comp_req - Indicates whether completion
	 *    should be posted, after packet is transmitted.
	 *    Valid only for first descriptor
	 * 30:29 : reserved29 - MBZ
	 * 31 : reserved31 - MBZ
	 */
	uint32_t len_ctrl;

	/* 5:0 : req_id_hi
	 * 31:6 : reserved6 - MBZ
	 */
	uint32_t word1;

	/* 7:0 : l3_hdr_len
	 * 15:8 : l3_hdr_off
	 * 21:16 : l4_hdr_len_in_words - counts the L4 header
	 *    length in words. there is an explicit assumption
	 *    that L4 header appears right after L3 header and
	 *    L4 offset is based on l3_hdr_off+l3_hdr_len
	 * 31:22 : mss_lo
	 */
	uint32_t word2;

	uint32_t reserved;
} enahw_tx_meta_desc_t;

typedef union enahw_tx_desc {
	enahw_tx_data_desc_t etd_data;
	enahw_tx_meta_desc_t etd_meta;
} enahw_tx_desc_t;

CTASSERT(sizeof (enahw_tx_data_desc_t) == sizeof (enahw_tx_meta_desc_t));
CTASSERT(sizeof (enahw_tx_data_desc_t) == sizeof (enahw_tx_desc_t));
CTASSERT(sizeof (enahw_tx_meta_desc_t) == sizeof (enahw_tx_desc_t));
CTASSERT(sizeof (struct ena_eth_io_tx_desc) == sizeof (enahw_tx_desc_t));
CTASSERT(sizeof (struct ena_eth_io_tx_meta_desc) == sizeof (enahw_tx_desc_t));


typedef struct enahw_tx_cdesc {
	/* Request ID[15:0] */
	uint16_t req_id;

	uint8_t status;

	/* flags
	 * 0 : phase
	 * 7:1 : reserved1
	 */
	uint8_t flags;
	uint16_t sub_qid;
	uint16_t sq_head_idx;
} enahw_tx_cdesc_t;

/* TODO kill? */
/* struct ena_com_tx_ctx { */
/* 	struct ena_com_tx_meta ena_meta; */
/* 	struct ena_com_buf *ena_bufs; */
/* 	/\* For LLQ, header buffer - pushed to the device mem space *\/ */
/* 	void *push_header; */

/* 	enum ena_eth_io_l3_proto_index l3_proto; */
/* 	enum ena_eth_io_l4_proto_index l4_proto; */
/* 	uint16_t num_bufs; */
/* 	uint16_t req_id; */
/* 	/\* For regular queue, indicate the size of the header */
/* 	 * For LLQ, indicate the size of the pushed buffer */
/* 	 *\/ */
/* 	uint16_t header_len; */

/* 	uint8_t meta_valid; */
/* 	uint8_t tso_enable; */
/* 	uint8_t l3_csum_enable; */
/* 	uint8_t l4_csum_enable; */
/* 	uint8_t l4_csum_partial; */
/* 	uint8_t df; /\* Don't fragment *\/ */
/* }; */

/* TODO kill? */
/* struct ena_com_rx_ctx { */
/* 	struct ena_com_rx_buf_info *ena_bufs; */
/* 	enum ena_eth_io_l3_proto_index l3_proto; */
/* 	enum ena_eth_io_l4_proto_index l4_proto; */
/* 	boolean_t l3_csum_err; */
/* 	boolean_t l4_csum_err; */
/* 	uint8_t l4_csum_checked; */
/* 	/\* fragmented packet *\/ */
/* 	boolean_t frag; */
/* 	uint32_t hash; */
/* 	uint16_t descs; */
/* 	int max_bufs; */
/* 	uint8_t pkt_offset; */
/* }; */

typedef struct enahw_rx_desc {
	/* In bytes. 0 means 64KB */
	uint16_t length;

	/* MBZ */
	uint8_t reserved2;

	/* 0 : phase
	 * 1 : reserved1 - MBZ
	 * 2 : first - Indicates first descriptor in
	 *    transaction
	 * 3 : last - Indicates last descriptor in transaction
	 * 4 : comp_req
	 * 5 : reserved5 - MBO
	 * 7:6 : reserved6 - MBZ
	 */
	uint8_t ctrl;

	uint16_t req_id;

	/* MBZ */
	uint16_t reserved6;

	uint32_t buff_addr_lo;

	uint16_t buff_addr_hi;

	/* MBZ */
	uint16_t reserved16_w3;
} enahw_rx_desc_t;

CTASSERT(sizeof (enahw_rx_desc_t) == sizeof (struct ena_eth_io_rx_desc));

/* rx_desc */
#define ENAHW_RX_DESC_PHASE_MASK                       BIT(0)
#define ENAHW_RX_DESC_FIRST_SHIFT                      2
#define ENAHW_RX_DESC_FIRST_MASK                       BIT(2)
#define ENAHW_RX_DESC_LAST_SHIFT                       3
#define ENAHW_RX_DESC_LAST_MASK                        BIT(3)
#define ENAHW_RX_DESC_COMP_REQ_SHIFT                   4
#define ENAHW_RX_DESC_COMP_REQ_MASK                    BIT(4)

#define	ENAHW_RX_DESC_PHASE(desc, val)				\
	((desc)->ctrl |= ((val) & ENAHW_RX_DESC_PHASE_MASK))

#define	ENAHW_RX_DESC_FIRST(desc)			\
	((desc)->ctrl |= ENAHW_RX_DESC_FIRST_MASK)

#define	ENAHW_RX_DESC_LAST(desc)			\
	((desc)->ctrl |= ENAHW_RX_DESC_LAST_MASK)

#define	ENAHW_RX_DESC_COMP_REQ(desc)			\
	((desc)->ctrl |= ENAHW_RX_DESC_COMP_REQ_MASK)

/*
 * Ethernet parsing information is only valid when last == 1.
 */
typedef struct enahw_rx_cdesc {
	/* 4:0 : l3_proto_idx
	 * 6:5 : src_vlan_cnt
	 * 7 : reserved7 - MBZ
	 * 12:8 : l4_proto_idx
	 * 13 : l3_csum_err - when set, either the L3
	 *    checksum error detected, or, the controller didn't
	 *    validate the checksum. This bit is valid only when
	 *    l3_proto_idx indicates IPv4 packet
	 * 14 : l4_csum_err - when set, either the L4
	 *    checksum error detected, or, the controller didn't
	 *    validate the checksum. This bit is valid only when
	 *    l4_proto_idx indicates TCP/UDP packet, and,
	 *    ipv4_frag is not set. This bit is valid only when
	 *    l4_csum_checked below is set.
	 * 15 : ipv4_frag - Indicates IPv4 fragmented packet
	 * 16 : l4_csum_checked - L4 checksum was verified
	 *    (could be OK or error), when cleared the status of
	 *    checksum is unknown
	 * 23:17 : reserved17 - MBZ
	 * 24 : phase
	 * 25 : l3_csum2 - second checksum engine result
	 * 26 : first - Indicates first descriptor in
	 *    transaction
	 * 27 : last - Indicates last descriptor in
	 *    transaction
	 * 29:28 : reserved28
	 * 30 : buffer - 0: Metadata descriptor. 1: Buffer
	 *    Descriptor was used
	 * 31 : reserved31
	 */
	uint32_t status;

	uint16_t length;
	uint16_t req_id;

	/* 32-bit hash result */
	uint32_t hash;
	uint16_t sub_qid;
	uint8_t offset;
	uint8_t reserved;
} enahw_rx_cdesc_t;

#define ENAHW_RX_CDESC_L3_PROTO_MASK          GENMASK(4, 0)
#define ENAHW_RX_CDESC_SRC_VLAN_CNT_SHIFT         5
#define ENAHW_RX_CDESC_SRC_VLAN_CNT_MASK          GENMASK(6, 5)
#define ENAHW_RX_CDESC_L4_PROTO_SHIFT         8
#define ENAHW_RX_CDESC_L4_PROTO_MASK          GENMASK(12, 8)
#define ENAHW_RX_CDESC_L3_CSUM_ERR_SHIFT          13
#define ENAHW_RX_CDESC_L3_CSUM_ERR_MASK           BIT(13)
#define ENAHW_RX_CDESC_L4_CSUM_ERR_SHIFT          14
#define ENAHW_RX_CDESC_L4_CSUM_ERR_MASK           BIT(14)
#define ENAHW_RX_CDESC_IPV4_FRAG_SHIFT            15
#define ENAHW_RX_CDESC_IPV4_FRAG_MASK             BIT(15)
#define ENAHW_RX_CDESC_L4_CSUM_CHECKED_SHIFT      16
#define ENAHW_RX_CDESC_L4_CSUM_CHECKED_MASK       BIT(16)
#define ENAHW_RX_CDESC_PHASE_SHIFT                24
#define ENAHW_RX_CDESC_PHASE_MASK                 BIT(24)
#define ENAHW_RX_CDESC_L3_CSUM2_SHIFT             25
#define ENAHW_RX_CDESC_L3_CSUM2_MASK              BIT(25)
#define ENAHW_RX_CDESC_FIRST_SHIFT                26
#define ENAHW_RX_CDESC_FIRST_MASK                 BIT(26)
#define ENAHW_RX_CDESC_LAST_SHIFT                 27
#define ENAHW_RX_CDESC_LAST_MASK                  BIT(27)
#define ENAHW_RX_CDESC_BUFFER_SHIFT               30
#define ENAHW_RX_CDESC_BUFFER_MASK                BIT(30)

#define	ENAHW_RX_CDESC_L3_PROTO(desc)			\
	((desc)->status & ENAHW_RX_CDESC_L3_PROTO_MASK)

#define	ENAHW_RX_CDESC_L3_CSUM_ERR(desc)			\
	((((desc)->status & ENAHW_RX_CDESC_L3_CSUM_ERR_MASK) >>	\
	    ENAHW_RX_CDESC_L3_CSUM_ERR_SHIFT) != 0)

#define	ENAHW_RX_CDESC_L4_PROTO(desc)				\
	(((desc)->status & ENAHW_RX_CDESC_L4_PROTO_MASK) >>	\
	    ENAHW_RX_CDESC_L4_PROTO_SHIFT)

#define	ENAHW_RX_CDESC_L4_CSUM_CHECKED(desc)				\
	((((desc)->status & ENAHW_RX_CDESC_L4_CSUM_CHECKED_MASK) >>	\
	    ENAHW_RX_CDESC_L4_CSUM_CHECKED_SHIFT) != 0)

/* TODO think about converting all these macros into inline funcs */
#define	ENAHW_RX_CDESC_PHASE(desc)			 \
	(((desc)->status & ENAHW_RX_CDESC_PHASE_MASK) >> \
	    ENAHW_RX_CDESC_PHASE_SHIFT)

#define	ENAHW_RX_CDESC_FIRST(desc)			 \
	((((desc)->status & ENAHW_RX_CDESC_FIRST_MASK) >> \
	    ENAHW_RX_CDESC_FIRST_SHIFT) == 1)

#define	ENAHW_RX_CDESC_LAST(desc)			 \
	((((desc)->status & ENAHW_RX_CDESC_LAST_MASK) >> \
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


extern int enahw_admin_cmd_status_to_errno(enahw_admin_cmd_status_t);

#endif	/* _ENA_HW_H */
