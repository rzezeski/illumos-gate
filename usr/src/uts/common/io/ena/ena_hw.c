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

#include "ena_hw.h"
#include "ena.h"

ena_hw_reg_nv_t	ena_hw_reg_cache[ENA_NUM_REGS] = {
	{ .ehrv_name = "Version", .ehrv_offset = ENA_REG_VERSION },
	{
		.ehrv_name = "Controller Version",
		.ehrv_offset = ENA_REG_CONTROLLER_VERSION
	},
	{ .ehrv_name = "Caps", .ehrv_offset = ENA_REG_CAPS },
	{ .ehrv_name = "Extended Caps", .ehrv_offset = ENA_REG_CAPS_EXT },
	{
		.ehrv_name = "Admin SQ Base Low",
		.ehrv_offset = ENA_REG_ASQ_BASE_LO
	},
	{
		.ehrv_name = "Admin SQ Base High",
		.ehrv_offset = ENA_REG_ASQ_BASE_HI
	},
	{ .ehrv_name = "Admin SQ Caps", .ehrv_offset = ENA_REG_ASQ_CAPS },
	{ .ehrv_name = "Gap 0x1C", .ehrv_offset = ENA_REG_GAP_1C },
	{
		.ehrv_name = "Admin CQ Base Low",
		.ehrv_offset = ENA_REG_ACQ_BASE_LO
	},
	{
		.ehrv_name = "Admin CQ Base High",
		.ehrv_offset = ENA_REG_ACQ_BASE_HI
	},
	{ .ehrv_name = "Admin CQ Caps", .ehrv_offset = ENA_REG_ACQ_CAPS },
	{ .ehrv_name = "Admin SQ Doorbell", .ehrv_offset = ENA_REG_ASQ_DB },
	{ .ehrv_name = "Admin CQ Tail", .ehrv_offset = ENA_REG_ACQ_TAIL },
	{
		.ehrv_name = "Admin Event Notification Queue Caps",
		.ehrv_offset = ENA_REG_AENQ_CAPS
	},
	{
		.ehrv_name = "Admin Event Notification Queue Base Low",
		.ehrv_offset = ENA_REG_AENQ_BASE_LO
	},
	{
		.ehrv_name = "Admin Event Notification Queue Base High",
		.ehrv_offset = ENA_REG_AENQ_BASE_HI
	},
	{
		.ehrv_name = "Admin Event Notification Queue Head Doorbell",
		.ehrv_offset = ENA_REG_AENQ_HEAD_DB
	},
	{
		.ehrv_name = "Admin Event Notification Queue Tail",
		.ehrv_offset = ENA_REG_AENQ_TAIL
	},
	{ .ehrv_name = "Gap 0x48", .ehrv_offset = ENA_REG_GAP_48 },
	{
		.ehrv_name = "Interrupt Mask (disable interrupts)",
		.ehrv_offset = ENA_REG_INTR_MASK
	},
	{ .ehrv_name = "Gap 0x50", .ehrv_offset = ENA_REG_GAP_50 },
	{ .ehrv_name = "Device Control", .ehrv_offset = ENA_REG_DEV_CTL },
	{ .ehrv_name = "Device Status", .ehrv_offset = ENA_REG_DEV_STS },
	{
		.ehrv_name = "MMIO Register Read",
		.ehrv_offset = ENA_REG_MMIO_REG_READ
	},
	{
		.ehrv_name = "MMIO Response Address Low",
		.ehrv_offset = ENA_REG_MMIO_RESP_LO
	},
	{
		.ehrv_name = "MMIO Response Address High",
		.ehrv_offset = ENA_REG_MMIO_RESP_HI
	},
	{
		.ehrv_name = "RSS Ind Entry Update", /* TODO what is "Ind"? */
		.ehrv_offset = ENA_REG_RSS_IND_ENTRY_UPDATE
	}
};

uint32_t
ena_hw_bar_read32(const ena_t *ena, const uint16_t offset)
{
	caddr_t addr = ena->ena_reg_base + offset;
	VERIFY3U(addr, >=, ena->ena_reg_base);
	VERIFY3U(addr, <, ena->ena_reg_base + (ena->ena_reg_size - 4));

	/*
	 * TODO make sure caddr_t is correct for reg_base to get
	 * appropriate pointer arith here.
	 */
	return (ddi_get32(ena->ena_reg_hdl,
		(uint32_t *)(ena->ena_reg_base + offset)));
}

uint32_t
ena_hw_abs_read32(const ena_t *ena, uint32_t *addr)
{
	VERIFY3U(addr, >=, ena->ena_reg_base);
	VERIFY3U(addr, <, ena->ena_reg_base + (ena->ena_reg_size - 4));

	/*
	 * TODO make sure caddr_t is correct for reg_base to get
	 * appropriate pointer arith here.
	 */
	return (ddi_get32(ena->ena_reg_hdl, addr));
}

void
ena_hw_bar_write32(const ena_t *ena, const uint16_t offset, const uint32_t val)
{
	caddr_t addr = ena->ena_reg_base + offset;
	VERIFY3U(addr, >=, ena->ena_reg_base);
	VERIFY3U(addr, <, ena->ena_reg_base + (ena->ena_reg_size - 4));

	ddi_put32(ena->ena_reg_hdl, (uint32_t *)(ena->ena_reg_base + offset),
	    val);
}

/*
 * TODO this is only being used for ehas_dbaddr, might be able to get
 * rid of that field and this function as well.
 */
void
ena_hw_abs_write32(const ena_t *ena, uint32_t *addr, const uint32_t val)
{
	VERIFY3P(ena, !=, NULL);
	VERIFY3P(addr, !=, NULL);
	VERIFY3U(addr, >=, ena->ena_reg_base);
	VERIFY3U(addr, <, ena->ena_reg_base + (ena->ena_reg_size - 4));

	ddi_put32(ena->ena_reg_hdl, addr, val);
}

void
ena_hw_update_reg_cache(const ena_t *ena)
{
	for (uint_t i = 0; i < ENA_NUM_REGS; i++) {
		ena_hw_reg_nv_t *nv = &ena_hw_reg_cache[i];

		nv->ehrv_value = ena_hw_bar_read32(ena, nv->ehrv_offset);
		ena_xxx(ena, "reg %s (0x%x) = 0x%x", nv->ehrv_name,
		    nv->ehrv_offset, nv->ehrv_value);
	}
}

int
enahw_admin_cmd_status_to_errno(enahw_admin_cmd_status_t status)
{
	int ret = 0;

	switch (status) {
	case ENA_ADMIN_SUCCESS:
		break;
	case ENA_ADMIN_RESOURCE_ALLOCATION_FAILURE:
		ret = ENOMEM;
		break;
	case ENA_ADMIN_UNSUPPORTED_OPCODE:
		ret = EOPNOTSUPP;
		break;
	case ENA_ADMIN_BAD_OPCODE:
	case ENA_ADMIN_MALFORMED_REQUEST:
	case ENA_ADMIN_ILLEGAL_PARAMETER:
	case ENA_ADMIN_UNKNOWN_ERROR:
		ret = EINVAL;
		break;
	case ENA_ADMIN_RESOURCE_BUSY:
		ret = EAGAIN;
		break;
	}

	return (ret);
}
