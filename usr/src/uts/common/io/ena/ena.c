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

/*
 * TODO LIST
 *
 *    o big theory statement
 *    o man page
 *    o admin queue interrupts (non-polling)
 *
 *      All AQ access is synchronous, one command at a time. Linux
 *      configures AQ to use interrupts and have multiple cmds in
 *      flight. However, the only API used by the driver is a
 *      synchronous one. So for now let's not worry about async AQ.
 *
 *    o MMIO AQ reads
 *    o AENQ keep alive watchdog timer
 *    o FMA
 *    o Tx checksum offloads
 *    o Rx checksum offloads
 *    o TSO
 *    o Tx DMA bind (borrow buffers)
 *    o Rx DMA bind (loan buffers)
 *    o less Tx recycling
 *    o less Rx refill.
 */

/*
 * XXX I'm not sure if this dicatates any specific behavior by the
 *     device (we send this into to the device in
 *     ena_set_host_info()), but we use the same values as Linux to
 *     play it safe for now.
 */
#define	ENA_DRV_VER_MAJOR	2
#define	ENA_DRV_VER_MINOR	2
#define	ENA_DRV_VER_SUBMINOR	11

void
ena_err(const ena_t *ena, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (ena != NULL && ena->ena_dip != NULL) {
		vdev_err(ena->ena_dip, CE_WARN, fmt, ap);
	} else {
		vcmn_err(CE_WARN, fmt, ap);
	}
	va_end(ap);
}

void
ena_log(const ena_t *ena, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (ena != NULL && ena->ena_dip != NULL) {
		vdev_err(ena->ena_dip, CE_NOTE, fmt, ap);
	} else {
		vcmn_err(CE_NOTE, fmt, ap);
	}
	va_end(ap);
}

/* TODO make real dbg that only prints when flag is set */
void
ena_dbg(const ena_t *ena, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (ena != NULL && ena->ena_dip != NULL) {
		vdev_err(ena->ena_dip, CE_NOTE, fmt, ap);
	} else {
		vcmn_err(CE_NOTE, fmt, ap);
	}
	va_end(ap);
}

int ena_xxx_flag = 0;

/*
 * TODO temporary tracing, kill this function once I have things more
 * fleshed out.
 */
void
ena_xxx(const ena_t *ena, const char *fmt, ...)
{
	va_list ap;

	if (ena_xxx_flag != 0) {
		va_start(ap, fmt);
		if (ena != NULL && ena->ena_dip != NULL) {
			vdev_err(ena->ena_dip, CE_NOTE, fmt, ap);
		} else {
			vcmn_err(CE_NOTE, fmt, ap);
		}
		va_end(ap);
	}
}

ena_aenq_grpstr_t ena_groups_str[ENAHW_AENQ_GROUP_NUM] = {
	{ .eag_type = ENAHW_AENQ_GROUP_LINK_CHANGE, .eag_str = "LINK CHANGE" },
	{ .eag_type = ENAHW_AENQ_GROUP_FATAL_ERROR, .eag_str = "FATAL ERROR" },
	{ .eag_type = ENAHW_AENQ_GROUP_WARNING, .eag_str = "WARNING" },
	{
		.eag_type = ENAHW_AENQ_GROUP_NOTIFICATION,
		.eag_str = "NOTIFICATION"
	},
	{ .eag_type = ENAHW_AENQ_GROUP_KEEP_ALIVE, .eag_str = "KEEP ALIVE" },
};

ena_aenq_synstr_t ena_syndrome_str[ENAHW_AENQ_SYNDROME_NUM] = {
	{ .eas_type = ENAHW_AENQ_SYNDROME_SUSPEND, .eas_str = "SUSPEND" },
	{ .eas_type = ENAHW_AENQ_SYNDROME_RESUME, .eas_str = "RESUME" },
	{
		.eas_type = ENAHW_AENQ_SYNDROME_UPDATE_HINTS,
		.eas_str = "UPDATE HINTS"
	},
};

void
ena_aenq_work(ena_t *ena)
{
	ena_aenq_t *aenq = &ena->ena_aenq;
	uint16_t head_mod = aenq->eaenq_head & (aenq->eaenq_num_descs - 1);
	boolean_t processed = B_FALSE;
	enahw_aenq_desc_t *desc = &aenq->eaenq_descs[head_mod];
	uint16_t ts;

	ts = ((uint64_t)desc->ead_ts_high << 32) | (uint64_t)desc->ead_ts_low;
	ENA_DMA_SYNC(aenq->eaenq_dma, DDI_DMA_SYNC_FORKERNEL);

	while (ENAHW_AENQ_DESC_PHASE(desc) == aenq->eaenq_phase) {
		ena_aenq_hdlr_t hdlr;

		ASSERT3U(desc->ead_group, <, ENAHW_AENQ_GROUP_NUM);
		processed = B_TRUE;
		ena_xxx(ena, "@@@ AENQ Group: (0x%x) %s Syndrome: 0x%x "
		    "ts: %llu us",
		    desc->ead_group,
		    ena_groups_str[desc->ead_group].eag_str,
		    desc->ead_syndrome, ts);

		hdlr = ena->ena_aenq.eaenq_hdlrs[desc->ead_group];
		hdlr(ena, desc);

		aenq->eaenq_head++;
		head_mod = aenq->eaenq_head & (aenq->eaenq_num_descs - 1);

		if (head_mod == 0)
			aenq->eaenq_phase = !aenq->eaenq_phase;

		desc = &aenq->eaenq_descs[head_mod];
	}

	if (processed)
		ena_hw_bar_write32(ena, ENA_REG_AENQ_HEAD_DB, aenq->eaenq_head);
}

/*
 * XXX Implement FMA capabilities.
 */
static void
ena_fm_init(ena_t *ena)
{
	ena->ena_fm_caps = DDI_FM_NOT_CAPABLE;
}

static boolean_t
ena_regs_map(ena_t *ena)
{
	int ret;

	if (ddi_dev_regsize(ena->ena_dip, ENA_REG_NUMBER, &ena->ena_reg_size) !=
	    DDI_SUCCESS) {
		ena_err(ena, "failed to get register set %d size",
		    ENA_REG_NUMBER);
		return (B_FALSE);
	}

	ena_dbg(ena, "register size: %u", ena->ena_reg_size);
	bzero(&ena->ena_reg_attr, sizeof (ena->ena_reg_attr));
	ena->ena_reg_attr.devacc_attr_version = DDI_DEVICE_ATTR_V1;
	ena->ena_reg_attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	ena->ena_reg_attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
	if (DDI_FM_ACC_ERR_CAP(ena->ena_fm_caps)) {
		ena->ena_reg_attr.devacc_attr_access = DDI_FLAGERR_ACC;
	} else {
		ena->ena_reg_attr.devacc_attr_access = DDI_DEFAULT_ACC;
	}

	if ((ret = ddi_regs_map_setup(ena->ena_dip, ENA_REG_NUMBER,
	    &ena->ena_reg_base, 0, ena->ena_reg_size, &ena->ena_reg_attr,
	    &ena->ena_reg_hdl)) != DDI_SUCCESS) {
		ena_err(ena, "failed to map register set: %d: %d",
		    ENA_REG_NUMBER, ret);
		return (B_FALSE);
	}

	ena_dbg(ena, "registers mapped to base: 0x%p",
	    (void *)ena->ena_reg_base);

	return (B_TRUE);
}

static void
ena_identify(ena_t *ena)
{
	ddi_acc_handle_t hdl = ena->ena_pci_hdl;

	ena->ena_pci_vid = pci_config_get16(hdl, PCI_CONF_VENID);
	ena->ena_pci_did = pci_config_get16(hdl, PCI_CONF_DEVID);
	ena->ena_pci_rev = pci_config_get8(hdl, PCI_CONF_REVID);
	ena->ena_pci_svid = pci_config_get16(hdl, PCI_CONF_SUBVENID);
	ena->ena_pci_sdid = pci_config_get16(hdl, PCI_CONF_SUBSYSID);

	/*
	 * XXX: rev & 0x1 == disabled mmio reg read
	 */
	ena_log(ena, "vid: 0x%x did: 0x%x rev: 0x%x svid: 0x%x sdid: 0x%x",
	    ena->ena_pci_vid, ena->ena_pci_did, ena->ena_pci_rev,
	    ena->ena_pci_svid, ena->ena_pci_sdid);
}

/* TODO copied */
#define ENA_ADMIN_HOST_INFO_MAJOR_MASK                      GENMASK(7, 0)
#define ENA_ADMIN_HOST_INFO_MINOR_SHIFT                     8
#define ENA_ADMIN_HOST_INFO_MINOR_MASK                      GENMASK(15, 8)
#define ENA_ADMIN_HOST_INFO_SUB_MINOR_SHIFT                 16
#define ENA_ADMIN_HOST_INFO_SUB_MINOR_MASK                  GENMASK(23, 16)
#define ENA_ADMIN_HOST_INFO_MODULE_TYPE_SHIFT               24
#define ENA_ADMIN_HOST_INFO_MODULE_TYPE_MASK                GENMASK(31, 24)
#define ENA_ADMIN_HOST_INFO_FUNCTION_MASK                   GENMASK(2, 0)
#define ENA_ADMIN_HOST_INFO_DEVICE_SHIFT                    3
#define ENA_ADMIN_HOST_INFO_DEVICE_MASK                     GENMASK(7, 3)
#define ENA_ADMIN_HOST_INFO_BUS_SHIFT                       8
#define ENA_ADMIN_HOST_INFO_BUS_MASK                        GENMASK(15, 8)
#define ENA_ADMIN_HOST_INFO_MUTABLE_RSS_TABLE_SIZE_MASK     BIT(0)
#define ENA_ADMIN_HOST_INFO_RX_OFFSET_SHIFT                 1
#define ENA_ADMIN_HOST_INFO_RX_OFFSET_MASK                  BIT(1)
#define ENA_ADMIN_HOST_INFO_INTERRUPT_MODERATION_SHIFT      2
#define ENA_ADMIN_HOST_INFO_INTERRUPT_MODERATION_MASK       BIT(2)
#define ENA_ADMIN_HOST_INFO_RX_BUF_MIRRORING_SHIFT          3
#define ENA_ADMIN_HOST_INFO_RX_BUF_MIRRORING_MASK           BIT(3)
#define ENA_ADMIN_HOST_INFO_RSS_CONFIGURABLE_FUNCTION_KEY_SHIFT 4
#define ENA_ADMIN_HOST_INFO_RSS_CONFIGURABLE_FUNCTION_KEY_MASK BIT(4)

/* TODO copied from Linux for now */
#define DRV_MODULE_GEN_MAJOR	2
#define DRV_MODULE_GEN_MINOR	2
#define DRV_MODULE_GEN_SUBMINOR 11

/* TODO copied */
#define ENA_COMMON_SPEC_VERSION_MAJOR        2
#define ENA_COMMON_SPEC_VERSION_MINOR        0

/* TODO copied */
enum ena_admin_os_type {
	ENA_ADMIN_OS_LINUX                          = 1,
	ENA_ADMIN_OS_WIN                            = 2,
	ENA_ADMIN_OS_DPDK                           = 3,
	ENA_ADMIN_OS_FREEBSD                        = 4,
	ENA_ADMIN_OS_IPXE                           = 5,
	ENA_ADMIN_OS_ESXI                           = 6,
	ENA_ADMIN_OS_GROUPS_NUM                     = 6,
};

/*
 * TODO doc
 *
 * ena_admin_host_info
 */
typedef struct ena_hw_admin_host_info {
	uint32_t	ehai_os_type;
	uint8_t		ehai_os_dist_str[128];
	uint32_t	ehai_os_dist;
	uint8_t		ehai_kernel_ver_str[32];
	uint32_t	ehai_kernel_ver;
	uint32_t	ehai_driver_ver;
	uint32_t	ehai_supported_net_features[2]; /* TODO used for? */
	uint16_t	ehai_ena_spec_version;
	uint16_t	ehai_bdf;
	uint16_t	ehai_num_cpus;
	uint16_t	ehai_rsvd;
	uint32_t	ehai_driver_supported_features;
} ena_hw_admin_host_info_t;

static boolean_t
ena_set_host_info(ena_t *ena)
{
	ena_hw_admin_host_info_t *ehi;
	enahw_admin_cmd_status_t status;
	int ret = 0;
	ena_dma_buf_t *hi_dma;
	ddi_dma_attr_t attr;
	ddi_device_acc_attr_t acc;
	enahw_cmd_desc_t cmd;
	uint32_t addr_low32, addr_high32;
	enahw_resp_desc_t resp;

	hi_dma = kmem_alloc(sizeof (*hi_dma), KM_SLEEP);
	ena->ena_host_info = hi_dma;

	/*
	 * TODO gonna need to stash this hi_dma somewhere so I can
	 * free it later.
	 */
	ena_dma_adminq_attr(ena, &attr, 4096);
	ena_dma_acc_attr(ena, &acc);
	if (!ena_dma_alloc(ena, hi_dma, &attr, &acc, 4096, B_FALSE)) {
		ena_err(ena, "failed to allocate DMA for host info");
		return (B_FALSE);
	}

	ehi = (void *)hi_dma->edb_va;
	ehi->ehai_ena_spec_version =
	    ((ENA_COMMON_SPEC_VERSION_MAJOR <<
		ENA_VERSION_MAJOR_VERSION_SHIFT) |
	    (ENA_COMMON_SPEC_VERSION_MINOR));

	/* TODO Figure out how to get the B/D/F from the dev_info_t. */
	ehi->ehai_bdf = 0; /* START HERE */

	/*
	 * XXX I'm not sure if AWS Nitro or the device are doing
	 *     anything special based on this value. I set it to
	 *     FreeBSD as that's the closest thing to us.
	 */
	ehi->ehai_os_type = ENA_ADMIN_OS_FREEBSD;

	ehi->ehai_kernel_ver = 1; /* TODO set a real version based on ??? */

	/*
	 * TODO not really a version
	 * TODO check return?
	 * TODO uncomment aftering adding strlcpy to ddi.mapfile
	 */
	/* (void)strlcpy((char *)ehi->ehai_kernel_ver_str, "illumos", */
	/*     sizeof(ehi->ehai_kernel_ver_str) - 1); */

	(void)strcpy((char *)ehi->ehai_kernel_ver_str, "illumos");

	ehi->ehai_os_dist = 0;	/* What everyone else does. */

	/*
	 * XXX This was aped from Linux just in case the
	 * driver_version dictates any specific behavior by the
	 * device.
	 */
	ehi->ehai_driver_ver =
	    (DRV_MODULE_GEN_MAJOR) |
	    (DRV_MODULE_GEN_MINOR << ENA_ADMIN_HOST_INFO_MINOR_SHIFT) |
	    (DRV_MODULE_GEN_SUBMINOR << ENA_ADMIN_HOST_INFO_SUB_MINOR_SHIFT) |
	    ("g"[0] << ENA_ADMIN_HOST_INFO_MODULE_TYPE_SHIFT);

	/* TODO uncomment aftering updating kernel.mapfile */
	/* ehi->ehai_num_cpus = ncpus_online; /\* XXX need cpuvar.h? *\/ */
	ehi->ehai_num_cpus = 2; /* XXX need cpuvar.h? */

	/* TODO Aped from Linux. */
	ehi->ehai_driver_supported_features =
	    ENA_ADMIN_HOST_INFO_RX_OFFSET_MASK |
	    ENA_ADMIN_HOST_INFO_INTERRUPT_MODERATION_MASK |
	    ENA_ADMIN_HOST_INFO_RX_BUF_MIRRORING_MASK |
	    ENA_ADMIN_HOST_INFO_RSS_CONFIGURABLE_FUNCTION_KEY_MASK;

	VERIFY0(ddi_dma_sync(hi_dma->edb_dma_hdl, 0, 0, DDI_DMA_SYNC_FORDEV));

	bzero(&cmd, sizeof (cmd));

	/*
	 * TODO do I want something like ena_com_mem_addr_set() to
	 * make sure DMA physical addrs are always in the correct
	 * range?
	 */
	addr_low32 = (uint32_t)(hi_dma->edb_cookie->dmac_laddress);
	addr_high32 = (uint32_t)(hi_dma->edb_cookie->dmac_laddress >> 32);

	/* TODO this is silly */
	cmd.ecd_payload.set_feat.egfc_cmd.host_attr.os_addr.eha_addr_low =
	    addr_low32;
	cmd.ecd_payload.set_feat.egfc_cmd.host_attr.os_addr.eha_addr_high =
	    addr_high32;

	/* TODO setup debug area */

	VERIFY0(ena_set_feature(ena, &cmd, &resp, ENAHW_FEAT_HOST_ATTR_CONFIG,
	    ENAHW_FEAT_HOST_ATTR_CONFIG_VER));

	status = resp.erd_status;
	ena_log(ena, "set feature resp status: 0x%x", status);
	if ((ret = enahw_admin_cmd_status_to_errno(status)) != 0) {
		ena_err(ena, "failed to set host attributes: %d", ret);
		goto error;
	}

	return (B_TRUE);

error:
	ena_dma_free(hi_dma);
	return (B_FALSE);
}

/*
 * END HOST INFO
 */

static boolean_t
ena_sq_init(ena_t *ena)
{
	ena_adminq_t *aq = &ena->ena_aq;
	ena_dma_buf_t *edb_sq = &aq->ea_sq.eas_dma;
	size_t size = aq->ea_qlen * sizeof (*aq->ea_sq.eas_entries);
	ddi_dma_attr_t attr;
	ddi_device_acc_attr_t acc;
	uint32_t addr_low, addr_high, wval;

	ena_dma_adminq_attr(ena, &attr, size);
	ena_dma_acc_attr(ena, &acc);
	if (!ena_dma_alloc(ena, edb_sq, &attr, &acc, size, B_FALSE)) {
		ena_err(ena, "failed to allocate DMA for SQ");
		return (B_FALSE);
	}

	aq->ea_sq.eas_entries = (void *)edb_sq->edb_va;
	aq->ea_sq.eas_paddr = edb_sq->edb_cookie->dmac_laddress;
	aq->ea_sq.eas_head = 0;
	aq->ea_sq.eas_tail = 0;
	aq->ea_sq.eas_phase = 1;
	aq->ea_sq.eas_dbaddr = (uint32_t *)(ena->ena_reg_base + ENA_REG_ASQ_DB);

	/*
	 * TODO do I want something like ena_com_mem_addr_set() to
	 * make sure DMA physical addrs are always in the correct
	 * range?
	 */
	addr_low = (uint32_t)(aq->ea_sq.eas_paddr);
	addr_high = (uint32_t)(aq->ea_sq.eas_paddr >> 32);
	ena_hw_bar_write32(ena, ENA_REG_ASQ_BASE_LO, addr_low);
	ena_hw_bar_write32(ena, ENA_REG_ASQ_BASE_HI, addr_high);

	wval = ENA_ASQ_CAPS_DEPTH(aq->ea_qlen) |
	    ENA_ASQ_CAPS_ENTRY_SIZE(sizeof (*aq->ea_sq.eas_entries));
	ena_hw_bar_write32(ena, ENA_REG_ASQ_CAPS, wval);

	return (B_TRUE);
}

static boolean_t
ena_cq_init(ena_t *ena)
{
	ena_adminq_t *aq = &ena->ena_aq;
	ena_dma_buf_t *edb_cq = &aq->ea_cq.eac_dma;
	size_t size = aq->ea_qlen * sizeof (*aq->ea_cq.eac_entries);
	ddi_dma_attr_t attr;
	ddi_device_acc_attr_t acc;
	uint32_t addr_low, addr_high, wval;

	ena_dma_adminq_attr(ena, &attr, size);
	ena_dma_acc_attr(ena, &acc);
	if (!ena_dma_alloc(ena, edb_cq, &attr, &acc, size, B_FALSE)) {
		ena_err(ena, "failed to allocate DMA for CQ");
		return (B_FALSE);
	}

	aq->ea_cq.eac_entries = (void *)edb_cq->edb_va;
	aq->ea_cq.eac_paddr = edb_cq->edb_cookie->dmac_laddress;
	aq->ea_cq.eac_head = 0;
	aq->ea_cq.eac_phase = 1;

	/*
	 * TODO do I want something like ena_com_mem_addr_set() to
	 * make sure DMA physical addrs are always in the correct
	 * range?
	 */
	addr_low = (uint32_t)(aq->ea_cq.eac_paddr);
	addr_high = (uint32_t)(aq->ea_cq.eac_paddr >> 32);
	ena_hw_bar_write32(ena, ENA_REG_ACQ_BASE_LO, addr_low);
	ena_hw_bar_write32(ena, ENA_REG_ACQ_BASE_HI, addr_high);

	wval = ENA_ACQ_CAPS_DEPTH(aq->ea_qlen) |
	    ENA_ACQ_CAPS_ENTRY_SIZE(sizeof (*aq->ea_cq.eac_entries));
	ena_hw_bar_write32(ena, ENA_REG_ACQ_CAPS, wval);

	return (B_TRUE);
}

static void
ena_aenq_default_hdlr(void *data, enahw_aenq_desc_t *desc)
{
	ena_t *ena = data;

	ena_xxx(ena, "unimplemented handler for aenq group: %s",
	    ena_groups_str[desc->ead_group].eag_str);
}

void
ena_set_link_state(ena_t *ena, link_state_t state)
{
	if (ena->ena_link_state == state)
		return;

	ena->ena_link_state = state;

	if (ena->ena_mh != NULL)
		mac_link_update(ena->ena_mh, ena->ena_link_state);
}

static void
ena_aenq_link_change_hdlr(void *data, enahw_aenq_desc_t *desc)
{
	ena_t *ena = data;
	boolean_t up = (desc->ead_payload.link_change.flags &
	    ENAHW_AENQ_LINK_CHANGE_LINK_STATUS_MASK) != 0;

	if (up)
		ena_set_link_state(ena, LINK_STATE_UP);
	else
		ena_set_link_state(ena, LINK_STATE_DOWN);
}

/* TODO need to have destroy function for cleanup */
static boolean_t
ena_aenq_init(ena_t *ena)
{
	ena_aenq_t *aenq = &ena->ena_aenq;
	size_t size;
	ddi_dma_attr_t attr;
	ddi_device_acc_attr_t acc;
	uint32_t addr_low, addr_high, wval;

	aenq->eaenq_num_descs = 16; /* TODO macro */
	size = aenq->eaenq_num_descs * sizeof (*aenq->eaenq_descs);
	ena_dma_adminq_attr(ena, &attr, size);
	ena_dma_acc_attr(ena, &acc);

	if (!ena_dma_alloc(ena, &aenq->eaenq_dma, &attr, &acc, size, B_FALSE)) {
		ena_err(ena, "failed to allocate DMA for AENQ");
		return (B_FALSE);
	}

	aenq->eaenq_descs = (void *)aenq->eaenq_dma.edb_va;
	/* aq->ea_aenq.eha_paddr = edb.edb_cookie->dmac_laddress; */
	aenq->eaenq_head = 0;
	aenq->eaenq_phase = 1;
	bzero(aenq->eaenq_descs, size);

	for (uint_t i = 0; i < ENAHW_AENQ_SYNDROME_NUM; i++) {
		aenq->eaenq_hdlrs[i] = ena_aenq_default_hdlr;
	}

	aenq->eaenq_hdlrs[ENAHW_AENQ_GROUP_LINK_CHANGE] =
	    ena_aenq_link_change_hdlr;

	addr_low = (uint32_t)(aenq->eaenq_dma.edb_cookie->dmac_laddress);
	addr_high = (uint32_t)(aenq->eaenq_dma.edb_cookie->dmac_laddress >> 32);
	ena_hw_bar_write32(ena, ENA_REG_AENQ_BASE_LO, addr_low);
	ena_hw_bar_write32(ena, ENA_REG_AENQ_BASE_HI, addr_high);
	ENA_DMA_SYNC(aenq->eaenq_dma, DDI_DMA_SYNC_FORDEV);
	wval = ENA_AENQ_CAPS_DEPTH(aenq->eaenq_num_descs) |
	    ENA_AENQ_CAPS_ENTRY_SIZE(sizeof (*aenq->eaenq_descs));
	ena_hw_bar_write32(ena, ENA_REG_AENQ_CAPS, wval);

	return (B_TRUE);
}

static void
ena_set_max_io_queues(ena_t *ena)
{
	ena_hw_t *hw = ena->ena_hw;
	uint32_t max = 128;

	max = MIN(ncpus_online, max);
	max = MIN(hw->eh_tx_max_sq_num, max);
	max = MIN(hw->eh_tx_max_cq_num, max);
	max = MIN(hw->eh_rx_max_sq_num, max);
	max = MIN(hw->eh_rx_max_cq_num, max);

	VERIFY3U(max, >, 0);
	hw->eh_max_io_queues = max;
}

static void
ena_update_buf_sizes(ena_t *ena)
{
	/* TODO pretty sure we are never writing the FCS, so don't
	 * include it in our frame header calculation. */
	/* ena->ena_max_frame_hdr = sizeof (struct ether_vlan_header) + ETHERFCSL; */
	ena->ena_max_frame_hdr = sizeof (struct ether_vlan_header);
	ena->ena_max_frame_total = ena->ena_max_frame_hdr + ena->ena_mtu;
	/* ena->ena_tx_buf_sz = ena->ena_max_frame_total; */
	ena->ena_tx_buf_sz = P2ROUNDUP_TYPED(ena->ena_max_frame_total,
	    ena->ena_page_sz, uint32_t);
	/* ena->ena_rx_buf_sz = ena->ena_max_frame_total + ENA_BUF_IPHDR_ALIGNMENT; */
	ena->ena_rx_buf_sz = P2ROUNDUP_TYPED(ena->ena_max_frame_total +
	    ENA_RX_BUF_IPHDR_ALIGNMENT, ena->ena_page_sz, uint32_t);

}

static boolean_t
ena_get_offloads(ena_t *ena)
{
	enahw_resp_desc_t resp;

	bzero(&resp, sizeof (resp));

	if (ena_get_feature(ena, &resp, ENAHW_FEAT_STATELESS_OFFLOAD_CONFIG,
	    ENAHW_FEAT_STATELESS_OFFLOAD_CONFIG_VER) != 0)
		return (B_FALSE);

	ena_xxx(ena, "offload rx_supported: 0x%x",
	    resp.erd_payload.get_feat_offload.rx_supported);

	ena_xxx(ena, "offload rx_enabled: 0x%x",
	    resp.erd_payload.get_feat_offload.rx_enabled);

	if (ENAHW_GET_FEATURE_OFFLOAD_TX_L3_CSUM_IPV4(resp.erd_payload.
	    get_feat_offload)) {
		ena->ena_hw->eh_rx_l3_ipv4_csum = B_TRUE;
	} else {
		ena->ena_hw->eh_rx_l3_ipv4_csum = B_FALSE;
	}

	if (ENAHW_GET_FEATURE_OFFLOAD_TX_L4_IPV4_CSUM_FULL(resp.erd_payload.
	    get_feat_offload)) {
		ena->ena_hw->eh_rx_l4_ipv4_full_csum = B_TRUE;
	} else {
		ena->ena_hw->eh_rx_l4_ipv4_full_csum = B_FALSE;
	}

	return (B_TRUE);
}

static int
ena_get_prop(ena_t *ena, char *propname, const int minval, const int maxval,
    const int defval)
{
	int value = ddi_prop_get_int(DDI_DEV_T_ANY, ena->ena_dip,
	    DDI_PROP_DONTPASS, propname, defval);

	if (value > maxval)
		value = maxval;

	if (value < minval)
		value = minval;

	return (value);
}

/*
 * Retrieve all configuration values which are modifiable via
 * ena.conf, and set ena_t members accordingly. While the conf values
 * have priority, they may be implicitly modified by the driver to
 * meet resource constraints on a given platform. If no value is
 * specified in the conf file, the driver will attempt to used the
 * largest value supported. While there should be no value large
 * enough, keep in mind that ena_get_prop() will cast the values to an
 * int.
 *
 * This function should be called after the device is initialized,
 * admin queue is established, and the hardware features/capabs have
 * been queried. But it should be called before mac registration.
 */
static void
ena_read_conf(ena_t *ena)
{
	uint32_t gcv;	/* Greatest Common Value */

	/*
	 * We expect that the queue lengths are the same for both the
	 * CQ and SQ, but technically the device could return
	 * different lengths. While it could make sense to use
	 * different lengths for performance reasons, for now lock
	 * these together.
	 */
	gcv = min(ena->ena_hw->eh_rx_max_sq_num_descs,
	    ena->ena_hw->eh_rx_max_cq_num_descs);
	ASSERT3U(gcv, <=, INT_MAX);
	ena->ena_rxq_num_descs = ena_get_prop(ena, ENA_PROP_RXQ_NUM_DESCS,
	    ENA_PROP_MIN_RXQ_NUM_DESCS, gcv, gcv);

	gcv = min(ena->ena_hw->eh_tx_max_sq_num_descs,
	    ena->ena_hw->eh_tx_max_cq_num_descs);
	ASSERT3U(gcv, <=, INT_MAX);
	ena->ena_txq_num_descs = ena_get_prop(ena, ENA_PROP_TXQ_NUM_DESCS,
	    ENA_PROP_MIN_TXQ_NUM_DESCS, gcv, gcv);

}

static boolean_t
ena_device_init(ena_t *ena)
{
	ena_adminq_t *aq = &ena->ena_aq;
	uint32_t rval, wval;
	uint8_t timeout, dma_width;
	hrtime_t expired;
	enahw_resp_desc_t resp;
	uint8_t *maddr;
	uint32_t supported_features;

	ena_log(ena, "attempting to read device status");
	/* TODO eventually move this stuff into function */
	rval = ena_hw_bar_read32(ena, ENA_REG_DEV_STS);
	if ((rval & ENA_DEV_STS_READY_MASK) == 0) {
		ena_err(ena, "device is not ready");
		return (B_FALSE);
	}

	ena_log(ena, "attempt to get devices reset timeout");
	/* Timeout value reprsents units of 100ms. */
	rval = ena_hw_bar_read32(ena, ENA_REG_CAPS);
	timeout = ENA_CAPS_RESET_TIMEOUT(rval);
	if (timeout == 0) {
		ena_err(ena, "device gave invalid timeout");
		return (B_FALSE);
	}
	expired = gethrtime() + (timeout * 100 * 1000 * 1000);

	ena_log(ena, "attempt to reset device");
	wval = ENA_DEV_CTL_DEV_RESET_MASK;
	wval |= (ENA_RESET_NORMAL << ENA_DEV_CTL_RESET_REASON_SHIFT) &
	    ENA_DEV_CTL_RESET_REASON_MASK;
	ena_hw_bar_write32(ena, ENA_REG_DEV_CTL, wval);
	/* TODO: do I need to do DMA sync's for BAR reads/writes? */

	ena_log(ena, "wait for reset to start");
	/* Make sure reset is in progress. */
	while (1) {
		rval = ena_hw_bar_read32(ena, ENA_REG_DEV_STS);

		if ((rval & ENA_DEV_STS_RESET_IN_PROGRESS_MASK) != 0) {
			break;
		}

		if (gethrtime() > expired) {
			ena_err(ena, "device reset start timed out");
			return (B_FALSE);
		}

		/* sleep for 100ms */
		delay(drv_usectohz(100 * 1000));
	}
	ena_log(ena, "wait for reset to finish");

	/*
	 * TODO I'm writing 0 based on that Linux does. There is also
	 * a RESET_FINISHED mask I can use (rather than asserting not
	 * in progress.
	 */
	ena_hw_bar_write32(ena, ENA_REG_DEV_CTL, 0);
	while (1) {
		rval = ena_hw_bar_read32(ena, ENA_REG_DEV_STS);

		if ((rval & ENA_DEV_STS_RESET_IN_PROGRESS_MASK) == 0) {
			break;
		}

		if (gethrtime() > expired) {
			ena_err(ena, "device reset finish timed out");
			return (B_FALSE);
		}

		/* sleep for 100ms */
		delay(drv_usectohz(100 * 1000));
	}

	ena_log(ena, "reset has finished");

	/* TODO ena_com_validation_version() */

	rval = ena_hw_bar_read32(ena, ENA_REG_CAPS);
	dma_width = ENA_CAPS_DMA_ADDR_WIDTH(rval);
	ena->ena_hw->eh_dma_width = dma_width;
	ena_log(ena, "DMA width: %u", dma_width);

	/* BEGIN INIT ADMIN QUEUE */
	/* TODO: equiv of Linux's ena_com_admin_init() */

	/*
	 * We already establish device ready earlier, but if this goes
	 * in its own function it makes sense to verify this first.
	 */
	rval = ena_hw_bar_read32(ena, ENA_REG_DEV_STS);
	if ((rval & ENA_DEV_STS_READY_MASK) == 0) {
		ena_err(ena, "device is not ready");
		return (B_FALSE);
	}

	ena_hw_update_reg_cache(ena);

	aq->ea_qlen = ENA_ADMINQ_DEPTH;
	aq->ea_pending_cmds = 0;

	/* TODO handle error */
	if (!ena_sq_init(ena))
		return (B_FALSE);

	if (!ena_cq_init(ena))
		return (B_FALSE);

	if(!ena_aenq_init(ena))
		return (B_FALSE);

	/* END INIT */

	/* SET POLLING MODE START (ena_com_set_admin_polling_mode)*/
	ena_log(ena, "turned interrupts off, polling on");
	/* ena_hw_bar_write32(ena, ENA_REG_INTR_MASK, ENA_INTR_MASK); */
	/* TODO temporarily turn on interrupt for test */
	ena_hw_bar_write32(ena, ENA_REG_INTR_MASK, 0);
	aq->ea_poll_mode = B_TRUE;
	/* SET POLLING MODE END */

	if(!ena_set_host_info(ena))
		return (B_FALSE);

	bzero(&resp, sizeof (resp));
	VERIFY0(ena_get_feature(ena, &resp, ENAHW_FEAT_DEVICE_ATTRIBUTES,
		ENAHW_FEAT_DEVICE_ATTRIBUTES_VER));

	/* TODO print response */
	ena_log(ena, "impl ID: %u", resp.erd_payload.get_feat_dev_attr.impl_id);
	ena_log(ena, "device version: %u",
	    resp.erd_payload.get_feat_dev_attr.device_version);
	ena_log(ena, "supported features: 0x%x",
	    resp.erd_payload.get_feat_dev_attr.supported_features);
	ena_log(ena, "phys addr width: %u",
	    resp.erd_payload.get_feat_dev_attr.phys_addr_width);
	ena_log(ena, "virt addr width: %u",
	    resp.erd_payload.get_feat_dev_attr.virt_addr_with);
	maddr = resp.erd_payload.get_feat_dev_attr.mac_addr;
	ena_log(ena, "mac addr: %x:%x:%x:%x:%x:%x", maddr[0], maddr[1],
	    maddr[2], maddr[3], maddr[4], maddr[5]);
	ena_log(ena, "max MTU: %u", resp.erd_payload.get_feat_dev_attr.max_mtu);

	bcopy(maddr, ena->ena_hw->eh_mac_addr, ETHERADDRL);
	ena->ena_hw->eh_max_mtu = resp.erd_payload.get_feat_dev_attr.max_mtu;

	ena_hw_update_reg_cache(ena);

	supported_features =
	    resp.erd_payload.get_feat_dev_attr.supported_features;
	bzero(&resp, sizeof (resp));

	if (supported_features & BIT(ENAHW_FEAT_MAX_QUEUES_EXT)) {
		/* TODO handle error */
		(void)ena_get_feature(ena, &resp, ENAHW_FEAT_MAX_QUEUES_EXT,
		    ENAHW_FEAT_MAX_QUEUES_EXT_VER);

		ena_log(ena, "Tx max SQs: %u CQs: %u",
		    resp.erd_payload.get_feat_max_queue_ext.max_tx_sq_num,
		    resp.erd_payload.get_feat_max_queue_ext.max_tx_cq_num);
		ena_log(ena, "Tx max SQ entires: %u max CQ entires: %u",
		    resp.erd_payload.get_feat_max_queue_ext.max_tx_sq_depth,
		    resp.erd_payload.get_feat_max_queue_ext.max_tx_cq_depth);
		ena_log(ena, "Tx max descs per packet: %u",
		    resp.erd_payload.get_feat_max_queue_ext.max_per_packet_tx_descs);
		ena_log(ena, "Tx max header size: %u",
		    resp.erd_payload.get_feat_max_queue_ext.max_tx_header_size);

		ena->ena_hw->eh_tx_max_sq_num =
		    resp.erd_payload.get_feat_max_queue_ext.max_tx_sq_num;
		ena->ena_hw->eh_tx_max_sq_num_descs =
		    resp.erd_payload.get_feat_max_queue_ext.max_tx_sq_depth;

		ena->ena_hw->eh_tx_max_cq_num =
		    resp.erd_payload.get_feat_max_queue_ext.max_tx_cq_num;
		ena->ena_hw->eh_tx_max_cq_num_descs =
		    resp.erd_payload.get_feat_max_queue_ext.max_tx_cq_depth;

		ena->ena_hw->eh_tx_max_desc_per_pkt =
		    resp.erd_payload.get_feat_max_queue_ext.max_per_packet_tx_descs;
		ena->ena_hw->eh_tx_max_hdr_len =
		    resp.erd_payload.get_feat_max_queue_ext.max_tx_header_size;


		ena_log(ena, "Rx max SQs: %u CQs: %u",
		    resp.erd_payload.get_feat_max_queue_ext.max_rx_sq_num,
		    resp.erd_payload.get_feat_max_queue_ext.max_rx_cq_num);
		ena_log(ena, "Rx max SQ entires: %u max CQ entires: %u",
		    resp.erd_payload.get_feat_max_queue_ext.max_rx_sq_depth,
		    resp.erd_payload.get_feat_max_queue_ext.max_rx_cq_depth);
		ena_log(ena, "Rx max descs per packet: %u",
		    resp.erd_payload.get_feat_max_queue_ext.max_per_packet_rx_descs);

		ena->ena_hw->eh_rx_max_sq_num =
		    resp.erd_payload.get_feat_max_queue_ext.max_rx_sq_num;
		ena->ena_hw->eh_rx_max_sq_num_descs =
		    resp.erd_payload.get_feat_max_queue_ext.max_rx_sq_depth;

		ena->ena_hw->eh_rx_max_cq_num =
		    resp.erd_payload.get_feat_max_queue_ext.max_rx_cq_num;
		ena->ena_hw->eh_rx_max_cq_num_descs =
		    resp.erd_payload.get_feat_max_queue_ext.max_rx_cq_depth;

		ena->ena_hw->eh_rx_max_desc_per_pkt =
		    resp.erd_payload.get_feat_max_queue_ext.max_per_packet_rx_descs;

		ena_set_max_io_queues(ena);


	} else {
		/* TODO handle error */
		(void)ena_get_feature(ena, &resp, ENAHW_FEAT_MAX_QUEUES_NUM,
		    ENAHW_FEAT_MAX_QUEUES_NUM_VER);

		/*
		 * TODO finish implementing this to work with older
		 * ENA device
		 */
	}

	ena_hw_update_reg_cache(ena);
	ena->ena_mtu = ena->ena_hw->eh_max_mtu;
	ena_update_buf_sizes(ena);

	if (!ena_setup_aenq(ena))
		return (B_FALSE);

	return (B_TRUE);
}

static void
ena_intr_free(ena_t *ena)
{
	for (uint_t i = 0; i < ena->ena_num_intrs; i++) {
		int ret = ddi_intr_free(ena->ena_intr_handles[i]);
		if (ret != DDI_SUCCESS) {
			ena_err(ena, "failed to free interrupt %u: %d", i, ret);
		}
	}

	if (ena->ena_intr_handles != NULL) {
		kmem_free(ena->ena_intr_handles, ena->ena_intr_handles_sz);
		ena->ena_intr_handles = NULL;
		ena->ena_intr_handles_sz = 0;
	}
}

static boolean_t
ena_intr_alloc(ena_t *ena)
{
	int ret;
	int types;
	int min, req, ideal, avail, actual;

	ret = ddi_intr_get_supported_types(ena->ena_dip, &types);
	if (ret != DDI_SUCCESS) {
		ena_err(ena, "failed to get interrupt types: %d", ret);
		return (B_FALSE);
	}

	ena_dbg(ena, "supported interttupt types: 0x%x", types);
	VERIFY((types & DDI_INTR_TYPE_MSIX) != 0);

	/* One for I/O, one for adminq. */
	min = 2;
	ideal = ena->ena_hw->eh_max_io_queues + 1;
	ret = ddi_intr_get_nintrs(ena->ena_dip, DDI_INTR_TYPE_MSIX, &avail);
	if (ret != DDI_SUCCESS) {
		ena_err(ena, "failed to get number of MSI-X interrupts: %d",
		    ret);
		return (B_FALSE);
	}

	if (avail < min) {
		ena_err(ena, "number of MSI-X interrupts is %d, but the driver "
		    "requires a minimum of %d", avail, min);
		return (B_FALSE);
	}

	ena_dbg(ena, "%d MSI-X interrupts available", avail);

	ret = ddi_intr_get_navail(ena->ena_dip, DDI_INTR_TYPE_MSIX, &avail);
	if (ret != DDI_SUCCESS) {
		ena_err(ena, "failed to get available interrupts: %d", ret);
		return (B_FALSE);
	}

	if (avail < min) {
		ena_err(ena, "number of available MSI-X interrupts is %d, "
		    "but the driver requires a minimum of %d", avail, min);
		return (B_FALSE);
	}

	req = MIN(ideal, avail);
	ena->ena_intr_handles_sz = req * sizeof (ddi_intr_handle_t);
	ena->ena_intr_handles = kmem_alloc(ena->ena_intr_handles_sz, KM_SLEEP);

	ret = ddi_intr_alloc(ena->ena_dip, ena->ena_intr_handles,
	    DDI_INTR_TYPE_MSIX, 0, req, &actual, DDI_INTR_ALLOC_NORMAL);
	if (ret != DDI_SUCCESS) {
		ena_err(ena, "failed to allocate %d MSI-X interrupts: %d",
		    req, ret);
		goto err;
	}

	if (actual < min) {
		ena_err(ena, "number of allocated interrupts is %d, but the "
		    "driver requires a minimum of %d", actual, min);
		goto err;
	}

	ena->ena_num_intrs = actual;

	ret = ddi_intr_get_cap(ena->ena_intr_handles[0], &ena->ena_intr_caps);
	if (ret != DDI_SUCCESS) {
		ena_err(ena, "failed to get interrupt capability: %d", ret);
		goto err;
	}

	ret = ddi_intr_get_pri(ena->ena_intr_handles[0], &ena->ena_intr_pri);
	if (ret != DDI_SUCCESS) {
		ena_err(ena, "failed to get interrupt priority: %d", ret);
		goto err;
	}

	ena_dbg(ena, "MSI-X interrupts allocated: %d, cap: 0x%x, pri: %u",
	    actual, ena->ena_intr_caps, ena->ena_intr_pri);

	return (B_TRUE);

err:
	ena_intr_free(ena);
	return (B_FALSE);
}

/*
 * Allocate the parent Rx queue structures. More importantly, this is
 * NOT allocating the queue descriptors or data buffers. Those are
 * allocated on demand as a queue is started.
 */
static boolean_t
ena_alloc_rxqs(ena_t *ena)
{
	ena->ena_rxqs = kmem_zalloc(ena->ena_num_rxqs * sizeof (*ena->ena_rxqs),
	    KM_SLEEP);

	for (uint_t i = 0; i < ena->ena_num_rxqs; i++) {
		ena_rxq_t *rxq = &ena->ena_rxqs[i];

		/* TODO priority? */
		mutex_init(&rxq->er_lock, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&rxq->er_stats_lock, NULL, MUTEX_DRIVER, NULL);
		rxq->er_ena = ena;
		rxq->er_sq_num_descs = ena->ena_rxq_num_descs;
		rxq->er_cq_num_descs = ena->ena_rxq_num_descs;
	}

	return (B_TRUE);
}

static void
ena_free_rxqs(ena_t *ena)
{
	for (uint_t i = 0; i < ena->ena_num_rxqs; i++) {
		mutex_destroy(&ena->ena_rxqs[i].er_lock);
		mutex_destroy(&ena->ena_rxqs[i].er_stats_lock);
	}

	kmem_free(ena->ena_rxqs, ena->ena_num_rxqs * sizeof (*ena->ena_rxqs));
}

/*
 * Allocate the parent Tx queue structures. More importantly, this is
 * NOT allocating the queue descriptors or data buffers. Those are
 * allocated on demand as a queue is started.
 */
static boolean_t
ena_alloc_txqs(ena_t *ena)
{
	ena->ena_txqs = kmem_zalloc(ena->ena_num_txqs * sizeof (*ena->ena_txqs),
	    KM_SLEEP);

	for (uint_t i = 0; i < ena->ena_num_txqs; i++) {
		ena_txq_t *txq = &ena->ena_txqs[i];

		/* TODO priority? */
		mutex_init(&txq->et_lock, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&txq->et_stats_lock, NULL, MUTEX_DRIVER, NULL);
		txq->et_ena = ena;
		txq->et_sq_num_descs = ena->ena_txq_num_descs;
		txq->et_cq_num_descs = ena->ena_txq_num_descs;
	}

	return (B_TRUE);
}

static void
ena_free_txqs(ena_t *ena)
{
	for (uint_t i = 0; i < ena->ena_num_rxqs; i++) {
		mutex_destroy(&ena->ena_txqs[i].et_lock);
		mutex_destroy(&ena->ena_txqs[i].et_stats_lock);
	}

	kmem_free(ena->ena_txqs, ena->ena_num_txqs * sizeof (*ena->ena_txqs));
}

static boolean_t
ena_set_mtu(ena_t *ena)
{
	enahw_cmd_desc_t cmd;
	enahw_resp_desc_t resp;

	bzero(&cmd, sizeof (cmd));
	bzero(&resp, sizeof(resp));

	/*
	 * TODO need to verify this feature is suppported, see
	 * ena_com_set_dev_mtu()
	 */
	cmd.ecd_payload.set_feat.egfc_cmd.mtu.mtu = ena->ena_mtu;
	if (ena_set_feature(ena, &cmd, &resp, ENAHW_FEAT_MTU,
	    ENAHW_FEAT_MTU_VER) != 0)
		return (B_FALSE);

	return (B_TRUE);
}

static boolean_t
ena_set_link_config(ena_t *ena)
{
	enahw_resp_desc_t resp;
	boolean_t full_duplex;

	ena_xxx(ena, "ena_set_link_config");

	bzero(&resp, sizeof (resp));

	/*
	 * TODO Should probably set stand-in values when this fails
	 * (this feature is optional, the t3.small returns unknown
	 * opcode).
	 */
	if (ena_get_feature(ena, &resp, ENAHW_FEAT_LINK_CONFIG,
	    ENAHW_FEAT_LINK_CONFIG_VER) != 0)
		return (B_FALSE);

	/* TODO link types supported */
	ena_xxx(ena, "speed: 0x%x", resp.erd_payload.get_feat_link_conf.speed);
	ena_xxx(ena, "supported: 0x%x",
	    resp.erd_payload.get_feat_link_conf.supported);
	ena_xxx(ena, "flags: 0x%x",
	    resp.erd_payload.get_feat_link_conf.flags);

	ena->ena_link_speed_mbits =
	    resp.erd_payload.get_feat_link_conf.speed;
	ena->ena_link_speeds = resp.erd_payload.get_feat_link_conf.supported;

	full_duplex = ENAHW_GET_FEATURE_LINK_CONF_FULL_DUPLEX(resp.erd_payload.
		get_feat_link_conf);

	ena->ena_link_duplex = full_duplex ? LINK_DUPLEX_FULL :
	    LINK_DUPLEX_HALF;

	ena->ena_link_autoneg =
	    ENAHW_GET_FEATURE_LINK_CONF_AUTONEG(resp.erd_payload.
		get_feat_link_conf);

	return (B_TRUE);
}

/*
 * This function undoes any work done by ena_attach(), either in
 * response to a failed attach or a planned detach. At the end of this
 * function ena_seq should be zero, otherwise it means something has
 * not be freed/uninitialized.
 */
static void
ena_cleanup(ena_t *ena)
{
	if (ena == NULL) {
		return;
	}

	if (ena->ena_seq & ENA_ATTACH_INTR_ENABLE) {
		VERIFY(ena_intrs_disable(ena));
		ena->ena_seq &= ~ENA_ATTACH_INTR_ENABLE;
	}

	/* TODO mac unregister */

	if (ena->ena_seq & ENA_ATTACH_RXQS_ALLOC) {
		ena_free_rxqs(ena);
		ena->ena_seq &= ~ENA_ATTACH_RXQS_ALLOC;
	}

	if (ena->ena_seq & ENA_ATTACH_TXQS_ALLOC) {
		ena_free_txqs(ena);
		ena->ena_seq &= ~ENA_ATTACH_TXQS_ALLOC;
	}

	if (ena->ena_seq & ENA_ATTACH_INTR_HDLRS) {
		ena_intr_remove_handles(ena);
		ena->ena_seq &= ~ENA_ATTACH_INTR_HDLRS;
	}

	if (ena->ena_seq & ENA_ATTACH_INTR_ALLOC) {
		ena_intr_free(ena);
		ena->ena_seq &= ~ENA_ATTACH_INTR_ALLOC;
	}

	/* TODO device init cleanup? */
	/* TODO adminq cleanup */

	if (ena->ena_seq & ENA_ATTACH_REGS) {
		ddi_regs_map_free(&ena->ena_reg_hdl);
		ena->ena_seq &= ~ENA_ATTACH_REGS;
	}

	if (ena->ena_seq & ENA_ATTACH_PCI) {
		pci_config_teardown(&ena->ena_pci_hdl);
		ena->ena_seq &= ~ENA_ATTACH_PCI;
	}

	if (ena->ena_seq & ENA_ATTACH_FM) {
		if (ena->ena_fm_caps != DDI_FM_NOT_CAPABLE) {
			ddi_fm_fini(ena->ena_dip);
		}
		ena->ena_seq &= ~ENA_ATTACH_FM;
	}

	/* TODO eventually make this VERIFY0 */
	if (ena->ena_seq != 0) {
		ena_err(ena, "failed to fully cleanup attach: 0x%x",
		    ena->ena_seq);
	}

	mutex_destroy(&ena->ena_hw->eh_lock);
	kmem_free(ena->ena_hw, sizeof (*ena->ena_hw));

	mutex_destroy(&ena->ena_lock);
	/* kmem_free(ena, sizeof (ena_t)); */
	ddi_soft_state_free(ena_state, 0);
}

static void
ena_print_offsets(ena_t *ena)
{
	ena_xxx(ena, "ena_admin_aq_create_cq_cmd.cq_caps_1: %u",
	    offsetof (struct ena_admin_aq_create_cq_cmd, cq_caps_1));
	ena_xxx(ena, "enahw_cmd_desc.ecd_payload.create_cq.cq_caps_1: %u",
	    offsetof (struct enahw_cmd_desc, ecd_payload.create_cq.cq_caps_1));
	ena_xxx(ena, "---");
}

/*
 * TODO Do we need to consider DDI_RESUME?
 */
static int
ena_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	ena_t *ena;

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	/* ena = kmem_zalloc(sizeof (ena_t), KM_SLEEP); */
	/* TODO: dynamic instance */
	VERIFY0(ddi_soft_state_zalloc(ena_state, 0));
	ena = ddi_get_soft_state(ena_state, 0);

	ena_log(ena, "entering ena_attach()");
	ena_print_offsets(ena);

	/* TODO priority? */
	mutex_init(&ena->ena_lock, NULL, MUTEX_DRIVER, NULL);
	ena->ena_hw = kmem_zalloc(sizeof (*ena->ena_hw), KM_SLEEP);
	mutex_init(&ena->ena_hw->eh_lock, NULL, MUTEX_DRIVER, NULL);
	ena->ena_dip = dip;
	ena->ena_inst = ddi_get_instance(dip);
	ena->ena_page_sz = ddi_ptob(dip, 1);
	ena_set_link_state(ena, LINK_STATE_DOWN);

	ena_fm_init(ena);
	ena->ena_seq |= ENA_ATTACH_FM;

	ena_log(ena, "calling pci_config_setup()");
	if (pci_config_setup(dip, &ena->ena_pci_hdl) != 0) {
		/* TODO add ret */
		ena_err(ena, "failed to initialize PCI config space");
		goto err;
	}
	ena->ena_seq |= ENA_ATTACH_PCI;
	ena_log(ena, "post pci_config_setup()");

	if (!ena_regs_map(ena)) {
		goto err;
	}
	ena->ena_seq |= ENA_ATTACH_REGS;

	ena_log(ena, "calling ena_identify()");
	ena_identify(ena);
	ena_log(ena, "post ena_identify()");

	if (!ena_device_init(ena)) {
		goto err;
	}
	ena->ena_seq |= ENA_ATTACH_DEV_INIT;
	/* TODO implement converse of dev init (freeing allocations) */

	ena_read_conf(ena);
	(void)ena_set_link_config(ena);
	VERIFY(ena_set_mtu(ena));
	VERIFY(ena_get_offloads(ena));

	/* TODO init interrupts (see ice_intr_ddi_alloc()) */
	if (!ena_intr_alloc(ena)) {
		goto err;
	}
	ena->ena_seq |= ENA_ATTACH_INTR_ALLOC;

	/* TODO add intr handlers (see ice_intr_add_ddi_handles()) */
	if (!ena_intr_add_handles(ena)) {
		goto err;
	}
	ena->ena_seq |= ENA_ATTACH_INTR_HDLRS;

	/* TODO implement task init (see ice_task_init()) */

	/*
	 * TODO Put this in a function. Also we don't necessairly want
	 * to limit the driver to a 1:1 mapping between interrupts and
	 * queues, but I think that's what Linux does and that's what
	 * I'm doing for the moment.
	 */
	ena->ena_num_txqs = ena->ena_num_intrs - 1;
	ena->ena_num_rxqs = ena->ena_num_intrs - 1;

	if (!ena_alloc_txqs(ena)) {
		goto err;
	}
	ena->ena_seq |= ENA_ATTACH_TXQS_ALLOC;

	if (!ena_alloc_rxqs(ena)) {
		goto err;
	}
	ena->ena_seq |= ENA_ATTACH_RXQS_ALLOC;

	/* TODO implement mac register (see ice_mac_register()) */
	if (!ena_mac_register(ena)) {
		goto err;
	}
	ena->ena_seq |= ENA_ATTACH_MAC;
	ena_dbg(ena, "mac registered");

	/* TODO implement intr enable (see ice_intr_ddi_enable()) */
	if (!ena_intrs_enable(ena)) {
		goto err;
	}
	ena->ena_seq |= ENA_ATTACH_INTR_ENABLE;

	/*
	 * Now that interrupts are enabled make sure to tell the
	 * device that all AENQ descriptors are ready for writing.
	 */
	ena_hw_bar_write32(ena, ENA_REG_AENQ_HEAD_DB,
	    ena->ena_aenq.eaenq_num_descs);

	return (DDI_SUCCESS);

err:
	ena_cleanup(ena);
	return (DDI_FAILURE);
}

static int
ena_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	/* TODO: ddi_soft_state_free() */
	ddi_soft_state_free(ena_state, 0);
	return (DDI_SUCCESS);
}

static struct cb_ops ena_cb_ops = {
	.cb_open = nodev,
	.cb_close = nodev,
	.cb_strategy = nodev,
	.cb_print = nodev,
	.cb_dump = nodev,
	.cb_read = nodev,
	.cb_write = nodev,
	.cb_ioctl = nodev,
	.cb_devmap = nodev,
	.cb_mmap = nodev,
	.cb_segmap = nodev,
	.cb_chpoll = nochpoll,
	.cb_prop_op = ddi_prop_op,
	.cb_flag = D_MP,
	.cb_rev = CB_REV,
	.cb_aread = nodev,
	.cb_awrite = nodev
};

static struct dev_ops ena_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = NULL,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = ena_attach,
	.devo_detach = ena_detach,
	.devo_reset = nodev,
	.devo_power = ddi_power,
	.devo_quiesce = ddi_quiesce_not_supported,
	.devo_cb_ops = &ena_cb_ops
};

static struct modldrv ena_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "AWS ENA Ethernet",
	.drv_dev_ops = &ena_dev_ops
};

static struct modlinkage ena_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &ena_modldrv, NULL }
};

/*
 * TODO: read mac_init_ops() just for your own understanding.
 */
int
_init(void)
{
	int ret;

	ret = ddi_soft_state_init(&ena_state, sizeof (ena_t), 1);
	if (ret != 0) {
		return (ret);
	}

	mac_init_ops(&ena_dev_ops, ENA_MODULE_NAME);

	if ((ret = mod_install(&ena_modlinkage)) != 0) {
		ddi_soft_state_fini(&ena_state);
		mac_fini_ops(&ena_dev_ops);
		return (ret);
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ena_modlinkage, modinfop));
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&ena_modlinkage)) != 0) {
		return (ret);
	}

	mac_fini_ops(&ena_dev_ops);
	ddi_soft_state_fini(&ena_state);

	return (ret);
}
