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

#ifdef DEBUG
boolean_t ena_debug = B_TRUE;
#else
boolean_t ena_debug = B_FALSE;
#endif	/* DEBUG */

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

void
ena_dbg(const ena_t *ena, const char *fmt, ...)
{
	va_list ap;

	if (ena_debug) {
		va_start(ap, fmt);
		if (ena != NULL && ena->ena_dip != NULL) {
			vdev_err(ena->ena_dip, CE_NOTE, fmt, ap);
		} else {
			vcmn_err(CE_NOTE, fmt, ap);
		}
		va_end(ap);
	}
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

	if (processed) {
		ena_hw_bar_write32(ena, ENAHW_REG_AENQ_HEAD_DB,
		    aenq->eaenq_head);
	}
}

/*
 * Use for attach sequences which perform no resource allocation (or
 * global state modification) and thus require no subsequent
 * deallocation.
 */
static int
ena_no_cleanup(ena_t *ena)
{
	return (0);
}

static int
ena_cleanup_fma(ena_t *ena)
{
	if (ena->ena_fm_caps != DDI_FM_NOT_CAPABLE)
		ddi_fm_fini(ena->ena_dip);

	return (0);
}

/*
 * XXX Implement FMA capabilities.
 */
static boolean_t
ena_attach_fma(ena_t *ena)
{
	ena->ena_fm_caps = DDI_FM_NOT_CAPABLE;
	return (B_TRUE);
}

static boolean_t
ena_attach_pci(ena_t *ena)
{
	ddi_acc_handle_t hdl;

	if (pci_config_setup(ena->ena_dip, &hdl) != 0) {
		return (B_FALSE);
	}

	ena->ena_pci_hdl = hdl;
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

	return (B_TRUE);
}

static int
ena_cleanup_pci(ena_t *ena)
{
	pci_config_teardown(&ena->ena_pci_hdl);
	return (0);
}

static int
ena_cleanup_regs_map(ena_t *ena)
{
	ddi_regs_map_free(&ena->ena_reg_hdl);
	return (0);
}

static boolean_t
ena_attach_regs_map(ena_t *ena)
{
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

	if (ddi_regs_map_setup(ena->ena_dip, ENA_REG_NUMBER, &ena->ena_reg_base,
	    0, ena->ena_reg_size, &ena->ena_reg_attr, &ena->ena_reg_hdl) !=
	    DDI_SUCCESS) {
		ena_err(ena, "failed to map register set: %d", ENA_REG_NUMBER);
		return (B_FALSE);
	}

	ena_dbg(ena, "registers mapped to base: 0x%p",
	    (void *)ena->ena_reg_base);

	return (B_TRUE);
}

/*
 * Free any resources related to the admin submission queue.
 */
static void
ena_admin_sq_free(ena_t *ena)
{
	ena_dma_free(&ena->ena_aq.ea_sq.eas_dma);
}

/*
 * Initialize the admin submission queue.
 */
static boolean_t
ena_admin_sq_init(ena_t *ena)
{
	ena_adminq_t *aq = &ena->ena_aq;
	ena_dma_buf_t *dma = &aq->ea_sq.eas_dma;
	size_t size = aq->ea_qlen * sizeof (*aq->ea_sq.eas_entries);
	ddi_dma_attr_t attr;
	ddi_device_acc_attr_t acc;
	uint32_t addr_low, addr_high, wval;

	ena_dma_adminq_attr(ena, &attr, size);
	ena_dma_acc_attr(ena, &acc);
	if (!ena_dma_alloc(ena, dma, &attr, &acc, size, B_FALSE)) {
		ena_err(ena, "failed to allocate DMA for SQ");
		return (B_FALSE);
	}

	aq->ea_sq.eas_entries = (void *)dma->edb_va;
	aq->ea_sq.eas_head = 0;
	aq->ea_sq.eas_tail = 0;
	aq->ea_sq.eas_phase = 1;
	aq->ea_sq.eas_dbaddr =
	    (uint32_t *)(ena->ena_reg_base + ENAHW_REG_ASQ_DB);
	ENA_DMA_VERIFY_ADDR(ena, dma->edb_cookie->dmac_laddress);
	addr_low = (uint32_t)(dma->edb_cookie->dmac_laddress);
	addr_high = (uint32_t)(dma->edb_cookie->dmac_laddress >> 32);
	ena_hw_bar_write32(ena, ENAHW_REG_ASQ_BASE_LO, addr_low);
	ena_hw_bar_write32(ena, ENAHW_REG_ASQ_BASE_HI, addr_high);
	wval = ENAHW_ASQ_CAPS_DEPTH(aq->ea_qlen) |
	    ENAHW_ASQ_CAPS_ENTRY_SIZE(sizeof (*aq->ea_sq.eas_entries));
	ena_hw_bar_write32(ena, ENAHW_REG_ASQ_CAPS, wval);
	return (B_TRUE);
}

/*
 * Free any resources related to the admin completion queue.
 */
static void
ena_admin_cq_free(ena_t *ena)
{
	ena_dma_free(&ena->ena_aq.ea_cq.eac_dma);
}

/*
 * Initialize the admin completion queue.
 */
static boolean_t
ena_admin_cq_init(ena_t *ena)
{
	ena_adminq_t *aq = &ena->ena_aq;
	ena_dma_buf_t *dma = &aq->ea_cq.eac_dma;
	size_t size = aq->ea_qlen * sizeof (*aq->ea_cq.eac_entries);
	ddi_dma_attr_t attr;
	ddi_device_acc_attr_t acc;
	uint32_t addr_low, addr_high, wval;

	ena_dma_adminq_attr(ena, &attr, size);
	ena_dma_acc_attr(ena, &acc);
	if (!ena_dma_alloc(ena, dma, &attr, &acc, size, B_FALSE)) {
		ena_err(ena, "failed to allocate DMA for CQ");
		return (B_FALSE);
	}

	aq->ea_cq.eac_entries = (void *)dma->edb_va;
	aq->ea_cq.eac_head = 0;
	aq->ea_cq.eac_phase = 1;
	ENA_DMA_VERIFY_ADDR(ena, dma->edb_cookie->dmac_laddress);
	addr_low = (uint32_t)(dma->edb_cookie->dmac_laddress);
	addr_high = (uint32_t)(dma->edb_cookie->dmac_laddress >> 32);
	ena_hw_bar_write32(ena, ENAHW_REG_ACQ_BASE_LO, addr_low);
	ena_hw_bar_write32(ena, ENAHW_REG_ACQ_BASE_HI, addr_high);
	wval = ENAHW_ACQ_CAPS_DEPTH(aq->ea_qlen) |
	    ENAHW_ACQ_CAPS_ENTRY_SIZE(sizeof (*aq->ea_cq.eac_entries));
	ena_hw_bar_write32(ena, ENAHW_REG_ACQ_CAPS, wval);
	return (B_TRUE);
}

/*
 * TODO add link speed
 * TODO add flow control
 */
void
ena_link_status_update(ena_t *ena)
{
	link_state_t ls;

	mutex_enter(&ena->ena_lock);

	if (ena->ena_link_up)
		ls = LINK_STATE_UP;
	else
		ls = LINK_STATE_DOWN;

	mac_link_update(ena->ena_mh, ls);
	mutex_exit(&ena->ena_lock);
}

static void
ena_aenq_default_hdlr(void *data, enahw_aenq_desc_t *desc)
{
	ena_t *ena = data;

	ena_dbg(ena, "unimplemented handler for aenq group: %s",
	    ena_groups_str[desc->ead_group].eag_str);
}

static void
ena_aenq_link_change_hdlr(void *data, enahw_aenq_desc_t *desc)
{
	ena_t *ena = data;

	mutex_enter(&ena->ena_lock);
	ena->ena_link_up = (desc->ead_payload.link_change.flags &
	    ENAHW_AENQ_LINK_CHANGE_LINK_STATUS_MASK) != 0;
	mutex_exit(&ena->ena_lock);

	ena_link_status_update(ena);
}

/*
 * Free any resources related to the Async Event Notification Queue.
 */
static void
ena_aenq_free(ena_t *ena)
{
	ena_dma_free(&ena->ena_aenq.eaenq_dma);
}

/*
 * Initialize the Async Event Notification Queue.
 */
static boolean_t
ena_aenq_init(ena_t *ena)
{
	ena_aenq_t *aenq = &ena->ena_aenq;
	size_t size;
	ddi_dma_attr_t attr;
	ddi_device_acc_attr_t acc;
	uint32_t addr_low, addr_high, wval;

	aenq->eaenq_num_descs = ENA_AENQ_NUM_DESCS;
	size = aenq->eaenq_num_descs * sizeof (*aenq->eaenq_descs);
	ena_dma_adminq_attr(ena, &attr, size);
	ena_dma_acc_attr(ena, &acc);

	if (!ena_dma_alloc(ena, &aenq->eaenq_dma, &attr, &acc, size, B_FALSE)) {
		ena_err(ena, "failed to allocate DMA for AENQ");
		return (B_FALSE);
	}

	aenq->eaenq_descs = (void *)aenq->eaenq_dma.edb_va;
	aenq->eaenq_head = 0;
	aenq->eaenq_phase = 1;
	bzero(aenq->eaenq_descs, size);

	for (uint_t i = 0; i < ENAHW_AENQ_SYNDROME_NUM; i++) {
		aenq->eaenq_hdlrs[i] = ena_aenq_default_hdlr;
	}

	aenq->eaenq_hdlrs[ENAHW_AENQ_GROUP_LINK_CHANGE] =
	    ena_aenq_link_change_hdlr;
	ENA_DMA_VERIFY_ADDR(ena, aenq->eaenq_dma.edb_cookie->dmac_laddress);
	addr_low = (uint32_t)(aenq->eaenq_dma.edb_cookie->dmac_laddress);
	addr_high = (uint32_t)(aenq->eaenq_dma.edb_cookie->dmac_laddress >> 32);
	ena_hw_bar_write32(ena, ENAHW_REG_AENQ_BASE_LO, addr_low);
	ena_hw_bar_write32(ena, ENAHW_REG_AENQ_BASE_HI, addr_high);
	ENA_DMA_SYNC(aenq->eaenq_dma, DDI_DMA_SYNC_FORDEV);
	wval = ENAHW_AENQ_CAPS_DEPTH(aenq->eaenq_num_descs) |
	    ENAHW_AENQ_CAPS_ENTRY_SIZE(sizeof (*aenq->eaenq_descs));
	ena_hw_bar_write32(ena, ENAHW_REG_AENQ_CAPS, wval);
	return (B_TRUE);
}

static void
ena_set_max_io_queues(ena_t *ena)
{
	uint32_t max = 128;

	max = MIN(ncpus_online, max);
	max = MIN(ena->ena_tx_max_sq_num, max);
	max = MIN(ena->ena_tx_max_cq_num, max);
	max = MIN(ena->ena_rx_max_sq_num, max);
	max = MIN(ena->ena_rx_max_cq_num, max);

	VERIFY3U(max, >, 0);
	ena->ena_max_io_queues = max;
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
	enahw_feat_offload_t *feat = &resp.erd_resp.erd_get_feat.ergf_offload;

	bzero(&resp, sizeof (resp));

	if (ena_get_feature(ena, &resp, ENAHW_FEAT_STATELESS_OFFLOAD_CONFIG,
	    ENAHW_FEAT_STATELESS_OFFLOAD_CONFIG_VER) != 0)
		return (B_FALSE);

	ena_xxx(ena, "offload rx_supported: 0x%x", feat->efo_rx_supported);
	ena_xxx(ena, "offload rx_enabled: 0x%x", feat->efo_rx_enabled);

	if (ENAHW_FEAT_OFFLOAD_TX_L3_CSUM_IPV4(feat)) {
		ena->ena_rx_l3_ipv4_csum = B_TRUE;
	} else {
		ena->ena_rx_l3_ipv4_csum = B_FALSE;
	}

	if (ENAHW_FEAT_OFFLOAD_TX_L4_IPV4_CSUM_FULL(feat)) {
		ena->ena_rx_l4_ipv4_full_csum = B_TRUE;
	} else {
		ena->ena_rx_l4_ipv4_full_csum = B_FALSE;
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
 * TODO move to ena_admin
 */
static boolean_t
ena_set_mtu(ena_t *ena)
{
	enahw_cmd_desc_t cmd;
	enahw_feat_mtu_t *feat =
	    &cmd.ecd_cmd.ecd_set_feat.ecsf_feat.ecsf_mtu;
	enahw_resp_desc_t resp;

	bzero(&cmd, sizeof (cmd));
	bzero(&resp, sizeof(resp));

	/*
	 * TODO need to verify this feature is suppported, see
	 * ena_com_set_dev_mtu()
	 */
	feat->efm_mtu = ena->ena_mtu;
	if (ena_set_feature(ena, &cmd, &resp, ENAHW_FEAT_MTU,
	    ENAHW_FEAT_MTU_VER) != 0)
		return (B_FALSE);

	return (B_TRUE);
}

static boolean_t
ena_set_link_config(ena_t *ena)
{
	enahw_resp_desc_t resp;
	enahw_feat_link_conf_t *feat =
	    &resp.erd_resp.erd_get_feat.ergf_link_conf;
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
	ena_xxx(ena, "speed: 0x%x", feat->eflc_speed);
	ena_xxx(ena, "supported: 0x%x", feat->eflc_supported);
	ena_xxx(ena, "flags: 0x%x", feat->eflc_flags);

	ena->ena_link_speed_mbits = feat->eflc_speed;
	ena->ena_link_speeds = feat->eflc_supported;

	full_duplex = ENAHW_FEAT_LINK_CONF_FULL_DUPLEX(feat);

	ena->ena_link_duplex = full_duplex ? LINK_DUPLEX_FULL :
	    LINK_DUPLEX_HALF;

	ena->ena_link_autoneg = ENAHW_FEAT_LINK_CONF_AUTONEG(feat);

	return (B_TRUE);
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
static boolean_t
ena_attach_read_conf(ena_t *ena)
{
	uint32_t gcv;	/* Greatest Common Value */

	/*
	 * We expect that the queue lengths are the same for both the
	 * CQ and SQ, but technically the device could return
	 * different lengths. While it could make sense to use
	 * different lengths for performance reasons, for now lock
	 * these together.
	 */
	gcv = min(ena->ena_rx_max_sq_num_descs, ena->ena_rx_max_cq_num_descs);
	ASSERT3U(gcv, <=, INT_MAX);
	ena->ena_rxq_num_descs = ena_get_prop(ena, ENA_PROP_RXQ_NUM_DESCS,
	    ENA_PROP_MIN_RXQ_NUM_DESCS, gcv, gcv);

	gcv = min(ena->ena_tx_max_sq_num_descs, ena->ena_tx_max_cq_num_descs);
	ASSERT3U(gcv, <=, INT_MAX);
	ena->ena_txq_num_descs = ena_get_prop(ena, ENA_PROP_TXQ_NUM_DESCS,
	    ENA_PROP_MIN_TXQ_NUM_DESCS, gcv, gcv);

	/* TODO these really probably shouldn't be in here, deferring
	 * decision */
	(void)ena_set_link_config(ena);
	VERIFY(ena_set_mtu(ena));
	VERIFY(ena_get_offloads(ena));

	return (B_TRUE);
}

/*
 * Free all resources allocated as part of ena_device_init().
 */
static int
ena_cleanup_device_init(ena_t *ena)
{
	int ret;

	if ((ret = ena_free_host_info(ena)) != 0)
		return (ret);

	ena_admin_sq_free(ena);
	ena_admin_cq_free(ena);
	ena_aenq_free(ena);
	return (0);
}

static boolean_t
ena_attach_device_init(ena_t *ena)
{
	ena_adminq_t *aq = &ena->ena_aq;
	uint32_t rval, wval;
	uint8_t timeout, dma_width;
	hrtime_t expired;
	enahw_resp_desc_t resp;
	enahw_feat_dev_attr_t *feat = &resp.erd_resp.erd_get_feat.ergf_dev_attr;
	uint8_t *maddr;
	uint32_t supported_features;

	ena_dbg(ena, "attempting to read device status");
	/* TODO eventually move this stuff into function */
	rval = ena_hw_bar_read32(ena, ENAHW_REG_DEV_STS);
	if ((rval & ENAHW_DEV_STS_READY_MASK) == 0) {
		ena_err(ena, "device is not ready");
		return (B_FALSE);
	}

	ena_dbg(ena, "attempt to get devices reset timeout");
	/* Timeout value reprsents units of 100ms. */
	rval = ena_hw_bar_read32(ena, ENAHW_REG_CAPS);
	timeout = ENAHW_CAPS_RESET_TIMEOUT(rval);
	if (timeout == 0) {
		ena_err(ena, "device gave invalid timeout");
		return (B_FALSE);
	}
	expired = gethrtime() + (timeout * 100 * 1000 * 1000);

	ena_dbg(ena, "attempt to reset device");
	wval = ENAHW_DEV_CTL_DEV_RESET_MASK;
	wval |= (ENAHW_RESET_NORMAL << ENAHW_DEV_CTL_RESET_REASON_SHIFT) &
	    ENAHW_DEV_CTL_RESET_REASON_MASK;
	ena_hw_bar_write32(ena, ENAHW_REG_DEV_CTL, wval);
	/* TODO: do I need to do DMA sync's for BAR reads/writes? */

	ena_dbg(ena, "wait for reset to start");
	/* Make sure reset is in progress. */
	while (1) {
		rval = ena_hw_bar_read32(ena, ENAHW_REG_DEV_STS);

		if ((rval & ENAHW_DEV_STS_RESET_IN_PROGRESS_MASK) != 0) {
			break;
		}

		if (gethrtime() > expired) {
			ena_err(ena, "device reset start timed out");
			return (B_FALSE);
		}

		/* sleep for 100ms */
		delay(drv_usectohz(100 * 1000));
	}
	ena_dbg(ena, "wait for reset to finish");

	/*
	 * TODO I'm writing 0 based on that Linux does. There is also
	 * a RESET_FINISHED mask I can use (rather than asserting not
	 * in progress).
	 */
	ena_hw_bar_write32(ena, ENAHW_REG_DEV_CTL, 0);
	while (1) {
		rval = ena_hw_bar_read32(ena, ENAHW_REG_DEV_STS);

		if ((rval & ENAHW_DEV_STS_RESET_IN_PROGRESS_MASK) == 0) {
			break;
		}

		if (gethrtime() > expired) {
			ena_err(ena, "device reset finish timed out");
			return (B_FALSE);
		}

		/* sleep for 100ms */
		delay(drv_usectohz(100 * 1000));
	}

	ena_dbg(ena, "reset has finished");

	/* TODO ena_com_validation_version() */

	rval = ena_hw_bar_read32(ena, ENAHW_REG_CAPS);
	dma_width = ENAHW_CAPS_DMA_ADDR_WIDTH(rval);
	ena->ena_dma_width = dma_width;
	ena_xxx(ena, "DMA width: %u", dma_width);

	/* BEGIN INIT ADMIN QUEUE */
	/* TODO: equiv of Linux's ena_com_admin_init() */

	/*
	 * We already establish device ready earlier, but if this goes
	 * in its own function it makes sense to verify this first.
	 */
	rval = ena_hw_bar_read32(ena, ENAHW_REG_DEV_STS);
	if ((rval & ENAHW_DEV_STS_READY_MASK) == 0) {
		ena_err(ena, "device is not ready");
		return (B_FALSE);
	}

	ena_hw_update_reg_cache(ena);
	aq->ea_qlen = ENA_ADMINQ_DEPTH;
	aq->ea_pending_cmds = 0;

	if (!ena_admin_sq_init(ena))
		goto error;

	if (!ena_admin_cq_init(ena))
		goto error;

	if (!ena_aenq_init(ena))
		goto error;

	/* END INIT */

	/* SET POLLING MODE START (ena_com_set_admin_polling_mode)*/
	ena_dbg(ena, "turned interrupts off, polling on");
	/* ena_hw_bar_write32(ena, ENA_REG_INTR_MASK, ENA_INTR_MASK); */
	/* TODO temporarily turn on interrupt for test */
	ena_hw_bar_write32(ena, ENAHW_REG_INTERRUPT_MASK, 0);
	aq->ea_poll_mode = B_TRUE;
	/* SET POLLING MODE END */

	if(!ena_init_host_info(ena))
		return (B_FALSE);

	bzero(&resp, sizeof (resp));
	VERIFY0(ena_get_feature(ena, &resp, ENAHW_FEAT_DEVICE_ATTRIBUTES,
		ENAHW_FEAT_DEVICE_ATTRIBUTES_VER));

	/* TODO print response */
	ena_dbg(ena, "impl ID: %u", feat->efda_impl_id);
	ena_dbg(ena, "device version: %u", feat->efda_device_version);
	ena_dbg(ena, "supported features: 0x%x",
	    feat->efda_supported_features);
	ena_dbg(ena, "phys addr width: %u", feat->efda_phys_addr_width);
	ena_dbg(ena, "virt addr width: %u", feat->efda_virt_addr_with);
	maddr = feat->efda_mac_addr;
	ena_dbg(ena, "mac addr: %x:%x:%x:%x:%x:%x", maddr[0], maddr[1],
	    maddr[2], maddr[3], maddr[4], maddr[5]);
	ena_dbg(ena, "max MTU: %u", feat->efda_max_mtu);

	bcopy(maddr, ena->ena_mac_addr, ETHERADDRL);
	ena->ena_max_mtu = feat->efda_max_mtu;

	ena_hw_update_reg_cache(ena);

	supported_features = feat->efda_supported_features;
	ena->ena_supported_features = feat->efda_supported_features;
	feat = NULL;
	bzero(&resp, sizeof (resp));

	if (supported_features & BIT(ENAHW_FEAT_MAX_QUEUES_EXT)) {
		enahw_feat_max_queue_ext_t *feat_mqe =
		    &resp.erd_resp.erd_get_feat.ergf_max_queue_ext;

		/* TODO handle error */
		(void)ena_get_feature(ena, &resp, ENAHW_FEAT_MAX_QUEUES_EXT,
		    ENAHW_FEAT_MAX_QUEUES_EXT_VER);

		ena_dbg(ena, "Tx max SQs: %u CQs: %u",
		    feat_mqe->efmqe_max_tx_sq_num,
		    feat_mqe->efmqe_max_tx_cq_num);
		ena_dbg(ena, "Tx max SQ entires: %u max CQ entires: %u",
		    feat_mqe->efmqe_max_tx_sq_depth,
		    feat_mqe->efmqe_max_tx_cq_depth);
		ena_dbg(ena, "Tx max descs per packet: %u",
		    feat_mqe->efmqe_max_per_packet_tx_descs);
		ena_dbg(ena, "Tx max header size: %u",
		    feat_mqe->efmqe_max_tx_header_size);

		ena->ena_tx_max_sq_num = feat_mqe->efmqe_max_tx_sq_num;
		ena->ena_tx_max_sq_num_descs = feat_mqe->efmqe_max_tx_sq_depth;
		ena->ena_tx_max_cq_num = feat_mqe->efmqe_max_tx_cq_num;
		ena->ena_tx_max_cq_num_descs = feat_mqe->efmqe_max_tx_cq_depth;

		ena->ena_tx_max_desc_per_pkt =
		    feat_mqe->efmqe_max_per_packet_tx_descs;
		ena->ena_tx_max_hdr_len = feat_mqe->efmqe_max_tx_header_size;

		ena_dbg(ena, "Rx max SQs: %u CQs: %u",
		    feat_mqe->efmqe_max_rx_sq_num,
		    feat_mqe->efmqe_max_rx_cq_num);
		ena_dbg(ena, "Rx max SQ entires: %u max CQ entires: %u",
		    feat_mqe->efmqe_max_rx_sq_depth,
		    feat_mqe->efmqe_max_rx_cq_depth);
		ena_dbg(ena, "Rx max descs per packet: %u",
		    feat_mqe->efmqe_max_per_packet_rx_descs);

		ena->ena_rx_max_sq_num = feat_mqe->efmqe_max_rx_sq_num;
		ena->ena_rx_max_sq_num_descs = feat_mqe->efmqe_max_rx_sq_depth;
		ena->ena_rx_max_cq_num = feat_mqe->efmqe_max_rx_cq_num;
		ena->ena_rx_max_cq_num_descs = feat_mqe->efmqe_max_rx_cq_depth;
		ena->ena_rx_max_desc_per_pkt =
		    feat_mqe->efmqe_max_per_packet_rx_descs;

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
	ena->ena_mtu = ena->ena_max_mtu;
	ena_update_buf_sizes(ena);

	if (!ena_setup_aenq(ena))
		return (B_FALSE);

	return (B_TRUE);

error:
	return (B_FALSE);
}

static int
ena_cleanup_intr_alloc(ena_t *ena)
{
	for (uint_t i = 0; i < ena->ena_num_intrs; i++) {
		int ret = ddi_intr_free(ena->ena_intr_handles[i]);
		if (ret != DDI_SUCCESS) {
			ena_err(ena, "failed to free interrupt %u: %d", i, ret);
			return (ret);
		}
	}

	if (ena->ena_intr_handles != NULL) {
		kmem_free(ena->ena_intr_handles, ena->ena_intr_handles_sz);
		ena->ena_intr_handles = NULL;
		ena->ena_intr_handles_sz = 0;
	}

	return (0);
}

static boolean_t
ena_attach_intr_alloc(ena_t *ena)
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
	ideal = ena->ena_max_io_queues + 1;
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

	/*
	 * The ena_lock should not be held in the datapath, but it is
	 * held as part of the AENQ handler, which runs in interrupt
	 * context. Therefore, we delay the initilization of this
	 * mutex until after the interrupts are allocated.
	 */
	mutex_init(&ena->ena_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(ena->ena_intr_pri));

	return (B_TRUE);

err:
	return (B_FALSE);
}

/*
 * Allocate the parent Rx queue structures. More importantly, this is
 * NOT allocating the queue descriptors or data buffers. Those are
 * allocated on demand as a queue is started.
 */
static boolean_t
ena_attach_alloc_rxqs(ena_t *ena)
{
	/* We rely on the interrupt priority for initializing the mutexes. */
	VERIFY3U(ena->ena_attach_seq, >=, ENA_ATTACH_INTR_ALLOC);

	/*
	 * TODO We don't necessairly want to limit the driver to a 1:1
	 * mapping between interrupts and queues, but I think that's
	 * what Linux does and that's what I'm doing for the moment.
	 */
	ena->ena_num_rxqs = ena->ena_num_intrs - 1;
	ena->ena_rxqs = kmem_zalloc(ena->ena_num_rxqs * sizeof (*ena->ena_rxqs),
	    KM_SLEEP);

	for (uint_t i = 0; i < ena->ena_num_rxqs; i++) {
		ena_rxq_t *rxq = &ena->ena_rxqs[i];

		mutex_init(&rxq->er_lock, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(ena->ena_intr_pri));
		mutex_init(&rxq->er_stats_lock, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(ena->ena_intr_pri));
		rxq->er_ena = ena;
		rxq->er_sq_num_descs = ena->ena_rxq_num_descs;
		rxq->er_cq_num_descs = ena->ena_rxq_num_descs;
	}

	return (B_TRUE);
}

static int
ena_cleanup_rxqs(ena_t *ena)
{
	for (uint_t i = 0; i < ena->ena_num_rxqs; i++) {
		mutex_destroy(&ena->ena_rxqs[i].er_lock);
		mutex_destroy(&ena->ena_rxqs[i].er_stats_lock);
	}

	kmem_free(ena->ena_rxqs, ena->ena_num_rxqs * sizeof (*ena->ena_rxqs));
	return (0);
}

/*
 * Allocate the parent Tx queue structures. More importantly, this is
 * NOT allocating the queue descriptors or data buffers. Those are
 * allocated on demand as a queue is started.
 */
static boolean_t
ena_attach_alloc_txqs(ena_t *ena)
{
	/* We rely on the interrupt priority for initializing the mutexes. */
	VERIFY3U(ena->ena_attach_seq, >=, ENA_ATTACH_INTR_ALLOC);

	/*
	 * TODO We don't necessairly want to limit the driver to a 1:1
	 * mapping between interrupts and queues, but I think that's
	 * what Linux does and that's what I'm doing for the moment.
	 */
	ena->ena_num_txqs = ena->ena_num_intrs - 1;
	ena->ena_txqs = kmem_zalloc(ena->ena_num_txqs * sizeof (*ena->ena_txqs),
	    KM_SLEEP);

	for (uint_t i = 0; i < ena->ena_num_txqs; i++) {
		ena_txq_t *txq = &ena->ena_txqs[i];

		mutex_init(&txq->et_lock, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(ena->ena_intr_pri));
		mutex_init(&txq->et_stats_lock, NULL, MUTEX_DRIVER,
			DDI_INTR_PRI(ena->ena_intr_pri));
		txq->et_ena = ena;
		txq->et_sq_num_descs = ena->ena_txq_num_descs;
		txq->et_cq_num_descs = ena->ena_txq_num_descs;
	}

	return (B_TRUE);
}

static int
ena_cleanup_txqs(ena_t *ena)
{
	for (uint_t i = 0; i < ena->ena_num_rxqs; i++) {
		mutex_destroy(&ena->ena_txqs[i].et_lock);
		mutex_destroy(&ena->ena_txqs[i].et_stats_lock);
	}

	kmem_free(ena->ena_txqs, ena->ena_num_txqs * sizeof (*ena->ena_txqs));
	return (0);
}

ena_attach_desc_t ena_attach_tbl[ENA_ATTACH_NUM_ENTRIES] = {
	{
		.ead_seq = ENA_ATTACH_FMA,
		.ead_name = "setup fault managment",
		.ead_attach_fn = ena_attach_fma,
		.ead_attach_hard_fail = B_TRUE,
		.ead_cleanup_fn = ena_cleanup_fma,
		.ead_cleanup_hard_fail = B_TRUE,
	},

	{
		.ead_seq = ENA_ATTACH_PCI,
		.ead_name = "setup PCI config",
		.ead_attach_fn = ena_attach_pci,
		.ead_attach_hard_fail = B_TRUE,
		.ead_cleanup_fn = ena_cleanup_pci,
		.ead_cleanup_hard_fail = B_TRUE,
	},

	{
		.ead_seq = ENA_ATTACH_REGS,
		.ead_name = "BAR mapping",
		.ead_attach_fn = ena_attach_regs_map,
		.ead_attach_hard_fail = B_TRUE,
		.ead_cleanup_fn = ena_cleanup_regs_map,
		.ead_cleanup_hard_fail = B_TRUE,
	},

	{
		.ead_seq = ENA_ATTACH_DEV_INIT,
		.ead_name = "device initialization",
		.ead_attach_fn = ena_attach_device_init,
		.ead_attach_hard_fail = B_TRUE,
		.ead_cleanup_fn = ena_cleanup_device_init,
		.ead_cleanup_hard_fail = B_TRUE,
	},

	{
		.ead_seq = ENA_ATTACH_READ_CONF,
		.ead_name = "read ena.conf file",
		.ead_attach_fn = ena_attach_read_conf,
		.ead_attach_hard_fail = B_TRUE,
		.ead_cleanup_fn = ena_no_cleanup,
		.ead_cleanup_hard_fail = B_TRUE,
	},

	{
		.ead_seq = ENA_ATTACH_INTR_ALLOC,
		.ead_name = "interrupt allocation",
		.ead_attach_fn = ena_attach_intr_alloc,
		.ead_attach_hard_fail = B_TRUE,
		.ead_cleanup_fn = ena_cleanup_intr_alloc,
		.ead_cleanup_hard_fail = B_TRUE,
	},

	{
		.ead_seq = ENA_ATTACH_INTR_HDLRS,
		.ead_name = "add interrupt handlers",
		.ead_attach_fn = ena_intr_add_handlers,
		.ead_attach_hard_fail = B_TRUE,
		.ead_cleanup_fn = ena_intr_remove_handlers,
		.ead_cleanup_hard_fail = B_TRUE,
	},

	/* TODO task init? see ice_task_init() */

	{
		.ead_seq = ENA_ATTACH_TXQS_ALLOC,
		.ead_name = "Tx queues allocation",
		.ead_attach_fn = ena_attach_alloc_txqs,
		.ead_attach_hard_fail = B_TRUE,
		.ead_cleanup_fn = ena_cleanup_txqs,
		.ead_cleanup_hard_fail = B_TRUE,
	},

	{
		.ead_seq = ENA_ATTACH_RXQS_ALLOC,
		.ead_name = "Rx queues allocation",
		.ead_attach_fn = ena_attach_alloc_rxqs,
		.ead_attach_hard_fail = B_TRUE,
		.ead_cleanup_fn = ena_cleanup_rxqs,
		.ead_cleanup_hard_fail = B_TRUE,
	},

	{
		.ead_seq = ENA_ATTACH_MAC_REGISTER,
		.ead_name = "register with mac framework",
		.ead_attach_fn = ena_mac_register,
		.ead_attach_hard_fail = B_TRUE,
		.ead_cleanup_fn = ena_mac_unregister,
		.ead_cleanup_hard_fail = B_TRUE,
	},

	{
		.ead_seq = ENA_ATTACH_INTRS_ENABLE,
		.ead_name = "enable interrupts",
		.ead_attach_fn = ena_intrs_enable,
		.ead_attach_hard_fail = B_TRUE,
		.ead_cleanup_fn = ena_intrs_disable,
		.ead_cleanup_hard_fail = B_TRUE,
	}
};

/*
 * This function undoes any work done by ena_attach(), either in
 * response to a failed attach or a planned detach. At the end of this
 * function ena_attach_seq should be zero, otherwise it means
 * something has not be freed/uninitialized.
 */
static int
ena_cleanup(ena_t *ena)
{
	if (ena == NULL || ena->ena_attach_seq == 0) {
		return (0);
	}

	VERIFY3U(ena->ena_attach_seq, <, ENA_ATTACH_NUM_ENTRIES);
	while (ena->ena_attach_seq > 0) {
		int ret;
		int idx = ena->ena_attach_seq - 1;
		ena_attach_desc_t *desc = &ena_attach_tbl[idx];

		ena_dbg(ena, "running cleanup sequence: %s (%d)",
		    desc->ead_name, idx);

		if ((ret = desc->ead_cleanup_fn(ena)) != 0) {
			ena_err(ena,
			    "cleanup sequence failed: %s (%d), with ret: %d",
			    desc->ead_name, idx, ret);

			if (desc->ead_cleanup_hard_fail)
				return (ret);
		}

		if (ret == 0)
			ena_dbg(ena, "cleanup sequence completed: %s (%d)",
			    desc->ead_name, idx);

		ena->ena_attach_seq--;
	}

	ASSERT3U(ena->ena_attach_seq, ==, 0);
	mutex_destroy(&ena->ena_lock);
	return (0);
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

	ena = kmem_zalloc(sizeof (ena_t), KM_SLEEP);
	ena->ena_instance = ddi_get_instance(dip);
	ddi_set_driver_private(dip, ena);
	ena->ena_dip = dip;
	ena->ena_instance = ddi_get_instance(dip);
	ena->ena_page_sz = ddi_ptob(dip, 1);

	for (int i = 0; i < ENA_ATTACH_NUM_ENTRIES; i++) {
		boolean_t ret;
		ena_attach_desc_t *desc = &ena_attach_tbl[i];

		ena_dbg(ena, "running attach sequence: %s (%d)", desc->ead_name,
		    i);
		/* VERIFY(desc->ead_attach_fn(ena)); */

		if (!(ret = desc->ead_attach_fn(ena))) {
			ena_err(ena, "attach sequence failed: %s (%d)",
			    desc->ead_name, i);

			/*
			 * Since the ead_seq is predicated on
			 * successful ead_attach_fn we must run the
			 * specific cleanup handler before calling the
			 * global cleanup routine. This also means
			 * that all cleanup functions must be able to
			 * deal with partial success of the
			 * corresponding ead_attach_fn.
			 */
			(void) desc->ead_cleanup_fn(ena);
			(void) ena_cleanup(ena);

			if (desc->ead_cleanup_hard_fail)
				return (DDI_FAILURE);
		}

		if (ret)
			ena_dbg(ena, "attach sequence completed: %s (%d)",
			    desc->ead_name, i);

		ena->ena_attach_seq = desc->ead_seq;
	}

	/*
	 * Now that interrupts are enabled make sure to tell the
	 * device that all AENQ descriptors are ready for writing.
	 *
	 * TODO This looks busted. This register is for the AENQ
	 * doorbell address, but I'm writing the number of
	 * descriptors.
	 *
	 * TODO Is there a way we can disable AENQ in ena_cleanup? Should we?
	 */
	ena_hw_bar_write32(ena, ENAHW_REG_AENQ_HEAD_DB,
	    ena->ena_aenq.eaenq_num_descs);

	return (DDI_SUCCESS);
}

static int
ena_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	ena_t *ena = (ena_t *)ddi_get_driver_private(dip);

	if (ena == NULL)
		return (DDI_FAILURE);

	if (ena_cleanup(ena) != 0)
		return (DDI_FAILURE);

	kmem_free(ena, sizeof (ena_t));
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

	mac_init_ops(&ena_dev_ops, ENA_MODULE_NAME);

	if ((ret = mod_install(&ena_modlinkage)) != 0) {
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
	return (ret);
}
