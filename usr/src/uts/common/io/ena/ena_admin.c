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
 * This file contains everything having to do with communicating with
 * the admin queue for sending commands to the device.
 */

#include "ena_hw.h"
#include "ena.h"

/*
 * Submit a command to the admin queue.
 *
 * ERROR RETURN VALUES
 *
 *     ENOSPC: The admin queue is currently full.
 *
 * TODO create cmd_ctx_t objects for command receipt.
 *
 * TODO mdb cmd to display all completed/pending commands in the cmd
 * ctx array.
 *
 */
int
ena_admin_submit_cmd(ena_t *ena, enahw_cmd_desc_t *cmd)
{
	ena_adminq_t *aq = &ena->ena_aq;
	ena_admin_sq_t *sq = &aq->ea_sq;
	uint16_t modulo_mask = aq->ea_qlen - 1;
	uint16_t tail_mod = sq->eas_tail & modulo_mask;

	VERIFY3U(cmd->ecd_opcode, !=, 0);

	if (aq->ea_pending_cmds >= aq->ea_qlen) {
		aq->ea_stats.queue_full++;
		return (ENOSPC);
	}

	/*
	 * TODO control buffer
	 *
	 * TODO why have ea_cmd_idx? It seems it should always be the
	 *      same value as modulo tail, no? So just use tail's value.
	 */
	cmd->ecd_flags = sq->eas_phase & ENAHW_CMD_PHASE_MASK;
	cmd->ecd_idx = aq->ea_cmd_idx & ENAHW_CMD_ID_MASK;
	bcopy(cmd, &sq->eas_entries[tail_mod], sizeof (*cmd));
	ENA_DMA_SYNC(sq->eas_dma, DDI_DMA_SYNC_FORDEV);
	aq->ea_cmd_idx = (aq->ea_cmd_idx + 1) & modulo_mask;
	sq->eas_tail++;
	aq->ea_stats.cmds_submitted++;
	ena_xxx(ena, "submit cmd 0x%x phase: %u tail_mod: %u ecd_idx: %u",
	    cmd->ecd_opcode, sq->eas_phase, tail_mod, cmd->ecd_idx);

	if ((sq->eas_tail & modulo_mask) == 0)
		sq->eas_phase = !sq->eas_phase;

	/*
	 * TODO I'm not sure this membar is needed but I want to make
	 * sure that the tail update is done before the update to the
	 * doorbell.
	 */
	membar_producer();
	ena_hw_abs_write32(ena, sq->eas_dbaddr, sq->eas_tail);
	ena_xxx(ena, "wrote tail: %u to eas_dbaddr: 0x%p", sq->eas_tail,
	    sq->eas_dbaddr);

	ena_hw_update_reg_cache(ena);

	return (0);
}

/*
 * Read a single response from the admin queue.
 */
int
ena_admin_read_resp(ena_t *ena, enahw_resp_desc_t *resp)
{
	ena_adminq_t *aq = &ena->ena_aq;
	ena_admin_cq_t *cq = &aq->ea_cq;
	uint16_t modulo_mask = aq->ea_qlen - 1;
	uint16_t head_mod = cq->eac_head & modulo_mask;
	uint8_t phase = cq->eac_phase & ENAHW_RESP_PHASE_MASK;
	uint_t cnt = 0;
	enahw_resp_desc_t *hwresp;

	ENA_DMA_SYNC(cq->eac_dma, DDI_DMA_SYNC_FORKERNEL);
	hwresp = &cq->eac_entries[head_mod];
	while ((hwresp->erd_flags & ENAHW_RESP_PHASE_MASK) != phase) {
		delay(drv_usectohz(1000));
		if (++cnt == 5) {
			ena_err(ena, "timeout reading response");
			aq->ea_stats.cmds_fail++;
			return (ETIMEDOUT);
		}
	}

	/*
	 * TODO I don't think this is needed, but here to make sure
	 * phase is read before the copy.
	 */
	membar_consumer();

	bcopy(hwresp, resp, sizeof (*hwresp));
	cq->eac_head++;
	if ((cq->eac_head & modulo_mask) == 0)
		cq->eac_phase = !phase;

	if (resp->erd_status != ENAHW_RESP_SUCCESS) {
		ena_xxx(ena, "ERROR response => 0x%x head_mod: %u, phase: %u "
		    "index: %u", resp->erd_status, head_mod, phase,
		    resp->erd_cmd_idx);
		aq->ea_stats.cmds_fail++;
		return (enahw_resp_status_to_errno(resp->erd_status));
	}

	ena_xxx(ena, "SUCCESS response => 0x%x head_mod: %u, phase: %u "
	    "index: %u", resp->erd_status, head_mod, phase,
	    resp->erd_cmd_idx);

	aq->ea_stats.cmds_success++;
	ena_hw_update_reg_cache(ena);
	return (0);
}

int
ena_free_host_info(ena_t *ena)
{
	ena_dma_free(&ena->ena_host_info);
	return (0);
}

boolean_t
ena_init_host_info(ena_t *ena)
{
	enahw_host_info_t *ehi;
	int ret = 0;
	ena_dma_buf_t *hi_dma;
	ddi_dma_attr_t attr;
	ddi_device_acc_attr_t acc;
	enahw_cmd_desc_t cmd;
	enahw_feat_host_attr_t *ha_cmd =
	    &cmd.ecd_cmd.ecd_set_feat.ecsf_feat.ecsf_host_attr;
	enahw_resp_desc_t resp;

	hi_dma = &ena->ena_host_info;
	ena_dma_adminq_attr(ena, &attr, sizeof (*ehi));
	ena_dma_acc_attr(ena, &acc);
	if (!ena_dma_alloc(ena, hi_dma, &attr, &acc, 4096, B_FALSE)) {
		ena_err(ena, "failed to allocate DMA for host info");
		return (B_FALSE);
	}

	ehi = (void *)hi_dma->edb_va;
	ehi->ehi_ena_spec_version =
	    ((ENAHW_SPEC_VERSION_MAJOR << ENAHW_VERSION_MAJOR_VERSION_SHIFT) |
		(ENAHW_SPEC_VERSION_MINOR));

	/* TODO Figure out how to get the B/D/F from the dev_info_t. */
	ehi->ehi_bdf = 0;

	/*
	 * There is no illumos OS type, it would be nice to ping
	 * someone at Amazon and see if we can't get one added.
	 */
	ehi->ehi_os_type = ENAHW_OS_FREEBSD;
	ehi->ehi_kernel_ver = 511; /* If you know you know */
	(void)strlcpy((char *)ehi->ehi_kernel_ver_str, utsname.version,
	    sizeof (ehi->ehi_kernel_ver_str));
	ehi->ehi_os_dist = 0;	/* What everyone else does. */
	ehi->ehi_driver_ver =
	    (ENA_MODULE_VER_MAJOR) |
	    (ENA_MODULE_VER_MINOR << ENAHW_HOST_INFO_MINOR_SHIFT) |
	    (ENA_MODULE_VER_SUBMINOR << ENAHW_HOST_INFO_SUB_MINOR_SHIFT);
	ehi->ehi_num_cpus = ncpus_online;

	/*
	 * ENA devices are not created equal. Some will support
	 * features not found in others. This field tells the device
	 * which features the driver supports.
	 *
	 * ENAHW_HOST_INFO_RX_OFFSET
	 *
	 *    Some ENA devices will write the frame data at an offset
	 *    in the buffer, presumably for alignment purposes. We
	 *    support this feature for the sole reason that the Linux
	 *    driver does as well.
	 *
	 * ENAHW_HOST_INFO_INTERRUPT_MODERATION
	 *
	 *    Based on the Linux history this flag indicates that the
	 *    driver "supports interrupt moderation properly". What
	 *    that means is anyone's guess. The Linux driver seems to
	 *    have some "adaptive" interrupt moderation, so perhaps
	 *    it's that? In any case, FreeBSD doesn't bother with
	 *    setting this flag, so we'll leave it be for now as well.
	 *
	 *    If you're curious to know if the device supports
	 *    interrupt moderation: the FEAT_INTERRUPT_MODERATION flag
	 *    will be set in ena_hw.eh_supported_features.
	 *
	 * ENAHW_HOST_INFO_RX_BUF_MIRRORING_SHIFT
	 *
	 *    Support traffic mirroring by allowing the hypervisor to
	 *    read the buffer memory directly. This probably has to do
	 *    with AWS flow logs, allowing more efficient mirroring.
	 *    But it's hard to say for sure given we only have the
	 *    Linux commit log to go off of. In any case, the only
	 *    requirement for this feature is that the Rx DMA buffers
	 *    be read/write, which they are.
	 *
	 * ENAHW_HOST_INFO_RSS_CONFIGURABLE_FUNCTION_KEY_SHIFT
	 *
	 *    The driver supports the retrieving and updating of the
	 *    RSS function and hash key. As we don't yet implement RSS
	 *    this is disabled.
	 *
	 *    TODO Implement RSS.
	 */
	ehi->ehi_driver_supported_features =
	    ENAHW_HOST_INFO_RX_OFFSET_MASK |
	    /* ENAHW_HOST_INFO_INTERRUPT_MODERATION_MASK | */
	    ENAHW_HOST_INFO_RX_BUF_MIRRORING_MASK;
	    /* ENAHW_HOST_INFO_RSS_CONFIGURABLE_FUNCTION_KEY_MASK; */

	ENA_DMA_SYNC(*hi_dma, DDI_DMA_SYNC_FORDEV);
	bzero(&cmd, sizeof (cmd));
	ena_set_dma_addr(ena, hi_dma->edb_cookie->dmac_laddress,
	    &ha_cmd->efha_os_addr);

	/* TODO setup debug area */
	ret = ena_set_feature(ena, &cmd, &resp, ENAHW_FEAT_HOST_ATTR_CONFIG,
	    ENAHW_FEAT_HOST_ATTR_CONFIG_VER);
	if (ret != 0) {
		ena_err(ena, "failed to set host attributes: %d", ret);
		ena_dma_free(hi_dma);
		return (B_FALSE);
	}

	return (B_TRUE);
}

int ena_create_cq(ena_t *ena, uint16_t num_descs, uint64_t phys_addr,
    boolean_t is_tx, uint32_t vector, uint16_t *hw_index,
    uint32_t **unmask_addr, uint32_t **headdb, uint32_t **numanode)
{
	int ret;
	enahw_cmd_desc_t cmd;
	enahw_cmd_create_cq_t *cmd_cq = &cmd.ecd_cmd.ecd_create_cq;
	enahw_resp_desc_t resp;
	enahw_resp_create_cq_t *resp_cq = &resp.erd_resp.erd_create_cq;

	/*
	 * TODO according to Linux comment this value must be 4 or 8,
	 * but Tx is 64-bit (2 32-bit words), and Rx is 128-bit (4
	 * 32-bit words). File an issue on GitHub.
	 */
	uint8_t desc_size = is_tx ? sizeof (enahw_tx_cdesc_t) :
	    sizeof (enahw_rx_cdesc_t);

	bzero(&cmd, sizeof (cmd));
	bzero(&resp, sizeof (resp));
	/* TODO assert vector lte to num rings */

	/*
	 * TODO I know I bzero'd the cmd but make sure to zero the
	 * ctrl_data flags in in ecd_flags, see
	 * ena_admin_aq_common_desc in Linux.
	 */
	cmd.ecd_opcode = ENAHW_CMD_CREATE_CQ;
	ENAHW_CMD_CREATE_CQ_INTERRUPT_MODE_ENABLE(cmd_cq);
	ASSERT3U(desc_size % 4, ==, 0);
	ENAHW_CMD_CREATE_CQ_DESC_SIZE_WORDS(cmd_cq, desc_size / 4);
	cmd_cq->ecq_num_descs = num_descs;
	cmd_cq->ecq_msix_vector = vector;
	ena_set_dma_addr(ena, phys_addr, &cmd_cq->ecq_addr);

	ena_xxx(ena, "ecq_caps_1: 0x%x", cmd_cq->ecq_caps_1);
	ena_xxx(ena, "ecq_caps_2: 0x%x", cmd_cq->ecq_caps_2);
	ena_xxx(ena, "ecq_num_descs: 0x%x", cmd_cq->ecq_num_descs);
	ena_xxx(ena, "ecq_msix_vector: 0x%x", cmd_cq->ecq_msix_vector);
	ena_xxx(ena, "ecq_addr.ea_low: 0x%x", cmd_cq->ecq_addr.ea_low);
	ena_xxx(ena, "ecq_addr.ea_high: 0x%x", cmd_cq->ecq_addr.ea_high);

	if ((ret = ena_admin_submit_cmd(ena, &cmd)) != 0) {
		ena_log(ena, "failed to submit Create CQ command: %d", ret);
		return (ret);
	}

	/*
	 * TODO If this fails (with exception of timeout) we are in
	 * real trouble, for now just crash, but eventually mark as
	 * faulty in FM and reset device.
	 */
	VERIFY0(ena_admin_read_resp(ena, &resp));

	/* TODO hmmm, this is probably why Linux has generic I/O sq/cq
	 * structures, I need to set things here that could be on txq
	 * or rxq... */
	*hw_index = resp_cq->ercq_idx;
	*unmask_addr = (uint32_t *)(ena->ena_reg_base +
	    resp_cq->ercq_interrupt_mask_reg_offset);

	if (resp_cq->ercq_head_db_reg_offset != 0) {
		*headdb = (uint32_t *)(ena->ena_reg_base +
		    resp_cq->ercq_head_db_reg_offset);
		panic("cq_head_db_reg_offset unexpectedly set");
	} else {
		*headdb = NULL;
	}

	if (resp_cq->ercq_numa_node_reg_offset != 0) {
		*numanode = (uint32_t *)(ena->ena_reg_base +
		    resp_cq->ercq_numa_node_reg_offset);
	} else {
		*numanode = NULL;
	}

	ena_xxx(ena, "created CQ idx: %u, Tx: %d, num descs: %u, "
	    "desc size: %u, msi-x vec: %u", *hw_index, is_tx, num_descs,
	    desc_size, vector);

	return (0);
}

int
ena_destroy_cq(ena_t *ena, uint16_t hw_idx)
{
	enahw_cmd_desc_t cmd;
	enahw_resp_desc_t resp;
	int ret;

	bzero(&cmd, sizeof (cmd));
	bzero(&resp, sizeof (resp));
	cmd.ecd_opcode = ENAHW_CMD_DESTROY_CQ;
	cmd.ecd_cmd.ecd_destroy_cq.edcq_idx = hw_idx;

	if ((ret = ena_admin_submit_cmd(ena, &cmd)) != 0) {
		ena_err(ena, "failed to submit Destroy CQ command: %d", ret);
		return (ret);
	}

	/*
	 * TODO If this fails (with exception of timeout) we are in
	 * real trouble, for now just crash, but eventually mark as
	 * faulty in FM and reset device.
	 */
	VERIFY0(ena_admin_read_resp(ena, &resp));
	ena_xxx(ena, "Destroy CQ idx: %u", hw_idx);
	return (0);
}

int
ena_create_sq(ena_t *ena, uint16_t num_descs, uint64_t phys_addr,
    boolean_t is_tx, uint16_t cq_index, uint16_t *hw_index, uint32_t **db_addr)
{
	int ret;
	enahw_cmd_desc_t cmd;
	enahw_cmd_create_sq_t *cmd_sq = &cmd.ecd_cmd.ecd_create_sq;
	enahw_resp_desc_t resp;
	enahw_resp_create_sq_t *resp_sq = &resp.erd_resp.erd_create_sq;
	enahw_sq_direction_t dir =
	    is_tx ? ENAHW_SQ_DIRECTION_TX : ENAHW_SQ_DIRECTION_RX;

	if (!ISP2(num_descs)) {
		ena_err(ena, "the number of descs must be a power of 2, but "
		    " is %d", num_descs);
		return (B_FALSE);
	}

	bzero(&cmd, sizeof (cmd));
	bzero(&resp, sizeof (resp));

	cmd.ecd_opcode = ENAHW_CMD_CREATE_SQ;
	ENAHW_CMD_CREATE_SQ_DIR(cmd_sq, dir);
	ENAHW_CMD_CREATE_SQ_PLACEMENT_POLICY(cmd_sq,
	    ENAHW_PLACEMENT_POLICY_HOST);
	/*
	 * TODO definitely look into various completion policies.
	 * Linux uses DESC only, but I think head-on-deman (write
	 * back) could be superior to ease up on CQ processing.
	 */
	ENAHW_CMD_CREATE_SQ_COMPLETION_POLICY(cmd_sq,
	    ENAHW_COMPLETION_POLICY_DESC);

	/*
	 * TODO make sure the DMA memory for these SQs are actually
	 * physically continguous.
	 */
	ENAHW_CMD_CREATE_SQ_PHYSMEM_CONTIG(cmd_sq);
	cmd_sq->ecsq_cq_idx = cq_index;
	cmd_sq->ecsq_num_descs = num_descs;

	/*
	 * XXX If we ever use a non-host placement policy, then guard
	 * this code against placement type (this value should not be
	 * set for device placement).
	 */
	ena_set_dma_addr(ena, phys_addr, &cmd_sq->ecsq_base);

	if ((ret = ena_admin_submit_cmd(ena, &cmd)) != 0) {
		ena_err(ena, "failed to submit create SQ command: %d", ret);
		return (ret);
	}

	/* TODO think about failure, is it actually helpful to return
	 * the reason for failed response here? What action would the
	 * caller take? Might it be better to a failed resp to lead to
	 * a new command to undo the submission above? If so, what if
	 * the undo command fails? etc...
	 *
	 * From what I can tell there is (once again) no command to
	 * query the current device state in terms of SQ/CQs
	 * allocated. Without the ability to know what exists the most
	 * logical thing to do upon failure to get a response from a
	 * create command is to reset the device and start from scratch.
	 *
	 * In fact, the more I think about it the more I think any
	 * admin or I/O cmd that fails to get a response should
	 * probably cause a device reset. If the device fails to
	 * respond, or some other part of the system loses the
	 * response, then the driver's view of the device state is
	 * suspect from here on out -- it could be right, it could be
	 * wrong, we have no way to query the device to know for sure,
	 * so best fail/reset the device. The only exception I can
	 * think of is in the case of a response timeout, in that case
	 * it seems okay to try waiting for the expected response
	 * again, but if we timeout multiple times we once again have
	 * to assume the device is in a bad way or the response was
	 * lost and reset.
	 */
	if ((ret = ena_admin_read_resp(ena, &resp)) != 0) {
		ena_err(ena, "failed to read create SQ response: %d", ret);
		return (ret);
	}

	VERIFY3U((uintptr_t)ena->ena_reg_base, >, 0);
	*hw_index = resp_sq->ersq_idx;
	*db_addr = (uint32_t *)(ena->ena_reg_base +
	    resp_sq->ersq_db_reg_offset);

	ena_xxx(ena, "created %s SQ idx: %u, CQ idx: %u, num descs: %u, "
	    "db_addr: 0x%p, placement: 0x%x, completion: 0x%x",
	    is_tx ? "Tx" : "Rx", *hw_index, cq_index, num_descs, *db_addr,
	    ENAHW_PLACEMENT_POLICY_HOST, ENAHW_COMPLETION_POLICY_DESC);

	return (0);
}

int
ena_destroy_sq(ena_t *ena, uint16_t hw_idx, boolean_t is_tx)
{
	enahw_cmd_desc_t cmd;
	enahw_cmd_destroy_sq_t *cmd_sq = &cmd.ecd_cmd.ecd_destroy_sq;
	enahw_resp_desc_t resp;
	int ret;

	bzero(&cmd, sizeof (cmd));
	bzero(&resp, sizeof (resp));
	cmd.ecd_opcode = ENAHW_CMD_DESTROY_SQ;
	cmd_sq->edsq_idx = hw_idx;
	ENAHW_CMD_DESTROY_SQ_DIR(cmd_sq, is_tx);

	if ((ret = ena_admin_submit_cmd(ena, &cmd)) != 0) {
		ena_err(ena, "failed to submit Destroy SQ command: %d", ret);
		return (ret);
	}

	/*
	 * TODO If this fails (with exception of timeout) we are in
	 * real trouble, for now just crash, but eventually mark as
	 * faulty in FM and reset device.
	 */
	VERIFY0(ena_admin_read_resp(ena, &resp));
	ena_xxx(ena, "Destroy SQ idx: %u dir: %s", hw_idx, is_tx ? "Tx" : "Rx");
	return (0);
}

int
ena_set_feature(ena_t *ena, enahw_cmd_desc_t *cmd, enahw_resp_desc_t *resp,
    const enahw_feature_id_t feat_id, const uint8_t feat_ver)
{
	enahw_cmd_set_feat_t *cmd_sf = &cmd->ecd_cmd.ecd_set_feat;

	cmd->ecd_opcode = ENAHW_CMD_SET_FEATURE;
	cmd_sf->ecsf_comm.efc_id = feat_id;
	cmd_sf->ecsf_comm.efc_version = feat_ver;
	cmd_sf->ecsf_comm.efc_flags = 0;

	VERIFY0(ena_admin_submit_cmd(ena, cmd));
	return (ena_admin_read_resp(ena, resp));
}

/*
 * TODO feature num to string for errors
 */
int
ena_get_feature(ena_t *ena, enahw_resp_desc_t *resp,
    const enahw_feature_id_t feat_id, const uint8_t feat_ver)
{
	enahw_cmd_desc_t cmd;
	enahw_cmd_get_feat_t *cmd_gf = &cmd.ecd_cmd.ecd_get_feat;

	/*
	 * TODO check supported feature,
	 * ena_com_check_supported_feature_id()
	 */

	bzero(&cmd, sizeof (cmd));
	cmd.ecd_opcode = ENAHW_CMD_GET_FEATURE;
	cmd_gf->ecgf_comm.efc_id = feat_id;
	cmd_gf->ecgf_comm.efc_version = feat_ver;
	/*
	 * TODO linux sets to 0 (via memset), but I expect it to be
	 * 0x1 (to indicate to read the current value).
	 */
	/* gf_cmd->ecgf_comm.efc_flags = 0; */
	cmd_gf->ecgf_comm.efc_flags = 1;

	VERIFY0(ena_admin_submit_cmd(ena, &cmd));
	return(ena_admin_read_resp(ena, resp));
}

boolean_t
ena_setup_aenq(ena_t *ena)
{
	enahw_cmd_desc_t cmd;
	enahw_feat_aenq_t *cmd_feat =
	    &cmd.ecd_cmd.ecd_set_feat.ecsf_feat.ecsf_aenq;
	enahw_resp_desc_t resp;
	enahw_feat_aenq_t *resp_feat = &resp.erd_resp.erd_get_feat.ergf_aenq;
	enahw_aenq_groups_t to_enable;

	bzero(&resp, sizeof (resp));
	if (ena_get_feature(ena, &resp, ENAHW_FEAT_AENQ_CONFIG,
	    ENAHW_FEAT_AENQ_CONFIG_VER) != 0)
		return (B_FALSE);

	ena_xxx(ena, "AENQ supported: 0x%x", resp_feat->efa_supported_groups);
	ena_xxx(ena, "AENQ enabled: 0x%x", resp_feat->efa_enabled_groups);

	for (uint_t i = 0; i < ENAHW_AENQ_GROUP_NUM; i++) {
		ena_aenq_grpstr_t *grpstr = &ena_groups_str[i];
		boolean_t supported = BIT(grpstr->eag_type) &
		    resp_feat->efa_supported_groups;
		boolean_t enabled = BIT(grpstr->eag_type) &
		    resp_feat->efa_enabled_groups;

		ena_xxx(ena, "%s supported: %s enabled: %s", grpstr->eag_str,
		    supported ? "Y" : "N", enabled ? "Y" : "N");
	}

	/* TODO add keep alive timeer */
	to_enable = BIT(ENAHW_AENQ_GROUP_LINK_CHANGE) |
	    BIT(ENAHW_AENQ_GROUP_FATAL_ERROR) |
	    BIT(ENAHW_AENQ_GROUP_WARNING) |
	    BIT(ENAHW_AENQ_GROUP_NOTIFICATION);
	/* TODO use feat pointer */
	to_enable &= resp_feat->efa_supported_groups;

	ena_xxx(ena, "setting AENQ groups to 0x%x", to_enable);
	bzero(&cmd, sizeof (cmd));
	bzero(&resp, sizeof (cmd));
	cmd_feat->efa_enabled_groups = to_enable;

	if (ena_set_feature(ena, &cmd, &resp, ENAHW_FEAT_AENQ_CONFIG,
	    ENAHW_FEAT_AENQ_CONFIG_VER) != 0)
		return (B_FALSE);

	bzero(&resp, sizeof (resp));
	if (ena_get_feature(ena, &resp, ENAHW_FEAT_AENQ_CONFIG,
	    ENAHW_FEAT_AENQ_CONFIG_VER) != 0)
		return (B_FALSE);

	ena_xxx(ena, "aenq supported: 0x%x", resp_feat->efa_supported_groups);
	ena_xxx(ena, "aenq enabled: 0x%x", resp_feat->efa_enabled_groups);

	for (uint_t i = 0; i < ENAHW_AENQ_GROUP_NUM; i++) {
		ena_aenq_grpstr_t *grpstr = &ena_groups_str[i];
		boolean_t supported = BIT(grpstr->eag_type) &
		    resp_feat->efa_supported_groups;
		boolean_t enabled = BIT(grpstr->eag_type) &
		    resp_feat->efa_enabled_groups;

		ena_xxx(ena, "%s supported: %s enabled: %s", grpstr->eag_str,
		    supported ? "Y" : "N", enabled ? "Y" : "N");
	}

	return (B_TRUE);
}
