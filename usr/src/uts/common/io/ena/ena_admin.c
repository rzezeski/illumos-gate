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
	cmd->ecd_flags = sq->eas_phase & ENA_HW_ASQ_CD_PHASE_MASK;
	cmd->ecd_idx = aq->ea_cmd_idx & ENA_HW_ASQ_CD_COMMAND_ID_MASK;
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
	uint8_t phase = cq->eac_phase & ENA_HW_ACQ_CD_PHASE_MASK;
	uint_t cnt = 0;
	enahw_resp_desc_t *hwresp;

	ENA_DMA_SYNC(cq->eac_dma, DDI_DMA_SYNC_FORKERNEL);
	hwresp = &cq->eac_entries[head_mod];
	while ((hwresp->erd_flags & ENA_HW_ACQ_CD_PHASE_MASK) != phase) {
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

	if (resp->erd_status != ENA_ADMIN_SUCCESS) {
		ena_xxx(ena, "ERROR response => 0x%x head_mod: %u, phase: %u "
		    "index: %u", resp->erd_status, head_mod, phase,
		    resp->erd_cmd_idx);
		aq->ea_stats.cmds_fail++;
		return (enahw_admin_cmd_status_to_errno(resp->erd_status));
	}

	ena_xxx(ena, "SUCCESS response => 0x%x head_mod: %u, phase: %u "
	    "index: %u", resp->erd_status, head_mod, phase,
	    resp->erd_cmd_idx);

	aq->ea_stats.cmds_success++;
	ena_hw_update_reg_cache(ena);
	return (0);
}

int ena_create_cq(ena_t *ena, uint16_t num_descs, uint64_t phys_addr,
    boolean_t is_tx, uint32_t vector, uint16_t *hw_index,
    uint32_t **unmask_addr, uint32_t **headdb, uint32_t **numanode)
{
	int ret;
	enahw_cmd_desc_t cmd;
	enahw_resp_desc_t resp;
	/*
	 * TODO according to Linux comment this value must be 4 or 8,
	 * but Tx is 64-bit (2 32-bit words), and Rx is 128-bit (4
	 * 32-bit words).
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
	cmd.ecd_opcode = ENA_ADMIN_CMD_CREATE_CQ;
	ENA_CMD_CREATE_CQ_INTERRUPT_MODE_ENABLE(cmd.ecd_payload.create_cq);
	ASSERT3U(desc_size % 4, ==, 0);
	ENA_CMD_CREATE_CQ_DESC_SIZE_WORDS(cmd.ecd_payload.create_cq,
	    desc_size / 4);
	/* ENA_CMD_CREATE_CQ_DESC_SIZE_WORDS(cmd.ecd_payload.create_cq, */
	/*     desc_size); */
	cmd.ecd_payload.create_cq.cq_num_descs = num_descs;
	cmd.ecd_payload.create_cq.cq_msix_vector = vector;
	ena_set_dma_addr(phys_addr, &cmd.ecd_payload.create_cq.cq_ba_low,
	    &cmd.ecd_payload.create_cq.cq_ba_high);

	ena_xxx(ena, "cq_caps_1: 0x%x", cmd.ecd_payload.create_cq.cq_caps_1);
	ena_xxx(ena, "cq_caps_2: 0x%x", cmd.ecd_payload.create_cq.cq_caps_2);
	ena_xxx(ena, "cq_num_descs: 0x%x",
	    cmd.ecd_payload.create_cq.cq_num_descs);
	ena_xxx(ena, "cq_msix_vector: 0x%x",
	    cmd.ecd_payload.create_cq.cq_msix_vector);
	ena_xxx(ena, "cq_ba_low: 0x%x",
	    cmd.ecd_payload.create_cq.cq_ba_low);
	ena_xxx(ena, "cq_ba_high: 0x%x",
	    cmd.ecd_payload.create_cq.cq_ba_high);
	ena_xxx(ena, "cq_rsvdw5: 0x%x",
	    cmd.ecd_payload.create_cq.cq_rsvdw5);

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
	*hw_index = resp.erd_payload.create_cq.cq_idx;
	*unmask_addr = (uint32_t *)(ena->ena_reg_base +
	    resp.erd_payload.create_cq.cq_interrupt_mask_reg_offset);

	if (resp.erd_payload.create_cq.cq_head_db_reg_offset != 0) {
		*headdb = (uint32_t *)(ena->ena_reg_base +
		    resp.erd_payload.create_cq.cq_head_db_reg_offset);
		panic("cq_head_db_reg_offset unexpectedly set");
	} else {
		*headdb = NULL;
	}

	if (resp.erd_payload.create_cq.cq_numa_node_reg_offset != 0) {
		*numanode = (uint32_t *)(ena->ena_reg_base +
		    resp.erd_payload.create_cq.cq_numa_node_reg_offset);
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
	cmd.ecd_opcode = ENA_ADMIN_CMD_DESTROY_CQ;
	cmd.ecd_payload.destroy_cq.cq_idx = hw_idx;

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
	enahw_resp_desc_t resp;
	enahw_sq_direction_t dir =
	    is_tx ? ENA_ADMIN_SQ_DIRECTION_TX : ENA_ADMIN_SQ_DIRECTION_RX;

	if (!ISP2(num_descs)) {
		ena_err(ena, "the number of descs must be a power of 2, but "
		    " is %d", num_descs);
		return (B_FALSE);
	}

	bzero(&cmd, sizeof (cmd));
	bzero(&resp, sizeof (resp));

	cmd.ecd_opcode = ENA_ADMIN_CMD_CREATE_SQ;
	ENA_CMD_CREATE_SQ_DIR(cmd.ecd_payload.create_sq, dir);
	ENA_CMD_CREATE_SQ_PLACEMENT_POLICY(cmd.ecd_payload.create_sq,
	    ENA_PLACEMENT_POLICY_HOST);
	/*
	 * TODO definitely look into various completion policies.
	 * Linux uses DESC only, but I think head-on-deman (write
	 * back) could be superior to ease up on CQ processing.
	 */
	ENA_CMD_CREATE_SQ_COMPLETION_POLICY(cmd.ecd_payload.create_sq,
	    ENA_COMPLETION_POLICY_DESC);

	/*
	 * TODO make sure the DMA memory for these SQs are actually
	 * physically continguous.
	 */
	ENA_CMD_CREATE_SQ_PHYSMEM_CONTIG(cmd.ecd_payload.create_sq);
	cmd.ecd_payload.create_sq.sq_cq_idx = cq_index;
	cmd.ecd_payload.create_sq.sq_num_descs = num_descs;

	/*
	 * XXX If we ever use a non-host placement policy, then guard
	 * this code again placement type (these values should not be
	 * set for device placement).
	 */
	ena_set_dma_addr(phys_addr, &cmd.ecd_payload.create_sq.sq_ba_low,
	    &cmd.ecd_payload.create_sq.sq_ba_high);

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
	*hw_index = resp.erd_payload.create_sq.sq_idx;
	*db_addr = (uint32_t *)(ena->ena_reg_base +
	    resp.erd_payload.create_sq.sq_db_reg_offset);

	ena_xxx(ena, "created %s SQ idx: %u, CQ idx: %u, num descs: %u, "
	    "db_addr: 0x%p, placement: 0x%x, completion: 0x%x",
	    is_tx ? "Tx" : "Rx", *hw_index, cq_index, num_descs, *db_addr,
	    ENA_PLACEMENT_POLICY_HOST, ENA_COMPLETION_POLICY_DESC);

	return (0);
}

int
ena_destroy_sq(ena_t *ena, uint16_t hw_idx, boolean_t is_tx)
{
	enahw_cmd_desc_t cmd;
	enahw_resp_desc_t resp;
	int ret;

	bzero(&cmd, sizeof (cmd));
	bzero(&resp, sizeof (resp));
	cmd.ecd_opcode = ENA_ADMIN_CMD_DESTROY_SQ;
	cmd.ecd_payload.destroy_sq.sq_idx = hw_idx;
	ENAHW_CMD_DESTROY_SQ_DIR(cmd.ecd_payload.destroy_sq, is_tx);

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
	cmd->ecd_opcode = ENA_ADMIN_CMD_SET_FEATURE;
	cmd->ecd_payload.set_feat.id = feat_id;
	cmd->ecd_payload.set_feat.version = feat_ver;
	cmd->ecd_payload.set_feat.flags = 0;

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

	/* TODO check supported feature, ena_com_check_supported_feature_id() */

	bzero(&cmd, sizeof (cmd));
	cmd.ecd_opcode = ENA_ADMIN_CMD_GET_FEATURE;
	cmd.ecd_payload.get_feat.id = feat_id;
	cmd.ecd_payload.get_feat.version = feat_ver;
	/*
	 * TODO linux sets to 0 (via memset), but I expect it to be
	 * 0x1 (to indicate to read the current value).
	 */
	/* cmd.ecd_payload.get_feat.flags = 0; */
	cmd.ecd_payload.get_feat.flags = 1;

	VERIFY0(ena_admin_submit_cmd(ena, &cmd));
	return(ena_admin_read_resp(ena, resp));
}

boolean_t
ena_setup_aenq(ena_t *ena)
{
	enahw_cmd_desc_t cmd;
	enahw_resp_desc_t resp;
	enahw_aenq_groups_t to_enable;

	bzero(&resp, sizeof (resp));
	if (ena_get_feature(ena, &resp, ENAHW_FEAT_AENQ_CONFIG,
	    ENAHW_FEAT_AENQ_CONFIG_VER) != 0)
		return (B_FALSE);

	ena_xxx(ena, "aenq supported groups: 0x%x",
	    resp.erd_payload.get_feat_aenq.supported_groups);
	ena_xxx(ena, "aenq enabled groups: 0x%x",
	    resp.erd_payload.get_feat_aenq.enabled_groups);

	for (uint_t i = 0; i < ENAHW_AENQ_GROUP_NUM; i++) {
		ena_aenq_grpstr_t *grpstr = &ena_groups_str[i];
		boolean_t supported = BIT(grpstr->eag_type) &
		    resp.erd_payload.get_feat_aenq.supported_groups;
		boolean_t enabled = BIT(grpstr->eag_type) &
		    resp.erd_payload.get_feat_aenq.enabled_groups;

		ena_xxx(ena, "%s supported: %s enabled: %s", grpstr->eag_str,
		    supported ? "Y" : "N", enabled ? "Y" : "N");
	}

	/* TODO add keep alive timeer */
	to_enable = BIT(ENAHW_AENQ_GROUP_LINK_CHANGE) |
	    BIT(ENAHW_AENQ_GROUP_FATAL_ERROR) |
	    BIT(ENAHW_AENQ_GROUP_WARNING) |
	    BIT(ENAHW_AENQ_GROUP_NOTIFICATION);
	to_enable &= resp.erd_payload.get_feat_aenq.supported_groups;

	ena_xxx(ena, "setting AENQ groups to 0x%x", to_enable);
	bzero(&cmd, sizeof (cmd));
	bzero(&resp, sizeof (cmd));
	cmd.ecd_payload.set_feat.egfc_cmd.aenq.enabled_groups = to_enable;

	if (ena_set_feature(ena, &cmd, &resp, ENAHW_FEAT_AENQ_CONFIG,
	    ENAHW_FEAT_AENQ_CONFIG_VER) != 0)
		return (B_FALSE);

	bzero(&resp, sizeof (resp));
	if (ena_get_feature(ena, &resp, ENAHW_FEAT_AENQ_CONFIG,
	    ENAHW_FEAT_AENQ_CONFIG_VER) != 0)
		return (B_FALSE);

	ena_xxx(ena, "aenq supported groups: 0x%x",
	    resp.erd_payload.get_feat_aenq.supported_groups);
	ena_xxx(ena, "aenq enabled groups: 0x%x",
	    resp.erd_payload.get_feat_aenq.enabled_groups);

	for (uint_t i = 0; i < ENAHW_AENQ_GROUP_NUM; i++) {
		ena_aenq_grpstr_t *grpstr = &ena_groups_str[i];
		boolean_t supported = BIT(grpstr->eag_type) &
		    resp.erd_payload.get_feat_aenq.supported_groups;
		boolean_t enabled = BIT(grpstr->eag_type) &
		    resp.erd_payload.get_feat_aenq.enabled_groups;

		ena_xxx(ena, "%s supported: %s enabled: %s", grpstr->eag_str,
		    supported ? "Y" : "N", enabled ? "Y" : "N");
	}

	return (B_TRUE);
}
