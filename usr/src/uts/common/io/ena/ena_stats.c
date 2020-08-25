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
#include "ena.h"

/*
 * The ENA device provides the following hardware stats. It appears
 * that all stats are available at both a device and per-queue level.
 *
 * BASIC (ENAHW_GET_STATS_TYPE_BASIC)
 *
 *     - Rx packets/bytes
 *     - Rx drops
 *     - Tx packets/bytes
 *     - Tx drops
 *
 * EXTENDED (ENAHW_GET_STATS_TYPE_EXTENDED)
 *
 *     There is no structure defined for these stats in the Linux
 *     driver. Based on the FreeBSD driver, it looks like extended
 *     stats are simply a buffer of C strings? Come back to this
 *     later.
 *
 * ENI (ENAHW_GET_STATS_TYPE_ENI)
 *
 *     - Rx Bandwidth Allowance Exceeded
 *     - Tx Bandwidth Allowance Exceeded
 *     - PPS Allowance Exceeded (presumably for combined Rx/Tx)
 *     - Connection Tracking PPS Allowance Exceeded
 *     - Link-local PPS Alloance Exceeded
 */
void
ena_admin_get_basic_stats(ena_t *ena)
{
	enahw_cmd_desc_t cmd;
	enahw_resp_desc_t resp;

	bzero(&cmd, sizeof (cmd));
	bzero(&resp, sizeof (resp));

	cmd.ecd_opcode = ENA_ADMIN_CMD_GET_STATS;
	cmd.ecd_payload.get_stats.type = ENAHW_GET_STATS_TYPE_BASIC;
	cmd.ecd_payload.get_stats.scope = ENAHW_GET_STATS_SCOPE_ETH;
	cmd.ecd_payload.get_stats.device_id = 0xFFFF;

	mutex_enter(&ena->ena_hw->eh_lock);
	VERIFY0(ena_admin_submit_cmd(ena, &cmd));
	VERIFY0(ena_admin_read_resp(ena, &resp));

	ena->ena_hw->eh_basic_stats.ebs_tx_bytes =
	    ((uint64_t)resp.erd_payload.get_stats_basic.tx_bytes_high << 32) |
	    (uint64_t)resp.erd_payload.get_stats_basic.tx_bytes_low;
	ena->ena_hw->eh_basic_stats.ebs_tx_pkts =
	    ((uint64_t)resp.erd_payload.get_stats_basic.tx_pkts_high << 32) |
	    (uint64_t)resp.erd_payload.get_stats_basic.tx_pkts_low;
	ena->ena_hw->eh_basic_stats.ebs_tx_drops =
	    ((uint64_t)resp.erd_payload.get_stats_basic.tx_drops_high << 32) |
	    (uint64_t)resp.erd_payload.get_stats_basic.tx_drops_low;

	ena->ena_hw->eh_basic_stats.ebs_rx_bytes =
	    ((uint64_t)resp.erd_payload.get_stats_basic.rx_bytes_high << 32) |
	    (uint64_t)resp.erd_payload.get_stats_basic.rx_bytes_low;
	ena->ena_hw->eh_basic_stats.ebs_rx_pkts =
	    ((uint64_t)resp.erd_payload.get_stats_basic.rx_pkts_high << 32) |
	    (uint64_t)resp.erd_payload.get_stats_basic.rx_pkts_low;
	ena->ena_hw->eh_basic_stats.ebs_rx_drops =
	    ((uint64_t)resp.erd_payload.get_stats_basic.rx_drops_high << 32) |
	    (uint64_t)resp.erd_payload.get_stats_basic.rx_drops_low;

	mutex_exit(&ena->ena_hw->eh_lock);
}

/*
 * TODO The ENA device supposedly provides per-queue stats, should we
 * pull from there instead of our own software stats?
 */
int
ena_ring_rx_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	ena_rxq_t *rxq = (ena_rxq_t *)rh;

	mutex_enter(&rxq->er_stats_lock);

	switch (stat) {
	case MAC_STAT_RBYTES:
		*val = rxq->er_stats.erxs_bytes.value.ui64;
		break;
	case MAC_STAT_IPACKETS:
		*val = rxq->er_stats.erxs_packets.value.ui64;
		break;
	default:
		*val = 0;
		return (ENOTSUP);
	}

	mutex_exit(&rxq->er_stats_lock);
	return (0);
}

/*
 * TODO The ENA device supposedly provides per-queue stats, should we
 * pull from there instead of our own software stats?
 */
int
ena_ring_tx_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	ena_txq_t *txq = (ena_txq_t *)rh;

	mutex_enter(&txq->et_stats_lock);

	switch (stat) {
	case MAC_STAT_OBYTES:
		*val = txq->et_stats.etxs_bytes.value.ui64;
		break;
	case MAC_STAT_OPACKETS:
		*val = txq->et_stats.etxs_packets.value.ui64;
		break;
	default:
		*val = 0;
		return (ENOTSUP);
	}

	mutex_exit(&txq->et_stats_lock);

	return (0);
}

int
ena_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	ena_t *ena = arg;
	int ret = 0;

	ena_admin_get_basic_stats(ena);
	mutex_enter(&ena->ena_hw->eh_lock);

	/*
	 * The ENA device does not provide a lot of the stats that a
	 * traditional NIC device would.
	 */
	switch (stat) {
	case MAC_STAT_NORCVBUF:
		*val = ena->ena_hw->eh_basic_stats.ebs_rx_drops;
		break;

	case MAC_STAT_RBYTES:
		*val = ena->ena_hw->eh_basic_stats.ebs_rx_bytes;
		break;

	case MAC_STAT_IPACKETS:
		*val = ena->ena_hw->eh_basic_stats.ebs_rx_pkts;
		break;

	case MAC_STAT_OBYTES:
		*val = ena->ena_hw->eh_basic_stats.ebs_tx_bytes;
		break;

	case MAC_STAT_OPACKETS:
		*val = ena->ena_hw->eh_basic_stats.ebs_tx_pkts;
		break;

	default:
		ret = ENOTSUP;
		break;
	}

	mutex_exit(&ena->ena_hw->eh_lock);
	return (ret);
}
