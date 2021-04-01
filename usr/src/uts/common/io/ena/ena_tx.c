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
#include "ena.h"

void
ena_free_tx_dma(ena_txq_t *txq)
{
	if (txq->et_tcbs != NULL) {
		for (uint_t i = 0; i < txq->et_sq_num_descs; i++) {
			ena_tx_control_block_t *tcb = &txq->et_tcbs[i];
			ena_dma_free(&tcb->etcb_dma);
		}

		kmem_free(txq->et_tcbs,
		    sizeof (*txq->et_tcbs) * txq->et_sq_num_descs);

		txq->et_tcbs = NULL;

	}

	ena_dma_free(&txq->et_cq_dma);
	txq->et_cq_descs = NULL;

	ena_dma_free(&txq->et_sq_dma);
	txq->et_sq_descs = NULL;

	txq->et_state &= ~ENA_TXQ_STATE_HOST_ALLOC;
}

static int
ena_alloc_tx_dma(ena_txq_t *txq)
{
	ena_t *ena = txq->et_ena;
	size_t cq_descs_sz;
	size_t sq_descs_sz;
	int err = 0;
	ddi_dma_attr_t attr;
	ddi_device_acc_attr_t acc;

	VERIFY0(txq->et_state & ENA_TXQ_STATE_HOST_ALLOC);

	cq_descs_sz = txq->et_cq_num_descs * sizeof (*txq->et_cq_descs);
	sq_descs_sz = txq->et_sq_num_descs * sizeof (*txq->et_sq_descs);

	VERIFY3P(ena, !=, NULL);
	VERIFY3U(sq_descs_sz, >, 0);
	ena_dma_adminq_attr(ena, &attr, sq_descs_sz);
	ena_dma_acc_attr(ena, &acc);
	if (!ena_dma_alloc(ena, &txq->et_sq_dma, &attr, &acc, sq_descs_sz,
	    B_FALSE))
		return (ENOMEM);

	bzero(txq->et_sq_dma.edb_va, sq_descs_sz);
	ena_xxx(ena, "Tx SQ descs phys: 0x%p virt: 0x%p size: %u",
	    txq->et_sq_dma.edb_cookie->dmac_laddress, txq->et_sq_dma.edb_va,
		sq_descs_sz);
	txq->et_sq_descs = (void *)txq->et_sq_dma.edb_va;
	txq->et_tcbs = kmem_zalloc(sizeof (*txq->et_tcbs) *
	    txq->et_sq_num_descs, KM_SLEEP);

	for (uint_t i = 0; i < txq->et_sq_num_descs; i++) {
		ena_tx_control_block_t *tcb = &txq->et_tcbs[i];

		VERIFY3U(ena->ena_tx_buf_sz, >, 0);
		ena_dma_io_attr(ena, &attr, ena->ena_tx_buf_sz);
		ena_dma_io_acc_attr(ena, &acc);
		if (!ena_dma_alloc(ena, &tcb->etcb_dma, &attr, &acc,
		    ena->ena_tx_buf_sz, B_TRUE)) {
			err = ENOMEM;
			goto error;
		}

		ena_xxx(ena, "Tx buf phys: 0x%p virt: 0x%p",
		    tcb->etcb_dma.edb_cookie->dmac_laddress,
		    tcb->etcb_dma.edb_va);

	}

	ena_dma_adminq_attr(ena, &attr, cq_descs_sz);
	ena_dma_acc_attr(ena, &acc);
	VERIFY3U(sizeof (*txq->et_cq_descs), >, 0);
	if (!ena_dma_alloc(ena, &txq->et_cq_dma, &attr, &acc, cq_descs_sz,
	    B_FALSE))
		return (ENOMEM);

	bzero(txq->et_cq_dma.edb_va, cq_descs_sz);
	ena_xxx(ena, "Tx CQ descs phys: 0x%p virt: 0x%p size: %u",
	    txq->et_cq_dma.edb_cookie->dmac_laddress, txq->et_cq_dma.edb_va,
		cq_descs_sz);
	txq->et_cq_descs = (void *)txq->et_cq_dma.edb_va;
	txq->et_state |= ENA_TXQ_STATE_HOST_ALLOC;
	return (0);

error:
	ena_free_tx_dma(txq);
	return (err);
}

void
ena_ring_tx_stop(mac_ring_driver_t rh)
{
	ena_txq_t *txq = (ena_txq_t *)rh;

	ena_xxx(txq->et_ena, "ena_ring_tx_stop");
	txq->et_state &= ~ENA_TXQ_STATE_RUNNING;
	txq->et_state &= ~ENA_TXQ_STATE_READY;

	VERIFY(txq->et_state & ENA_TXQ_STATE_SQ_CREATED);
	VERIFY0(ena_destroy_sq(txq->et_ena, txq->et_sq_hw_index, B_TRUE));
	txq->et_sq_hw_index = 0;
	txq->et_sq_db_addr = NULL;
	txq->et_sq_tail_idx = 0;
	txq->et_sq_phase = 0;
	txq->et_state &= ~ENA_TXQ_STATE_SQ_CREATED;

	VERIFY(txq->et_state & ENA_TXQ_STATE_CQ_CREATED);
	VERIFY0(ena_destroy_cq(txq->et_ena, txq->et_cq_hw_index));
	txq->et_cq_hw_index = 0;
	txq->et_cq_head_idx = 0;
	txq->et_cq_phase = 0;
	txq->et_cq_head_db_addr = NULL;
	txq->et_cq_unmask_addr = NULL;
	txq->et_cq_numa_addr = NULL;
	txq->et_state &= ~ENA_TXQ_STATE_CQ_CREATED;

	VERIFY(txq->et_state & ENA_TXQ_STATE_HOST_ALLOC);
	ena_free_tx_dma(txq);
	txq->et_state &= ~ENA_TXQ_STATE_HOST_ALLOC;
	VERIFY3S(txq->et_state, ==, ENA_TXQ_STATE_NONE);
}

int
ena_ring_tx_start(mac_ring_driver_t rh, uint64_t gen_num)
{
	ena_txq_t *txq = (ena_txq_t *)rh;
	ena_t *ena = txq->et_ena;
	uint16_t cq_hw_index, sq_hw_index;
	uint32_t *cq_unmask_addr, *cq_headdb, *cq_numanode;
	uint32_t *sq_db_addr;
	uint32_t intr_ctrl;
	int ret;

	ena_xxx(ena, "ena_ring_tx_start");
	if ((ret = ena_alloc_tx_dma(txq)) != 0)
		return (ret);

	VERIFY(txq->et_state & ENA_TXQ_STATE_HOST_ALLOC);
	ret = ena_create_cq(ena, txq->et_cq_num_descs,
	    txq->et_cq_dma.edb_cookie->dmac_laddress, B_TRUE,
	    txq->et_intr_vector, &cq_hw_index, &cq_unmask_addr, &cq_headdb,
	    &cq_numanode);

	if (ret != 0) {
		ena_err(ena, "failed to create Tx CQ: %d", ret);
		return (ret);
	}

	txq->et_cq_hw_index = cq_hw_index;
	txq->et_cq_phase = 1;
	txq->et_cq_unmask_addr = cq_unmask_addr;
	txq->et_cq_head_db_addr = cq_headdb;
	txq->et_cq_numa_addr = cq_numanode;
	txq->et_state |= ENA_TXQ_STATE_CQ_CREATED;

	/* TODO assert unmask_addr is within reg base + len range */

	/*
	 * For the moment let's assume SQ/CQ are the same legnth.
	 */
	ASSERT3U(txq->et_sq_num_descs, ==, txq->et_cq_num_descs);
	ret = ena_create_sq(ena, txq->et_sq_num_descs,
	    txq->et_sq_dma.edb_cookie->dmac_laddress, B_TRUE, cq_hw_index,
	    &sq_hw_index, &sq_db_addr);
	VERIFY0(ret);

	VERIFY3P(sq_db_addr, !=, NULL);
	txq->et_sq_hw_index = sq_hw_index;
	txq->et_sq_db_addr = sq_db_addr;
	/* The phase must always start on 1. */
	txq->et_sq_phase = 1;
	txq->et_sq_avail_descs = txq->et_sq_num_descs;
	txq->et_state |= ENA_TXQ_STATE_SQ_CREATED;

	mutex_enter(&txq->et_lock);
	txq->et_m_gen_num = gen_num;
	mutex_exit(&txq->et_lock);

	intr_ctrl = ena_hw_abs_read32(ena, txq->et_cq_unmask_addr);
	ENAHW_REG_INTR_UNMASK(intr_ctrl);
	ena_hw_abs_write32(ena, txq->et_cq_unmask_addr, intr_ctrl);

	ena_xxx(ena, "Tx intr mask: 0x%x",
	    ena_hw_abs_read32(ena, txq->et_cq_unmask_addr));

	txq->et_state |= ENA_TXQ_STATE_READY;
	txq->et_state |= ENA_TXQ_STATE_RUNNING;

	return (0);
}

static void
ena_tx_copy_fragment(ena_tx_control_block_t *tcb, const mblk_t *mp,
    const size_t off, const size_t len)
{
	const void *soff = mp->b_rptr + off;
	void *doff =
	    (void *)(tcb->etcb_dma.edb_va + tcb->etcb_dma.edb_used_len);

	ASSERT3U(len, >, 0);
	ASSERT3P(soff, >=, mp->b_rptr);
	ASSERT3P(soff, <=, mp->b_wptr);
	ASSERT3U(len, <=, MBLKL(mp));
	ASSERT3U((uintptr_t)soff + len, <=, (uintptr_t)mp->b_wptr);
	ASSERT3U(tcb->etcb_dma.edb_used_len + len, <, tcb->etcb_dma.edb_len);

	bcopy(soff, doff, len);
	tcb->etcb_type = ENA_TCB_COPY;
	tcb->etcb_dma.edb_used_len += len;
	/*
	 * TODO i40e has a sync here but I'm thinking do that once
	 * after all calls to this function.
	 */
}

ena_tx_control_block_t *
ena_pull_tcb(const ena_txq_t *txq, mblk_t *mp)
{
	mblk_t *nmp = mp;
	ena_t *ena = txq->et_ena;
	ena_tx_control_block_t *tcb = NULL;
	const uint16_t tail_mod =
	    txq->et_sq_tail_idx & (txq->et_sq_num_descs - 1);

	ASSERT3U(msgsize(mp), <, ena->ena_tx_buf_sz);

	while (nmp != NULL) {
		const size_t nmp_len = MBLKL(nmp);

		if (nmp_len == 0) {
			nmp = nmp->b_cont;
			continue;
		}

		/* TODO for now TCB is bound to SQ desc */
		if (tcb == NULL)
			tcb = &txq->et_tcbs[tail_mod];

		ena_tx_copy_fragment(tcb, nmp, 0, nmp_len);
		nmp = nmp->b_cont;
	}

	ASSERT3P(nmp, ==, NULL);
	ASSERT3P(tcb, !=, NULL);
	return (tcb);
}


/* TODO inline function?
 *
 * TODO write an mdb dcmd to iterate/print all Tx descs on a queue,
 * this information proved very useful in i40e.
 */
static void
ena_fill_tx_data_desc(ena_txq_t *txq, ena_tx_control_block_t *tcb,
    uint16_t tail, uint8_t phase, enahw_tx_data_desc_t *desc,
    mac_ether_offload_info_t *meo, size_t mlen)
{
	/* enahw_tx_data_desc_t *ddesc = &desc->etd_data; */
	size_t hdr_len = meo->meoi_l2hlen + meo->meoi_l3hlen + meo->meoi_l4hlen;

	ena_xxx(txq->et_ena, "ena_fill_tx_data_desc l2: %u l3: %u l4: %u "
	    "hdr_len: %u", meo->meoi_l2hlen, meo->meoi_l3hlen, meo->meoi_l4hlen,
	    hdr_len);
	ASSERT3U(mlen, <=, ENAHW_TX_DESC_LENGTH_MASK);
	ASSERT3U(hdr_len, <=, txq->et_ena->ena_tx_max_hdr_len);

	bzero(desc, sizeof (*desc));
	ENAHW_TX_DESC_FIRST_ON(desc);
	ENAHW_TX_DESC_LENGTH(desc, mlen);
	ENAHW_TX_DESC_REQID_HI(desc, tail);
	ENAHW_TX_DESC_REQID_LO(desc, tail);
	ENAHW_TX_DESC_PHASE(desc, phase);
	ENAHW_TX_DESC_DF_ON(desc);
	ENAHW_TX_DESC_LAST_ON(desc);
	ENAHW_TX_DESC_COMP_REQ_ON(desc);
	ENAHW_TX_DESC_META_DESC_OFF(desc);
	ENAHW_TX_DESC_ADDR_LO(desc, tcb->etcb_dma.edb_cookie->dmac_laddress);
	ENAHW_TX_DESC_ADDR_HI(desc, tcb->etcb_dma.edb_cookie->dmac_laddress);
	/*
	 * According to the comments in Linux and FreeBSD, the header
	 * length can be set to zero and the device will figure it
	 * out. Do this for now to see if I can get packets moving.
	 *
	 * XXX This has worked thus far. But according to the comments
	 * for enahw_tx_data_desc_t this should be set to the header
	 * length when there is non-header data, and should be 0 when
	 * it is header-only data.
	 */
	ENAHW_TX_DESC_HEADER_LENGTH(desc, 0);
	ENAHW_TX_DESC_TSO_OFF(desc);
	ENAHW_TX_DESC_L3_CSUM_OFF(desc);
	ENAHW_TX_DESC_L4_CSUM_OFF(desc);
	/*
	 * Enabling this bit tells the device NOT to calculate the
	 * pseudo header checksum.
	 *
	 * XXX If I turn this off will the packet fail to send?
	 */
	ENAHW_TX_DESC_L4_CSUM_PARTIAL_ON(desc);
	/* TODO if packets don't send try making sure FCS disable is false. */
}

/* TODO this and ena_fill_tx_desc() should be merged. */
static void
ena_submit_tx(ena_txq_t *txq, uint16_t desc_index)
{
	ena_hw_abs_write32(txq->et_ena, txq->et_sq_db_addr, desc_index);
}

/*
 * RPZ if you look at i40e you'll notice it has enter/exit functions
 * around Tx, presumably to know if there are outstanding Tx requests.
 * However, mac already does this on behalf of drivers with
 * MAC_TX_TRY_HOLD.
 *
 * For now let's do the simplest thing possible. All Tx will use bcopy
 * to pre-allocated buffers, no checksum, no TSO, msgpullup if needed,
 * etc.
 */
mblk_t *
ena_ring_tx(void *arg, mblk_t *mp)
{
	ena_txq_t *txq = arg;
	ena_t *ena = txq->et_ena;
	mac_ether_offload_info_t meo;
	size_t mlen;
	enahw_tx_data_desc_t *desc;
	ena_tx_control_block_t *tcb;
	const uint16_t tail_mod =
	    txq->et_sq_tail_idx & (txq->et_sq_num_descs - 1);

	ena_xxx(ena, "ena_ring_tx 0x%x", ena->ena_state);
	ASSERT3P(mp->b_next, ==, NULL);
	mutex_enter(&txq->et_lock);
	/*
	 * TODO check ena_state here (fed by AENQ)
	 *
	 * TODO need to use atomic ops for ena_state so we can avoid mutex
	 */
	if (!(ena->ena_state & ENA_STATE_RUNNING) ||
	    !(txq->et_state & ENA_TXQ_STATE_RUNNING)) {
		freemsg(mp);
		return (NULL);
	}
	mutex_exit(&txq->et_lock);

	if (mac_ether_offload_info(mp, &meo) != 0) {
		ena_xxx(ena, "ena_ring_tx mac_ether_offload fail");
		freemsg(mp);
		mutex_enter(&txq->et_stats_lock);
		txq->et_stats.etxs_hck_meoifail.value.ui64++;
		mutex_exit(&txq->et_stats_lock);
		return (NULL);
	}

	mutex_enter(&txq->et_lock);
	/*
	 * For the moment there is a 1:1 mapping between Tx descs and
	 * Tx contexts. This is so because we are only copying and
	 * each context buffer is guaranteed to be as big as MTU.
	 */
	if (txq->et_sq_avail_descs == 0) {
		ena_xxx(ena, "ena_ring_tx no descs avail");
		/* TODO implement Tx blocking/flow control */
		txq->et_state = ENA_TXQ_STATE_BLOCKED;
		mutex_enter(&txq->et_stats_lock);
		txq->et_stats.etxs_blocked.value.ui64++;
		mutex_exit(&txq->et_stats_lock);
		mutex_exit(&txq->et_lock);
		return (mp);
	}

	mlen = msgsize(mp);
	ASSERT3U(mlen, <=, ena->ena_max_frame_total);
	/* TODO seems like a lock should be held? */
	tcb = ena_pull_tcb(txq, mp);
	ASSERT3P(tcb, !=, NULL);
	tcb->etcb_mp = mp;
	txq->et_sq_avail_descs--;

	/* Now fill in the device's Tx descriptor. */
	desc = &(txq->et_sq_descs[tail_mod].etd_data);
	ena_fill_tx_data_desc(txq, tcb, tail_mod, txq->et_sq_phase, desc, &meo,
	    mlen);

	ena_xxx(ena, "Tx desc len_ctrl: 0x%x", desc->etd_len_ctrl);
	ena_xxx(ena, "Tx desc meta_ctrl: 0x%x", desc->etd_meta_ctrl);
	ena_xxx(ena, "Tx phys addr: 0x%p",
	    (void *)tcb->etcb_dma.edb_cookie->dmac_laddress);
	ena_xxx(ena, "Tx desc buff_addr_hi_hdr_sz: 0x%x",
	    desc->etd_buff_addr_hi_hdr_sz);
	ena_xxx(ena, "Tx desc buf_addr_lo: 0x%x", desc->etd_buff_addr_lo);

	/*
	 * Remember, we write the raw tail value, the hardware will
	 * perform its own modulo like we did to get tail_mod.
	 */
	txq->et_sq_tail_idx++;
	/*
	 * TODO I'm not sure this membar is needed but I want to make
	 * sure that the tail update is done before the write to the
	 * doorbell.
	 */
	membar_producer();
	ena_submit_tx(txq, txq->et_sq_tail_idx);

	ena_xxx(ena, "sent Tx idx: %u phase: %d size: %u", tail_mod,
	    txq->et_sq_phase, mlen);
	mutex_enter(&txq->et_stats_lock);
	txq->et_stats.etxs_packets.value.ui64++;
	txq->et_stats.etxs_bytes.value.ui64 += mlen;
	mutex_exit(&txq->et_stats_lock);

	if ((txq->et_sq_tail_idx & (txq->et_sq_num_descs - 1)) == 0)
		txq->et_sq_phase = !txq->et_sq_phase;

	mutex_exit(&txq->et_lock);
	return (NULL);
}

void
ena_tx_intr_work(ena_txq_t *txq)
{
	uint16_t head_mod;
	enahw_tx_cdesc_t *cdesc;
	ena_tx_control_block_t *tcb;
	uint16_t req_id;

	mutex_enter(&txq->et_lock);
	head_mod = txq->et_cq_head_idx & (txq->et_cq_num_descs - 1);
	ENA_DMA_SYNC(txq->et_cq_dma, DDI_DMA_SYNC_FORKERNEL);
	cdesc = &txq->et_cq_descs[head_mod];

	/* No descriptors to read. */
	/* TODO use phase mask macro */
	while ((cdesc->etc_flags & 0x1) == txq->et_cq_phase) {
		mblk_t *mp;

		/* TODO Linux would use a read barrier here, I think
		 * our DMA sync is enough. */
		req_id = cdesc->etc_req_id;

		/* TODO invalid req id, this should reset device */
		VERIFY3U(req_id, <=, txq->et_sq_num_descs);

		tcb = &txq->et_tcbs[req_id];
		tcb->etcb_dma.edb_used_len = 0;
		mp = tcb->etcb_mp;
		/*
		 * TODO if mp is NULL something has gone seriously
		 * wrong, reset device
		 */
		ASSERT3P(mp, !=, NULL);
		if (mp == NULL)
			panic("invalid req_id, this should reset device");

		freemsg(mp);
		tcb->etcb_mp = NULL;
		txq->et_sq_avail_descs++;
		txq->et_cq_head_idx++;
		ena_xxx(txq->et_ena, "completed Tx idx: %u, phase: %d", req_id,
		    txq->et_cq_phase);
		head_mod = txq->et_cq_head_idx & (txq->et_cq_num_descs - 1);

		if (head_mod == 0)
			txq->et_cq_phase = !txq->et_cq_phase;

		mutex_enter(&txq->et_stats_lock);
		txq->et_stats.etxs_recycled_descs.value.ui64++;
		mutex_exit(&txq->et_stats_lock);
		cdesc = &txq->et_cq_descs[head_mod];
	}

	mutex_exit(&txq->et_lock);
}
