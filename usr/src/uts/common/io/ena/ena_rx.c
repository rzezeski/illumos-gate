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

static void
ena_refill_rx(ena_rxq_t *rxq, uint16_t num)
{
	VERIFY3P(rxq, !=, NULL);
	uint16_t tail_mod = rxq->er_sq_tail_idx & (rxq->er_sq_num_descs - 1);
	/* ena_t *ena = rxq->er_ena; */

	/*
	 * TODO I wonder if we could be most of refill behind a
	 * different mutex than er_lock?
	 */
	ASSERT(MUTEX_HELD(&rxq->er_lock));
	ena_xxx(rxq->er_ena, "ena_refill_rx: %u", num);

	/* ASSERT3U(first & (rxq->er_sq_num_descs - 1), !=, 0); */
	ASSERT3U(num, <=, rxq->er_sq_num_descs);

	while (num != 0) {
		enahw_rx_desc_t *desc = &rxq->er_sq_descs[tail_mod];
		ena_rx_ctrl_block_t *rcb = &rxq->er_rcbs[tail_mod];

		VERIFY3U(tail_mod, <, rxq->er_sq_num_descs);
		VERIFY3P(desc, !=, NULL);
		VERIFY3P(rcb, !=, NULL);
		VERIFY3P(desc, >=, rxq->er_sq_descs);
		VERIFY3P(desc, <=,
		    (rxq->er_sq_descs + rxq->er_sq_num_descs - 1));

		/*
		 * TODO the only thing that really changes in the desc
		 * after the first initialization is the phase, I
		 * could potentially save some work.
		 */
		desc->erd_length = rcb->ercb_dma.edb_len;
		desc->erd_req_id = tail_mod;
		VERIFY3P(rcb->ercb_dma.edb_cookie, !=, NULL);
		ena_set_dma_addr_values(rxq->er_ena,
		    rcb->ercb_dma.edb_cookie->dmac_laddress,
		    &desc->erd_buff_addr_lo, &desc->erd_buff_addr_hi);
		ENAHW_RX_DESC_PHASE(desc, rxq->er_sq_phase);
		ENAHW_RX_DESC_FIRST(desc);
		ENAHW_RX_DESC_LAST(desc);
		ENAHW_RX_DESC_COMP_REQ(desc);
		/* TODO replace with refill dtrace probe */
		ena_xxx(rxq->er_ena, "refilled descriptor %u phase %u",
		    tail_mod, rxq->er_sq_phase);
		ena_xxx(rxq->er_ena, "length: 0x%x reserved1: 0x%x ctrl: 0x%x "
		    "req_id: 0x%x reserved2: 0x%x buff_addr_lo: 0x%x "
		    "buff_addr_hi: 0x%x reserved3: 0x%x", desc->erd_length,
		    desc->erd_reserved1, desc->erd_ctrl, desc->erd_req_id,
		    desc->erd_reserved2, desc->erd_buff_addr_lo,
		    desc->erd_buff_addr_hi, desc->erd_reserved3);
		rxq->er_sq_tail_idx++;
		tail_mod = rxq->er_sq_tail_idx & (rxq->er_sq_num_descs - 1);

		if (tail_mod == 0)
			rxq->er_sq_phase = !rxq->er_sq_phase;

		num--;
	}

	VERIFY3P(rxq->er_sq_db_addr, !=, NULL);
	/*
	 * TODO I'm not sure this membar is needed but I want to make
	 * sure that the tail updates are done before the write to the
	 * doorbell.
	 */
	membar_producer();
	ena_hw_abs_write32(rxq->er_ena, rxq->er_sq_db_addr,
	    rxq->er_sq_tail_idx);
}

void
ena_free_rx_dma(ena_rxq_t *rxq)
{
	VERIFY(rxq->er_state & ENA_RXQ_STATE_HOST_ALLOC);

	if (rxq->er_rcbs != NULL) {
		for (uint_t i = 0; i < rxq->er_sq_num_descs; i++) {
			ena_rx_ctrl_block_t *rcb = &rxq->er_rcbs[i];
			ena_dma_free(&rcb->ercb_dma);
		}

		kmem_free(rxq->er_rcbs,
		    sizeof (*rxq->er_rcbs) * rxq->er_sq_num_descs);

		rxq->er_rcbs = NULL;
	}

	ena_dma_free(&rxq->er_cq_dma);
	rxq->er_cq_descs = NULL;
	rxq->er_cq_num_descs = 0;

	ena_dma_free(&rxq->er_sq_dma);
	rxq->er_sq_descs = NULL;
	rxq->er_sq_num_descs = 0;

	rxq->er_state &= ~ENA_RXQ_STATE_HOST_ALLOC;
}

static int
ena_alloc_rx_dma(ena_rxq_t *rxq)
{
	ena_t *ena = rxq->er_ena;
	size_t pagesz = ena->ena_page_sz;
	size_t cq_descs_sz;
	size_t sq_descs_sz;
	ddi_dma_attr_t attr;
	ddi_device_acc_attr_t acc;
	int err = 0;

	cq_descs_sz = rxq->er_cq_num_descs * sizeof (*rxq->er_cq_descs);
	sq_descs_sz = rxq->er_sq_num_descs * sizeof (*rxq->er_sq_descs);

	/* TODO add bzero DMA alloc */
	ena_dma_adminq_attr(ena, &attr, sq_descs_sz);
	ena_dma_acc_attr(ena, &acc);
	if (!ena_dma_alloc(ena, &rxq->er_sq_dma, &attr, &acc, sq_descs_sz,
	    B_FALSE))
		return (ENOMEM);

	ena_xxx(ena, "Rx SQ descs phys: 0x%p virt: 0x%p size: %u",
	    rxq->er_sq_dma.edb_cookie->dmac_laddress, rxq->er_sq_dma.edb_va,
		sq_descs_sz);

	rxq->er_sq_descs = (void *)rxq->er_sq_dma.edb_va;
	bzero(rxq->er_sq_descs, sq_descs_sz);
	ENA_DMA_SYNC(rxq->er_sq_dma, DDI_DMA_SYNC_FORDEV);

	rxq->er_rcbs = kmem_zalloc(sizeof (*rxq->er_rcbs) *
	    rxq->er_sq_num_descs, KM_SLEEP);

	/*
	 * TODO since I'm coying data out I don't want to keep calling
	 * dma alloc, if RCB already has a buffer then just write the
	 * desc.
	 */
	for (uint_t i = 0; i < rxq->er_sq_num_descs; i++) {
		ena_rx_ctrl_block_t *rcb = &rxq->er_rcbs[i];

		/* TODO ena_mtu (see i40e_tx_buf_size)  */
		/* VERIFY0(ctrl); */
		/* ctrl = kmem_zalloc(sizeof (*txq->et_tx_ctrls), KM_SLEEP); */
		ena_dma_io_attr(ena, &attr, ena->ena_rx_buf_sz);
		ena_dma_io_acc_attr(ena, &acc);
		if (!ena_dma_alloc(ena, &rcb->ercb_dma, &attr, &acc,
		    ena->ena_rx_buf_sz, B_TRUE)) {
			err = ENOMEM;
			goto error;
		}

		ena_xxx(ena, "Rx buf phys: 0x%p virt: 0x%p",
		    rcb->ercb_dma.edb_cookie->dmac_laddress,
		    rcb->ercb_dma.edb_va);

		if ((rcb->ercb_dma.edb_cookie->dmac_laddress % pagesz) != 0)
			ena_xxx(ena, "Rx buf phys is not on page boundary");

		if (((uintptr_t)(rcb->ercb_dma.edb_va) % pagesz) != 0)
			ena_xxx(ena, "Rx buf virt is not on page boundary");

		if (rcb->ercb_dma.edb_real_len != ena->ena_rx_buf_sz)
			ena_xxx(ena, "Rx buf real len is not ena_rx_buf_sz: "
			    " %u != %u",
			    ena->ena_rx_buf_sz, rcb->ercb_dma.edb_real_len);
	}

	ena_dma_adminq_attr(ena, &attr, cq_descs_sz);
	ena_dma_acc_attr(ena, &acc);
	if (!ena_dma_alloc(ena, &rxq->er_cq_dma, &attr, &acc, cq_descs_sz,
	    B_FALSE))
		return (ENOMEM);

	ena_xxx(ena, "Rx CQ descs phys: 0x%p virt: 0x%p size: %u",
	    rxq->er_cq_dma.edb_cookie->dmac_laddress, rxq->er_cq_dma.edb_va,
		cq_descs_sz);

	rxq->er_cq_descs = (void *)rxq->er_cq_dma.edb_va;
	bzero(rxq->er_cq_descs, cq_descs_sz);
	ENA_DMA_SYNC(rxq->er_cq_dma, DDI_DMA_SYNC_FORDEV);
	rxq->er_state |= ENA_RXQ_STATE_HOST_ALLOC;
	return (0);

error:
	ena_free_rx_dma(rxq);
	return (err);
}

void
ena_ring_rx_stop(mac_ring_driver_t rh)
{
	ena_rxq_t *rxq = (ena_rxq_t *)rh;

	ena_xxx(rxq->er_ena, "ena_ring_rx_stop");
	rxq->er_state &= ~ENA_RXQ_STATE_RUNNING;
	rxq->er_state &= ~ENA_RXQ_STATE_READY;

	VERIFY(rxq->er_state & ENA_RXQ_STATE_SQ_CREATED);
	VERIFY0(ena_destroy_sq(rxq->er_ena, rxq->er_sq_hw_index, B_FALSE));
	rxq->er_sq_hw_index = 0;
	rxq->er_sq_db_addr = NULL;
	rxq->er_sq_tail_idx = 0;
	rxq->er_sq_phase = 0;
	rxq->er_state &= ~ENA_RXQ_STATE_SQ_CREATED;

	VERIFY(rxq->er_state & ENA_RXQ_STATE_CQ_CREATED);
	VERIFY0(ena_destroy_cq(rxq->er_ena, rxq->er_cq_hw_index));
	rxq->er_cq_hw_index = 0;
	rxq->er_cq_head_idx = 0;
	rxq->er_cq_phase = 0;
	rxq->er_cq_head_db_addr = NULL;
	rxq->er_cq_unmask_addr = NULL;
	rxq->er_cq_numa_addr = NULL;
	rxq->er_state &= ~ENA_RXQ_STATE_CQ_CREATED;

	VERIFY(rxq->er_state & ENA_RXQ_STATE_HOST_ALLOC);
	ena_free_rx_dma(rxq);
	rxq->er_state &= ~ENA_RXQ_STATE_HOST_ALLOC;

	VERIFY3S(rxq->er_state, ==, ENA_RXQ_STATE_NONE);
}

int
ena_ring_rx_start(mac_ring_driver_t rh, uint64_t gen_num)
{
	ena_rxq_t *rxq = (ena_rxq_t *)rh;
	ena_t *ena = rxq->er_ena;
	uint16_t cq_hw_index, sq_hw_index;
	uint32_t *cq_unmask_addr, *cq_headdb, *cq_numanode;
	uint32_t *sq_db_addr;
	uint32_t intr_ctrl;
	int ret;

	ena_xxx(rxq->er_ena, "ena_ring_rx_start");
	if ((ret = ena_alloc_rx_dma(rxq)) != 0)
		return (ret);

	VERIFY(rxq->er_state & ENA_RXQ_STATE_HOST_ALLOC);
	ret = ena_create_cq(ena,  rxq->er_cq_num_descs,
	    rxq->er_cq_dma.edb_cookie->dmac_laddress, B_FALSE,
	    rxq->er_intr_vector, &cq_hw_index, &cq_unmask_addr, &cq_headdb,
	    &cq_numanode);

	if (ret != 0) {
		ena_err(ena, "failed to create Rx CQ: %d", ret);
		return (ret);
	}

	rxq->er_cq_phase = 1;
	rxq->er_cq_hw_index = cq_hw_index;
	rxq->er_cq_unmask_addr = cq_unmask_addr;
	rxq->er_cq_head_db_addr = cq_headdb;
	rxq->er_cq_numa_addr = cq_numanode;
	rxq->er_state |= ENA_RXQ_STATE_CQ_CREATED;

	ASSERT3U(rxq->er_sq_num_descs, ==, rxq->er_cq_num_descs);
	ret = ena_create_sq(ena, rxq->er_sq_num_descs,
	    rxq->er_sq_dma.edb_cookie->dmac_laddress, B_FALSE, cq_hw_index,
	    &sq_hw_index, &sq_db_addr);
	VERIFY0(ret);

	VERIFY3P(sq_db_addr, !=, NULL);
	rxq->er_sq_hw_index = sq_hw_index;
	rxq->er_sq_db_addr = sq_db_addr;
	/*
	 * TODO If rings can start/stop separate from a device reset,
	 * then this is probably the wrong place to set phase. As I
	 * imagine we would want it to persist if the driver state
	 * hasn't changed. However, I'm not sure if the phase value is
	 * actually checked by the hardware during submission or it's
	 * just a pass-thru value from SQ to CQ to allow the driver to
	 * determine which CQ descs are valid.
	 */
	/* The phase must always start at 1. */
	rxq->er_sq_phase = 1;
	rxq->er_sq_avail_descs = rxq->er_sq_num_descs; /* TODO not used */
	rxq->er_mode = ENA_RXQ_MODE_INTR;
	rxq->er_state |= ENA_RXQ_STATE_SQ_CREATED;

	mutex_enter(&rxq->er_lock);
	ena_refill_rx(rxq, rxq->er_sq_num_descs);
	rxq->er_m_gen_num = gen_num;
	mutex_exit(&rxq->er_lock);

	intr_ctrl = ena_hw_abs_read32(ena, rxq->er_cq_unmask_addr);
	ENAHW_REG_INTR_UNMASK(intr_ctrl);
	ena_hw_abs_write32(ena, rxq->er_cq_unmask_addr, intr_ctrl);

	ena_xxx(ena, "Rx intr mask: 0x%x",
	    ena_hw_abs_read32(ena, rxq->er_cq_unmask_addr));

	rxq->er_state |= ENA_TXQ_STATE_READY;
	rxq->er_state |= ENA_TXQ_STATE_RUNNING;
	return (0);
}

/*
 * TODO for the moment we are allowing interrupt to run wild and
 * always flush the entire backlog.
 *
 * TODO return to my old mac polling fix.
 */
mblk_t *
ena_ring_rx(ena_rxq_t *rxq, int poll_bytes)
{
	ena_t *ena = rxq->er_ena;
	uint16_t head_mod = rxq->er_cq_head_idx & (rxq->er_cq_num_descs - 1);
	uint64_t total_bytes = 0;
	enahw_rx_cdesc_t *cdesc;
	uint16_t completed = 0;
	boolean_t polling = B_TRUE;
	mblk_t *head = NULL;
	mblk_t *tail = NULL;

	ASSERT(MUTEX_HELD(&rxq->er_lock));
	ENA_DMA_SYNC(rxq->er_cq_dma, DDI_DMA_SYNC_FORKERNEL);

	if (poll_bytes == ENA_POLL_NULL)
		polling = B_FALSE;

	cdesc = &rxq->er_cq_descs[head_mod];
	VERIFY3P(cdesc, >=, rxq->er_cq_descs);
	VERIFY3P(cdesc, <=, (rxq->er_cq_descs + rxq->er_cq_num_descs - 1));

	while (ENAHW_RX_CDESC_PHASE(cdesc) == rxq->er_cq_phase) {
		boolean_t first, last;
		ena_rx_ctrl_block_t *rcb;
		uint16_t req_id;
		mblk_t *mp;
		enahw_io_l3_proto_t l3proto;
		enahw_io_l4_proto_t l4proto;
		boolean_t l4csum_checked;
		uint32_t hflags = 0;

		VERIFY3U(head_mod, <, rxq->er_cq_num_descs);
		/*
		 * TODO At this point we are keeping MTU at 1500 and
		 * thus every incoming frame should be in a single Rx
		 * desc. But eventually we'll want to read descriptors
		 * until we hit last, linking mblks together via b_cont.
		 */
		first = ENAHW_RX_CDESC_FIRST(cdesc);
		VERIFY(first);
		last = ENAHW_RX_CDESC_LAST(cdesc);
		VERIFY(last);
		req_id = cdesc->erc_req_id;
		VERIFY3U(req_id, <, rxq->er_cq_num_descs);
		rcb = &rxq->er_rcbs[req_id];
		/* TODO might need to use offset to adjust rprt? */
		rcb->ercb_offset = cdesc->erc_offset;
		rcb->ercb_length = cdesc->erc_length;
		if (cdesc->erc_offset != 0) {
			ena_dbg(ena, "non-zxero offset: offset: %u "
			    "length: %u", rcb->ercb_offset, rcb->ercb_length);
		}

		ASSERT3U(rcb->ercb_length, <=, ena->ena_max_frame_total);
		mp = allocb(rcb->ercb_length + ENA_RX_BUF_IPHDR_ALIGNMENT, 0);

		if (head == NULL)
			head = mp;
		else
			tail->b_next = mp;

		tail = mp;
		VERIFY3P(mp->b_rptr, ==, mp->b_wptr);
		/*
		 * TODO when we start allowing desballoc we will need
		 * to make sure the DMA buffs offset their address so
		 * the device writes to the correct offset. But for
		 * right now everything is copy.
		 */
		mp->b_wptr += ENA_RX_BUF_IPHDR_ALIGNMENT;
		mp->b_rptr += ENA_RX_BUF_IPHDR_ALIGNMENT;
		bcopy(rcb->ercb_dma.edb_va + rcb->ercb_offset, mp->b_wptr,
		    rcb->ercb_length);
		mp->b_wptr += rcb->ercb_length;
		total_bytes += rcb->ercb_length;
		VERIFY3P(mp->b_wptr, >, mp->b_rptr);
		VERIFY3P(mp->b_wptr, <=, mp->b_datap->db_lim);
		mutex_enter(&rxq->er_stats_lock);
		rxq->er_stats.erxs_packets.value.ui64++;
		mutex_exit(&rxq->er_stats_lock);

		/* TODO flag to turn off Rx HW checksum like ixgbe */
		/* TODO move to function */
		l3proto = ENAHW_RX_CDESC_L3_PROTO(cdesc);
		l4proto = ENAHW_RX_CDESC_L4_PROTO(cdesc);
		if (ena->ena_rx_l3_ipv4_csum &&
		    l3proto == ENAHW_IO_L3_PROTO_IPV4) {
			boolean_t l3_csum_err =
			    ENAHW_RX_CDESC_L3_CSUM_ERR(cdesc);
			if (l3_csum_err) {
				ena_xxx(ena, "Rx L3 csum error");
				/* TODO increment kstat */
			} else {
				hflags |= HCK_IPV4_HDRCKSUM_OK;
			}
		}

		l4csum_checked = ENAHW_RX_CDESC_L4_CSUM_CHECKED(cdesc);
		if (ena->ena_rx_l4_ipv4_full_csum && l4csum_checked &&
		    l4proto == ENAHW_IO_L4_PROTO_TCP) {
			hflags |= HCK_FULLCKSUM_OK;
		}

		if (hflags != 0)
			mac_hcksum_set(mp, 0, 0, 0, 0, hflags);

		completed++;
		rxq->er_cq_head_idx++;
		head_mod = rxq->er_cq_head_idx & (rxq->er_cq_num_descs - 1);

		if (head_mod == 0)
			rxq->er_cq_phase = !rxq->er_cq_phase;

		if (polling) {
			mutex_enter(&rxq->er_stats_lock);
			rxq->er_stats.erxs_poll_packets.value.ui64++;
			mutex_exit(&rxq->er_stats_lock);

			if (total_bytes > poll_bytes)
				break;
		} else {
			mutex_enter(&rxq->er_stats_lock);
			rxq->er_stats.erxs_intr_packets.value.ui64++;
			mutex_exit(&rxq->er_stats_lock);
		}

		cdesc = &rxq->er_cq_descs[head_mod];
		VERIFY3P(cdesc, >=, rxq->er_cq_descs);
		VERIFY3P(cdesc, <=,
		    (rxq->er_cq_descs + rxq->er_cq_num_descs - 1));
	}

	mutex_enter(&rxq->er_stats_lock);
	rxq->er_stats.erxs_bytes.value.ui64 += total_bytes;

	/*
	 * TODO I think the polling/intr stats are already kept by
	 * mac, maybe delete these.
	 */
	if (polling)
		rxq->er_stats.erxs_poll_bytes.value.ui64 += total_bytes;
	else
		rxq->er_stats.erxs_intr_bytes.value.ui64 += total_bytes;
	mutex_exit(&rxq->er_stats_lock);

	ena_xxx(ena, "Rx %s completed: %u total_bytes: %u",
	    polling ? "poll" : "intr", completed, total_bytes);
	/* TODO probably want to spawn this as a task */
	ena_refill_rx(rxq, completed);

	return (head);
}

/* TODO see Linux ena_clean_rx_irq() */
void
ena_rx_intr_work(ena_rxq_t *rxq)
{
	mblk_t *mp;

	mutex_enter(&rxq->er_lock);
	mp = ena_ring_rx(rxq, ENA_POLL_NULL);
	mutex_exit(&rxq->er_lock);

	if (mp == NULL)
		return;

	mac_rx_ring(rxq->er_ena->ena_mh, rxq->er_mrh, mp, rxq->er_m_gen_num);
}

mblk_t *
ena_ring_rx_poll(void *rh, int poll_bytes)
{
	ena_rxq_t *rxq = rh;
	mblk_t *mp;

	ASSERT3S(poll_bytes, >, 0);

	mutex_enter(&rxq->er_lock);
	mp = ena_ring_rx(rxq, poll_bytes);
	mutex_exit(&rxq->er_lock);

	return (mp);
}
