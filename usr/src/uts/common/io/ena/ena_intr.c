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
 * We currently limit the number of Tx/Rx queues to the number of
 * available interrupts (minus one for the admin queue).
 */
static uint_t
ena_io_intr(caddr_t arg1, caddr_t arg2)
{
	ena_t *ena = (ena_t *)arg1;
	uint16_t vector = (uintptr_t)(void *)arg2; /* TODO 32-bit? */
	ena_txq_t *txq = &ena->ena_txqs[vector - 1];
	ena_rxq_t *rxq = &ena->ena_rxqs[vector - 1];
	uint32_t intr_ctrl;

	ASSERT3U(vector, >, 0);
	ASSERT3U(vector, <=, ena->ena_num_intrs);
	ASSERT3P(txq, !=, NULL);
	ASSERT3P(rxq, !=, NULL);
	ena_tx_intr_work(txq);
	ena_rx_intr_work(rxq);

	/*
	 * The Rx/Tx queue share the same interrupt, only need to
	 * unmask interrupts on one of them.
	 */
	intr_ctrl = ena_hw_abs_read32(ena, txq->et_cq_unmask_addr);
	ENAHW_REG_INTR_UNMASK(intr_ctrl);
	ena_hw_abs_write32(ena, txq->et_cq_unmask_addr, intr_ctrl);

	return (DDI_INTR_CLAIMED);
}

/*
 * TODO used for both admin and AENQ
 *
 * AENQ: see ena_com_aenq_intr_handler()
 */
static uint_t
ena_admin_intr(caddr_t arg1, caddr_t arg2)
{
	ena_t *ena = (ena_t *)arg1;
	uint16_t vector = (uintptr_t)(void *)arg2;

	ena_xxx(ena, "XXX implement admin intr on vec: %u", vector);

	/* TODO Linux guards this behind ENA_FLAG_DEVICE_RUNNING */
	ena_aenq_work(ena);

	return (DDI_INTR_CLAIMED);
}

void
ena_intr_remove_handles(ena_t *ena)
{
	for (uint_t i = 0; i < ena->ena_num_intrs; i++) {
		int ret = ddi_intr_remove_handler(ena->ena_intr_handles[i]);

		/* Nothing we can really do except log. */
		if (ret != DDI_SUCCESS) {
			ena_err(ena, "failed to remove interrupt handler for "
			    "vector %d: %d", i, ret);
		}
	}
}

boolean_t
ena_intr_add_handles(ena_t *ena)
{
	/* TODO use separate vector space for admin and I/O. Set first
	 * handler to ena_admin_intr and assign it vector 0. Then
	 * assign all additional interrupt slots to ena_io_intr, and
	 * start their vector space at 0 for ring 1, 1 for ring 2,
	 * etc. */
	ASSERT3U(ena->ena_num_intrs, >=, 2);
	if (ddi_intr_add_handler(ena->ena_intr_handles[0], ena_admin_intr, ena,
	    (void *)(uintptr_t)0) != DDI_SUCCESS) {
		ena_err(ena, "failed to add admin interrupt handler");
		return (B_FALSE);
	}


	for (uint_t i = 1; i < ena->ena_num_intrs; i++) {
		caddr_t vector = (void *)(uintptr_t)(i);
		int ret = ddi_intr_add_handler(ena->ena_intr_handles[i],
		    ena_io_intr, ena, vector);

		if (ret != DDI_SUCCESS) {
			ena_err(ena, "failed to add I/O interrupt handler "
			    "for vector %u", vector);

			while (i != 0) {
				i--;
				(void) ddi_intr_remove_handler(
					ena->ena_intr_handles[i]);
			}

			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

boolean_t
ena_intrs_disable(ena_t *ena)
{
	int ret;
	boolean_t rval = B_TRUE;

	if (ena->ena_intr_caps & DDI_INTR_FLAG_BLOCK) {
		if ((ret = ddi_intr_block_disable(ena->ena_intr_handles,
		    ena->ena_num_intrs)) != DDI_SUCCESS) {
			ena_err(ena, "failed to block disable interrupts: %d",
			    ret);
			rval = B_FALSE;
		}
	} else {
		int i;
		for (i = 0; i < ena->ena_num_intrs; i++) {
			ret = ddi_intr_disable(ena->ena_intr_handles[i]);
			if (ret != DDI_SUCCESS) {
				ena_err(ena, "failed to disable interrupt "
				    "%d: %d", i, ret);
				rval = B_FALSE;
			}
		}
	}

	return (rval);
}

boolean_t
ena_intrs_enable(ena_t *ena)
{
	int ret;

	if (ena->ena_intr_caps & DDI_INTR_FLAG_BLOCK) {
		ena_xxx(ena, "ena_intrs_enable block enable");
		if ((ret = ddi_intr_block_enable(ena->ena_intr_handles,
		    ena->ena_num_intrs)) != DDI_SUCCESS) {
			ena_err(ena, "failed to block enable interrupts: %d",
			    ret);
			return (B_FALSE);
		}
	} else {
		ena_xxx(ena, "ena_intrs_enable per-intr enable");
		for (int i = 0; i < ena->ena_num_intrs; i++) {
			if ((ret = ddi_intr_enable(ena->ena_intr_handles[i])) !=
			    DDI_SUCCESS) {
				ena_err(ena, "failed to enable interrupt "
				    "%d: %d", i, ret);
				while (--i >= 0) {
					(void) ddi_intr_disable(
					    ena->ena_intr_handles[i]);
				}
				return (B_FALSE);
			}
		}
	}

	return (B_TRUE);
}
