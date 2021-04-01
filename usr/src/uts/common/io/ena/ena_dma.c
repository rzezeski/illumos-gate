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

/*
 * Construct appropraite DMA attributes for the admin queue.
 */
void
ena_dma_adminq_attr(ena_t *ena, ddi_dma_attr_t *attrp, size_t size)
{
	/*
	 * Round up to next page. An allocation must at least be a
	 * page in size, but in this case we round all values.
	 */
	const size_t size_up =
	    P2ROUNDUP_TYPED(size, ena->ena_page_sz, size_t);

	attrp->dma_attr_version = DMA_ATTR_V0;

	/*
	 * The device tells us the window it supports in terms of
	 * number of bits, we convert that to the appropriate mask.
	 */
	ASSERT3U(ena->ena_dma_width, >=, 32);
	ASSERT3U(ena->ena_dma_width, <=, 48);
	attrp->dma_attr_addr_lo = 0x0;
	attrp->dma_attr_addr_hi = ENA_DMA_BIT_MASK(ena->ena_dma_width);

	/*
	 * This indicates the amount of data that can fit in one
	 * cookie. For now we do exactly as Linux does. Remember, this
	 * value must be _one less_ than the desired max.
	 *
	 * TODO I'm adding a page of overhead to the max segment size
	 * because of what seems to be a bug in rootnex on line 3184
	 * where we compare the size of the current cookie plus a page
	 * to the maximum segment. Either subtracting one is the
	 * problem (which was done in i40e because of the way rootnex
	 * calculated the max), of the logic in rootnex is the
	 * problem.
	 */
	attrp->dma_attr_count_max = (size_up + ena->ena_page_sz) - 1;

	/*
	 * The alignment and segment are related issues. The alignment
	 * tells us the alignment of the starting address, while the
	 * segment tells us an address alignment that the allocated
	 * memory segment cannot cross.
	 */
	attrp->dma_attr_align = ENAHW_DMA_ADMINQ_ALIGNMENT;
	attrp->dma_attr_seg = UINT64_MAX;

	/*
	 * The burst size member is supposed to be used to indicate
	 * different supproted bits of the maximum amount of data that
	 * can be sent. It's not obvious that this value is usd by the
	 * PCIe engines for determining anything anymore.
	 *
	 * TODO is size_up really the answer here?
	 */
	attrp->dma_attr_burstsizes = size_up;

	/*
	 * Minimum and maximum amount of data we can send. This isn't
	 * strictly limited by PCI in hardare, as it'll just make the
	 * appropriate number of requests. Simiarly, PCIe allows for
	 * an arbitrary granularity. We set this to one, as it's
	 * really a matter of what hardware is requesting from us.
	 */
	attrp->dma_attr_minxfer = 0x1;
	attrp->dma_attr_maxxfer = (size_up + ena->ena_page_sz);
	attrp->dma_attr_granular = 0x1;

	/*
	 * The admin queue allows for a single cookie worth of data
	 * only.
	 */
	attrp->dma_attr_sgllen = 1;

	if (DDI_FM_DMA_ERR_CAP(ena->ena_fm_caps)) {
		attrp->dma_attr_flags = DDI_DMA_FLAGERR;
	} else {
		attrp->dma_attr_flags = 0;
	}
}

/*
 * We are setting this up to allocate single pages (assuming 4K pages
 * at the moment) for the purpose of Rx I/O (Tx is using maximum frame
 * size). The reason for this is multifold: 1) FreeBSD and Linux
 * allocate Rx buffers in units of a page, 2) I think this will be
 * better for the underlying memory system as it will avoid straddling
 * page boundaries and such and works with the natural size of the
 * machine.
 */
void
ena_dma_io_attr(ena_t *ena, ddi_dma_attr_t *attrp, size_t size)
{
	VERIFY3U(size % ena->ena_page_sz, ==, 0);
	attrp->dma_attr_version = DMA_ATTR_V0;

	/*
	 * The device tells us the window it supports in terms of
	 * number of bits, we convert that to the appropriate mask.
	 */
	ASSERT3U(ena->ena_dma_width, >=, 32);
	ASSERT3U(ena->ena_dma_width, <=, 48);
	attrp->dma_attr_addr_lo = 0x0;
	attrp->dma_attr_addr_hi = ENA_DMA_BIT_MASK(ena->ena_dma_width);

	/*
	 * This indicates the amount of data that can fit in one
	 * cookie. For now we do exactly as Linux does. Remember, this
	 * value must be _one less_ than the desired max.
	 *
	 * TODO See note for adminq attr.
	 */
	attrp->dma_attr_count_max = (size + ena->ena_page_sz) - 1;

	/*
	 * The alignment and segment are related issues. The alignment
	 * tells us the alignment of the starting address, while the
	 * segment tells us an address alignment that the allocated
	 * memory segment cannot cross.
	 */
	attrp->dma_attr_align = ena->ena_page_sz;
	attrp->dma_attr_seg = UINT64_MAX;

	/*
	 * The burst size member is supposed to be used to indicate
	 * different supproted bits of the maximum amount of data that
	 * can be sent. It's not obvious that this value is usd by the
	 * PCIe engines for determining anything anymore.
	 *
	 * TODO is size really the answer here?
	 */
	attrp->dma_attr_burstsizes = size;

	/*
	 * Minimum and maximum amount of data we can send. This isn't
	 * strictly limited by PCI in hardare, as it'll just make the
	 * appropriate number of requests. Simiarly, PCIe allows for
	 * an arbitrary granularity. We set this to one, as it's
	 * really a matter of what hardware is requesting from us.
	 */
	attrp->dma_attr_minxfer = 0x1;
	attrp->dma_attr_maxxfer = (size + ena->ena_page_sz);
	attrp->dma_attr_granular = 0x1;

	/*
	 * The admin queue allows for a single cookie worth of data
	 * only.
	 */
	attrp->dma_attr_sgllen = 1;

	if (DDI_FM_DMA_ERR_CAP(ena->ena_fm_caps)) {
		attrp->dma_attr_flags = DDI_DMA_FLAGERR;
	} else {
		attrp->dma_attr_flags = 0;
	}
}

void
ena_dma_acc_attr(ena_t *ena, ddi_device_acc_attr_t *accp)
{
	accp->devacc_attr_version = DDI_DEVICE_ATTR_V1;
	accp->devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	accp->devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	if (DDI_FM_DMA_ERR_CAP(ena->ena_fm_caps)) {
		accp->devacc_attr_access = DDI_FLAGERR_ACC;
	} else {
		accp->devacc_attr_access = DDI_DEFAULT_ACC;
	}
}

void
ena_dma_io_acc_attr(ena_t *ena, ddi_device_acc_attr_t *accp)
{
	accp->devacc_attr_version = DDI_DEVICE_ATTR_V1;
	accp->devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	accp->devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	if (DDI_FM_DMA_ERR_CAP(ena->ena_fm_caps)) {
		accp->devacc_attr_access = DDI_FLAGERR_ACC;
	} else {
		accp->devacc_attr_access = DDI_DEFAULT_ACC;
	}
}


void
ena_dma_free(ena_dma_buf_t *edb)
{
	if (edb->edb_cookie != NULL) {
		(void) ddi_dma_unbind_handle(edb->edb_dma_hdl);
		edb->edb_cookie = NULL;
		edb->edb_real_len = 0;
	}

	if (edb->edb_acc_hdl != NULL) {
		ddi_dma_mem_free(&edb->edb_acc_hdl);
		edb->edb_acc_hdl = NULL;
		edb->edb_va = NULL;
	}

	if (edb->edb_dma_hdl != NULL) {
		ddi_dma_free_handle(&edb->edb_dma_hdl);
		edb->edb_dma_hdl = NULL;
	}

	edb->edb_len = 0;
}

boolean_t
ena_dma_alloc(ena_t *ena, ena_dma_buf_t *edb, ddi_dma_attr_t *attrp,
    ddi_device_acc_attr_t *accp, size_t size, boolean_t stream)
{
	int ret;
	size_t size_allocated;
	uint_t flags = stream ? DDI_DMA_STREAMING : DDI_DMA_CONSISTENT;

	/*
	 * Round up to next page. An allocation must at least be a
	 * page in size, but in this case we round all values.
	 */
	const size_t size_up = P2ROUNDUP_TYPED(size, ena->ena_page_sz, size_t);

	ret = ddi_dma_alloc_handle(ena->ena_dip, attrp, DDI_DMA_DONTWAIT, NULL,
	    &edb->edb_dma_hdl);
	if (ret != DDI_SUCCESS) {
		ena_err(ena, "!failed to allocate DMA handle: %d", ret);
		return (B_FALSE);
	}

	ret = ddi_dma_mem_alloc(edb->edb_dma_hdl, size_up, accp, flags,
	    DDI_DMA_DONTWAIT, NULL, &edb->edb_va, &size_allocated,
	    &edb->edb_acc_hdl);
	if (ret != DDI_SUCCESS) {
		ena_err(ena, "!failed to allocate %lu bytes of DMA "
		    "memory: %d", size_up, ret);
		ena_dma_free(edb);
		return (B_FALSE);
	}

	bzero(edb->edb_va, size_allocated);

	ret = ddi_dma_addr_bind_handle(edb->edb_dma_hdl, NULL, edb->edb_va,
	    size_allocated, DDI_DMA_RDWR | flags, DDI_DMA_DONTWAIT, NULL, NULL,
	    NULL);
	if (ret != DDI_SUCCESS) {
		ena_err(ena, "!failed to bind %lu bytes of DMA "
		    "memory: %d", size_allocated, ret);
		ena_dma_free(edb);
		return (B_FALSE);
	}

	edb->edb_len = size_up;
	edb->edb_real_len = size_allocated;
	edb->edb_cookie = ddi_dma_cookie_one(edb->edb_dma_hdl);

	ena_xxx(ena, "DMA size: %u size_allocated: %u virt: 0x%p phys: 0x%p",
	    size_up, size_allocated, (void *)edb->edb_va,
	    (void *)edb->edb_cookie->dmac_laddress);
	return (B_TRUE);
}

/*
 * Write the physical DMA address to the ENA hardware address pointer.
 * While the DMA engine should guarantee that the allocation is within
 * the specified range, we double check here to catch programmer error
 * and avoid hard-to-debug situations.
 */
void
ena_set_dma_addr(const ena_t *ena, const uint64_t phys_addr,
    enahw_addr_t *hwaddrp)
{
	ENA_DMA_VERIFY_ADDR(ena, phys_addr);
	hwaddrp->ea_low = (uint32_t)phys_addr;
	hwaddrp->ea_high = (uint16_t)(phys_addr >> 32);
}

/*
 * The same as the above function, but writes the phsyical address to
 * the supplied value pointers instead. Mostly used as a sanity check
 * that the address fits in the reported DMA width.
 */
void
ena_set_dma_addr_values(const ena_t *ena, const uint64_t phys_addr,
    uint32_t *dst_low, uint16_t *dst_high)
{
	ENA_DMA_VERIFY_ADDR(ena, phys_addr);
	*dst_low = (uint32_t)phys_addr;
	*dst_high = (uint16_t)(phys_addr >> 32);
}
