/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * This file is part of the Chelsio T4 support code.
 *
 * Copyright (C) 2011-2013 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/queue.h>

#include "t4nex.h"
#include "common/common.h"
#include "common/t4_regs.h"
#ifdef ENABLE_CUDBG
#include "cudbg.h"
#endif

/* helpers */
static int pci_rw(struct adapter *sc, void *data, int flags, int write);
static int reg_rw(struct adapter *sc, void *data, int flags, int write);
static int regdump(struct adapter *sc, void *data, int flags);
static int get_sge_context(struct adapter *sc, void *data, int flags);
static int get_devlog(struct adapter *sc, void *data, int flags);
static int validate_mem_range(struct adapter *, uint32_t, int);
static int read_card_mem(struct adapter *sc, void *data, int flags);
static int read_tid_tab(struct adapter *sc, void *data, int flags);
static int read_mbox(struct adapter *sc, void *data, int flags);
static int read_cim_la(struct adapter *sc, void *data, int flags);
static int read_cim_qcfg(struct adapter *sc, void *data, int flags);
static int read_cim_ibq(struct adapter *sc, void *data, int flags);
static int read_edc(struct adapter *sc, void *data, int flags);
static int flash_fw(struct adapter *, void *, int);
/* RPZ: The cudbg code might be moving to a firmware impl, ignore for now. */
#ifdef ENABLE_CUDBG
static int get_cudbg(struct adapter *, void *, int);
#endif

int
t4_ioctl(struct adapter *sc, int cmd, void *data, int mode)
{
	int rc = ENOTSUP;

	switch (cmd) {
	case T4_IOCTL_PCIGET32:
	case T4_IOCTL_PCIPUT32:
		rc = pci_rw(sc, data, mode, cmd == T4_IOCTL_PCIPUT32);
		break;
	case T4_IOCTL_GET32:
	case T4_IOCTL_PUT32:
		rc = reg_rw(sc, data, mode, cmd == T4_IOCTL_PUT32);
		break;
	case T4_IOCTL_REGDUMP:
		rc = regdump(sc, data, mode);
		break;
	case T4_IOCTL_SGE_CONTEXT:
		rc = get_sge_context(sc, data, mode);
		break;
	case T4_IOCTL_DEVLOG:
		rc = get_devlog(sc, data, mode);
		break;
	case T4_IOCTL_GET_MEM:
		rc = read_card_mem(sc, data, mode);
		break;
	case T4_IOCTL_GET_TID_TAB:
		rc = read_tid_tab(sc, data, mode);
		break;
	case T4_IOCTL_GET_MBOX:
		rc = read_mbox(sc, data, mode);
		break;
	case T4_IOCTL_GET_CIM_LA:
		rc = read_cim_la(sc, data, mode);
		break;
	case T4_IOCTL_GET_CIM_QCFG:
		rc = read_cim_qcfg(sc, data, mode);
		break;
	case T4_IOCTL_GET_CIM_IBQ:
		rc = read_cim_ibq(sc, data, mode);
		break;
	case T4_IOCTL_GET_EDC:
		rc = read_edc(sc, data, mode);
		break;
	case T4_IOCTL_LOAD_FW:
		rc = flash_fw(sc, data, mode);
		break;
#ifdef ENABLE_CUDBG
	case T4_IOCTL_GET_CUDBG:
		rc = get_cudbg(sc, data, mode);
		break;
#endif
	default:
		return (EINVAL);
	}

	return (rc);
}

static int
pci_rw(struct adapter *sc, void *data, int flags, int write)
{
	struct t4_reg32_cmd r;

	if (ddi_copyin(data, &r, sizeof (r), flags) < 0)
		return (EFAULT);

	/* address must be 32 bit aligned */
	r.reg &= ~0x3;

	if (write != 0)
		t4_os_pci_write_cfg4(sc, r.reg, r.value);
	else {
		t4_os_pci_read_cfg4(sc, r.reg, &r.value);
		if (ddi_copyout(&r, data, sizeof (r), flags) < 0)
			return (EFAULT);
	}

	return (0);
}

static int
reg_rw(struct adapter *sc, void *data, int flags, int write)
{
	struct t4_reg32_cmd r;

	if (ddi_copyin(data, &r, sizeof (r), flags) < 0)
		return (EFAULT);

	/* Register address must be 32 bit aligned */
	r.reg &= ~0x3;

	if (write != 0)
		t4_write_reg(sc, r.reg, r.value);
	else {
		r.value = t4_read_reg(sc, r.reg);
		if (ddi_copyout(&r, data, sizeof (r), flags) < 0)
			return (EFAULT);
	}

	return (0);
}

/*
 * Return a version number to identify the type of adapter.  The scheme is:
 * - bits 0..9: chip version
 * - bits 10..15: chip revision
 * - bits 16..23: register dump version
 */
static inline
unsigned int mk_adap_vers(const struct adapter *sc)
{
	return CHELSIO_CHIP_VERSION(sc->params.chip) |
		(CHELSIO_CHIP_RELEASE(sc->params.chip) << 10) | (1 << 16);
}

static int
regdump(struct adapter *sc, void *data, int flags)
{
	struct t4_regdump r;
	unsigned int reglen = t4_get_regs_len(sc);
	uint8_t *buf = NULL;
	int rc = 0;

	if (ddi_copyin(data, &r, sizeof (r), flags) < 0) {
		return (EFAULT);
	}

	if (r.len < reglen) {
		rc = ENOBUFS;
		goto out;
	}

	buf = kmem_zalloc(reglen, KM_SLEEP);
	t4_get_regs(sc, buf, reglen);

	if (ddi_copyout(buf, r.data, reglen, flags) < 0)
		rc = EFAULT;

out:
	kmem_free(buf, reglen);
	r.version = mk_adap_vers(sc);
	r.len = reglen;

	if (ddi_copyout(&r, data, sizeof (r), flags) < 0)
		return (EFAULT);

	return (rc);
}

static int
get_sge_context(struct adapter *sc, void *data, int flags)
{
	struct t4_sge_context sgec;
	uint32_t buff[SGE_CTXT_SIZE / 4];
	int rc = 0;

	if (ddi_copyin(data, &sgec, sizeof (sgec), flags) < 0) {
		rc = EFAULT;
		goto _exit;
	}

	if (sgec.len < SGE_CTXT_SIZE || sgec.addr > M_CTXTQID) {
		rc = EINVAL;
		goto _exit;
	}

	if ((sgec.mem_id != T4_CTXT_EGRESS) && (sgec.mem_id != T4_CTXT_FLM) &&
	    (sgec.mem_id != T4_CTXT_INGRESS)) {
		rc = EINVAL;
		goto _exit;
	}

	rc = (sc->flags & FW_OK) ?
	    -t4_sge_ctxt_rd(sc, sc->mbox, sgec.addr, sgec.mem_id, buff) :
	    -t4_sge_ctxt_rd_bd(sc, sgec.addr, sgec.mem_id, buff);
	if (rc != 0)
		goto _exit;

	sgec.version = 4 | (sc->params.chip << 10);

	/* copyout data and then t4_sge_context */
	rc = ddi_copyout(buff, sgec.data, sgec.len, flags);
	if (rc == 0)
		rc = ddi_copyout(&sgec, data, sizeof (sgec), flags);
	/* if ddi_copyout fails, return EFAULT - for either of the two */
	if (rc != 0)
		rc = EFAULT;

_exit:
	return (rc);
}

static int
read_tid_tab(struct adapter *sc, void *data, int flags)
{
	struct t4_tid_info t4tid;
	uint32_t *buf, *b;
	struct tid_info *t = &sc->tids;
	int rc = 0;

	if (ddi_copyin(data, &t4tid, sizeof (t4tid), flags) < 0) {
		rc = EFAULT;
		goto _exit;
	}

	buf = b = kmem_zalloc(t4tid.len, KM_NOSLEEP);
	if (buf == NULL) {
		rc = ENOMEM;
		goto _exit;
	}

	*b++ = t->tids_in_use;
	*b++ = t->atids_in_use;
	*b = t->stids_in_use;

	if (ddi_copyout(buf, t4tid.data, t4tid.len, flags) < 0)
		rc = EFAULT;

	kmem_free(buf, t4tid.len);

_exit:
	return (rc);
}

/*
 * Verify that the memory range specified by the addr/len pair is valid and lies
 * entirely within a single region (EDCx or MCx).
 */
static int
validate_mem_range(struct adapter *sc, uint32_t addr, int len)
{
	uint32_t em, addr_len, maddr, mlen;

	/* Memory can only be accessed in naturally aligned 4 byte units */
	if (addr & 3 || len & 3 || len == 0)
		return (EINVAL);

	/* Enabled memories */
	em = t4_read_reg(sc, A_MA_TARGET_MEM_ENABLE);
	if (em & F_EDRAM0_ENABLE) {
		addr_len = t4_read_reg(sc, A_MA_EDRAM0_BAR);
		maddr = G_EDRAM0_BASE(addr_len) << 20;
		mlen = G_EDRAM0_SIZE(addr_len) << 20;
		if (mlen > 0 && addr >= maddr && addr < maddr + mlen &&
				addr + len <= maddr + mlen)
			return (0);
	}
	if (em & F_EDRAM1_ENABLE) {
		addr_len = t4_read_reg(sc, A_MA_EDRAM1_BAR);
		maddr = G_EDRAM1_BASE(addr_len) << 20;
		mlen = G_EDRAM1_SIZE(addr_len) << 20;
		if (mlen > 0 && addr >= maddr && addr < maddr + mlen &&
				addr + len <= maddr + mlen)
			return (0);
	}
	if (em & F_EXT_MEM_ENABLE) {
		addr_len = t4_read_reg(sc, A_MA_EXT_MEMORY_BAR);
		maddr = G_EXT_MEM_BASE(addr_len) << 20;
		mlen = G_EXT_MEM_SIZE(addr_len) << 20;
		if (mlen > 0 && addr >= maddr && addr < maddr + mlen &&
				addr + len <= maddr + mlen)
			return (0);
	}
	if (!is_t4(sc->params.chip) && em & F_EXT_MEM1_ENABLE) {
		addr_len = t4_read_reg(sc, A_MA_EXT_MEMORY1_BAR);
		maddr = G_EXT_MEM1_BASE(addr_len) << 20;
		mlen = G_EXT_MEM1_SIZE(addr_len) << 20;
		if (mlen > 0 && addr >= maddr && addr < maddr + mlen &&
				addr + len <= maddr + mlen)
			return (0);
	}

	return (EFAULT);
}

static int
read_card_mem(struct adapter *sc, void *data, int flags)
{
	struct t4_mem_range mr;
	uint32_t addr, off, remaining, i, n;
	uint32_t *buf, *b;
	int rc = 0;
	uint32_t mw_base, mw_aperture;
	uint8_t *dst;

	if (ddi_copyin(data, &mr, sizeof (mr), flags) < 0) {
		rc = EFAULT;
		goto _exit;
	}

	rc = validate_mem_range(sc, mr.addr, mr.len);
	if (rc != 0)
		return (rc);

	memwin_info(sc, 2, &mw_base, &mw_aperture);
	buf = b = kmem_zalloc(min(mr.len, mw_aperture), KM_NOSLEEP);
	if (buf == NULL) {
		rc = ENOMEM;
		goto _exit;
	}

	addr = mr.addr;
	remaining = mr.len;
	dst = (void *)mr.data;

	while (remaining) {
		off = position_memwin(sc, 2, addr);

		/* number of bytes that we'll copy in the inner loop */
		n = min(remaining, mw_aperture - off);

		for (i = 0; i < n; i += 4)
			*b++ = t4_read_reg(sc, mw_base + off + i);
		rc = ddi_copyout(buf, dst, n, flags);
		if (rc != 0) {
			rc = EFAULT;
			break;
		}

		b = buf;
		dst += n;
		remaining -= n;
		addr += n;
	}

	kmem_free(buf, min(mr.len, mw_aperture));
_exit:
	return (rc);
}

static int
get_devlog(struct adapter *sc, void *data, int flags)
{
	/* RPZ: need to deal with multi-core. */
	struct devlog_params *dparams = &sc->params.devlog[0];
	struct fw_devlog_e *buf;
	struct t4_devlog dl;
	int rc = 0;

	if (ddi_copyin(data, &dl, sizeof (dl), flags) < 0) {
		rc = EFAULT;
		goto done;
	}

	if (dparams->start == 0) {
		dparams->memtype = 0;
		dparams->start = 0x84000;
		dparams->size = 32768;
	}

	if (dl.len < dparams->size) {
		dl.len = dparams->size;
		rc = ddi_copyout(&dl, data, sizeof (dl), flags);
		/*
		 * rc = 0 indicates copyout was successful, then return ENOBUFS
		 * to indicate that the buffer size was not enough. Return of
		 * EFAULT indicates that the copyout was not successful.
		 */
		rc = (rc == 0) ? ENOBUFS : EFAULT;
		goto done;
	}

	buf = kmem_zalloc(dparams->size, KM_NOSLEEP);
	if (buf == NULL) {
		rc = ENOMEM;
		goto done;
	}

	rc = -t4_memory_rw(sc, sc->params.drv_memwin, dparams->memtype,
			   dparams->start, dparams->size, (void *)buf,
			   T4_MEMORY_READ);
	if (rc != 0)
		goto done1;

	/* Copyout device log buffer and then carrier buffer */
	if (ddi_copyout(buf, (void *)((uintptr_t)data + sizeof(dl)), dl.len,
	    flags) < 0)
		rc = EFAULT;

	if (ddi_copyout(&dl, data, sizeof(dl), flags) < 0)
		rc = EFAULT;

done1:
	kmem_free(buf, dparams->size);

done:
	return (rc);
}

static int
read_cim_qcfg(struct adapter *sc, void *data, int flags)
{
	struct t4_cim_qcfg t4cimqcfg;
	int rc = 0;
	unsigned int ibq_rdaddr, obq_rdaddr, nq;

	if (ddi_copyin(data, &t4cimqcfg, sizeof (t4cimqcfg), flags) < 0) {
		rc = EFAULT;
		goto _exit;
	}

        if (is_t4(sc->params.chip)) {
		t4cimqcfg.num_obq = CIM_NUM_OBQ;
                ibq_rdaddr = A_UP_IBQ_0_RDADDR;
                obq_rdaddr = A_UP_OBQ_0_REALADDR;
        } else {
                t4cimqcfg.num_obq = CIM_NUM_OBQ_T5;
                ibq_rdaddr = A_UP_IBQ_0_SHADOW_RDADDR;
                obq_rdaddr = A_UP_OBQ_0_SHADOW_REALADDR;
        }
	nq = CIM_NUM_IBQ + t4cimqcfg.num_obq;

	rc = -t4_cim_read(sc, ibq_rdaddr, 4 * nq, t4cimqcfg.stat);
	if (rc == 0)
		rc = -t4_cim_read(sc, obq_rdaddr, 2 * t4cimqcfg.num_obq,
		    t4cimqcfg.obq_wr);
	if (rc != 0)
		return (rc);

	t4_read_cimq_cfg(sc, t4cimqcfg.base, t4cimqcfg.size, t4cimqcfg.thres);

	if (ddi_copyout(&t4cimqcfg, data, sizeof (t4cimqcfg), flags) < 0)
		rc = EFAULT;

_exit:
	return (rc);
}

static int
read_edc(struct adapter *sc, void *data, int flags)
{
	struct t4_edc t4edc;
	int rc = 0;
	u32 count, pos = 0;
	u32 memoffset;
	__be32 *edc = NULL;

	if (ddi_copyin(data, &t4edc, sizeof (t4edc), flags) < 0) {
		rc = EFAULT;
		goto _exit;
	}

	if (t4edc.mem > 2)
		goto _exit;

	edc = kmem_zalloc(t4edc.len, KM_NOSLEEP);
	if (edc == NULL) {
		rc = ENOMEM;
		goto _exit;
	}
	/*
	 * Offset into the region of memory which is being accessed
	 * MEM_EDC0 = 0
	 * MEM_EDC1 = 1
	 * MEM_MC   = 2
	 */
	memoffset = (t4edc.mem * (5 * 1024 * 1024));
	count = t4edc.len;
	pos = t4edc.pos;

	while (count) {
		u32 len;

		rc = t4_memory_rw(sc, sc->params.drv_memwin, memoffset, pos,
				  count, edc, T4_MEMORY_READ);
		if (rc != 0) {
			kmem_free(edc, t4edc.len);
			goto _exit;
		}

		len = MEMWIN0_APERTURE;
		pos += len;
		count -= len;
	}

	if (ddi_copyout(edc, t4edc.data, t4edc.len, flags) < 0)
		rc = EFAULT;

	kmem_free(edc, t4edc.len);
_exit:
	return (rc);
}

static int
read_cim_ibq(struct adapter *sc, void *data, int flags)
{
	struct t4_ibq t4ibq;
	int rc = 0;
	__be64 *buf;

	if (ddi_copyin(data, &t4ibq, sizeof (t4ibq), flags) < 0) {
		rc = EFAULT;
		goto _exit;
	}

	buf = kmem_zalloc(t4ibq.len, KM_NOSLEEP);
	if (buf == NULL) {
		rc = ENOMEM;
		goto _exit;
	}

	rc = t4_read_cim_ibq(sc, 3, (u32 *)buf, CIM_IBQ_SIZE * 4);
	if (rc < 0) {
		kmem_free(buf, t4ibq.len);
		return (rc);
	} else
		rc = 0;

	if (ddi_copyout(buf, t4ibq.data, t4ibq.len, flags) < 0)
		rc = EFAULT;

	kmem_free(buf, t4ibq.len);

_exit:
	return (rc);
}

static int
read_cim_la(struct adapter *sc, void *data, int flags)
{
	struct t4_cim_la t4cimla;
	int rc = 0;
	unsigned int cfg;
	__be64 *buf;

	rc = t4_cim_read(sc, A_UP_UP_DBG_LA_CFG, 1, &cfg);
	if (rc != 0)
		return (rc);

	if (ddi_copyin(data, &t4cimla, sizeof (t4cimla), flags) < 0) {
		rc = EFAULT;
		goto _exit;
	}

	buf = kmem_zalloc(t4cimla.len, KM_NOSLEEP);
	if (buf == NULL) {
		rc = ENOMEM;
		goto _exit;
	}

	rc = t4_cim_read_la(sc, (u32 *)buf, NULL);
	if (rc != 0) {
		kmem_free(buf, t4cimla.len);
		return (rc);
	}

	if (ddi_copyout(buf, t4cimla.data, t4cimla.len, flags) < 0)
		rc = EFAULT;

	kmem_free(buf, t4cimla.len);

_exit:
	return (rc);
}

static int
read_mbox(struct adapter *sc, void *data, int flags)
{
	struct t4_mbox t4mbox;
	int rc = 0, i;
	__be64 *p, *buf;

	u32 data_reg = PF_REG(4, A_CIM_PF_MAILBOX_DATA);

	if (ddi_copyin(data, &t4mbox, sizeof (t4mbox), flags) < 0) {
		rc = EFAULT;
		goto _exit;
	}

	buf = p = kmem_zalloc(t4mbox.len, KM_NOSLEEP);
	if (buf == NULL) {
		rc = ENOMEM;
		goto _exit;
	}

	for (i = 0; i < t4mbox.len; i += 8, p++)
		*p =  t4_read_reg64(sc, data_reg + i);

	if (ddi_copyout(buf, t4mbox.data, t4mbox.len, flags) < 0)
		rc = EFAULT;

	kmem_free(buf, t4mbox.len);

_exit:
	return (rc);
}

static int
flash_fw(struct adapter *sc, void *data, int flags)
{
	unsigned int mbox = M_PCIE_FW_MASTER + 1;
	struct t4_ldfw fw;
	u8 *ptr = NULL;
	int rc = 0;

	if (ddi_copyin(data, &fw, sizeof(struct t4_ldfw), flags) < 0)
		return EFAULT;

	if (!fw.len)
		return EINVAL;

	ptr = (u8 *)kmem_zalloc(fw.len, KM_NOSLEEP);
	if (ptr == NULL)
		return ENOMEM;

	if (ddi_copyin((void *)((uintptr_t)data + sizeof(fw)), ptr, fw.len,
	    flags) < 0) {
		kmem_free(ptr, fw.len);
		return EFAULT;
	}

	if (sc->flags & FULL_INIT_DONE)
		mbox = sc->mbox;

	rc = -t4_fw_upgrade(sc, mbox, ptr, fw.len, true);
	ddi_ufm_update(sc->ufm_hdl);

	kmem_free(ptr, fw.len);

	return (rc);
}

#ifdef ENABLE_CUDBG
static int
get_cudbg(struct adapter *sc, void *data, int flags)
{
	struct t4_cudbg_dump dump;
	struct cudbg_init *cudbg;
	void *handle, *buf;
	int size;
	int rc = 0;

	if (ddi_copyin(data, &dump, sizeof(struct t4_cudbg_dump), flags) < 0)
		return EFAULT;

	size = dump.len;
	buf = (u8 *)kmem_zalloc(dump.len, KM_NOSLEEP);
	if (buf == NULL)
		return ENOMEM;

	handle = cudbg_alloc_handle();
	if (handle == NULL) {
		rc = ENOMEM;
		goto free;
	}

	cudbg = cudbg_get_init(handle);
	cudbg->adap = sc;
	cudbg->print = cxgb_printf;

	ASSERT3U(sizeof (cudbg->dbg_bitmap), ==, sizeof (dump->bitmap));
	memcpy(cudbg->dbg_bitmap, dump.bitmap, sizeof(cudbg->dbg_bitmap));

	rc = cudbg_collect(handle, buf, &dump.len);
	if (rc != 0) {
		cxgb_printf(sc->dip, CE_WARN, "cudbg collect failed\n");
		goto exit;
	}

	if(ddi_copyout(buf, (void *)((uintptr_t)data + sizeof(dump)),
	   dump.len, flags) < 0){
		rc = EFAULT;
	}

	if (ddi_copyout(&dump, data, sizeof(dump), flags) < 0){
		rc = EFAULT;
	}
exit:
	cudbg_free_handle(handle);
free:
	kmem_free(buf, size);

	return rc;
}
#endif
