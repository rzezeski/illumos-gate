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
 * Copyright (c) 2019, Joyent, Inc.
 * Copyright 2025 Oxide Computer Company
 */

/*
 * This file implements general TCP large receive offload (LRO).
 *
 * XXX Expand
 */

#include <sys/types.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/pattr.h>
#include <sys/kmem.h>
#include <sys/mac_impl.h>
#include <inet/tcp_impl.h>
#include <inet/udp_impl.h>
#include <sys/sdt.h>

/*
 *
 * MLF_GENVE
 *
 *     The LRO state is for a Geneve ecapsulated flow.
 */
typedef enum mac_lro_flags {
	MLF_VALID	= 1 << 0,
	MLF_IPV4	= 1 << 1,
	MLF_TS_VALID	= 1 << 2,
	MLF_GENEVE	= 1 << 3,
	/* RPZ TODO This flag is not currently used */
	MLF_L2_INCLUDED	= 1 << 4,
} mac_lro_flags_t;

struct mac_lro_state_s {
	/*
	 * These fields track relevant state.
	 */
	mblk_t		*mls_head;
	mblk_t		*mls_tail;
	tcpha_t		*mls_tcp;

	/*
	 * RPZ Currently this only supports IPv6/UDP based encap.
	 *
	 * Since we are in receiving context:
	 *     lport = src port
	 *     dport = dest ort
	 *
	 */
	in6_addr_t	mls_encap_src;
	in6_addr_t	mls_encap_dst;
	uint16_t	mls_encap_lport;
	uint16_t	mls_encap_fport;
	/* uint_t		mls_encap_ip6len; */
	/* uint_t		mls_encap_udplen; */

	/* RPZ TODO Instead of caching all these header values we could
	 * just point to the headers and bcmp() values for matching.
	 * Although that might mean more pointer chasing. */

	/*
	 * These fields are kept in network endianness and (with the exception
	 * of TCP flags) are not modified from the packet.
	 */
	in6_addr_t	mls_src;
	in6_addr_t	mls_dst;
	uint16_t	mls_lport;
	uint16_t	mls_fport;
	uint32_t	mls_ip_ecn;
	uint32_t	mls_tcp_ack;
	uint16_t	mls_tcp_window;
	uint8_t		mls_tcp_flags;

	/*
	 * These fields are kept in host endianness.
	 */
	mac_lro_flags_t	mls_flags;
	/* uint_t		mls_len; */
	uint_t		mls_count;
	/* RPZ The number of bytes remaining before this LRO must commit. */
	uint32_t	mls_remain;
	uint32_t	mls_exp_seq;
	uint32_t	mls_tsval;
	uint32_t	mls_tsecr;

	uint8_t		mls_outer_l4hlen;
	uint8_t		mls_outer_tunhlen;
	uint8_t		mls_inner_l2hlen;
	uint8_t		mls_inner_l3hlen;
	/* Offset of non-encap IP header from b_rptr. */
	uint8_t		mls_ip_offset;

	ip6_t		*mls_encap_ip6;
	udpha_t		*mls_encap_udp;
};

/*
 * Number of LRO entries to allocate for a soft ring.
 *
 * RPZ TODO This should be configurable. Perhaps on a per-link or
 * per-client basis via dladm?
 */
uint_t mac_lro_cache_size = 8;

/*
 * Rough statistics. We don't try and serialize these across CPUs, so they will
 * be lossy.
 */
uint_t mac_lro_full;

void
mac_lro_free(mac_lro_state_t *lrop, uint_t count)
{
	kmem_free(lrop, sizeof (mac_lro_state_t) * count);
}

void
mac_lro_alloc(mac_lro_state_t **lropp, uint_t *countp)
{
	*countp = mac_lro_cache_size;
	*lropp = kmem_zalloc(sizeof (mac_lro_state_t) * *countp,
	    KM_SLEEP);
}

static void
mac_lro_append_bnext(mblk_t *mp, mblk_t **head, mblk_t **tail)
{
	ASSERT3P(mp->b_next, ==, NULL);

	if (*head == NULL) {
		*head = mp;
	}

	if (*tail != NULL) {
		(*tail)->b_next = mp;
	}

	*tail = mp;
}

static inline void
mac_lro_append_bcont(mblk_t *mp, mblk_t **head, mblk_t **tail)
{
	if (*head == NULL) {
		*head = mp;
	}

	if (*tail != NULL) {
		(*tail)->b_cont = mp;
	}

	while (mp->b_cont != NULL) {
		mp = mp->b_cont;
	}
	ASSERT3P(mp, !=, NULL);
	*tail = mp;
}

static mac_lro_state_t *
mac_lro_find_free_slot(mac_lro_state_t *lrop, uint_t count)
{
	uint_t i;

	for (i = 0; i < count; i++, lrop++) {
		if ((lrop->mls_flags & MLF_VALID) == 0)
			return (lrop);
	}

	return (NULL);
}

static void
mac_lro_commit(mac_lro_state_t *lro, mblk_t **headp, mblk_t **tailp)
{
	tcpha_t *tcp;

	VERIFY3S((lro->mls_flags & MLF_VALID), !=, 0);
	VERIFY3U(lro->mls_count, >, 0);
	if (lro->mls_count == 1) {
		goto done;
	}

	/* RPZ Make sure mls_remain did not underflow */
	VERIFY3U(lro->mls_remain, <, IP_MAXPACKET);

	/*
	 * For both the encap and non-ecap case, len represents the
	 * IPv4 "Total Length" or the IPv6 "Payload Length". However,
	 * for encap it contains the encap header's value. Therefore,
	 * in order to determine the new inner header values,
	 * subtraction of the outer headers must be done.
	 */
	uint16_t len = IP_MAXPACKET - lro->mls_remain;

	/*
	 * Update the encap header lengths and then adjust 'len' for
	 * the inner IP header length.
	 */
	if ((lro->mls_flags & MLF_GENEVE) != 0) {
		/*
		 * IPv6 payload len DOES NOT include the IPv6 header
		 * length; but UDP length DOES include the UDP header
		 * length.
		 */
		lro->mls_encap_ip6->ip6_plen = htons(len);
		lro->mls_encap_udp->uha_length = htons(len);

		/*
		 * Now that the outer header length values are set,
		 * subtract headers to get inner IP length.
		 */
		len -= lro->mls_outer_l4hlen + lro->mls_outer_tunhlen +
		    lro->mls_inner_l2hlen + lro->mls_inner_l3hlen;
	}

	/*
	 * We've joined multiple segments. This means that we need to update the
	 * following fields:
	 *
	 *  o IP Payload
	 *  o IP Checksum (zero)
	 *  o TCP ACK
	 *  o TCP Window Size
	 *  o TCP Checksum (zero)
	 *  o Timestamp
	 *  o TCP flags
	 */
	tcp = lro->mls_tcp;
	/* ASSERT3U(lro->mls_len, <=, IP_MAXPACKET); */
	/* RPZ Make sure mls_remain did not underflow */
	/* VERIFY3U(lro->mls_remain, <, IP_MAXPACKET); */
	/* uint16_t len = IP_MAXPACKET - lro->mls_remain; */

	if ((lro->mls_flags & MLF_IPV4) != 0) {
		ipha_t *ip = (ipha_t *)(lro->mls_head->b_rptr +
		    lro->mls_ip_offset);
		/*
		 * Perform incremental update of the checksum by
		 * subtracting the old length from the sum and adding the
		 * new length.
		 */
		uint32_t ipsum = ip->ipha_hdr_checksum;
		ipsum += (uint32_t)(ip->ipha_length);
		ipsum += (uint32_t)(~htons(len) & 0xFFFF);
		while (ipsum >> 16) {
			ipsum = (ipsum & 0xFFFF) + (ipsum >> 16);
		}
		if (ipsum == 0) {
			ipsum = 0xFFFF;
		}
		ip->ipha_hdr_checksum = (uint16_t)ipsum;
		ip->ipha_length = htons(len);

		uint32_t pcsum = 0;
		pcsum += (ip->ipha_src >> 16) + (ip->ipha_src & 0xFFFF);
		pcsum += (ip->ipha_dst >> 16) + (ip->ipha_dst & 0xFFFF);
		pcsum += htons(IPPROTO_TCP);
		/* The pseudo-header checksum uses the transport length. */
		pcsum += htons(len - lro->mls_inner_l3hlen);

		while (pcsum >> 16) {
			pcsum = (pcsum & 0xFFFF) + (pcsum >> 16);
		}

		tcp->tha_sum = (uint16_t)pcsum;
	} else {
		ip6_t *ip = (ip6_t *)(lro->mls_head->b_rptr +
		    lro->mls_ip_offset);

		ip->ip6_plen = htons(len);
		/* RPZ TODO need to calculate pcsum for IPv6. */
		tcp->tha_sum = 0;
	}

	tcp->tha_ack = lro->mls_tcp_ack;
	tcp->tha_win = lro->mls_tcp_window;

	if ((lro->mls_flags & MLF_TS_VALID) != 0) {
		uint32_t *ts = (uint32_t *)(tcp + 1);
		ts[1] = htonl(lro->mls_tsval);
		ts[2] = htonl(lro->mls_tsecr);
	}
	tcp->tha_flags = lro->mls_tcp_flags;

done:
	DTRACE_PROBE3(mac__lro__commit, mblk_t *, lro->mls_head,
	    mac_lro_state_t *, lro, tcpha_t *, tcp);
	/* RPZ TODO Do no access flags directly like this, need provider API. */
	lro->mls_head->b_datap->db_struioun.cksum.flags |= MBLK_SW_LRO;
	mac_lro_append_bnext(lro->mls_head, headp, tailp);
	ASSERT3P(*tailp, ==, lro->mls_head);
	ASSERT3P(lro->mls_tail->b_cont, ==, NULL);
	ASSERT3P(lro->mls_tail->b_next, ==, NULL);
	bzero(lro, sizeof (*lro));
}

#ifdef DEBUG
static void
mac_lro_verify_chain(mblk_t **head, mblk_t **tail)
{
	mblk_t *mp = *head;

	if (mp == NULL) {
		VERIFY3P(*tail, ==, NULL);
		return;
	}

	while (mp != NULL) {
		mblk_t *cont;

		cont = mp->b_cont;
		while (cont != NULL) {
			VERIFY3P(cont->b_next, ==, NULL);
			cont = cont->b_cont;
		}

		if (mp->b_next == NULL) {
			VERIFY3P(mp, ==, *tail);
		}
		mp = mp->b_next;
	}

	VERIFY3P((*tail)->b_next, ==, NULL);
	mp = *tail;
	while (mp->b_cont != NULL) {
		mp = mp->b_cont;
		VERIFY3P(mp->b_next, ==, NULL);
	}

	mp = *head;
	while (mp != NULL) {
		if (mp == *tail)
			break;
		mp = mp->b_next;
	}
	VERIFY3P(mp, !=, NULL);
}
#endif

typedef enum mac_lro_suitable {
	MLS_OK = 0,
	MLS_L3_PROTO,
	MLS_L4_PROTO,
	MLS_FRAGMENT,
	MLS_MBLK_LAYOUT,
	MLS_IPV4_OPTS,
	MLS_IPV6_EH,
	MLS_L3_CKSUM,
	MLS_L4_CKSUM,
	MLS_TCP_OPTS,
	MLS_TUN_TYPE,
} mac_lro_suitable_t;

static mac_lro_suitable_t
mac_sw_lro_encap_is_suitable(const mblk_t *mp, const mac_ether_offload_info_t *meoi,
    uint32_t hck_flags)
{
	/* Must be IPv6 + UPD. */
	if ((meoi->meoi_flags & MEOI_L3INFO_SET) == 0 ||
	    (meoi->meoi_flags & MEOI_L4INFO_SET) == 0) {
		return (MLS_L3_PROTO);
	}

	if (meoi->meoi_l3proto != ETHERTYPE_IPV6) {
		return (MLS_L3_PROTO);
	}

	if (meoi->meoi_l4proto != IPPROTO_UDP) {
		return (MLS_L4_PROTO);
	}

	/* RPZ Is it correct to check for both FRAG_MORE and FRAG_OFFSET? Or
	 * should it just be one of them? */
	/* Cannot be fragmented */
	if ((meoi->meoi_flags & (MEOI_L3_FRAG_MORE|MEOI_L3_FRAG_OFFSET)) != 0) {
		return (MLS_FRAGMENT);
	}

	/* First mblk does not contain all headers */
	const uint_t hdr_size = meoi->meoi_l2hlen + meoi->meoi_l3hlen +
	    meoi->meoi_l4hlen + meoi->meoi_tunhlen;
	if (MBLKL(mp) < hdr_size) {
		return (MLS_MBLK_LAYOUT);
	}

	/* IPv6 must not carry extension headers */
	if (meoi->meoi_l3hlen != IPV6_HDR_LEN) {
		return (MLS_IPV6_EH);
	}

	/* The L4 cksum must be valid */
	if ((hck_flags & HCK_FULLCKSUM_OK) == 0) {
		return (MLS_L4_CKSUM);
	}

	if ((meoi->meoi_flags & MEOI_FULLTUN) != 0 &&
	    meoi->meoi_tuntype != METT_GENEVE) {
		/*
		 * RPZ TODO right now I'm assuming oxide, but to be
		 * complete we would need a way for admin to
		 * enable/disable tunneled LRO as well as specifying the
		 * port number used to identify Geneve
		 */
		return (MLS_TUN_TYPE);
	}

	return (MLS_OK);
}

/* RPZ For encap packets we need to set offset to start of inner packet. */
static mac_lro_suitable_t
mac_sw_lro_is_suitable(const mblk_t *mp, const uint8_t offset,
    const mac_ether_offload_info_t *meoi, uint32_t hck_flags)
{
	/* Must be TCP/UDP over IPv4/IPv6. */
	if ((meoi->meoi_flags & MEOI_L3INFO_SET) == 0 ||
	    (meoi->meoi_flags & MEOI_L4INFO_SET) == 0) {
		return (MLS_L3_PROTO);
	}
	if (meoi->meoi_l3proto != ETHERTYPE_IP &&
	    meoi->meoi_l3proto != ETHERTYPE_IPV6) {
		return (MLS_L3_PROTO);
	}

	/* RPZ It would be nice to support UDP LRO as well */
	if (meoi->meoi_l4proto != IPPROTO_TCP) {
		return (MLS_L4_PROTO);
	}

	/* RPZ Is it correct to check for both FRAG_MORE and FRAG_OFFSET? Or
	 * should it just be one of them? */
	/* Cannot be fragmented */
	if ((meoi->meoi_flags & (MEOI_L3_FRAG_MORE|MEOI_L3_FRAG_OFFSET)) != 0) {
		return (MLS_FRAGMENT);
	}

	/* First mblk does not contain all headers */
	/*
	 * RPZ BUG This is a theoretical problem: realisticaly nothing
	 * should deliver mblks to us with headers split across mblks.
	 * However, if it were to happen, this could cause us to send
	 * up a TCP segment out-of-order if it belongs to a flow that
	 * currently has LRO state associated with it.
	 */
	const uint_t hdr_size =
	    (meoi->meoi_l2hlen + meoi->meoi_l3hlen + meoi->meoi_l4hlen);
	if (MBLKL(mp) < hdr_size) {
		return (MLS_MBLK_LAYOUT);
	}

	/* IPv4 must not carry options, and must contain a valid L3 cksum */
	/*
	 * RPZ BUG This could also be a problem: this might belong to
	 * a TCP flow with an existing LRO state (though very unlikely).
	 */
	if (meoi->meoi_l3proto == ETHERTYPE_IP) {
		if (meoi->meoi_l3hlen != IP_SIMPLE_HDR_LENGTH) {
			return (MLS_IPV4_OPTS);
		}

		/* RPZ TODO need to use INNER csum flag when dealing with
		 * encap? */
		if ((hck_flags & HCK_IPV4_HDRCKSUM_OK) == 0) {
			return (MLS_L3_CKSUM);
		}
	}

	/* IPv6 must not carry extension headers */
	if (meoi->meoi_l3proto == ETHERTYPE_IPV6 &&
	    meoi->meoi_l3hlen != IPV6_HDR_LEN) {
		return (MLS_IPV6_EH);
	}

	/* RPZ TODO need to use INNER csum flag when dealing with
	 * encap? */

	/* The L4 cksum must be valid */
	/*
	 * RPZ BUG What if this packet is for a TCP flow with existing
	 * LRO state? Is that a scenario that can happen?
	 */
	if ((hck_flags & HCK_FULLCKSUM_OK) == 0) {
		return (MLS_L4_CKSUM);
	}

	/*
	 * RPZ BUG It is DEFINITELY a bug to reject TCP packets right
	 * here as this packet could belong to a flow with existing
	 * LRO state, we need to delay this check until after we find
	 * the existing flow so that it can be flushed and we can
	 * maintain proper ordering of packets.
	 */
	if (meoi->meoi_l4proto == IPPROTO_TCP) {
		/* The only TCP option permitted for now is timestamp */
		const uint_t tcp_ts_len =
		    (TCP_MIN_HEADER_LENGTH + TCPOPT_REAL_TS_LEN);

		if (meoi->meoi_l4hlen > tcp_ts_len) {
			return (MLS_TCP_OPTS);
		} else if (meoi->meoi_l4hlen == tcp_ts_len) {
			/*
			 * RPZ DONE Added 'offset' to make sure we are
			 * accessing inner header.
			 */
			const uint32_t *tsp = (const uint32_t *)(mp->b_rptr +
			    offset + meoi->meoi_l2hlen + meoi->meoi_l3hlen +
			    sizeof (tcpha_t));
			if (*tsp != TCPOPT_NOP_NOP_TSTAMP) {
				return (MLS_TCP_OPTS);
			}
		}
	}

	return (MLS_OK);
}

static boolean_t
mac_sw_lro_extract_tcp_ts(const tcpha_t *tcpha,
    const mac_ether_offload_info_t *meoi, uint32_t *tsval, uint32_t *tsecr)
{
	ASSERT(meoi->meoi_flags & MEOI_L4INFO_SET);
	ASSERT3U(meoi->meoi_l4proto, ==, IPPROTO_TCP);

	if (meoi->meoi_l4hlen == TCP_MIN_HEADER_LENGTH) {
		return (B_FALSE);
	}

	const uint32_t *tsp = (const uint32_t *)(tcpha + 1);

	/*
	 * mac_sw_lro_is_suitable() should have already rejected any packets
	 * which had options other than timestamp.
	 */
	ASSERT3U(*tsp, ==, TCPOPT_NOP_NOP_TSTAMP);
	ASSERT3U(meoi->meoi_l4hlen, ==,
	    TCP_MIN_HEADER_LENGTH + TCPOPT_REAL_TS_LEN);

	*tsval = ntohl(tsp[1]);
	*tsecr = ntohl(tsp[2]);
	return (B_TRUE);
}

/* static inline boolean_t */
/* mac_lro_is_full(mac_lro_state_t *lrop, uint_t new_data_len) */
/* { */

/* 	/\* */
/* 	 * RPZ TODO: The data_len check must be diffrent */
/* 	 * for IPv4 vs IPv6, as the former considers the */
/* 	 * header as part of the length, and the later */
/* 	 * does not. */
/* 	 * */
/* 	 * For encap we have to consider outer IPv6 */
/* 	 * length, which includes */
/* 	 * */
/* 	 *  - outer UDP */
/* 	 *  - outer Geneve */
/* 	 *  - inner L2 */
/* 	 *  - inner L3 */
/* 	 *  - inner L4 */
/* 	 *  - data_len (combined payload) */
/* 	 *\/ */
/* 	/\* if (force_commit || *\/ */
/* 	/\*     data_len > IP_MAXPACKET - l->mls_len || *\/ */
/* 	/\*     seq != l->mls_exp_seq || *\/ */

/* 	uint_t remain = IP_MAXPACKET - lrop->mls_len; */
/* 	if (lrop->mls_flags & MLF_GENEVE) { */
/* 		/\* RPZ Maybe pull these from meoi outer since they don't change? *\/ */
/* 		remain -= lrop->mls_encap_udplen; */
/* 		/\* Geneve header len *\/ */
/* 		remain -= lrop->mls_encap_hlen; */

/* 		remain -= inner->meoi_l2hlen; */
/* 		remain -= inner->meoi_l3hlen; */
/* 		remain -= inner->meoi_l4hlen; */
/* } */

/*
 * Perform software LRO on a stream of message blocks that exist in a chain.
 * This is commonly called from soft ring processing after fanout has occurred
 * to a protocol ring. We make the following assumptions only about the message
 * blocks:
 *
 *  o The packet has an IP + L4 header in the first message block. This property
 *    is currently maintained by all callers today.
 *
 *
 *    RPZ TODO: Since I am now doing LRO in SRS processing this is no
 *    longer true. We'll need some way to say if LRO should account for
 *    outer L2 or not. This caused a bug in my new encap lro impl, because
 *    lro commit assumed that b_rptr started at IP.
 *
 *  o The L2 header has already been consumed by the mac_rx path and so the
 *    message blocks b_rptr starts at the IP header.
 *
 *  o We do _not_ assume that we will only encounter TCP data. While callers
 *    today make sure that we have TCP, we should assume that UDP or other types
 *    of IP packets may show up.
 *
 *  o We are given some number of LRO state structures to use.
 *
 * We will join TCP packets together under the following circumstances:
 *
 *  o The packet is TCP
 *  o The TCP packet checksummed has been confirmed by hardware
 *  o The IP checksum, if IPv4, has been confirmed by hardware
 *  o There are no IP options or extensions
 *  o The packets have the same 4-tuple
 *  o We have not already joined more than 64k of data.
 *  o No TCP flags other than ACK are present or PUSH are present.
 *  o TCP Sequence numbers match
 *  o If TCP options are present, the TCP option is the timestamp and we only
 *    see timestamps that are larger than the current. The previous packet must
 *    match the current packet with respect to options.
 *  o The TCP packet isn't an empty ack.
 *  o There is no urgent window set.
 *
 * The combined message block has the following properties in its headers:
 *
 *  o The IP Packet Length value is updated
 *  o (RPZ changed) The IP Checksum header is zeroed
 *  o The TCP header ACK is set to the last ACK seen
 *  o The TCP header flags are set to the combination of seen ACK/PUSH flags.
 *  o The TCP window is set to the last seen TCP window
 *  o If a TCP timestamp is present, the last timestamp is used.
 *
 * Finally, we will store a number of in-use LRO states based upon the passed in
 * state. Because this is occurring after protocol fanout (in most cases where
 * we'd care to multiple software rings), we assume that the likelihood of this
 * being a higher hit rate and therefore will traverse the lro state linearly.
 */
void
mac_sw_lro(mac_lro_state_t *lrop, uint_t lrocnt, mblk_t **mp_chain,
    mblk_t **tailp, int *cntp, size_t *sizep)
{
	mblk_t *mp;
	mblk_t *head = NULL, *tail = NULL;
	mblk_t *free_head = NULL, *free_tail = NULL;

	/* RPZ TODO should not be accessing flags directly here, should be
	 * behind api. */
	/* Check if the chain was already subject to LRO. */
	if ((*mp_chain)->b_datap->db_struioun.cksum.flags & MBLK_SW_LRO) {
		return;
	}

	/* RPZ Overly defensive programming, make these asserts
	 * instead. */
	if (lrop == NULL || lrocnt == 0) {
		return;
	}

	for (uint_t i = 0; i < lrocnt; i++) {
		lrop[i].mls_flags = 0;
	}

	mp = *mp_chain;
	while (mp != NULL) {
		mblk_t *next = mp->b_next;
		mp->b_next = NULL;

		/*
		 * Gather header info from packet. For the case of
		 * non-ecap, only the 'outer' is filled out.
		 */
		mac_ether_offload_info_t *meoi = NULL;
		mac_ether_offload_info_t outer = { 0 };
		mac_ether_offload_info_t inner = { 0 };
		uint32_t flags;

		if (MBLKL(mp) == 0) {
			goto skip;
		}

		/* RPZ This should have already been set at beginning of
		 * Rx SRS processing. */
		mac_ether_offload_info(mp, &outer, &inner);
		mac_hcksum_get(mp, NULL, NULL, NULL, NULL, &flags);
		meoi = &outer;

		/* RPZ for now we only care about IPv6/UDP Geneve encap */
		ip6_t *encap_ip6 = NULL;
		uint32_t encap_ip_ecn;
		udpha_t *encap_udp = NULL;
		/* The offset from beginning to packet to end of last
		 * encap header. */
		uint_t encap_hdrs_len = 0;
		/* The encap header and inner headers that are counted
		 * towards the outer IP data length. */
		uint_t encap_data_len = 0;
		/* RPZ Don't we have bool in mac now? */
		boolean_t is_encap = B_FALSE;

		if (meoi->meoi_tuntype != METT_NONE) {
			/* RPZ Currently only support Geneve. Remove
			 * this VERIFY after done with dev. */
			VERIFY3U(meoi->meoi_tuntype, ==, METT_GENEVE);

			mac_lro_suitable_t s = mac_sw_lro_encap_is_suitable(mp,
			    meoi, flags);
			if (s != MLS_OK) {
				DTRACE_PROBE3(mac__lro__encap__unsuitable,
				    mblk_t *, mp, mac_ether_offload_info *,
				    meoi, mac_lro_suitable_t, s);
			}

			is_encap = B_TRUE;
			encap_ip6 = (ip6_t *)(mp->b_rptr + meoi->meoi_l2hlen);
			encap_ip_ecn = encap_ip6->ip6_vcf;
			encap_udp = (udpha_t *)
			    (mp->b_rptr + meoi->meoi_l2hlen +
			    meoi->meoi_l3hlen);
			/*
			 * RPZ TODO If LRO is called from softring
			 * processing, where the L2 header has been
			 * stripped, then meoi_l2hlen should be 0, and
			 * everything after this should "just work". Need
			 * to write a ktest for this.
			 */
			encap_hdrs_len = meoi->meoi_l2hlen + meoi->meoi_l3hlen +
			    meoi->meoi_l4hlen + meoi->meoi_tunhlen;
			/* RPZ TODO this needs to include any extension
			 * headers in the length (if we allow them for
			 * LRO), we should be able to subtract 40 from
			 * l3hlen */
			encap_data_len = meoi->meoi_l4hlen + meoi->meoi_tunhlen;
			/* RPZ Now that we've read the outer/encap
			 * headers, lets inspect the inner. */
			meoi = &inner;
		}

		/*
		 * At this point, if encap is on the scene, then meoi
		 * = inner. Otherwise, meoi = outer.
		 */

		/*
		 * RPZ ALERT after this point need to remember to add
		 * encap_hdr_len to b_rptr for any reference into the
		 * data, of course I'm assuming all headers are in the
		 * first mblk, hopefully that's true.
		 */
		mac_lro_suitable_t s = mac_sw_lro_is_suitable(mp, encap_hdrs_len,
		    meoi, flags);
		if (s != MLS_OK) {
			DTRACE_PROBE3(mac__lro__unsuitable, mblk_t *,
			    mp, mac_ether_offload_info_t *, meoi,
			    mac_lro_suitable_t, s);
			goto skip;
		}

		const boolean_t is_ipv4 = meoi->meoi_l3proto == ETHERTYPE_IP;
		ipha_t *ip4 = NULL;
		ip6_t *ip6 = NULL;
		uint32_t ip_ecn;
		if (is_ipv4) {
			ip4 = (ipha_t *)(mp->b_rptr + encap_hdrs_len +
			    meoi->meoi_l2hlen);
			ip_ecn = ip4->ipha_type_of_service;
		} else {
			ip6 = (ip6_t *)(mp->b_rptr + encap_hdrs_len +
			    meoi->meoi_l2hlen);
			ip_ecn = ip6->ip6_vcf;
		}

		tcpha_t *tcp = (tcpha_t *)(mp->b_rptr + encap_hdrs_len +
		    meoi->meoi_l2hlen + meoi->meoi_l3hlen);

		/*
		 * RPZ previously we were counting all headers against the
		 * IP_MAXPACKET/data_len calc, but we can exclude the L2
		 * len when not in encap as well as the L3 len when IPv6.
		 *
		 *   hdr_len: Length of inner L2 + L3 + L4 headers.
		 *
		 *   ip_len: Length of inner L3 + L4 headers.
		 *
		 *   data_len: Length of inner TCP payload for this mp.
		 *
		 *   Remember, we are adding payload bytes to
		 *   statically-sized L2/L3/L4 headers.
		 */
		const uint_t hdr_len =
		    meoi->meoi_l2hlen + meoi->meoi_l3hlen + meoi->meoi_l4hlen;
		const uint_t ip_len = meoi->meoi_l3hlen + meoi->meoi_l4hlen;
		const uint_t data_len = meoi->meoi_len - hdr_len;
		/* RPZ NOTE ip_offset is for the inner IP */
		const uint8_t ip_offset = encap_hdrs_len + meoi->meoi_l2hlen;

		boolean_t force_commit = B_FALSE;
		if (tcp != NULL &&
		    ((tcp->tha_flags & ~(TH_ACK | TH_PUSH)) != 0 ||
		    tcp->tha_urp != 0)) {
			force_commit = B_TRUE;
		} else if (data_len == 0) {
			/*
			 * RPZ TODO Can we check data_len earlier?
			 * This applies to pure-ACK packets and we
			 * should minimize the amount of work we do
			 * for them.
			 *
			 * Part of the solution here might be to have
			 * a minimum frame length to even be
			 * considered for LRO, and that would be
			 * checked as early as possible.
			 */

			/*
			 * RPZ TODO We have a few places where we skip
			 * BEFORE checking to see if this mblk matches
			 * an existing LRO flow: that seems like it
			 * could lead to out-of-rder delivery. I guess
			 * it is fine as long as a key property is
			 * held: it must be a packet for which we
			 * would not be able to determine an LRO hash.
			 * E.g. right now that would entail any
			 * non-TCP flows.
			 *
			 * I think this is a problem for some
			 * scenarios. E.g., the is-suitable check can
			 * fail for a TCP packet for which we have a
			 * current flow for, say because it has some
			 * options we don't support. In that case we
			 * need to make sure to commit the current LRO
			 * state for that flow before skipping the
			 * packet.
			 *
			 * I think the only safe way to do this is by
			 * only allowing one LRO flow at a time, the
			 * moment we see a packet for a different flow
			 * or that is not suitable for LRO we commit
			 * the current flow. The issue with this
			 * implementation is that if the various
			 * flows's packets are interleaved well, then
			 * we don't get any benefit, and maybe end up
			 * doing more work for no reason. I need to
			 * ask chatgpt about how linux GRO handles
			 * this.
			 */
			goto skip;
		}

		uint32_t tsval, tsecr;
		const boolean_t ts_valid =
		    mac_sw_lro_extract_tcp_ts(tcp, meoi, &tsval, &tsecr);

		/*
		 * At this point, we have a TCP segment which may or may not be
		 * valid. We can't just skip this and instead have to see if
		 * there's already a record of its flow. There are a few
		 * different cases to consider from here:
		 *
		 * 1) There is no record of the flow. In this case, if its
		 * valid, we'll open a new flow record, otherwise, we'll just
		 * append it as is ('skip' label).
		 *
		 * 2) There is a record for this flow and this packet is invalid
		 * for LRO or there is a mismatch in the sequence numbers or
		 * timestamp data. In that case we need to commit the current
		 * flow's packets, append the committed data to the output
		 * chain, and then append this as is.
		 *
		 * 3) There is a record for this flow and this packet would push
		 * us beyond 64k of payload data. We will commit the current
		 * flow's data and then start a new flow.
		 *
		 * 4) There is a record for this flow and this packet fits in
		 * the current bounds, so append it to the current state.
		 */

		/* !!! REMEMBER THAT MEOI POINTS TO INNER !!! */
		mac_lro_state_t *matched = NULL;
		mac_lro_state_t *l = NULL;
		for (uint_t i = 0; i < lrocnt; i++) {
			l = &lrop[i];

			if ((l->mls_flags & MLF_VALID) == 0) {
				continue;
			}

			/*
			 * RPZ TODO Instead of having all these different
			 * probes below, which requires extra assembly for
			 * setting up arguments for each one, just use one
			 * probe with a reason string/enum.
			 */
			if (((l->mls_flags & MLF_GENEVE) != 0) &&
			    outer.meoi_tuntype != METT_GENEVE) {
				DTRACE_PROBE2(mac__lro__mismatch__encap,
				    mblk_t *, mp, mac_lro_state_t *, l);
				continue;
			}

			if (is_encap) {
				if (!IN6_ARE_ADDR_EQUAL(&encap_ip6->ip6_src,
				    &l->mls_encap_src) ||
				    !IN6_ARE_ADDR_EQUAL(&encap_ip6->ip6_dst,
				    &l->mls_encap_dst)) {
					DTRACE_PROBE2(
					    mac__lro__mismatch__encap_addr,
					    mblk_t *, mp, mac_lro_state_t *, l);
					continue;
				}

				if (encap_udp->uha_src_port != l->mls_encap_lport ||
				    encap_udp->uha_dst_port != l->mls_encap_fport) {
					DTRACE_PROBE2(
						mac__lro__mismatch__encap__port,
						mblk_t *, mp, mac_lro_state_t *, l);
					continue;
				}
			}

			if (((l->mls_flags & MLF_IPV4) != 0) != is_ipv4) {
				DTRACE_PROBE2(mac__lro__mismatch__proto,
				    mblk_t *, mp, mac_lro_state_t *, l);
				continue;
			}
			if (l->mls_lport != tcp->tha_lport ||
			    l->mls_fport != tcp->tha_fport) {
				DTRACE_PROBE2(mac__lro__mismatch__port,
				    mblk_t *, mp, mac_lro_state_t *, l);
				continue;
			}
			if (is_ipv4 &&
			    (ip4->ipha_src != V4_PART_OF_V6(l->mls_src) ||
			    ip4->ipha_dst != V4_PART_OF_V6(l->mls_dst))) {
				DTRACE_PROBE2(mac__lro__mismatch__addr__v4,
				    mblk_t *, mp, mac_lro_state_t *, l);
				continue;
			}
			if (!is_ipv4 &&
			    (!IN6_ARE_ADDR_EQUAL(&ip6->ip6_src, &l->mls_src) ||
			    !IN6_ARE_ADDR_EQUAL(&ip6->ip6_dst, &l->mls_dst))) {
				DTRACE_PROBE2(mac__lro__mismatch__addr__v6,
				    mblk_t *, mp, mac_lro_state_t *, l);
				continue;
			}

			const uint32_t seq = ntohl(tcp->tha_seq);
			const boolean_t ent_ts_valid =
			    (l->mls_flags & MLF_TS_VALID) != 0;

			/*
			 * RPZ TODO: The data_len check must be diffrent
			 * for IPv4 vs IPv6, as the former considers the
			 * header as part of the length, and the later
			 * does not.
			 *
			 * For encap we have to consider outer IPv6
			 * length, which includes
			 *
			 *  - outer UDP
			 *  - outer Geneve
			 *  - inner L2
			 *  - inner L3
			 *  - inner L4
			 *  - data_len (combined payload)
			 *
			 * RPZ TODO For Geneve encap we have to verify
			 * that the options are the same, otherwise we
			 * need to commit the current LRO and start a new
			 * one. This could drag down perf given that I
			 * believe we are sending an MSS option in every
			 * Geneve header?
			 */
			if (force_commit ||
			    /*
			     * RPZ TODO Wel'll want to write a test that
			     * excercises data_len == l->mls_remain.
			     */
			    data_len > l->mls_remain ||
			    seq != l->mls_exp_seq ||
			    ts_valid != ent_ts_valid ||
			    (ts_valid && l->mls_tsval > tsval) ||
			    ip_ecn != l->mls_ip_ecn) {
				DTRACE_PROBE5(mac__lro__force__commit,
				    mblk_t *, mp, mac_lro_state_t *, l,
				    tcpha_t *, tcp, uint_t, data_len,
				    uint16_t, ip_ecn);
				/*
				 * In some cases it could make sense to try and
				 * use this new packet to start a new sequence,
				 * but for the time being, we'll just append
				 * this directly.
				 */

				/*
				 * RPZ Yes, we really should be starting a
				 * new sequence here to maximize batching/perf.
				 *
				 * RPZ TODO 04/22 I think this is the
				 * cause of my out-of-order packets in the
				 * guest, where we hit the LRO size limit,
				 * but then the next packet/mblk (the
				 * current one) is sent as-is instead of
				 * being combined because we are jumping
				 * to `skip` which immeidately adds the
				 * current mblk as a next pointer. The
				 * problem is that skip is overloaded
				 * here, it's main use is to skip
				 * attempting to perform LRO on a given
				 * mblk (because it's unsuitable for
				 * whatever reason), but in this case we
				 * should be starting a new LRO packet.
				 */
				mac_lro_commit(l, &head, &tail);

				if (force_commit) {
					/*
					 * The current packet has a
					 * matching LRO segment, but it is
					 * not eligible for merging.
					 * Commit the current LRO segment,
					 * followed by this packet.
					 */
					goto skip;
				} else {
					/*
					 * The current packet has a
					 * matching LRO segment and is
					 * eligible for merging, but not
					 * as part of the current segment.
					 * Commit the current segment and
					 * initialize a new one starting
					 * with this packet.
					 */
					goto reset;
				}
			}

			/* RPZ TODO NEXT Need to track updates to encap
			 * IPv6 len, encap UDP len */
			DTRACE_PROBE4(mac__lro__append, mblk_t *, mp,
			    mac_lro_state_t *, l, tcpha_t *, tcp,
			    uint_t, data_len);
			l->mls_tcp_ack = tcp->tha_ack;
			l->mls_tcp_window = tcp->tha_win;
			l->mls_remain -= data_len;
			/* l->mls_encap_ip6len += data_len; */
			/* l->mls_encap_udplen += data_len; */
			l->mls_count++;
			l->mls_exp_seq += data_len;
			if (ts_valid) {
				l->mls_tsval = tsval;
				l->mls_tsecr = tsecr;
			}
			l->mls_tcp_flags |= tcp->tha_flags;

			/*
			 * XXX Consider something with a b_cont as not being fit
			 * for inclusion rather than this
			 *
			 * RPZ Part of me agrees with this XXX. If we are
			 * doing LRO at the NIC SRS, then the headers and
			 * initial data should be in the first mblk.
			 * However, that's only because I don't think we
			 * make use of header splitting in any of our
			 * drivers.
			 *
			 * RPZ Had to update this to skip the encap
			 * headers as well, otherwse the resulting mblk is
			 * much too large and its size doesn't match up
			 * with the IP header length.
			 */
			mp->b_rptr += encap_hdrs_len + hdr_len;
			if (MBLKL(mp) == 0) {
				mblk_t *tmp = mp;
				mp = tmp->b_cont;
				VERIFY3P(mp, !=, NULL);
				tmp->b_cont = NULL;
				mac_lro_append_bnext(tmp, &free_head,
				    &free_tail);
			}
			ASSERT3P(mp->b_next, ==, NULL);
			mac_lro_append_bcont(mp, &l->mls_head, &l->mls_tail);
			(*cntp)--;
			ASSERT3S(*cntp, >=, 1);
			/*
			 * RPZ I believe I fixed this so that sizep is
			 * always set.
			 *
			 * sizep may be zero if we're not under bandwidth
			 * control
			 */
			if (*sizep != 0) {
				ASSERT3S(*sizep, >, hdr_len);
				(*sizep) -= hdr_len;
			}
			matched = l;
			break;
		}

		if (matched != NULL) {
			DTRACE_PROBE2(mac__lro__hit, mblk_t *, mp,
			    mac_lro_state_t *, matched);
			/* Processed above */
			mp = next;
			continue;
		} else {
			l = mac_lro_find_free_slot(lrop, lrocnt);
			if (l == NULL) {
				DTRACE_PROBE1(mac__lro__full, mblk_t *, mp);
				/* RPZ TODO This should be a per SRS/LRO
				 * state kstat */
				mac_lro_full++;
				goto skip;
			}
reset:

			l->mls_flags = MLF_VALID |
			    (is_ipv4 ? MLF_IPV4 : 0) |
			    (ts_valid ? MLF_TS_VALID : 0);

			l->mls_remain = IP_MAXPACKET;

			if (outer.meoi_tuntype == METT_GENEVE) {
				l->mls_flags |= MLF_GENEVE;
				l->mls_encap_src = encap_ip6->ip6_src;
				l->mls_encap_dst = encap_ip6->ip6_dst;
				l->mls_encap_lport = encap_udp->uha_src_port;
				l->mls_encap_fport = encap_udp->uha_dst_port;

				VERIFY3U(encap_data_len, >, 0);
				/*
				 * RPZ Use mls_remain to determine
				 * `len` in commit. The len value
				 * represents the value of the encap
				 * IP header length value. Subtracting
				 * from mls_remain is the same as
				 * adding to length. In this case, the
				 * IPv6 payload length should include
				 * the "encap data" (UDP length +
				 * tunnel header len), inner header
				 * lengths, and payload
				 */
				l->mls_remain -= encap_data_len;
				l->mls_remain -= inner.meoi_l2hlen +
				    inner.meoi_l3hlen + inner.meoi_l4hlen +
				    data_len;

				l->mls_outer_l4hlen = outer.meoi_l4hlen;
				l->mls_outer_tunhlen = outer.meoi_tunhlen;
				l->mls_inner_l2hlen = meoi->meoi_l2hlen;
				l->mls_inner_l3hlen = meoi->meoi_l3hlen;
			} else {
				/* VERIFY3U(inner.meoi_flags, ==, 0); */
				/* VERIFY3U(encap_data_len, ==, 0); */

				/*
				 * IPv4 counts its header as part of the
				 * IP length; IPv6 does not.
				 */
				if (is_ipv4) {
					l->mls_remain -= meoi->meoi_l3hlen;
				}

				l->mls_remain -= meoi->meoi_l4hlen + data_len;
				l->mls_outer_l4hlen = 0;
				l->mls_outer_tunhlen = 0;
				l->mls_inner_l2hlen = meoi->meoi_l2hlen;
				l->mls_inner_l3hlen = meoi->meoi_l3hlen;
			}

			l->mls_ip_offset = ip_offset;
			/*
			 * RPZ TODO These encap pointers should be in
			 * the GENEVE if block above.
			 */
			l->mls_encap_ip6 = encap_ip6;
			l->mls_encap_udp = encap_udp;
			mac_lro_append_bcont(mp, &l->mls_head, &l->mls_tail);
			l->mls_tcp = tcp;

			if (is_ipv4) {
				V6_SET_ZERO(l->mls_src);
				V4_PART_OF_V6(l->mls_src) = ip4->ipha_src;
				V6_SET_ZERO(l->mls_dst);
				V4_PART_OF_V6(l->mls_dst) = ip4->ipha_dst;
			} else {
				l->mls_src = ip6->ip6_src;
				l->mls_dst = ip6->ip6_dst;
			}
			l->mls_lport = tcp->tha_lport;
			l->mls_fport = tcp->tha_fport;

			/* l->mls_len = encap_data_len + ip_len + data_len; */
			l->mls_count = 1;
			l->mls_exp_seq = ntohl(tcp->tha_seq) + data_len;
			l->mls_tcp_ack = tcp->tha_ack;
			l->mls_tcp_window = tcp->tha_win;
			l->mls_ip_ecn = ip_ecn;
			l->mls_tsval = tsval;
			l->mls_tsecr = tsecr;
			l->mls_tcp_flags = tcp->tha_flags;

			DTRACE_PROBE3(mac__lro__create, mblk_t *, mp,
			    mac_lro_state_t *, l, tcpha_t *, tcp);

			mp = next;
			continue;
		}

skip:
		DTRACE_PROBE2(mac__lro__skip, mblk_t *, mp,
		    mac_ether_offload_info_t *, &meoi);
		mac_lro_append_bnext(mp, &head, &tail);
		mp = next;
	}

	for (uint_t i = 0; i < lrocnt; i++) {
		if ((lrop[i].mls_flags & MLF_VALID) != 0) {
			mac_lro_commit(&lrop[i], &head, &tail);
		}
	}

#ifdef DEBUG
	mac_lro_verify_chain(&head, &tail);
#endif
	*mp_chain = head;
	*tailp = tail;
	freemsgchain(free_head);
}
