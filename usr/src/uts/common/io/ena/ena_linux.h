#include <sys/stddef.h>

#ifndef _ENA_LINUX_H
#define _ENA_LINUX_H


#define	GENMASK(h, l)	(((~0U) - (1U << (l)) + 1) & (~0U >> (32 - 1 - (h))))
#define	BIT(b)		(1UL << (b))

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

/* ENA operates with 48-bit memory addresses. ena_mem_addr_t */
struct ena_common_mem_addr {
	uint32_t mem_addr_low;

	uint16_t mem_addr_high;

	/* MBZ */
	uint16_t reserved16;
};




#define ENA_ADMIN_RSS_KEY_PARTS              10

struct ena_admin_aq_common_desc {
	/* 11:0 : command_id
	 * 15:12 : reserved12
	 */
	u16 command_id;

	/* as appears in ena_admin_aq_opcode */
	u8 opcode;

	/* 0 : phase
	 * 1 : ctrl_data - control buffer address valid
	 * 2 : ctrl_data_indirect - control buffer address
	 *    points to list of pages with addresses of control
	 *    buffers
	 * 7:3 : reserved3
	 */
	u8 flags;
};

/* used in ena_admin_aq_entry. Can point directly to control data, or to a
 * page list chunk. Used also at the end of indirect mode page list chunks,
 * for chaining.
 */
struct ena_admin_ctrl_buff_info {
	u32 length;

	struct ena_common_mem_addr address;
};

struct ena_linux_admin_sq {
	u16 sq_idx;

	/* 4:0 : reserved
	 * 7:5 : sq_direction - 0x1 - Tx; 0x2 - Rx
	 */
	u8 sq_identity;

	u8 reserved1;
};

struct ena_admin_aq_entry {
	struct ena_admin_aq_common_desc aq_common_descriptor;

	union {
		u32 inline_data_w1[3];

		struct ena_admin_ctrl_buff_info control_buffer;
	} u;

	u32 inline_data_w4[12];
};

struct ena_admin_acq_common_desc {
	/* command identifier to associate it with the aq descriptor
	 * 11:0 : command_id
	 * 15:12 : reserved12
	 */
	u16 command;

	u8 status;

	/* 0 : phase
	 * 7:1 : reserved1
	 */
	u8 flags;

	u16 extended_status;

	/* indicates to the driver which AQ entry has been consumed by the
	 * device and could be reused
	 */
	u16 sq_head_indx;
};

struct ena_admin_acq_entry {
	struct ena_admin_acq_common_desc acq_common_descriptor;

	u32 response_specific_data[14];
};

struct ena_admin_aq_create_sq_cmd {
	struct ena_admin_aq_common_desc aq_common_descriptor;

	/* 4:0 : reserved0_w1
	 * 7:5 : sq_direction - 0x1 - Tx, 0x2 - Rx
	 */
	u8 sq_identity;

	u8 reserved8_w1;

	/* 3:0 : placement_policy - Describing where the SQ
	 *    descriptor ring and the SQ packet headers reside:
	 *    0x1 - descriptors and headers are in OS memory,
	 *    0x3 - descriptors and headers in device memory
	 *    (a.k.a Low Latency Queue)
	 * 6:4 : completion_policy - Describing what policy
	 *    to use for generation completion entry (cqe) in
	 *    the CQ associated with this SQ: 0x0 - cqe for each
	 *    sq descriptor, 0x1 - cqe upon request in sq
	 *    descriptor, 0x2 - current queue head pointer is
	 *    updated in OS memory upon sq descriptor request
	 *    0x3 - current queue head pointer is updated in OS
	 *    memory for each sq descriptor
	 * 7 : reserved15_w1
	 */
	u8 sq_caps_2;

	/* 0 : is_physically_contiguous - Described if the
	 *    queue ring memory is allocated in physical
	 *    contiguous pages or split.
	 * 7:1 : reserved17_w1
	 */
	u8 sq_caps_3;

	/* associated completion queue id. This CQ must be created prior to SQ
	 * creation
	 */
	u16 cq_idx;

	/* submission queue depth in entries */
	u16 sq_depth;

	/* SQ physical base address in OS memory. This field should not be
	 * used for Low Latency queues. Has to be page aligned.
	 */
	struct ena_common_mem_addr sq_ba;

	/* specifies queue head writeback location in OS memory. Valid if
	 * completion_policy is set to completion_policy_head_on_demand or
	 * completion_policy_head. Has to be cache aligned
	 */
	struct ena_common_mem_addr sq_head_writeback;

	u32 reserved0_w7;

	u32 reserved0_w8;
};

struct ena_admin_acq_create_sq_resp_desc {
	struct ena_admin_acq_common_desc acq_common_desc;

	u16 sq_idx;

	u16 reserved;

	/* queue doorbell address as an offset to PCIe MMIO REG BAR */
	u32 sq_doorbell_offset;

	/* low latency queue ring base address as an offset to PCIe MMIO
	 * LLQ_MEM BAR
	 */
	u32 llq_descriptors_offset;

	/* low latency queue headers' memory as an offset to PCIe MMIO
	 * LLQ_MEM BAR
	 */
	u32 llq_headers_offset;
};

struct ena_admin_aq_destroy_sq_cmd {
	struct ena_admin_aq_common_desc aq_common_descriptor;

	struct ena_linux_admin_sq sq;
};

struct ena_admin_acq_destroy_sq_resp_desc {
	struct ena_admin_acq_common_desc acq_common_desc;
};

struct ena_admin_aq_create_cq_cmd {
	struct ena_admin_aq_common_desc aq_common_descriptor;

	/* 4:0 : reserved5
	 * 5 : interrupt_mode_enabled - if set, cq operates
	 *    in interrupt mode, otherwise - polling
	 * 7:6 : reserved6
	 */
	u8 cq_caps_1;

	/* 4:0 : cq_entry_size_words - size of CQ entry in
	 *    32-bit words, valid values: 4, 8.
	 * 7:5 : reserved7
	 */
	u8 cq_caps_2;

	/* completion queue depth in # of entries. must be power of 2 */
	u16 cq_depth;

	/* msix vector assigned to this cq */
	u32 msix_vector;

	/* cq physical base address in OS memory. CQ must be physically
	 * contiguous
	 */
	struct ena_common_mem_addr cq_ba;
};

struct ena_admin_acq_create_cq_resp_desc {
	struct ena_admin_acq_common_desc acq_common_desc;

	u16 cq_idx;

	/* actual cq depth in number of entries */
	u16 cq_actual_depth;

	u32 numa_node_register_offset;

	u32 cq_head_db_register_offset;

	u32 cq_interrupt_unmask_register_offset;
};

struct ena_admin_aq_destroy_cq_cmd {
	struct ena_admin_aq_common_desc aq_common_descriptor;

	u16 cq_idx;

	u16 reserved1;
};

struct ena_admin_acq_destroy_cq_resp_desc {
	struct ena_admin_acq_common_desc acq_common_desc;
};

/* ENA AQ Get Statistics command. Extended statistics are placed in control
 * buffer pointed by AQ entry
 */
struct ena_admin_aq_get_stats_cmd {
	struct ena_admin_aq_common_desc aq_common_descriptor;

	union {
		/* command specific inline data */
		u32 inline_data_w1[3];

		struct ena_admin_ctrl_buff_info control_buffer;
	} u;

	/* stats type as defined in enum ena_admin_get_stats_type */
	u8 type;

	/* stats scope defined in enum ena_admin_get_stats_scope */
	u8 scope;

	u16 reserved3;

	/* queue id. used when scope is specific_queue */
	u16 queue_idx;

	/* device id, value 0xFFFF means mine. only privileged device can get
	 * stats of other device
	 */
	u16 device_id;
};

/* Basic Statistics Command. */
struct ena_admin_basic_stats {
	u32 tx_bytes_low;

	u32 tx_bytes_high;

	u32 tx_pkts_low;

	u32 tx_pkts_high;

	u32 rx_bytes_low;

	u32 rx_bytes_high;

	u32 rx_pkts_low;

	u32 rx_pkts_high;

	u32 rx_drops_low;

	u32 rx_drops_high;

	u32 tx_drops_low;

	u32 tx_drops_high;
};

/* ENI Statistics Command. */
struct ena_admin_eni_stats {
	/* The number of packets shaped due to inbound aggregate BW
	 * allowance being exceeded
	 */
	u64 bw_in_allowance_exceeded;

	/* The number of packets shaped due to outbound aggregate BW
	 * allowance being exceeded
	 */
	u64 bw_out_allowance_exceeded;

	/* The number of packets shaped due to PPS allowance being exceeded */
	u64 pps_allowance_exceeded;

	/* The number of packets shaped due to connection tracking
	 * allowance being exceeded and leading to failure in establishment
	 * of new connections
	 */
	u64 conntrack_allowance_exceeded;

	/* The number of packets shaped due to linklocal packet rate
	 * allowance being exceeded
	 */
	u64 linklocal_allowance_exceeded;
};

struct ena_admin_acq_get_stats_resp {
	struct ena_admin_acq_common_desc acq_common_desc;

	union {
		u64 raw[7];

		struct ena_admin_basic_stats basic_stats;

		struct ena_admin_eni_stats eni_stats;
	} u;
};

struct ena_admin_get_set_feature_common_desc {
	/* 1:0 : select - 0x1 - current value; 0x3 - default
	 *    value
	 * 7:3 : reserved3
	 */
	u8 flags;

	/* as appears in ena_admin_aq_feature_id */
	u8 feature_id;

	/* The driver specifies the max feature version it supports and the
	 * device responds with the currently supported feature version. The
	 * field is zero based
	 */
	u8 feature_version;

	u8 reserved8;
};

struct ena_admin_device_attr_feature_desc {
	u32 impl_id;

	u32 device_version;

	/* bitmap of ena_admin_aq_feature_id, which represents supported
	 * subcommands for the set/get feature admin commands.
	 */
	u32 supported_features;

	u32 reserved3;

	/* Indicates how many bits are used physical address access. */
	u32 phys_addr_width;

	/* Indicates how many bits are used virtual address access. */
	u32 virt_addr_width;

	/* unicast MAC address (in Network byte order) */
	u8 mac_addr[6];

	u8 reserved7[2];

	u32 max_mtu;
};

enum ena_admin_llq_header_location {
	/* header is in descriptor list */
	ENA_ADMIN_INLINE_HEADER                     = 1,
	/* header in a separate ring, implies 16B descriptor list entry */
	ENA_ADMIN_HEADER_RING                       = 2,
};

enum ena_admin_llq_ring_entry_size {
	ENA_ADMIN_LIST_ENTRY_SIZE_128B              = 1,
	ENA_ADMIN_LIST_ENTRY_SIZE_192B              = 2,
	ENA_ADMIN_LIST_ENTRY_SIZE_256B              = 4,
};

enum ena_admin_llq_num_descs_before_header {
	ENA_ADMIN_LLQ_NUM_DESCS_BEFORE_HEADER_0     = 0,
	ENA_ADMIN_LLQ_NUM_DESCS_BEFORE_HEADER_1     = 1,
	ENA_ADMIN_LLQ_NUM_DESCS_BEFORE_HEADER_2     = 2,
	ENA_ADMIN_LLQ_NUM_DESCS_BEFORE_HEADER_4     = 4,
	ENA_ADMIN_LLQ_NUM_DESCS_BEFORE_HEADER_8     = 8,
};

/* packet descriptor list entry always starts with one or more descriptors,
 * followed by a header. The rest of the descriptors are located in the
 * beginning of the subsequent entry. Stride refers to how the rest of the
 * descriptors are placed. This field is relevant only for inline header
 * mode
 */
enum ena_admin_llq_stride_ctrl {
	ENA_ADMIN_SINGLE_DESC_PER_ENTRY             = 1,
	ENA_ADMIN_MULTIPLE_DESCS_PER_ENTRY          = 2,
};

enum ena_admin_accel_mode_feat {
	ENA_ADMIN_DISABLE_META_CACHING              = 0,
	ENA_ADMIN_LIMIT_TX_BURST                    = 1,
};

struct ena_admin_accel_mode_get {
	/* bit field of enum ena_admin_accel_mode_feat */
	u16 supported_flags;

	/* maximum burst size between two doorbells. The size is in bytes */
	u16 max_tx_burst_size;
};

struct ena_admin_accel_mode_set {
	/* bit field of enum ena_admin_accel_mode_feat */
	u16 enabled_flags;

	u16 reserved;
};

struct ena_admin_accel_mode_req {
	union {
		u32 raw[2];

		struct ena_admin_accel_mode_get get;

		struct ena_admin_accel_mode_set set;
	} u;
};

struct ena_admin_feature_llq_desc {
	u32 max_llq_num;

	u32 max_llq_depth;

	/*  specify the header locations the device supports. bitfield of enum
	 * ena_admin_llq_header_location.
	 */
	u16 header_location_ctrl_supported;

	/* the header location the driver selected to use. */
	u16 header_location_ctrl_enabled;

	/* if inline header is specified - this is the size of descriptor list
	 * entry. If header in a separate ring is specified - this is the size
	 * of header ring entry. bitfield of enum ena_admin_llq_ring_entry_size.
	 * specify the entry sizes the device supports
	 */
	u16 entry_size_ctrl_supported;

	/* the entry size the driver selected to use. */
	u16 entry_size_ctrl_enabled;

	/* valid only if inline header is specified. First entry associated with
	 * the packet includes descriptors and header. Rest of the entries
	 * occupied by descriptors. This parameter defines the max number of
	 * descriptors precedding the header in the first entry. The field is
	 * bitfield of enum ena_admin_llq_num_descs_before_header and specify
	 * the values the device supports
	 */
	u16 desc_num_before_header_supported;

	/* the desire field the driver selected to use */
	u16 desc_num_before_header_enabled;

	/* valid only if inline was chosen. bitfield of enum
	 * ena_admin_llq_stride_ctrl
	 */
	u16 descriptors_stride_ctrl_supported;

	/* the stride control the driver selected to use */
	u16 descriptors_stride_ctrl_enabled;

	/* reserved */
	u32 reserved1;

	/* accelerated low latency queues requirement. driver needs to
	 * support those requirements in order to use accelerated llq
	 */
	struct ena_admin_accel_mode_req accel_mode;
};

struct ena_admin_queue_ext_feature_fields {
	u32 max_tx_sq_num;

	u32 max_tx_cq_num;

	u32 max_rx_sq_num;

	u32 max_rx_cq_num;

	u32 max_tx_sq_depth;

	u32 max_tx_cq_depth;

	u32 max_rx_sq_depth;

	u32 max_rx_cq_depth;

	u32 max_tx_header_size;

	/* Maximum Descriptors number, including meta descriptor, allowed for a
	 * single Tx packet
	 */
	u16 max_per_packet_tx_descs;

	/* Maximum Descriptors number allowed for a single Rx packet */
	u16 max_per_packet_rx_descs;
};

struct ena_admin_queue_feature_desc {
	u32 max_sq_num;

	u32 max_sq_depth;

	u32 max_cq_num;

	u32 max_cq_depth;

	u32 max_legacy_llq_num;

	u32 max_legacy_llq_depth;

	u32 max_header_size;

	/* Maximum Descriptors number, including meta descriptor, allowed for a
	 * single Tx packet
	 */
	u16 max_packet_tx_descs;

	/* Maximum Descriptors number allowed for a single Rx packet */
	u16 max_packet_rx_descs;
};

struct ena_admin_set_feature_mtu_desc {
	/* exclude L2 */
	u32 mtu;
};

struct ena_admin_get_extra_properties_strings_desc {
	u32 count;
};

struct ena_admin_get_extra_properties_flags_desc {
	u32 flags;
};

struct ena_admin_set_feature_host_attr_desc {
	/* host OS info base address in OS memory. host info is 4KB of
	 * physically contiguous
	 */
	struct ena_common_mem_addr os_info_ba;

	/* host debug area base address in OS memory. debug area must be
	 * physically contiguous
	 */
	struct ena_common_mem_addr debug_ba;

	/* debug area size */
	u32 debug_area_size;
};

struct ena_admin_feature_intr_moder_desc {
	/* interrupt delay granularity in usec */
	u16 intr_delay_resolution;

	u16 reserved;
};

struct ena_admin_get_feature_link_desc {
	/* Link speed in Mb */
	u32 speed;

	/* bit field of enum ena_admin_link types */
	u32 supported;

	/* 0 : autoneg
	 * 1 : duplex - Full Duplex
	 * 31:2 : reserved2
	 */
	u32 flags;
};

struct ena_admin_feature_aenq_desc {
	/* bitmask for AENQ groups the device can report */
	u32 supported_groups;

	/* bitmask for AENQ groups to report */
	u32 enabled_groups;
};

struct ena_admin_feature_offload_desc {
	/* 0 : TX_L3_csum_ipv4
	 * 1 : TX_L4_ipv4_csum_part - The checksum field
	 *    should be initialized with pseudo header checksum
	 * 2 : TX_L4_ipv4_csum_full
	 * 3 : TX_L4_ipv6_csum_part - The checksum field
	 *    should be initialized with pseudo header checksum
	 * 4 : TX_L4_ipv6_csum_full
	 * 5 : tso_ipv4
	 * 6 : tso_ipv6
	 * 7 : tso_ecn
	 */
	u32 tx;

	/* Receive side supported stateless offload
	 * 0 : RX_L3_csum_ipv4 - IPv4 checksum
	 * 1 : RX_L4_ipv4_csum - TCP/UDP/IPv4 checksum
	 * 2 : RX_L4_ipv6_csum - TCP/UDP/IPv6 checksum
	 * 3 : RX_hash - Hash calculation
	 */
	u32 rx_supported;

	u32 rx_enabled;
};

enum ena_admin_hash_functions {
	ENA_ADMIN_TOEPLITZ                          = 1,
	ENA_ADMIN_CRC32                             = 2,
};

struct ena_admin_feature_rss_flow_hash_control {
	u32 key_parts;

	u32 reserved;

	u32 key[ENA_ADMIN_RSS_KEY_PARTS];
};

struct ena_admin_feature_rss_flow_hash_function {
	/* 7:0 : funcs - bitmask of ena_admin_hash_functions */
	u32 supported_func;

	/* 7:0 : selected_func - bitmask of
	 *    ena_admin_hash_functions
	 */
	u32 selected_func;

	/* initial value */
	u32 init_val;
};

/* RSS flow hash protocols */
enum ena_admin_flow_hash_proto {
	ENA_ADMIN_RSS_TCP4                          = 0,
	ENA_ADMIN_RSS_UDP4                          = 1,
	ENA_ADMIN_RSS_TCP6                          = 2,
	ENA_ADMIN_RSS_UDP6                          = 3,
	ENA_ADMIN_RSS_IP4                           = 4,
	ENA_ADMIN_RSS_IP6                           = 5,
	ENA_ADMIN_RSS_IP4_FRAG                      = 6,
	ENA_ADMIN_RSS_NOT_IP                        = 7,
	/* TCPv6 with extension header */
	ENA_ADMIN_RSS_TCP6_EX                       = 8,
	/* IPv6 with extension header */
	ENA_ADMIN_RSS_IP6_EX                        = 9,
	ENA_ADMIN_RSS_PROTO_NUM                     = 16,
};

/* RSS flow hash fields */
enum ena_admin_flow_hash_fields {
	/* Ethernet Dest Addr */
	ENA_ADMIN_RSS_L2_DA                         = BIT(0),
	/* Ethernet Src Addr */
	ENA_ADMIN_RSS_L2_SA                         = BIT(1),
	/* ipv4/6 Dest Addr */
	ENA_ADMIN_RSS_L3_DA                         = BIT(2),
	/* ipv4/6 Src Addr */
	ENA_ADMIN_RSS_L3_SA                         = BIT(3),
	/* tcp/udp Dest Port */
	ENA_ADMIN_RSS_L4_DP                         = BIT(4),
	/* tcp/udp Src Port */
	ENA_ADMIN_RSS_L4_SP                         = BIT(5),
};

struct ena_admin_proto_input {
	/* flow hash fields (bitwise according to ena_admin_flow_hash_fields) */
	u16 fields;

	u16 reserved2;
};

struct ena_admin_feature_rss_hash_control {
	struct ena_admin_proto_input supported_fields[ENA_ADMIN_RSS_PROTO_NUM];

	struct ena_admin_proto_input selected_fields[ENA_ADMIN_RSS_PROTO_NUM];

	struct ena_admin_proto_input reserved2[ENA_ADMIN_RSS_PROTO_NUM];

	struct ena_admin_proto_input reserved3[ENA_ADMIN_RSS_PROTO_NUM];
};

struct ena_admin_feature_rss_flow_hash_input {
	/* supported hash input sorting
	 * 1 : L3_sort - support swap L3 addresses if DA is
	 *    smaller than SA
	 * 2 : L4_sort - support swap L4 ports if DP smaller
	 *    SP
	 */
	u16 supported_input_sort;

	/* enabled hash input sorting
	 * 1 : enable_L3_sort - enable swap L3 addresses if
	 *    DA smaller than SA
	 * 2 : enable_L4_sort - enable swap L4 ports if DP
	 *    smaller than SP
	 */
	u16 enabled_input_sort;
};

/* enum ena_admin_os_type { */
/* 	ENA_ADMIN_OS_LINUX                          = 1, */
/* 	ENA_ADMIN_OS_WIN                            = 2, */
/* 	ENA_ADMIN_OS_DPDK                           = 3, */
/* 	ENA_ADMIN_OS_FREEBSD                        = 4, */
/* 	ENA_ADMIN_OS_IPXE                           = 5, */
/* 	ENA_ADMIN_OS_ESXI                           = 6, */
/* 	ENA_ADMIN_OS_GROUPS_NUM                     = 6, */
/* }; */

struct ena_admin_host_info {
	/* defined in enum ena_admin_os_type */
	u32 os_type;

	/* os distribution string format */
	u8 os_dist_str[128];

	/* OS distribution numeric format */
	u32 os_dist;

	/* kernel version string format */
	u8 kernel_ver_str[32];

	/* Kernel version numeric format */
	u32 kernel_ver;

	/* 7:0 : major
	 * 15:8 : minor
	 * 23:16 : sub_minor
	 * 31:24 : module_type
	 */
	u32 driver_version;

	/* features bitmap */
	u32 supported_network_features[2];

	/* ENA spec version of driver */
	u16 ena_spec_version;

	/* ENA device's Bus, Device and Function
	 * 2:0 : function
	 * 7:3 : device
	 * 15:8 : bus
	 */
	u16 bdf;

	/* Number of CPUs */
	u16 num_cpus;

	u16 reserved;

	/* 0 : mutable_rss_table_size
	 * 1 : rx_offset
	 * 2 : interrupt_moderation
	 * 3 : rx_buf_mirroring
	 * 4 : rss_configurable_function_key
	 * 31:5 : reserved
	 */
	u32 driver_supported_features;
};

struct ena_admin_rss_ind_table_entry {
	u16 cq_idx;

	u16 reserved;
};

struct ena_admin_feature_rss_ind_table {
	/* min supported table size (2^min_size) */
	u16 min_size;

	/* max supported table size (2^max_size) */
	u16 max_size;

	/* table size (2^size) */
	u16 size;

	/* 0 : one_entry_update - The ENA device supports
	 *    setting a single RSS table entry
	 */
	u8 flags;

	u8 reserved;

	/* index of the inline entry. 0xFFFFFFFF means invalid */
	u32 inline_index;

	/* used for updating single entry, ignored when setting the entire
	 * table through the control buffer.
	 */
	struct ena_admin_rss_ind_table_entry inline_entry;
};

/* When hint value is 0, driver should use it's own predefined value */
struct ena_admin_ena_hw_hints {
	/* value in ms */
	u16 mmio_read_timeout;

	/* value in ms */
	u16 driver_watchdog_timeout;

	/* Per packet tx completion timeout. value in ms */
	u16 missing_tx_completion_timeout;

	u16 missed_tx_completion_count_threshold_to_reset;

	/* value in ms */
	u16 admin_completion_tx_timeout;

	u16 netdev_wd_timeout;

	u16 max_tx_sgl_size;

	u16 max_rx_sgl_size;

	u16 reserved[8];
};

struct ena_admin_get_feat_cmd {
	struct ena_admin_aq_common_desc aq_common_descriptor;

	struct ena_admin_ctrl_buff_info control_buffer;

	struct ena_admin_get_set_feature_common_desc feat_common;

	u32 raw[11];
};

struct ena_admin_queue_ext_feature_desc {
	/* version */
	u8 version;

	u8 reserved1[3];

	union {
		struct ena_admin_queue_ext_feature_fields max_queue_ext;

		u32 raw[10];
	} ;
};

struct ena_admin_get_feat_resp {
	struct ena_admin_acq_common_desc acq_common_desc;

	union {
		u32 raw[14];

		struct ena_admin_device_attr_feature_desc dev_attr;

		struct ena_admin_feature_llq_desc llq;

		struct ena_admin_queue_feature_desc max_queue;

		struct ena_admin_queue_ext_feature_desc max_queue_ext;

		struct ena_admin_feature_aenq_desc aenq;

		struct ena_admin_get_feature_link_desc link;

		struct ena_admin_feature_offload_desc offload;

		struct ena_admin_feature_rss_flow_hash_function flow_hash_func;

		struct ena_admin_feature_rss_flow_hash_input flow_hash_input;

		struct ena_admin_feature_rss_ind_table ind_table;

		struct ena_admin_feature_intr_moder_desc intr_moderation;

		struct ena_admin_ena_hw_hints hw_hints;

		struct ena_admin_get_extra_properties_strings_desc extra_properties_strings;

		struct ena_admin_get_extra_properties_flags_desc extra_properties_flags;
	} u;
};

struct ena_admin_set_feat_cmd {
	struct ena_admin_aq_common_desc aq_common_descriptor;

	struct ena_admin_ctrl_buff_info control_buffer;

	struct ena_admin_get_set_feature_common_desc feat_common;

	union {
		u32 raw[11];

		/* mtu size */
		struct ena_admin_set_feature_mtu_desc mtu;

		/* host attributes */
		struct ena_admin_set_feature_host_attr_desc host_attr;

		/* AENQ configuration */
		struct ena_admin_feature_aenq_desc aenq;

		/* rss flow hash function */
		struct ena_admin_feature_rss_flow_hash_function flow_hash_func;

		/* rss flow hash input */
		struct ena_admin_feature_rss_flow_hash_input flow_hash_input;

		/* rss indirection table */
		struct ena_admin_feature_rss_ind_table ind_table;

		/* LLQ configuration */
		struct ena_admin_feature_llq_desc llq;
	} u;
};

struct ena_admin_set_feat_resp {
	struct ena_admin_acq_common_desc acq_common_desc;

	union {
		u32 raw[14];
	} u;
};

struct ena_admin_aenq_common_desc {
	u16 group;

	u16 syndrome;

	/* 0 : phase
	 * 7:1 : reserved - MBZ
	 */
	u8 flags;

	u8 reserved1[3];

	u32 timestamp_low;

	u32 timestamp_high;
};

/* asynchronous event notification groups */
enum ena_admin_aenq_group {
	ENA_ADMIN_LINK_CHANGE                       = 0,
	ENA_ADMIN_FATAL_ERROR                       = 1,
	ENA_ADMIN_WARNING                           = 2,
	ENA_ADMIN_NOTIFICATION                      = 3,
	ENA_ADMIN_KEEP_ALIVE                        = 4,
	ENA_ADMIN_AENQ_GROUPS_NUM                   = 5,
};

enum ena_admin_aenq_notification_syndrome {
	ENA_ADMIN_SUSPEND                           = 0,
	ENA_ADMIN_RESUME                            = 1,
	ENA_ADMIN_UPDATE_HINTS                      = 2,
};

struct ena_admin_aenq_entry {
	struct ena_admin_aenq_common_desc aenq_common_desc;

	/* command specific inline data */
	u32 inline_data_w4[12];
};

struct ena_admin_aenq_link_change_desc {
	struct ena_admin_aenq_common_desc aenq_common_desc;

	/* 0 : link_status */
	u32 flags;
};

struct ena_admin_aenq_keep_alive_desc {
	struct ena_admin_aenq_common_desc aenq_common_desc;

	u32 rx_drops_low;

	u32 rx_drops_high;

	u32 tx_drops_low;

	u32 tx_drops_high;
};

struct ena_admin_ena_mmio_req_read_less_resp {
	u16 req_id;

	u16 reg_off;

	/* value is valid when poll is cleared */
	u32 reg_val;
};



/*
 * ena_eth_io_defs.h
 */
struct ena_eth_io_tx_desc {
	/* 15:0 : length - Buffer length in bytes, must
	 *    include any packet trailers that the ENA supposed
	 *    to update like End-to-End CRC, Authentication GMAC
	 *    etc. This length must not include the
	 *    'Push_Buffer' length. This length must not include
	 *    the 4-byte added in the end for 802.3 Ethernet FCS
	 * 21:16 : req_id_hi - Request ID[15:10]
	 * 22 : reserved22 - MBZ
	 * 23 : meta_desc - MBZ
	 * 24 : phase
	 * 25 : reserved1 - MBZ
	 * 26 : first - Indicates first descriptor in
	 *    transaction
	 * 27 : last - Indicates last descriptor in
	 *    transaction
	 * 28 : comp_req - Indicates whether completion
	 *    should be posted, after packet is transmitted.
	 *    Valid only for first descriptor
	 * 30:29 : reserved29 - MBZ
	 * 31 : reserved31 - MBZ
	 */
	u32 len_ctrl;

	/* 3:0 : l3_proto_idx - L3 protocol. This field
	 *    required when l3_csum_en,l3_csum or tso_en are set.
	 * 4 : DF - IPv4 DF, must be 0 if packet is IPv4 and
	 *    DF flags of the IPv4 header is 0. Otherwise must
	 *    be set to 1
	 * 6:5 : reserved5
	 * 7 : tso_en - Enable TSO, For TCP only.
	 * 12:8 : l4_proto_idx - L4 protocol. This field need
	 *    to be set when l4_csum_en or tso_en are set.
	 * 13 : l3_csum_en - enable IPv4 header checksum.
	 * 14 : l4_csum_en - enable TCP/UDP checksum.
	 * 15 : ethernet_fcs_dis - when set, the controller
	 *    will not append the 802.3 Ethernet Frame Check
	 *    Sequence to the packet
	 * 16 : reserved16
	 * 17 : l4_csum_partial - L4 partial checksum. when
	 *    set to 0, the ENA calculates the L4 checksum,
	 *    where the Destination Address required for the
	 *    TCP/UDP pseudo-header is taken from the actual
	 *    packet L3 header. when set to 1, the ENA doesn't
	 *    calculate the sum of the pseudo-header, instead,
	 *    the checksum field of the L4 is used instead. When
	 *    TSO enabled, the checksum of the pseudo-header
	 *    must not include the tcp length field. L4 partial
	 *    checksum should be used for IPv6 packet that
	 *    contains Routing Headers.
	 * 20:18 : reserved18 - MBZ
	 * 21 : reserved21 - MBZ
	 * 31:22 : req_id_lo - Request ID[9:0]
	 */
	u32 meta_ctrl;

	u32 buff_addr_lo;

	/* address high and header size
	 * 15:0 : addr_hi - Buffer Pointer[47:32]
	 * 23:16 : reserved16_w2
	 * 31:24 : header_length - Header length. For Low
	 *    Latency Queues, this fields indicates the number
	 *    of bytes written to the headers' memory. For
	 *    normal queues, if packet is TCP or UDP, and longer
	 *    than max_header_size, then this field should be
	 *    set to the sum of L4 header offset and L4 header
	 *    size(without options), otherwise, this field
	 *    should be set to 0. For both modes, this field
	 *    must not exceed the max_header_size.
	 *    max_header_size value is reported by the Max
	 *    Queues Feature descriptor
	 */
	u32 buff_addr_hi_hdr_sz;
};

struct ena_eth_io_tx_meta_desc {
	/* 9:0 : req_id_lo - Request ID[9:0]
	 * 11:10 : reserved10 - MBZ
	 * 12 : reserved12 - MBZ
	 * 13 : reserved13 - MBZ
	 * 14 : ext_valid - if set, offset fields in Word2
	 *    are valid Also MSS High in Word 0 and bits [31:24]
	 *    in Word 3
	 * 15 : reserved15
	 * 19:16 : mss_hi
	 * 20 : eth_meta_type - 0: Tx Metadata Descriptor, 1:
	 *    Extended Metadata Descriptor
	 * 21 : meta_store - Store extended metadata in queue
	 *    cache
	 * 22 : reserved22 - MBZ
	 * 23 : meta_desc - MBO
	 * 24 : phase
	 * 25 : reserved25 - MBZ
	 * 26 : first - Indicates first descriptor in
	 *    transaction
	 * 27 : last - Indicates last descriptor in
	 *    transaction
	 * 28 : comp_req - Indicates whether completion
	 *    should be posted, after packet is transmitted.
	 *    Valid only for first descriptor
	 * 30:29 : reserved29 - MBZ
	 * 31 : reserved31 - MBZ
	 */
	u32 len_ctrl;

	/* 5:0 : req_id_hi
	 * 31:6 : reserved6 - MBZ
	 */
	u32 word1;

	/* 7:0 : l3_hdr_len
	 * 15:8 : l3_hdr_off
	 * 21:16 : l4_hdr_len_in_words - counts the L4 header
	 *    length in words. there is an explicit assumption
	 *    that L4 header appears right after L3 header and
	 *    L4 offset is based on l3_hdr_off+l3_hdr_len
	 * 31:22 : mss_lo
	 */
	u32 word2;

	u32 reserved;
};

struct ena_eth_io_tx_cdesc {
	/* Request ID[15:0] */
	u16 req_id;

	u8 status;

	/* flags
	 * 0 : phase
	 * 7:1 : reserved1
	 */
	u8 flags;

	u16 sub_qid;

	u16 sq_head_idx;
};

struct ena_eth_io_rx_desc {
	/* In bytes. 0 means 64KB */
	u16 length;

	/* MBZ */
	u8 reserved2;

	/* 0 : phase
	 * 1 : reserved1 - MBZ
	 * 2 : first - Indicates first descriptor in
	 *    transaction
	 * 3 : last - Indicates last descriptor in transaction
	 * 4 : comp_req
	 * 5 : reserved5 - MBO
	 * 7:6 : reserved6 - MBZ
	 */
	u8 ctrl;

	u16 req_id;

	/* MBZ */
	u16 reserved6;

	u32 buff_addr_lo;

	u16 buff_addr_hi;

	/* MBZ */
	u16 reserved16_w3;
};

/* 4-word format Note: all ethernet parsing information are valid only when
 * last=1
 */
struct ena_eth_io_rx_cdesc_base {
	/* 4:0 : l3_proto_idx
	 * 6:5 : src_vlan_cnt
	 * 7 : reserved7 - MBZ
	 * 12:8 : l4_proto_idx
	 * 13 : l3_csum_err - when set, either the L3
	 *    checksum error detected, or, the controller didn't
	 *    validate the checksum. This bit is valid only when
	 *    l3_proto_idx indicates IPv4 packet
	 * 14 : l4_csum_err - when set, either the L4
	 *    checksum error detected, or, the controller didn't
	 *    validate the checksum. This bit is valid only when
	 *    l4_proto_idx indicates TCP/UDP packet, and,
	 *    ipv4_frag is not set. This bit is valid only when
	 *    l4_csum_checked below is set.
	 * 15 : ipv4_frag - Indicates IPv4 fragmented packet
	 * 16 : l4_csum_checked - L4 checksum was verified
	 *    (could be OK or error), when cleared the status of
	 *    checksum is unknown
	 * 23:17 : reserved17 - MBZ
	 * 24 : phase
	 * 25 : l3_csum2 - second checksum engine result
	 * 26 : first - Indicates first descriptor in
	 *    transaction
	 * 27 : last - Indicates last descriptor in
	 *    transaction
	 * 29:28 : reserved28
	 * 30 : buffer - 0: Metadata descriptor. 1: Buffer
	 *    Descriptor was used
	 * 31 : reserved31
	 */
	u32 status;

	u16 length;

	u16 req_id;

	/* 32-bit hash result */
	u32 hash;

	u16 sub_qid;

	u8 offset;

	u8 reserved;
};

/* 8-word format */
struct ena_eth_io_rx_cdesc_ext {
	struct ena_eth_io_rx_cdesc_base base;

	u32 buff_addr_lo;

	u16 buff_addr_hi;

	u16 reserved16;

	u32 reserved_w6;

	u32 reserved_w7;
};

struct ena_eth_io_intr_reg {
	/* 14:0 : rx_intr_delay
	 * 29:15 : tx_intr_delay
	 * 30 : intr_unmask
	 * 31 : reserved
	 */
	u32 intr_control;
};

struct ena_eth_io_numa_node_cfg_reg {
	/* 7:0 : numa
	 * 30:8 : reserved
	 * 31 : enabled
	 */
	u32 numa_cfg;
};

#endif









