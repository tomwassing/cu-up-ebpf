/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "pdcp_pdu.h"

enum PDCP_SIZE {B12 = 12, B18 = 18};
#define PDCP_SN = B12;

// https://github.com/srsran/srsRAN_Project/blob/5e6f50a202c6efa671d5b231d7c911dc6c3d86ed/lib/pdcp/pdcp_entity_tx_rx_base.h#L35
int pdpc_header_size(enum PDCP_SIZE type) {
	return (type == B12) ? 2 : 3;
}

int pdpc_window_size(enum PDCP_SIZE type) {
	return (type == B12) ? 2048 : 131072;
}

int parse_pdcp_header(struct xdp_md *ctx, struct pdcp_data_pdu_header *hdr) {
	enum PDCP_SIZE curr = B12;

	__u32 *data = (void *)(long)ctx->data;
	__u32 *data_end = (void *)(long)ctx->data_end;

	switch (curr) {
    case B12:
      hdr->sn = (*data & 0x0fU) << 8U; // first 4 bits SN
      ++data;
      hdr->sn |= (*data & 0xffU); // last 8 bits SN
      ++data;
      break;
    case B18:
      hdr->sn = (*data & 0x03U) << 16U; // first 2 bits SN
      ++data;
      hdr->sn |= (*data & 0xffU) << 8U; // middle 8 bits SN
      ++data;
      hdr->sn |= (*data & 0xffU); // last 8 bits SN
      ++data;
      break;
    default:
      // logger.log_error("Invalid SN size config. sn_size={}", cfg.sn_size);
      return 0;
  }

	return 1;
}

SEC("xdp")
int  xdp_prog_simple(struct xdp_md *ctx) {

  struct pdcp_data_pdu_header hdr;
  if (!parse_pdcp_header(ctx, &hdr)) {
    return XDP_DROP;
  }

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
