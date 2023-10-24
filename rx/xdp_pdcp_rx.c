/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdbool.h>

#include "ciphering.h"
#include "pdcp_pdu.h"
#include "pdcp_entity_base.h"

const bool ciphering_enabled = true;

/// PDCP RX state variables,
/// TS 38.323, section 7.1
struct pdcp_rx_state {
  /// RX_NEXT indicates the COUNT value of the next PDCP SDU expected to be received.
  uint32_t rx_next;
  /// RX_DELIV indicates the COUNT value of the first PDCP SDU not delivered to the upper layers, but still
  /// waited for.
  uint32_t rx_deliv;
  /// RX_REORD indicates the COUNT value following the COUNT value associated with the PDCP Data PDU which
  /// triggered t-Reordering.
  uint32_t rx_reord;
};

struct pdcp_rx_state st = {
  .rx_next = 0,
  .rx_deliv = 0,
  .rx_reord = 0
};

bool parse_pdcp_header(struct xdp_md *ctx, struct pdcp_data_pdu_header *hdr) {
	uint32_t *data = (void *)(long)ctx->data;
	uint32_t *data_end = (void *)(long)ctx->data_end;

	switch (PDCP_SN) {
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
      return false;
  }

	return true;
}

SEC("xdp")
int  xdp_prog_simple(struct xdp_md *ctx) {

  // Unpack header
  struct pdcp_data_pdu_header hdr;
  if (!parse_pdcp_header(ctx, &hdr)) {
    return XDP_DROP;
  }

  // Calculate RCVD_COUNT:
  uint32_t rcvd_hfn, rcvd_count;
  if ((int64_t)hdr.sn < (int64_t)SN(st.rx_deliv) - (int64_t)window_size(PDCP_SN)) {
    rcvd_hfn = HFN(st.rx_deliv) + 1;
  } else if (hdr.sn >= SN(st.rx_deliv) + window_size(PDCP_SN)) {
    rcvd_hfn = HFN(st.rx_deliv) - 1;
  } else {
    rcvd_hfn = HFN(st.rx_deliv);
  }
  rcvd_count = COUNT(rcvd_hfn, hdr.sn);

  // TODO: check COUNT and notifiy RRC.

  // Deciphering
  uint32_t* out;
  if (ciphering_enabled) {
    out = cipher_decrypt(&ctx->data, &ctx->data_end, rcvd_count);
  } else {
    out = &ctx->data;
  }

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
