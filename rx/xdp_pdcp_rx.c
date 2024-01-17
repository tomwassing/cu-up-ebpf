/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
// #include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdbool.h>

#include "ciphering.h"
#include "integrity.h"
#include "pdcp_pdu.h"
#include "pdcp_entity_base.h"

const bool ciphering_enabled = false;
const bool integrity_check_enabled = true;

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

int parse_pdcp_header(struct xdp_md *ctx, struct pdcp_data_pdu_header *hdr) {
	uint32_t *data = (void *)(long)ctx->data;
	uint32_t *data_end = (void *)(long)ctx->data_end;


  // check size
  if (data + pdpc_header_size(PDCP_SN) > data_end) {
    // logger.log_error("PDCP header too small. size={}", data_end - data);
    return 0;
  }

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
      return 0;
  }

	return 1;
}

SEC("xdp")
int xdp_pdcp_rx(struct xdp_md *ctx) {
  // Unpack header
  struct pdcp_data_pdu_header hdr;
  if (!parse_pdcp_header(ctx, &hdr)) {
    return XDP_DROP;
  }

  // Calculate RCVD_COUNT:
  uint32_t rcvd_hfn, rcvd_count;
  if ((int64_t)hdr.sn < (int64_t)SN(st.rx_deliv) - (int64_t)pdpc_window_size(PDCP_SN)) {
    rcvd_hfn = HFN(st.rx_deliv) + 1;
  } else if (hdr.sn >= SN(st.rx_deliv) + pdpc_window_size(PDCP_SN)) {
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

  if (integrity_check_enabled) {
    // extract MAC from PDCP SDU trailer
    sec_mac mac;
    uint32_t mac_offset = ctx->data_end - ctx->data - 4;

    for (uint8_t i = 0; i < 4; i++) {
      mac[i] = out[mac_offset + i];
    }

    sec_128_key key = {0};
    bool valid = check_integrity(&ctx->data, &ctx->data_end, rcvd_count, &mac, &key);
    // bpf_printk("valid  mac: %d\n", (int) mac[0]);
    if (!valid) {
      return XDP_DROP;
    }
  }

  // removing PDCP header
  bpf_xdp_adjust_head(ctx, pdpc_header_size(PDCP_SN));

	return XDP_PASS;
}

int main() {
  return 0;
}

char _license[] SEC("license") = "GPL";
