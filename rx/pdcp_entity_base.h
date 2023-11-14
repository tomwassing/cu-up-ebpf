#include <stdint.h>

enum pdcp_size {B12 = 12, B18 = 18};

const enum pdcp_size PDCP_SN = B12; 

// https://github.com/srsran/srsRAN_Project/blob/5e6f50a202c6efa671d5b231d7c911dc6c3d86ed/lib/pdcp/pdcp_entity_tx_rx_base.h#L35
int pdpc_header_size(enum pdcp_size type) {
	return (type == B12) ? 2 : 3;
}

int pdpc_window_size(enum pdcp_size type) {
	return (type == B12) ? 2048 : 131072;
}


uint8_t pdcp_sn_size_to_uint(enum pdcp_size sn_size) {
    return (uint8_t) sn_size;
}

uint32_t pdcp_compute_sn(uint32_t count, enum pdcp_size sn_size)
{
  return count & (0xffffffffU >> (32U - pdcp_sn_size_to_uint(sn_size)));
}

uint32_t pdcp_compute_hfn(uint32_t count, enum pdcp_size sn_size)
{
  return (count >> pdcp_sn_size_to_uint(sn_size));
}

uint32_t pdcp_compute_count(uint32_t hfn, uint32_t sn, enum pdcp_size sn_size)
{
  return (hfn << pdcp_sn_size_to_uint(sn_size)) | sn;
}

uint32_t SN(uint32_t count) { 
    return pdcp_compute_sn(count, PDCP_SN); 
}

uint32_t HFN(uint32_t count) { 
    return pdcp_compute_hfn(count, PDCP_SN);
}

uint32_t COUNT(uint32_t hfn, uint32_t sn) {
    return pdcp_compute_count(hfn, sn, PDCP_SN);
}