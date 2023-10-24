#include <stdint.h>

/// PDCP Data PDU header
/// Ref: TS 38.323 Sec. 6.2.2
struct pdcp_data_pdu_header {
  uint32_t sn; ///< Sequence number
};


/// PDCP Control PDU header
/// Ref: TS 38.323 Sec. 6.2.3
// struct pdcp_control_pdu_header {
//   pdcp_control_pdu_type cpt; ///< Control PDU type (control PDU only, ignored for data PDUs)
// };