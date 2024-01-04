#include "s3g.h"

enum integrity_algorithm
{
    nia0,
    nia1,
    nia2,
    nia3
};

const enum integrity_algorithm integrity_algo = nia1;
const int K_128_Key = 1;

struct nia1_params
{
    sec_mac mac;
    sec_128_key key;
    uint32_t count;
    uint8_t bearer;
    enum security_direction direction;
    uint32_t *msg_begin;
    uint32_t *msg_end;
    uint32_t msg_len;
};

void security_nia1(sec_mac *mac, struct nia1_params *params)
{
    // FIXME for now we copy the byte buffer to a contiguous piece of memory.
    // This will be fixed later.
    //   std::vector<uint8_t> continuous_buf;
    uint32_t len = params->msg_end - params->msg_begin;
    //   continuous_buf.reserve(len);

    // for (uint32_t i = 0; i < len; i++)
    // {
    //     continuous_buf.push_back(*msg_begin);
    //     msg_begin++;
    // }

    if ((params->msg_len + 7) / 8 <= len)
    {
        struct f9_params f9_params = {
            .key = params->key,
            .count = params->count,
            .fresh = params->bearer << 27,
            .dir = params->direction,
            .data = params->msg_begin,
            .length = params->msg_len
        };

        s3g_f9(mac, &f9_params);
        // s3g_f9(mac, key.data(), count, bearer << 27, static_cast<uint8_t>(direction), continuous_buf.data(), msg_len);
    }
}

bool check_integrity(uint32_t *data, uint32_t *data_end, uint32_t count, sec_mac *mac)
{
    sec_mac mac_exp;
    sec_128_key key;

    struct nia1_params params = {
        .key = key,
        .count = count,
        .bearer = 0,
        .direction = uplink,
        .msg_begin = data,
        .msg_end = data_end,
        .msg_len = data_end - data
    };

    switch (integrity_algo)
    {
    case nia0:
        return true;
    case nia1:
        security_nia1(&mac_exp, &params);
        break;
    }

    if (integrity_algo != nia0) {
        for (uint8_t i = 0; i < 4; i++) {
            if (*mac[i] != mac_exp[i]) {
                return false;
            }
        }
    }

    return true;
}