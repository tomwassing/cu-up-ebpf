#include <stdint.h>
#include <stdio.h> 

#include "s3g.h"

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))


typedef uint8_t sec_128_key[16];

enum ciphering_algorithm
{
    nea0,
    nea1,
    nea2,
    nea3
};

enum security_direction {
    uplink = 0,
    downlink = 1
};

const enum ciphering_algorithm cipher_algo = nea1;

uint32_t* cipher_decrypt(uint32_t* data, uint32_t* data_end, uint32_t count)
{

    switch (cipher_algo)
    {
    case nea0:
        return data;
    case nea1:
        // return security_nea1(sec_cfg.k_128_enc, count, bearer_id, uplink, data, data_end, data);
        return NULL;
    default:
        return NULL;
    }
}

uint32_t* security_nea1(const sec_128_key key,
                   uint32_t count,
                   uint8_t bearer,
                   enum security_direction direction,
                   uint32_t* msg_begin,
                   uint32_t* msg_end,
                   uint32_t msg_len)
{
    s3g_state state, *state_ptr;
    uint32_t k[] = {0, 0, 0, 0};
    uint32_t iv[] = {0, 0, 0, 0};
    int32_t i;
    uint32_t msg_len_block_8, msg_len_block_32;
    uint32_t len = msg_end - msg_begin;

    state_ptr = &state;
    msg_len_block_8 = (msg_len + 7) / 8;
    msg_len_block_32 = (msg_len + 31) / 32;

    uint32_t ks[msg_len_block_32];

    uint32_t output_size = (msg_len_block_32 - 1) + MAX(0, msg_len_block_8 - (msg_len_block_32 - 1) * 4);
    uint32_t msg_out[output_size];
    
    if (msg_len_block_8 <= len)
    {
        // Transform key
        for (i = 3; i >= 0; i--)
        {
            k[i] = (key[4 * (3 - i) + 0] << 24) | (key[4 * (3 - i) + 1] << 16) | (key[4 * (3 - i) + 2] << 8) |
                   (key[4 * (3 - i) + 3]);
        }

        // Construct iv
        iv[3] = count;
        iv[2] = ((bearer & 0x1f) << 27) | ((((uint8_t) (direction)) & 0x01) << 26);
        iv[1] = iv[3];
        iv[0] = iv[2];

        // Initialize keystream
        s3g_initialize(state_ptr, k, iv);

        // Generate keystream
        s3g_generate_keystream(state_ptr, msg_len_block_32, ks);

        // Generate output except last block
        for (i = 0; i < (int32_t)msg_len_block_32 - 1; i++)
        {
            msg_out[i] = (*msg_begin++ ^ ((ks[i] >> 24) & 0xff));
            msg_out[i] = (*msg_begin++ ^ ((ks[i] >> 16) & 0xff));
            msg_out[i] = (*msg_begin++ ^ ((ks[i] >> 8) & 0xff));
            msg_out[i] = (*msg_begin++ ^ ((ks[i]) & 0xff));
        }

        // process last bytes
        for (i = (msg_len_block_32 - 1) * 4; i < (int32_t)msg_len_block_8; i++)
        {
            msg_out[i] = (*msg_begin++ ^ ((ks[i / 4] >> ((3 - (i % 4)) * 8)) & 0xff));
        }

        // Zero tailing bits
        // zero_tailing_bits(msg_out.back(), msg_len);

        // Clean up
        // free(ks);
        // s3g_deinitialize(state_ptr);
    }

    return msg_out;
}

