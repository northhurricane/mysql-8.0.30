/* Copyright 2019, Tencent Technology (Shenzhen) Co Ltd
 
 This file is part of the Tencent SM (Lite Version) Library.
 
 The Tencent SM (Lite Version) Library is free software; you can redistribute it and/or modify
 it under the terms of either:
 
 * the GNU Lesser General Public License as published by the Free
 Software Foundation; either version 3 of the License, or (at your
 option) any later version.
 
 or
 
 * the GNU General Public License as published by the Free Software
 Foundation; either version 2 of the License, or (at your option) any
 later version.
 
 or both in parallel, as here.
 
 The Tencent SM (Lite Version) Library is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 for more details.
 
 You should have received copies of the GNU General Public License and the
 GNU Lesser General Public License along with the Tencent SM (Lite Version) Library.  If not,
 see https://www.gnu.org/licenses/.  */
#include "../include/tc_sm4.h"
#include "../include/tc_sm4_lcl.h"

static uint32_t FK[4] = {
	0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc,
};

static uint32_t CK[32] = {
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
};

#define ENC_ROUND(x0, x1, x2, x3, x4, i)    \
    x4 = x1 ^ x2 ^ x3 ^ *(CK + i);        \
    t0 = SMS4_KEY_T1[(uint8_t)x4];      \
    x4 >>= 8;            \
    x0 ^= t0;            \
    t0 = SMS4_KEY_T2[(uint8_t)x4];      \
    x4 >>= 8;            \
    x0 ^= t0;            \
    t0 = SMS4_KEY_T3[(uint8_t)x4];      \
    x4 >>= 8;            \
    x0 ^= t0;            \
    t1 = SMS4_KEY_T4[x4];          \
    x4 = x0 ^ t1;          \
    *(rk + i) = x4

#define DEC_ROUND(x0, x1, x2, x3, x4, i)    \
    x4 = x1 ^ x2 ^ x3 ^ *(CK + i);        \
    t0 = SMS4_KEY_T1[(uint8_t)x4];      \
    x4 >>= 8;            \
    x0 ^= t0;            \
    t0 = SMS4_KEY_T2[(uint8_t)x4];      \
    x4 >>= 8;            \
    x0 ^= t0;            \
    t0 = SMS4_KEY_T3[(uint8_t)x4];      \
    x4 >>= 8;            \
    x0 ^= t0;            \
    t1 = SMS4_KEY_T4[x4];          \
    x4 = x0 ^ t1;          \
    *(rk + 31 - i) = x4

extern const uint32_t SMS4_KEY_T1[256];
extern const uint32_t SMS4_KEY_T2[256];
extern const uint32_t SMS4_KEY_T3[256];
extern const uint32_t SMS4_KEY_T4[256];


void tcsm_sms4_set_encrypt_key(tcsm_sms4_key_t *key, const unsigned char *user_key)
{
	uint32_t *rk = key->rk;
	uint32_t x0, x1, x2, x3, x4;

	x0 = GET32(user_key     ) ^ FK[0];
	x1 = GET32(user_key  + 4) ^ FK[1];
	x2 = GET32(user_key  + 8) ^ FK[2];
	x3 = GET32(user_key + 12) ^ FK[3];

#define ROUND ENC_ROUND
	uint32_t t0, t1;
	ROUNDS(x0, x1, x2, x3, x4);

	x0 = x1 = x2 = x3 = x4 = 0;
}

void tcsm_sms4_set_decrypt_key(tcsm_sms4_key_t *key, const unsigned char *user_key)
{
	uint32_t *rk = key->rk;
	uint32_t x0, x1, x2, x3, x4;	

	x0 = GET32(user_key     ) ^ FK[0];
	x1 = GET32(user_key  + 4) ^ FK[1];
	x2 = GET32(user_key  + 8) ^ FK[2];
	x3 = GET32(user_key + 12) ^ FK[3];

#undef ROUND
#define ROUND DEC_ROUND
	uint32_t t0, t1;
	ROUNDS(x0, x1, x2, x3, x4);
	
	x0 = x1 = x2 = x3 = x4 = 0;
}
