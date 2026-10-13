/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * HMAC states in the key layout of the Fortinet CP7 crypto engine and of
 * the NP4Lite IPsec engine (FortiSOC1, FortiSOC2)
 *
 * The crypto engine (CP7) and the IPsec engine of the network processor
 * both take HMAC keys as the two states after one block of key ^ ipad and
 * key ^ opad: big-endian words for SHA-1 and SHA-256, little-endian words
 * for MD5. These helpers write them into a key block of FCP_HMAC_KB_SIZE
 * bytes at the offsets of the crypto engine: the inner state at
 * FCP_HMAC_KB_IN, the outer one at FCP_HMAC_KB_OUT (MD5, SHA-1) or
 * FCP_HMAC_KB_SHA256_OUT (SHA-256). Nothing else of the block is written.
 */
#ifndef __LINUX_SOC_FORTINET_CP_HMAC_H
#define __LINUX_SOC_FORTINET_CP_HMAC_H

#include <crypto/md5.h>
#include <crypto/sha1.h>
#include <crypto/sha2.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/unaligned.h>

#define FCP_HMAC_KB_IN		0x20
#define FCP_HMAC_KB_OUT		0x34
#define FCP_HMAC_KB_SHA256_OUT	0x40
#define FCP_HMAC_KB_SIZE	96

static inline void fcp_hmac_sha1_states(u8 *kb, const u8 *key,
					unsigned int keylen)
{
	struct hmac_sha1_key hk;
	unsigned int i;

	hmac_sha1_preparekey(&hk, key, keylen);
	for (i = 0; i < ARRAY_SIZE(hk.istate.h); i++) {
		put_unaligned_be32(hk.istate.h[i],
				   kb + FCP_HMAC_KB_IN + 4 * i);
		put_unaligned_be32(hk.ostate.h[i],
				   kb + FCP_HMAC_KB_OUT + 4 * i);
	}
	memzero_explicit(&hk, sizeof(hk));
}

static inline void fcp_hmac_md5_states(u8 *kb, const u8 *key,
				       unsigned int keylen)
{
	struct hmac_md5_key hk;
	unsigned int i;

	hmac_md5_preparekey(&hk, key, keylen);
	for (i = 0; i < ARRAY_SIZE(hk.istate.h); i++) {
		put_unaligned_le32(hk.istate.h[i],
				   kb + FCP_HMAC_KB_IN + 4 * i);
		put_unaligned_le32(hk.ostate.h[i],
				   kb + FCP_HMAC_KB_OUT + 4 * i);
	}
	memzero_explicit(&hk, sizeof(hk));
}

/* FortiSOC2: big-endian words, 32 bytes each, the outer ones at 0x40. */
static inline void fcp_hmac_sha256_states(u8 *kb, const u8 *key,
					  unsigned int keylen)
{
	struct hmac_sha256_key hk;
	unsigned int i;

	hmac_sha256_preparekey(&hk, key, keylen);
	for (i = 0; i < ARRAY_SIZE(hk.key.istate.h); i++) {
		put_unaligned_be32(hk.key.istate.h[i],
				   kb + FCP_HMAC_KB_IN + 4 * i);
		put_unaligned_be32(hk.key.ostate.h[i],
				   kb + FCP_HMAC_KB_SHA256_OUT + 4 * i);
	}
	memzero_explicit(&hk, sizeof(hk));
}

#endif /* __LINUX_SOC_FORTINET_CP_HMAC_H */
