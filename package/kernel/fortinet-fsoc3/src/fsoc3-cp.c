// SPDX-License-Identifier: GPL-2.0-only
/*
 * Fortinet FortiSOC3 symmetric crypto engine ("vpn" engine): cbc(aes),
 * cbc(des), cbc(des3_ede), authenc(hmac(md5|sha1|sha256|sha384|sha512),
 * cbc(aes|des3_ede)), rfc4106(gcm(aes)) and gcm(aes) for the crypto API
 *
 * Established on the FortiGate 100E (bring-up sessions 8-12, and the vendor
 * firmware for the queue settings):
 *
 * The engine takes the descriptors of the CP7 engine of the FortiSOC1/2
 * (fortinet-cp7): 64 bytes, w0 = length | offset (words) << 16 | command
 * << 24 (hash selector in bits 15 and 22), w2 = source, w3 = destination,
 * bytes 16-31 = IV, w8 = key block; command = cipher | hash | decrypt (bit
 * 0); the same key block (cipher key at 0, AES decryption key as the round
 * keys Nr and Nr - 1, HMAC states from 0x20, raw HMAC key there for
 * SHA-384/512); an authenticated descriptor works in place, the ESP way,
 * the ICV written after the text. Differences with the CP7:
 *  - the descriptors are fed through host TX queue 16 of the NP6Lite queue
 *    fabric (vendor name vpntx_0, block 0xf5018000): ring base with the
 *    upper address byte 0x27, size, head (written to submit), done and
 *    processed pointers (read); queue control 0x11 (enable, per packet
 *    write-back) and the DMA parameters of the vendor firmware;
 *  - word 1 is not a status the engine writes but a flag word: bit 0 makes
 *    the engine report the completion (the processed pointer follows the
 *    done one); without it the queue stops after four descriptors;
 *  - no per-descriptor status reaches the host here (the vendor firmware
 *    gets it through the network processor). A descriptor the engine
 *    rejects leaves a nonzero command check status in its debug register
 *    (sub_eng txpci_dbg1 bits 19:9), read after each descriptor. A failed
 *    ICV check is not reported at all: an AEAD decryption is checked by
 *    encrypting the plaintext again on the engine (CBC gives back the same
 *    ciphertext) and comparing the ICV it computes with the one received;
 *    the plaintext is only copied out when they match;
 *  - HMAC-SHA-384 is right (wrong on the FortiSOC2);
 *  - AES-GCM, the IPsec way (rfc4106(gcm(aes))): command AES | 0x08 with
 *    bit 23 of w0, offset 4 words over the ESP header and the 8-byte IV
 *    of the packet (the IV the engine uses is the one of the descriptor),
 *    the AES key at 0 of the key block, the hash key H = E(K, 0^128) at
 *    0x20, the 4-byte salt at 0x30; J0 = salt | IV | 1, GHASH over the 8
 *    bytes of ESP header and the ciphertext, a 16-byte tag after the text.
 *    Text lengths must be multiples of 4; ESN (12 bytes of AD) is refused.
 *    Other GCM requests are fitted to that layout (gcm(aes): 12-byte IV
 *    = salt | descriptor IV): AD of up to 8 bytes goes zero-padded in the
 *    place of the ESP header, a text whose length is not a multiple of 4
 *    is padded to one; GHASH being linear, the tag is then corrected in
 *    software (pad bytes of the last ciphertext block times H^2, the
 *    difference of the length blocks times H). Tags shorter than 16 bytes
 *    are the truncated tag.
 * Not found on this engine: CTR (the GCM counter starts at 2), ECB, hash
 * only.
 *
 * One descriptor is in flight at a time, polled (the interrupts of the
 * queue are not established), under a spinlock: requests are processed
 * synchronously (also from softirq, IPsec). Buffers go through a bounce
 * area of coherent DMA memory, cleaned and invalidated from the outer
 * cache around each descriptor (the ACP profiles are left as the boot
 * loader set them on the 100E). Each ring slot has its own key block, so
 * two consecutive descriptors never share a key address (CP7 gotcha).
 * Requests the engine cannot do go to the software implementations; after
 * a timeout the engine is no longer used.
 */

#include <crypto/aes.h>
#include <crypto/algapi.h>
#include <crypto/authenc.h>
#include <crypto/b128ops.h>
#include <crypto/gcm.h>
#include <crypto/gf128mul.h>
#include <crypto/internal/aead.h>
#include <crypto/internal/des.h>
#include <crypto/internal/skcipher.h>
#include <crypto/scatterwalk.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/soc/fortinet/cp-hmac.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <asm/outercache.h>

/* Host TX queue 16 (first register window) */
#define Q_RING			0x000
#define Q_RING_HI		0x008
#define Q_WB			0x010
#define Q_WB_HI			0x018
#define Q_SIZE			0x038
#define Q_HEAD			0x040
#define Q_DONE			0x050
#define Q_PROC			0x058
#define Q_PPR			0x0a0
#define Q_CTRL			0x0b8
#define  Q_CTRL_EN		BIT(0)
#define  Q_CTRL_RESET		BIT(2)
#define  Q_CTRL_PWB		BIT(4)
#define Q_WIN			0x400
/* Per-queue DMA parameters and control (second window, 0xf500d860) */
#define VQ_PPR			0x08
#define VQ_DEV			0x18
#define VQ_WIN			0x20
/* Engine debug registers (third window, 0xf500e000) */
#define ENG_TXPCI_DBG1		0x10
#define  ENG_CHECK_STATUS(v)	(((v) >> 9) & 0x7ff)
#define ENG_WIN			0x48

/* Values of the vendor firmware */
#define Q_PPR_INIT		0x02010001
#define VQ_DEV_INIT		0x00030011
#define ADDR_HI_ACP		0x27

#define CMD_DECRYPT		BIT(0)
#define CMD_DES			0x04
#define CMD_3DES		0x06
#define CMD_AES128		0x22
#define CMD_AES192		0x24
#define CMD_AES256		0x26
#define CMD_HMAC_MD5		0x10
#define CMD_HMAC_SHA		0x18
#define CMD_GHASH		0x08
#define GCM_MODE		BIT(23)
#define KB_GCM_H		0x20
#define KB_GCM_SALT		0x30
#define GCM_SALT		4
#define GCM_TAG			16
#define GCM_HDR			8	/* AD the engine hashes (ESP header) */
#define GCM_OFF			16	/* ESP header and packet IV */
#define GCM_KB			(KB_GCM_SALT + GCM_SALT)
/*
 * GCM data at 16 bytes into the bounce areas: the text then starts at a
 * 32-byte boundary. The CPU reads the uncached buffer by bursts; an
 * unaligned copy takes about twice as long (session 21).
 */
#define GCM_BASE		16
#define HSEL_LO			BIT(15)
#define HSEL_HI			BIT(22)
#define DESC_REPORT		BIT(0)

#define RING_N			16
#define KEY_STRIDE		128
#define KEY_BLOCK		96
#define KEY_RAW_MAX		(KEY_BLOCK - FCP_HMAC_KB_IN)	/* 64 */

/* Layout of the DMA buffer */
#define BUF_RING		0x0000
#define BUF_WB			0x0400
#define BUF_KEYS		0x0800
#define BUF_A			0x1000
#define BUF_B			0x6000
#define AREA			0x4400
#define BUF_SIZE		0xa400
#define PIECE_MAX		0x4000	/* bytes of text per descriptor */

#define POLL_US			20000

#define SKCIPHER_PRIORITY	300
#define AEAD_PRIORITY		4000

struct fsoc3_cp_desc {
	__le32 ctrl;
	__le32 flags;
	__le32 src;
	__le32 dst;
	u8 iv[AES_BLOCK_SIZE];
	__le32 key;
	__le32 reserved[7];
};

struct fsoc3_cp {
	struct device *dev;
	void __iomem *q, *vq, *eng;
	spinlock_t lock;		/* the ring, the buffer, the counters */
	u8 *buf;
	dma_addr_t dma;
	unsigned int head;
	bool dead;
	u64 descs, rejected;
};

static struct fsoc3_cp *fsoc3_cp;
/* Requests (or their remainders) done by the software */
static atomic_long_t fsoc3_cp_fallbacks;

struct fsoc3_cp_sk_ctx {
	struct crypto_skcipher *fallback;
	u8 cmd;
	unsigned int keylen;
	u8 key_enc[AES_MAX_KEY_SIZE];
	u8 key_dec[2 * AES_BLOCK_SIZE];
};

struct fsoc3_cp_aead_alg {
	struct aead_alg alg;
	u8 cipher;		/* 0 for AES: set by the key size */
	u8 hash;		/* CMD_HMAC_* */
	u8 hsel;		/* hash selector: 1 SHA-256, 2 SHA-384, 3 SHA-512 */
	u8 icv;			/* the only authsize the engine does */
	u8 gcm;			/* 0, GCM_IPSEC or GCM_PLAIN */
};

#define GCM_IPSEC		1	/* rfc4106(gcm(aes)) */
#define GCM_PLAIN		2	/* gcm(aes) */

struct fsoc3_cp_aead_ctx {
	struct crypto_aead *fallback;
	struct gf128mul_4k *h4k;	/* GCM: multiplication by H */
	u8 cmd;
	bool hw_key;		/* the engine can take the key */
	u8 kb_enc[KEY_BLOCK];
	u8 kb_dec[KEY_BLOCK];
};

/* --- engine ----------------------------------------------------------- */

static void fsoc3_cp_flush(struct fsoc3_cp *cp, unsigned int off,
			   unsigned int len)
{
	phys_addr_t pa = cp->dma + off;	/* no IOMMU, no DMA offset */

	outer_flush_range(pa, pa + len);
}

/*
 * Runs one descriptor; lock held. The data is in the buffer at src_off
 * (and dst_off); the key block is copied into the key slot of the ring
 * slot. Returns 0, -EIO if the engine rejected the descriptor, or
 * -ETIMEDOUT (the engine is then no longer used).
 */
static int fsoc3_cp_run(struct fsoc3_cp *cp, u32 ctrl, unsigned int src_off,
			unsigned int dst_off, unsigned int data_len,
			const u8 *iv, unsigned int ivsize, const u8 *kb,
			unsigned int kblen)
{
	unsigned int idx = cp->head, next = (idx + 1) % RING_N, us;
	struct fsoc3_cp_desc *d = (void *)(cp->buf + BUF_RING) + idx * sizeof(*d);
	unsigned int koff = BUF_KEYS + idx * KEY_STRIDE;
	u32 base = lower_32_bits(cp->dma), st;

	if (cp->dead)
		return -EIO;

	memcpy(cp->buf + koff, kb, kblen);
	memset(d, 0, sizeof(*d));
	d->ctrl = cpu_to_le32(ctrl);
	d->flags = cpu_to_le32(DESC_REPORT);
	d->src = cpu_to_le32(base + src_off);
	d->dst = cpu_to_le32(base + dst_off);
	memcpy(d->iv, iv, ivsize);
	d->key = cpu_to_le32(base + koff);

	wmb();
	fsoc3_cp_flush(cp, BUF_RING + idx * sizeof(*d), sizeof(*d));
	fsoc3_cp_flush(cp, koff, KEY_STRIDE);
	fsoc3_cp_flush(cp, min(src_off, dst_off),
		       max(src_off, dst_off) - min(src_off, dst_off) + data_len);

	writel(next, cp->q + Q_HEAD);
	for (us = 0; us < POLL_US; us++) {
		if (readl(cp->q + Q_DONE) == next &&
		    readl(cp->q + Q_PROC) == next)
			break;
		udelay(1);
	}
	if (us == POLL_US) {
		dev_err(cp->dev, "descriptor %u not done after %u us (done %u, processed %u): engine no longer used\n",
			idx, POLL_US, readl(cp->q + Q_DONE),
			readl(cp->q + Q_PROC));
		cp->dead = true;
		memzero_explicit(cp->buf + koff, KEY_STRIDE);
		return -ETIMEDOUT;
	}
	cp->head = next;
	cp->descs++;
	memzero_explicit(cp->buf + koff, KEY_STRIDE);

	fsoc3_cp_flush(cp, min(src_off, dst_off),
		       max(src_off, dst_off) - min(src_off, dst_off) + data_len);
	rmb();

	st = ENG_CHECK_STATUS(readl(cp->eng + ENG_TXPCI_DBG1));
	if (st) {
		cp->rejected++;
		dev_dbg(cp->dev, "descriptor %08x rejected, check status %#x\n",
			ctrl, st);
		return -EIO;
	}
	return 0;
}

/* --- skcipher ------------------------------------------------------------ */

/* The software does the request from byte off on, with the IV iv */
static int fsoc3_cp_sk_fallback(struct skcipher_request *req, bool dec,
				unsigned int off, u8 *iv)
{
	struct fsoc3_cp_sk_ctx *ctx = crypto_skcipher_ctx(crypto_skcipher_reqtfm(req));
	struct skcipher_request *sub = skcipher_request_ctx(req);
	struct scatterlist s[2], d[2], *src = req->src, *dst = req->dst;

	atomic_long_inc(&fsoc3_cp_fallbacks);
	if (off) {
		src = scatterwalk_ffwd(s, req->src, off);
		dst = scatterwalk_ffwd(d, req->dst, off);
	}
	skcipher_request_set_tfm(sub, ctx->fallback);
	skcipher_request_set_callback(sub, req->base.flags, req->base.complete,
				      req->base.data);
	skcipher_request_set_crypt(sub, src, dst, req->cryptlen - off, iv);
	return dec ? crypto_skcipher_decrypt(sub) : crypto_skcipher_encrypt(sub);
}

static int fsoc3_cp_sk_crypt(struct skcipher_request *req, bool dec)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct fsoc3_cp_sk_ctx *ctx = crypto_skcipher_ctx(tfm);
	unsigned int bs = crypto_skcipher_blocksize(tfm);
	unsigned int ivsize = crypto_skcipher_ivsize(tfm);
	unsigned int off, n;
	struct fsoc3_cp *cp = fsoc3_cp;
	u8 iv[AES_BLOCK_SIZE], next[AES_BLOCK_SIZE];
	int nsrc, ndst;
	const u8 *kb;
	int ret = 0;

	if (req->cryptlen % bs)
		return -EINVAL;
	if (!req->cryptlen)
		return 0;
	if (!cp || READ_ONCE(cp->dead))
		return fsoc3_cp_sk_fallback(req, dec, 0, req->iv);

	nsrc = sg_nents_for_len(req->src, req->cryptlen);
	ndst = sg_nents_for_len(req->dst, req->cryptlen);
	if (nsrc <= 0 || ndst <= 0)
		return -EINVAL;
	kb = dec && ctx->cmd >= CMD_AES128 ? ctx->key_dec : ctx->key_enc;
	memcpy(iv, req->iv, ivsize);

	/* The lock is taken per piece: the chaining state is local */
	for (off = 0; off < req->cryptlen; off += n) {
		n = min(req->cryptlen - off, (unsigned int)PIECE_MAX);
		spin_lock_bh(&cp->lock);
		sg_pcopy_to_buffer(req->src, nsrc, cp->buf + BUF_A, n, off);
		if (dec)
			memcpy(next, cp->buf + BUF_A + n - ivsize, ivsize);
		ret = fsoc3_cp_run(cp, n | (u32)(ctx->cmd | (dec ? CMD_DECRYPT : 0)) << 24,
				   BUF_A, BUF_A, n, iv, ivsize, kb,
				   ctx->cmd >= CMD_AES128 ? 2 * AES_BLOCK_SIZE : ctx->keylen);
		if (!ret) {
			if (!dec)
				memcpy(next, cp->buf + BUF_A + n - ivsize, ivsize);
			sg_pcopy_from_buffer(req->dst, ndst, cp->buf + BUF_A, n, off);
		}
		memzero_explicit(cp->buf + BUF_A, n);
		spin_unlock_bh(&cp->lock);
		if (ret)
			break;
		memcpy(iv, next, ivsize);
	}

	/*
	 * After a failure, the software does the rest (from the source still
	 * untouched, with the IV of the pieces done) and sets the output IV.
	 */
	if (ret) {
		memcpy(req->iv, iv, ivsize);
		return fsoc3_cp_sk_fallback(req, dec, off, req->iv);
	}
	memcpy(req->iv, iv, ivsize);
	return 0;
}

static int fsoc3_cp_sk_encrypt(struct skcipher_request *req)
{
	return fsoc3_cp_sk_crypt(req, false);
}

static int fsoc3_cp_sk_decrypt(struct skcipher_request *req)
{
	return fsoc3_cp_sk_crypt(req, true);
}

static int fsoc3_cp_aes_dec_key(const u8 *key, unsigned int keylen, u8 *out)
{
	struct crypto_aes_ctx *aes;
	unsigned int nr = 6 + keylen / 4, i;
	int err;

	aes = kmalloc(sizeof(*aes), GFP_KERNEL);
	if (!aes)
		return -ENOMEM;
	err = aes_expandkey(aes, key, keylen);
	if (!err)
		for (i = 0; i < 4; i++) {
			put_unaligned_le32(aes->key_enc[4 * nr + i], &out[4 * i]);
			put_unaligned_le32(aes->key_enc[4 * (nr - 1) + i],
					   &out[16 + 4 * i]);
		}
	kfree_sensitive(aes);
	return err;
}

static int fsoc3_cp_sk_setkey(struct crypto_skcipher *tfm, const u8 *key,
			      unsigned int keylen)
{
	struct fsoc3_cp_sk_ctx *ctx = crypto_skcipher_ctx(tfm);
	const char *name = crypto_tfm_alg_name(crypto_skcipher_tfm(tfm));
	u8 dec[2 * AES_BLOCK_SIZE];
	u8 cmd;
	int err;

	if (!strcmp(name, "cbc(aes)")) {
		cmd = keylen == AES_KEYSIZE_128 ? CMD_AES128 :
		      keylen == AES_KEYSIZE_192 ? CMD_AES192 : CMD_AES256;
		err = aes_check_keylen(keylen) ?:
		      fsoc3_cp_aes_dec_key(key, keylen, dec);
	} else if (!strcmp(name, "cbc(des)")) {
		cmd = CMD_DES;
		err = verify_skcipher_des_key(tfm, key);
	} else {
		cmd = CMD_3DES;
		err = verify_skcipher_des3_key(tfm, key);
	}
	/* The fallback checks the key as the software does */
	err = err ?: crypto_skcipher_setkey(ctx->fallback, key, keylen);
	if (err)
		return err;
	ctx->cmd = cmd;
	ctx->keylen = keylen;
	memset(ctx->key_enc, 0, sizeof(ctx->key_enc));
	memcpy(ctx->key_enc, key, keylen);
	if (cmd >= CMD_AES128)
		memcpy(ctx->key_dec, dec, sizeof(dec));
	memzero_explicit(dec, sizeof(dec));
	return 0;
}

static int fsoc3_cp_sk_init(struct crypto_skcipher *tfm)
{
	struct fsoc3_cp_sk_ctx *ctx = crypto_skcipher_ctx(tfm);
	const char *name = crypto_tfm_alg_name(crypto_skcipher_tfm(tfm));

	ctx->fallback = crypto_alloc_skcipher(name, 0, CRYPTO_ALG_NEED_FALLBACK |
						    CRYPTO_ALG_ASYNC);
	if (IS_ERR(ctx->fallback))
		return PTR_ERR(ctx->fallback);
	crypto_skcipher_set_reqsize(tfm, sizeof(struct skcipher_request) +
				    crypto_skcipher_reqsize(ctx->fallback));
	return 0;
}

static void fsoc3_cp_sk_exit(struct crypto_skcipher *tfm)
{
	struct fsoc3_cp_sk_ctx *ctx = crypto_skcipher_ctx(tfm);

	memzero_explicit(ctx->key_enc, sizeof(ctx->key_enc));
	memzero_explicit(ctx->key_dec, sizeof(ctx->key_dec));
	crypto_free_skcipher(ctx->fallback);
}

#define FSOC3_CP_SK(algname, drv, bsize, minkey, maxkey)			\
	{								\
		.base = {						\
			.cra_name = algname,				\
			.cra_driver_name = drv,				\
			.cra_priority = SKCIPHER_PRIORITY,		\
			.cra_flags = CRYPTO_ALG_NEED_FALLBACK |		\
				     CRYPTO_ALG_KERN_DRIVER_ONLY,	\
			.cra_blocksize = bsize,				\
			.cra_ctxsize = sizeof(struct fsoc3_cp_sk_ctx),	\
			.cra_module = THIS_MODULE,			\
		},							\
		.min_keysize = minkey,					\
		.max_keysize = maxkey,					\
		.ivsize = bsize,					\
		.setkey = fsoc3_cp_sk_setkey,				\
		.encrypt = fsoc3_cp_sk_encrypt,				\
		.decrypt = fsoc3_cp_sk_decrypt,				\
		.init = fsoc3_cp_sk_init,				\
		.exit = fsoc3_cp_sk_exit,				\
	}

static struct skcipher_alg fsoc3_cp_skciphers[] = {
	FSOC3_CP_SK("cbc(aes)", "cbc-aes-fsoc3", AES_BLOCK_SIZE,
		    AES_MIN_KEY_SIZE, AES_MAX_KEY_SIZE),
	FSOC3_CP_SK("cbc(des)", "cbc-des-fsoc3", DES_BLOCK_SIZE,
		    DES_KEY_SIZE, DES_KEY_SIZE),
	FSOC3_CP_SK("cbc(des3_ede)", "cbc-des3_ede-fsoc3", DES3_EDE_BLOCK_SIZE,
		    DES3_EDE_KEY_SIZE, DES3_EDE_KEY_SIZE),
};

/* --- aead ---------------------------------------------------------------- */

static struct fsoc3_cp_aead_alg *fsoc3_cp_aead_alg(struct crypto_aead *tfm)
{
	return container_of(crypto_aead_alg(tfm), struct fsoc3_cp_aead_alg, alg);
}

static int fsoc3_cp_aead_fallback(struct aead_request *req, bool dec)
{
	struct fsoc3_cp_aead_ctx *ctx = crypto_aead_ctx(crypto_aead_reqtfm(req));
	struct aead_request *sub = aead_request_ctx(req);

	atomic_long_inc(&fsoc3_cp_fallbacks);
	aead_request_set_tfm(sub, ctx->fallback);
	aead_request_set_callback(sub, req->base.flags, req->base.complete,
				  req->base.data);
	aead_request_set_crypt(sub, req->src, req->dst, req->cryptlen, req->iv);
	aead_request_set_ad(sub, req->assoclen);
	return dec ? crypto_aead_decrypt(sub) : crypto_aead_encrypt(sub);
}

/*
 * Corrects the tag the engine computed over its layout (AD = the 8 bytes
 * of the ESP header place, text padded to t4 bytes) into the tag of the
 * request (AD of aad <= 8 bytes, zero-padded there, text of tlen bytes).
 * Only the last ciphertext block (the pad bytes the engine hashed; zero
 * in the request) and the length block differ, so GHASH, linear, differs
 * by dc * H^2 + dl * H = (dc * H + dl) * H.
 */
static void fsoc3_cp_gcm_fix(const struct gf128mul_4k *h4k, const u8 *text,
			     unsigned int tlen, unsigned int t4,
			     unsigned int aad, u8 *tag)
{
	be128 x = {};

	if (aad == GCM_HDR && t4 == tlen)
		return;
	memcpy((u8 *)&x + tlen % AES_BLOCK_SIZE, text + tlen, t4 - tlen);
	gf128mul_4k_lle(&x, h4k);
	x.a ^= cpu_to_be64((u64)aad * 8 ^ (u64)GCM_HDR * 8);
	x.b ^= cpu_to_be64((u64)tlen * 8 ^ (u64)t4 * 8);
	gf128mul_4k_lle(&x, h4k);
	crypto_xor(tag, (u8 *)&x, GCM_TAG);
	memzero_explicit(&x, sizeof(x));
}

/*
 * rfc4106(gcm(aes)) and gcm(aes). The engine takes, at offset 16 of the
 * data, the text after 8 bytes hashed as AD and 8 bytes it skips (the
 * ESP header and the IV of the packet); the counter block is the salt of
 * the key block, the 8-byte IV of the descriptor and the counter.
 */
static int fsoc3_cp_gcm_crypt(struct aead_request *req, bool dec)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct fsoc3_cp_aead_ctx *ctx = crypto_aead_ctx(tfm);
	struct fsoc3_cp_aead_alg *a = fsoc3_cp_aead_alg(tfm);
	unsigned int icv = crypto_aead_authsize(tfm);
	unsigned int alen = req->assoclen, aad, tlen, t4, total;
	struct fsoc3_cp *cp = fsoc3_cp;
	u8 kb[GCM_KB], iv[8], tag_in[GCM_TAG], tag[GCM_TAG];
	int nsrc, ndst, ret;
	u32 ctrl;
	u8 *buf;

	if (dec && req->cryptlen < icv)
		return -EINVAL;
	tlen = req->cryptlen - (dec ? icv : 0);
	t4 = round_up(tlen, 4);
	/* rfc4106: the AD then the IV in the AD place, ESN not done */
	aad = a->gcm == GCM_IPSEC ? (alen == GCM_OFF ? GCM_HDR : GCM_OFF) :
	      alen;

	/* What the engine is known to do: else the software */
	if (!cp || READ_ONCE(cp->dead) || !ctx->hw_key || aad > GCM_HDR ||
	    !tlen || t4 > PIECE_MAX)
		return fsoc3_cp_aead_fallback(req, dec);

	nsrc = sg_nents_for_len(req->src, alen + req->cryptlen);
	ndst = sg_nents_for_len(req->dst, alen + tlen + (dec ? 0 : icv));
	if (nsrc <= 0 || ndst <= 0)
		return -EINVAL;

	memcpy(kb, ctx->kb_enc, GCM_KB);
	if (a->gcm == GCM_IPSEC) {
		memcpy(iv, req->iv, sizeof(iv));
	} else {
		memcpy(kb + KB_GCM_SALT, req->iv, GCM_SALT);
		memcpy(iv, req->iv + GCM_SALT, sizeof(iv));
	}
	total = GCM_OFF + t4 + GCM_TAG;
	ctrl = (GCM_OFF + t4) | (GCM_OFF / 4) << 16 | GCM_MODE;

	spin_lock_bh(&cp->lock);
	buf = cp->buf + BUF_A + GCM_BASE;
	/* ESP header place: the AD, zero-padded; then the IV, as ESP has it */
	memset(buf, 0, GCM_OFF);
	sg_pcopy_to_buffer(req->src, nsrc, buf, aad, 0);
	memcpy(buf + GCM_HDR, iv, sizeof(iv));
	sg_pcopy_to_buffer(req->src, nsrc, buf + GCM_OFF, req->cryptlen, alen);
	if (dec)
		memcpy(tag_in, buf + GCM_OFF + tlen, icv);
	memset(buf + GCM_OFF + tlen, 0, t4 - tlen);

	if (!dec) {
		ret = fsoc3_cp_run(cp, ctrl | (u32)ctx->cmd << 24,
				   BUF_A + GCM_BASE, BUF_A + GCM_BASE + GCM_OFF,
				   total, iv, sizeof(iv), kb, GCM_KB);
		if (!ret) {
			memcpy(tag, buf + GCM_OFF + t4, GCM_TAG);
			fsoc3_cp_gcm_fix(ctx->h4k, buf + GCM_OFF, tlen, t4, aad,
					 tag);
			memcpy(buf + GCM_OFF + tlen, tag, icv);
			sg_pcopy_from_buffer(req->dst, ndst, buf + GCM_OFF,
					     tlen + icv, alen);
		}
	} else {
		/*
		 * Decrypt in A (the pad: zero ciphertext), then encrypt the
		 * whole plaintext again in B: that gives back the received
		 * ciphertext, zero pad included, and its tag.
		 */
		u8 *bufb = cp->buf + BUF_B + GCM_BASE;

		ret = fsoc3_cp_run(cp, ctrl | (u32)(ctx->cmd | CMD_DECRYPT) << 24,
				   BUF_A + GCM_BASE, BUF_A + GCM_BASE + GCM_OFF,
				   total, iv, sizeof(iv), kb, GCM_KB);
		if (!ret) {
			/* From the start of the areas: an aligned copy */
			memcpy(cp->buf + BUF_B, cp->buf + BUF_A,
			       GCM_BASE + GCM_OFF + t4);
			ret = fsoc3_cp_run(cp, ctrl | (u32)ctx->cmd << 24,
					   BUF_B + GCM_BASE,
					   BUF_B + GCM_BASE + GCM_OFF, total, iv,
					   sizeof(iv), kb, GCM_KB);
		}
		if (!ret) {
			memcpy(tag, bufb + GCM_OFF + t4, GCM_TAG);
			fsoc3_cp_gcm_fix(ctx->h4k, bufb + GCM_OFF, tlen, t4, aad,
					 tag);
			if (crypto_memneq(tag_in, tag, icv))
				ret = -EBADMSG;
		}
		if (!ret)
			sg_pcopy_from_buffer(req->dst, ndst, buf + GCM_OFF, tlen,
					     alen);
		memzero_explicit(cp->buf + BUF_B, GCM_BASE + total);
	}
	memzero_explicit(cp->buf + BUF_A, GCM_BASE + total);
	spin_unlock_bh(&cp->lock);
	memzero_explicit(kb, sizeof(kb));
	memzero_explicit(tag, sizeof(tag));

	if (ret == -EIO || ret == -ETIMEDOUT)
		return fsoc3_cp_aead_fallback(req, dec);
	return ret;
}

static int fsoc3_cp_aead_crypt(struct aead_request *req, bool dec)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct fsoc3_cp_aead_ctx *ctx = crypto_aead_ctx(tfm);
	struct fsoc3_cp_aead_alg *a = fsoc3_cp_aead_alg(tfm);
	unsigned int ivsize = crypto_aead_ivsize(tfm);
	unsigned int bs = crypto_aead_blocksize(tfm);
	unsigned int icv = crypto_aead_authsize(tfm);
	unsigned int alen = req->assoclen, tlen, total;
	struct fsoc3_cp *cp = fsoc3_cp;
	u8 icv_in[SHA512_DIGEST_SIZE];
	int nsrc, ndst, ret;
	u32 ctrl;

	if (a->gcm)
		return fsoc3_cp_gcm_crypt(req, dec);
	if (dec && req->cryptlen < icv)
		return -EINVAL;
	tlen = req->cryptlen - (dec ? icv : 0);
	total = alen + tlen + icv;

	/* What the engine is known to do: else the software */
	if (!cp || READ_ONCE(cp->dead) || !ctx->hw_key || icv != a->icv ||
	    !tlen || tlen > PIECE_MAX || (alen != 8 && alen != 8 + ivsize) ||
	    tlen % bs)
		return fsoc3_cp_aead_fallback(req, dec);

	nsrc = sg_nents_for_len(req->src, alen + req->cryptlen);
	ndst = sg_nents_for_len(req->dst, alen + tlen + (dec ? 0 : icv));
	if (nsrc <= 0 || ndst <= 0)
		return -EINVAL;

	ctrl = (alen + tlen) | (alen / 4) << 16 |
	       (a->hsel & 1 ? HSEL_LO : 0) | (a->hsel & 2 ? HSEL_HI : 0);

	spin_lock_bh(&cp->lock);
	sg_pcopy_to_buffer(req->src, nsrc, cp->buf + BUF_A, alen + req->cryptlen, 0);
	if (!dec) {
		ret = fsoc3_cp_run(cp, ctrl | (u32)ctx->cmd << 24, BUF_A,
				   BUF_A + alen, total, req->iv, ivsize,
				   ctx->kb_enc, KEY_BLOCK);
		if (!ret)
			sg_pcopy_from_buffer(req->dst, ndst, cp->buf + BUF_A,
					     total, 0);
	} else {
		/*
		 * Decrypt in A, then encrypt the plaintext again in B: the
		 * ICV computed there is the one of the received ciphertext,
		 * compared with the received one, saved before anything runs.
		 */
		memcpy(icv_in, cp->buf + BUF_A + alen + tlen, icv);
		ret = fsoc3_cp_run(cp, ctrl | (u32)(ctx->cmd | CMD_DECRYPT) << 24,
				   BUF_A, BUF_A + alen, total, req->iv, ivsize,
				   ctx->kb_dec, KEY_BLOCK);
		if (!ret) {
			memcpy(cp->buf + BUF_B, cp->buf + BUF_A, alen + tlen);
			ret = fsoc3_cp_run(cp, ctrl | (u32)ctx->cmd << 24, BUF_B,
					   BUF_B + alen, total, req->iv, ivsize,
					   ctx->kb_enc, KEY_BLOCK);
		}
		if (!ret && crypto_memneq(icv_in, cp->buf + BUF_B + alen + tlen,
					  icv))
			ret = -EBADMSG;
		if (!ret)
			sg_pcopy_from_buffer(req->dst, ndst, cp->buf + BUF_A,
					     alen + tlen, 0);
		memzero_explicit(cp->buf + BUF_B, total);
	}
	memzero_explicit(cp->buf + BUF_A, total);
	spin_unlock_bh(&cp->lock);

	if (ret == -EIO || ret == -ETIMEDOUT)
		return fsoc3_cp_aead_fallback(req, dec);
	return ret;
}

static int fsoc3_cp_aead_encrypt(struct aead_request *req)
{
	return fsoc3_cp_aead_crypt(req, false);
}

static int fsoc3_cp_aead_decrypt(struct aead_request *req)
{
	return fsoc3_cp_aead_crypt(req, true);
}

static int fsoc3_cp_aead_setkey(struct crypto_aead *tfm, const u8 *key,
				unsigned int keylen)
{
	struct fsoc3_cp_aead_ctx *ctx = crypto_aead_ctx(tfm);
	struct fsoc3_cp_aead_alg *a = fsoc3_cp_aead_alg(tfm);
	struct crypto_authenc_keys keys;
	u8 *kb_enc = ctx->kb_enc, *kb_dec = ctx->kb_dec;
	int err;

	err = crypto_authenc_extractkeys(&keys, key, keylen) ?:
	      crypto_aead_setkey(ctx->fallback, key, keylen);
	if (err)
		goto out;

	memset(kb_enc, 0, KEY_BLOCK);
	memset(kb_dec, 0, KEY_BLOCK);
	ctx->hw_key = false;
	if (a->cipher == CMD_3DES) {
		err = verify_aead_des3_key(tfm, keys.enckey, keys.enckeylen);
		if (err)
			goto out;
		ctx->cmd = CMD_3DES;
		memcpy(kb_enc, keys.enckey, keys.enckeylen);
		memcpy(kb_dec, keys.enckey, keys.enckeylen);
	} else {
		err = aes_check_keylen(keys.enckeylen);
		if (err)
			goto out;
		ctx->cmd = keys.enckeylen == AES_KEYSIZE_128 ? CMD_AES128 :
			   keys.enckeylen == AES_KEYSIZE_192 ? CMD_AES192 :
			   CMD_AES256;
		memcpy(kb_enc, keys.enckey, keys.enckeylen);
		err = fsoc3_cp_aes_dec_key(keys.enckey, keys.enckeylen, kb_dec);
		if (err)
			goto out;
	}
	ctx->cmd |= a->hash;

	switch (a->hsel) {
	case 0:
		if (a->hash == CMD_HMAC_MD5)
			fcp_hmac_md5_states(kb_enc, keys.authkey, keys.authkeylen);
		else
			fcp_hmac_sha1_states(kb_enc, keys.authkey, keys.authkeylen);
		break;
	case 1:
		fcp_hmac_sha256_states(kb_enc, keys.authkey, keys.authkeylen);
		break;
	default:
		/* SHA-384/512: the raw HMAC key, at most 64 bytes */
		if (keys.authkeylen > KEY_RAW_MAX)
			goto out;
		memcpy(kb_enc + FCP_HMAC_KB_IN, keys.authkey, keys.authkeylen);
		break;
	}
	memcpy(kb_dec + FCP_HMAC_KB_IN, kb_enc + FCP_HMAC_KB_IN,
	       KEY_BLOCK - FCP_HMAC_KB_IN);
	ctx->hw_key = true;
out:
	memzero_explicit(&keys, sizeof(keys));
	return err;
}

/*
 * rfc4106: AES key, then the 4-byte salt; gcm: AES key (the salt comes
 * with each request, the first 4 bytes of its IV)
 */
static int fsoc3_cp_gcm_setkey(struct crypto_aead *tfm, const u8 *key,
			       unsigned int keylen)
{
	struct fsoc3_cp_aead_ctx *ctx = crypto_aead_ctx(tfm);
	struct fsoc3_cp_aead_alg *a = fsoc3_cp_aead_alg(tfm);
	static const u8 zero[AES_BLOCK_SIZE];
	unsigned int salt = a->gcm == GCM_IPSEC ? GCM_SALT : 0;
	struct gf128mul_4k *h4k;
	struct crypto_aes_ctx *aes;
	unsigned int klen;
	be128 h;
	int err;

	if (keylen < salt)
		return -EINVAL;
	klen = keylen - salt;
	ctx->hw_key = false;
	err = aes_check_keylen(klen) ?:
	      crypto_aead_setkey(ctx->fallback, key, keylen);
	if (err)
		return err;
	aes = kmalloc(sizeof(*aes), GFP_KERNEL);
	if (!aes)
		return -ENOMEM;
	err = aes_expandkey(aes, key, klen);
	if (!err) {
		memset(ctx->kb_enc, 0, KEY_BLOCK);
		memcpy(ctx->kb_enc, key, klen);
		aes_encrypt(aes, ctx->kb_enc + KB_GCM_H, zero);
		memcpy(ctx->kb_enc + KB_GCM_SALT, key + klen, salt);
		/* CTR mode: the same key block for both directions */
		memcpy(ctx->kb_dec, ctx->kb_enc, KEY_BLOCK);
		ctx->cmd = (klen == AES_KEYSIZE_128 ? CMD_AES128 :
			    klen == AES_KEYSIZE_192 ? CMD_AES192 : CMD_AES256) |
			   CMD_GHASH;
		/* The table for the tag correction (as ghash-generic) */
		memcpy(&h, ctx->kb_enc + KB_GCM_H, sizeof(h));
		h4k = gf128mul_init_4k_lle(&h);
		memzero_explicit(&h, sizeof(h));
		if (h4k) {
			if (ctx->h4k)
				gf128mul_free_4k(ctx->h4k);
			ctx->h4k = h4k;
			ctx->hw_key = true;
		}
	}
	kfree_sensitive(aes);
	return err;
}

static int fsoc3_cp_aead_setauthsize(struct crypto_aead *tfm,
				     unsigned int authsize)
{
	struct fsoc3_cp_aead_ctx *ctx = crypto_aead_ctx(tfm);

	/*
	 * The fallback checks the size. authenc: other sizes than the ICV
	 * of the engine go to the fallback; GCM: the tag is truncated.
	 */
	return crypto_aead_setauthsize(ctx->fallback, authsize);
}

static int fsoc3_cp_aead_init(struct crypto_aead *tfm)
{
	struct fsoc3_cp_aead_ctx *ctx = crypto_aead_ctx(tfm);
	const char *name = crypto_tfm_alg_name(crypto_aead_tfm(tfm));

	ctx->fallback = crypto_alloc_aead(name, 0, CRYPTO_ALG_NEED_FALLBACK |
						CRYPTO_ALG_ASYNC);
	if (IS_ERR(ctx->fallback))
		return PTR_ERR(ctx->fallback);
	crypto_aead_set_reqsize(tfm, sizeof(struct aead_request) +
				crypto_aead_reqsize(ctx->fallback));
	return 0;
}

static void fsoc3_cp_aead_exit(struct crypto_aead *tfm)
{
	struct fsoc3_cp_aead_ctx *ctx = crypto_aead_ctx(tfm);

	memzero_explicit(ctx->kb_enc, sizeof(ctx->kb_enc));
	memzero_explicit(ctx->kb_dec, sizeof(ctx->kb_dec));
	if (ctx->h4k)
		gf128mul_free_4k(ctx->h4k);
	crypto_free_aead(ctx->fallback);
}

#define FSOC3_CP_AEAD(hname, hdrv, cname, cdrv, CIPHER, bsize, HASH, HSEL, icvsize, maxauth) \
	{								\
		.alg = {						\
			.base = {					\
				.cra_name = "authenc(hmac(" hname "),cbc(" cname "))", \
				.cra_driver_name = "authenc-hmac-" hdrv "-cbc-" cdrv "-fsoc3", \
				.cra_priority = AEAD_PRIORITY,		\
				.cra_flags = CRYPTO_ALG_NEED_FALLBACK |	\
					     CRYPTO_ALG_KERN_DRIVER_ONLY, \
				.cra_blocksize = bsize,			\
				.cra_ctxsize = sizeof(struct fsoc3_cp_aead_ctx), \
				.cra_module = THIS_MODULE,		\
			},						\
			.ivsize = bsize,				\
			.maxauthsize = maxauth,				\
			.setkey = fsoc3_cp_aead_setkey,			\
			.setauthsize = fsoc3_cp_aead_setauthsize,	\
			.encrypt = fsoc3_cp_aead_encrypt,		\
			.decrypt = fsoc3_cp_aead_decrypt,		\
			.init = fsoc3_cp_aead_init,			\
			.exit = fsoc3_cp_aead_exit,			\
		},							\
		.cipher = CIPHER,					\
		.hash = HASH,						\
		.hsel = HSEL,						\
		.icv = icvsize,						\
	}

#define FSOC3_CP_AEAD_PAIR(hname, hdrv, HASH, HSEL, icvsize, maxauth)	\
	FSOC3_CP_AEAD(hname, hdrv, "aes", "aes", 0, AES_BLOCK_SIZE,	\
		      HASH, HSEL, icvsize, maxauth),			\
	FSOC3_CP_AEAD(hname, hdrv, "des3_ede", "des3_ede", CMD_3DES,	\
		      DES3_EDE_BLOCK_SIZE, HASH, HSEL, icvsize, maxauth)

static struct fsoc3_cp_aead_alg fsoc3_cp_aeads[] = {
	FSOC3_CP_AEAD_PAIR("md5", "md5", CMD_HMAC_MD5, 0, 12, MD5_DIGEST_SIZE),
	FSOC3_CP_AEAD_PAIR("sha1", "sha1", CMD_HMAC_SHA, 0, 12, SHA1_DIGEST_SIZE),
	FSOC3_CP_AEAD_PAIR("sha256", "sha256", CMD_HMAC_SHA, 1, 16, SHA256_DIGEST_SIZE),
	FSOC3_CP_AEAD_PAIR("sha384", "sha384", CMD_HMAC_SHA, 2, 24, SHA384_DIGEST_SIZE),
	FSOC3_CP_AEAD_PAIR("sha512", "sha512", CMD_HMAC_SHA, 3, 32, SHA512_DIGEST_SIZE),
	{
		.alg = {
			.base = {
				.cra_name = "rfc4106(gcm(aes))",
				.cra_driver_name = "rfc4106-gcm-aes-fsoc3",
				.cra_priority = AEAD_PRIORITY,
				.cra_flags = CRYPTO_ALG_NEED_FALLBACK |
					     CRYPTO_ALG_KERN_DRIVER_ONLY,
				.cra_blocksize = 1,
				.cra_ctxsize = sizeof(struct fsoc3_cp_aead_ctx),
				.cra_module = THIS_MODULE,
			},
			.ivsize = GCM_RFC4106_IV_SIZE,
			.maxauthsize = GCM_TAG,
			.setkey = fsoc3_cp_gcm_setkey,
			.setauthsize = fsoc3_cp_aead_setauthsize,
			.encrypt = fsoc3_cp_aead_encrypt,
			.decrypt = fsoc3_cp_aead_decrypt,
			.init = fsoc3_cp_aead_init,
			.exit = fsoc3_cp_aead_exit,
		},
		.icv = GCM_TAG,
		.gcm = GCM_IPSEC,
	},
	{
		.alg = {
			.base = {
				.cra_name = "gcm(aes)",
				.cra_driver_name = "gcm-aes-fsoc3",
				.cra_priority = AEAD_PRIORITY,
				.cra_flags = CRYPTO_ALG_NEED_FALLBACK |
					     CRYPTO_ALG_KERN_DRIVER_ONLY,
				.cra_blocksize = 1,
				.cra_ctxsize = sizeof(struct fsoc3_cp_aead_ctx),
				.cra_module = THIS_MODULE,
			},
			.ivsize = GCM_AES_IV_SIZE,
			.maxauthsize = GCM_TAG,
			.setkey = fsoc3_cp_gcm_setkey,
			.setauthsize = fsoc3_cp_aead_setauthsize,
			.encrypt = fsoc3_cp_aead_encrypt,
			.decrypt = fsoc3_cp_aead_decrypt,
			.init = fsoc3_cp_aead_init,
			.exit = fsoc3_cp_aead_exit,
		},
		.icv = GCM_TAG,
		.gcm = GCM_PLAIN,
	},
};

/* --- device -------------------------------------------------------------- */

/* NIST SP 800-38A, F.2.1 (CBC-AES128.Encrypt), first two blocks */
static int fsoc3_cp_selftest(struct fsoc3_cp *cp)
{
	static const u8 key[16] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	static const u8 iv[16] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	static const u8 pt[32] = {
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
		0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
		0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
		0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 };
	static const u8 ct[32] = {
		0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
		0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
		0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
		0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2 };
	int ret;

	spin_lock_bh(&cp->lock);
	memcpy(cp->buf + BUF_A, pt, sizeof(pt));
	ret = fsoc3_cp_run(cp, sizeof(pt) | (u32)CMD_AES128 << 24, BUF_A, BUF_A,
			   sizeof(pt), iv, sizeof(iv), key, sizeof(key));
	if (!ret && memcmp(cp->buf + BUF_A, ct, sizeof(ct)))
		ret = -EIO;
	spin_unlock_bh(&cp->lock);
	return ret;
}

/* Use counters: descriptors run and rejected, requests done in software */
static ssize_t stats_show(struct device *dev, struct device_attribute *attr,
			  char *page)
{
	struct fsoc3_cp *cp = dev_get_drvdata(dev);
	u64 descs = 0, rejected = 0;

	if (cp) {
		spin_lock_bh(&cp->lock);
		descs = cp->descs;
		rejected = cp->rejected;
		spin_unlock_bh(&cp->lock);
	}
	return sysfs_emit(page, "descriptors %llu\nrejected %llu\nfallbacks %lu\ndead %d\n",
			  descs, rejected,
			  atomic_long_read(&fsoc3_cp_fallbacks),
			  cp ? READ_ONCE(cp->dead) : 1);
}
static DEVICE_ATTR_RO(stats);

static struct attribute *fsoc3_cp_attrs[] = {
	&dev_attr_stats.attr,
	NULL
};
ATTRIBUTE_GROUPS(fsoc3_cp);

/* Resets and disables the queue; false if it does not leave the reset */
static bool fsoc3_cp_stop(struct fsoc3_cp *cp)
{
	unsigned int i;

	writel(Q_CTRL_RESET, cp->q + Q_CTRL);
	for (i = 0; i < 1000 && (readl(cp->q + Q_CTRL) & Q_CTRL_RESET); i++)
		udelay(10);
	if (readl(cp->q + Q_CTRL) & Q_CTRL_RESET)
		return false;
	writel(0, cp->q + Q_CTRL);
	return true;
}

/* Frees the buffer if the queue is stopped; else leaves it (leaked) */
static void fsoc3_cp_release(struct fsoc3_cp *cp)
{
	if (fsoc3_cp_stop(cp)) {
		memzero_explicit(cp->buf, BUF_SIZE);
		dma_free_coherent(cp->dev, BUF_SIZE, cp->buf, cp->dma);
	} else {
		dev_err(cp->dev, "queue still busy: DMA buffer not freed\n");
	}
}

static int fsoc3_cp_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct fsoc3_cp *cp;
	struct resource *r;
	u32 base;
	int ret, i;

	if (fsoc3_cp)
		return -EBUSY;
	cp = devm_kzalloc(dev, sizeof(*cp), GFP_KERNEL);
	if (!cp)
		return -ENOMEM;
	cp->dev = dev;
	spin_lock_init(&cp->lock);

	/* Inside the NP6Lite window, requested by its driver: not requested */
	r = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (r && resource_size(r) >= Q_WIN)
		cp->q = devm_ioremap(dev, r->start, Q_WIN);
	r = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (r && resource_size(r) >= VQ_WIN)
		cp->vq = devm_ioremap(dev, r->start, VQ_WIN);
	r = platform_get_resource(pdev, IORESOURCE_MEM, 2);
	if (r && resource_size(r) >= ENG_WIN)
		cp->eng = devm_ioremap(dev, r->start, ENG_WIN);
	if (!cp->q || !cp->vq || !cp->eng)
		return dev_err_probe(dev, -EINVAL, "three register windows expected\n");

	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(32));
	if (ret)
		return ret;
	/*
	 * Not managed: freed only once the queue is known stopped (a wedged
	 * engine could still write into it).
	 */
	cp->buf = dma_alloc_coherent(dev, BUF_SIZE, &cp->dma, GFP_KERNEL);
	if (!cp->buf)
		return -ENOMEM;
	memset(cp->buf, 0, BUF_SIZE);
	base = lower_32_bits(cp->dma);

	/* Queue start as the vendor firmware sets it (fnp6l_ring_start order) */
	if (!fsoc3_cp_stop(cp)) {
		dev_err(dev, "queue does not leave reset: buffer kept\n");
		return -EBUSY;
	}
	writel(Q_PPR_INIT, cp->vq + VQ_PPR);
	writel(VQ_DEV_INIT, cp->vq + VQ_DEV);
	writel(Q_PPR_INIT, cp->q + Q_PPR);
	writel(base + BUF_RING, cp->q + Q_RING);
	writel(base + BUF_WB, cp->q + Q_WB);
	writel(ADDR_HI_ACP, cp->q + Q_RING_HI);
	writel(ADDR_HI_ACP, cp->q + Q_WB_HI);
	writel(RING_N, cp->q + Q_SIZE);
	writel(0, cp->q + Q_HEAD);
	writel(Q_CTRL_EN | Q_CTRL_PWB, cp->q + Q_CTRL);
	cp->head = 0;

	ret = fsoc3_cp_selftest(cp);
	if (ret) {
		dev_err(dev, "self-test failed (%d): engine not used\n", ret);
		goto stop;
	}

	platform_set_drvdata(pdev, cp);
	fsoc3_cp = cp;
	ret = crypto_register_skciphers(fsoc3_cp_skciphers,
					ARRAY_SIZE(fsoc3_cp_skciphers));
	if (ret)
		goto err;
	for (i = 0; i < ARRAY_SIZE(fsoc3_cp_aeads); i++) {
		ret = crypto_register_aead(&fsoc3_cp_aeads[i].alg);
		if (ret) {
			while (--i >= 0)
				crypto_unregister_aead(&fsoc3_cp_aeads[i].alg);
			crypto_unregister_skciphers(fsoc3_cp_skciphers,
						    ARRAY_SIZE(fsoc3_cp_skciphers));
			goto err;
		}
	}
	dev_info(dev, "self-test passed: %zu skciphers, %zu AEADs registered\n",
		 ARRAY_SIZE(fsoc3_cp_skciphers), ARRAY_SIZE(fsoc3_cp_aeads));
	return 0;
err:
	fsoc3_cp = NULL;
	dev_err(dev, "cannot register the algorithms (%d)\n", ret);
stop:
	fsoc3_cp_release(cp);
	return ret;
}

static void fsoc3_cp_remove(struct platform_device *pdev)
{
	struct fsoc3_cp *cp = platform_get_drvdata(pdev);
	int i;

	for (i = ARRAY_SIZE(fsoc3_cp_aeads) - 1; i >= 0; i--)
		crypto_unregister_aead(&fsoc3_cp_aeads[i].alg);
	crypto_unregister_skciphers(fsoc3_cp_skciphers,
				    ARRAY_SIZE(fsoc3_cp_skciphers));
	fsoc3_cp = NULL;
	dev_info(cp->dev, "%llu descriptors, %llu rejected\n", cp->descs,
		 cp->rejected);
	fsoc3_cp_release(cp);
}

static const struct of_device_id fsoc3_cp_of_match[] = {
	{ .compatible = "fortinet,fsoc3-cp" },
	{ }
};
MODULE_DEVICE_TABLE(of, fsoc3_cp_of_match);

static struct platform_driver fsoc3_cp_driver = {
	.probe = fsoc3_cp_probe,
	.remove = fsoc3_cp_remove,
	.driver = {
		.name = "fsoc3-cp",
		.of_match_table = fsoc3_cp_of_match,
		.dev_groups = fsoc3_cp_groups,
		.suppress_bind_attrs = true,
	},
};
module_platform_driver(fsoc3_cp_driver);

MODULE_DESCRIPTION("Fortinet FortiSOC3 symmetric crypto engine");
MODULE_LICENSE("GPL");
