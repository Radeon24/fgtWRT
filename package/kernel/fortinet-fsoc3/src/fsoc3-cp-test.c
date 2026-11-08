// SPDX-License-Identifier: GPL-2.0-only
/*
 * Differential test of the fsoc3-cp algorithms against software
 * implementations (bring-up tool, not loaded at boot).
 *
 * At load: for each skcipher (cbc(aes) 128/192/256, cbc(des),
 * cbc(des3_ede)) and each AEAD (authenc(hmac(md5|sha1|sha256|sha384|
 * sha512),cbc(aes|des3_ede))), random keys, IVs and data of several
 * lengths: the -fsoc3 driver and a software instance (generic ciphers)
 * must give the same output (and output IV); the driver must decrypt what
 * the software encrypted; for the AEADs with assoclen 8 and 8 + ivsize,
 * and a modified ICV must give -EBADMSG. Then the time of 1504-byte and
 * 16 KiB requests, driver and software. One line per algorithm.
 * rfc4106(gcm(aes)) with tags of 16, 12 and 8 bytes; gcm(aes) with AD of
 * 0-20 bytes, texts of 0-16385 bytes (also not multiples of 4), tags of
 * 4-16 bytes, in place and out of place over split scatterlists.
 */

#include <crypto/aead.h>
#include <crypto/authenc.h>
#include <crypto/skcipher.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/rtnetlink.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>

static unsigned int iters = 3;
module_param(iters, uint, 0);
MODULE_PARM_DESC(iters, "random keys per length (default 3)");

static bool speed;
module_param(speed, bool, 0);
MODULE_PARM_DESC(speed, "only the time table (encrypt and decrypt)");

#define BUF_MAX		(48 * 1024)

static u8 *b1, *b2, *b3, *b4;

static int run_sk(struct crypto_skcipher *tfm, bool dec, u8 *buf,
		  unsigned int len, u8 *iv)
{
	struct skcipher_request *req;
	struct scatterlist sg;
	DECLARE_CRYPTO_WAIT(wait);
	int ret;

	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req)
		return -ENOMEM;
	sg_init_one(&sg, buf, len);
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_SLEEP |
				      CRYPTO_TFM_REQ_MAY_BACKLOG,
				      crypto_req_done, &wait);
	skcipher_request_set_crypt(req, &sg, &sg, len, iv);
	ret = crypto_wait_req(dec ? crypto_skcipher_decrypt(req) :
				    crypto_skcipher_encrypt(req), &wait);
	skcipher_request_free(req);
	return ret;
}

static int run_aead(struct crypto_aead *tfm, bool dec, u8 *buf,
		    unsigned int alen, unsigned int clen, u8 *iv)
{
	struct aead_request *req;
	struct scatterlist sg;
	DECLARE_CRYPTO_WAIT(wait);
	unsigned int icv = crypto_aead_authsize(tfm);
	int ret;

	req = aead_request_alloc(tfm, GFP_KERNEL);
	if (!req)
		return -ENOMEM;
	sg_init_one(&sg, buf, alen + clen + (dec ? 0 : icv));
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_SLEEP |
				  CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);
	aead_request_set_crypt(req, &sg, &sg, clen, iv);
	aead_request_set_ad(req, alen);
	ret = crypto_wait_req(dec ? crypto_aead_decrypt(req) :
				    crypto_aead_encrypt(req), &wait);
	aead_request_free(req);
	return ret;
}

static const char *drv(struct crypto_tfm *t)
{
	return crypto_tfm_alg_driver_name(t);
}

static s64 speed_sk(struct crypto_skcipher *tfm, unsigned int len)
{
	u8 iv[16] = {};
	ktime_t t0 = ktime_get();
	unsigned int i;

	for (i = 0; i < 50; i++)
		run_sk(tfm, false, b1, len, iv);
	return div_s64(ktime_us_delta(ktime_get(), t0), 50);
}

static void test_sk(const char *name, const char *hwname, const char * const *swnames,
		    unsigned int keylen)
{
	static const unsigned int lens[] = { 16, 64, 1504, 4096, 16384, 40000 };
	struct crypto_skcipher *hw, *sw = ERR_PTR(-ENOENT);
	unsigned int bs, l, i, ok = 0, tot = 0;
	u8 key[32], iv1[16], iv2[16], iv0[16];
	int r1, r2, j;

	hw = crypto_alloc_skcipher(hwname, 0, 0);
	for (j = 0; swnames[j] && IS_ERR(sw); j++)
		sw = crypto_alloc_skcipher(swnames[j], 0, 0);
	if (IS_ERR(hw) || IS_ERR(sw)) {
		pr_info("fsoc3-cp-test: %s: cannot allocate (%d, %d)\n", name,
			PTR_ERR_OR_ZERO(hw), PTR_ERR_OR_ZERO(sw));
		goto out;
	}
	bs = crypto_skcipher_blocksize(hw);
	for (l = 0; l < ARRAY_SIZE(lens); l++) {
		unsigned int len = lens[l] / bs * bs;

		for (i = 0; i < iters; i++) {
			tot++;
			get_random_bytes(key, keylen);
			get_random_bytes(iv0, sizeof(iv0));
			get_random_bytes(b1, len);
			memcpy(b2, b1, len);
			memcpy(b3, b1, len);
			memcpy(iv1, iv0, 16);
			memcpy(iv2, iv0, 16);
			if (crypto_skcipher_setkey(hw, key, keylen) ||
			    crypto_skcipher_setkey(sw, key, keylen)) {
				tot--;	/* weak DES key: draw again */
				i--;
				continue;
			}
			r1 = run_sk(hw, false, b2, len, iv1);
			r2 = run_sk(sw, false, b3, len, iv2);
			if (r1 || r2 || memcmp(b2, b3, len) || memcmp(iv1, iv2, bs)) {
				pr_info("fsoc3-cp-test: %s %u bit len %u: encryption differs (%d, %d)\n",
					name, keylen * 8, len, r1, r2);
				continue;
			}
			memcpy(iv1, iv0, 16);
			r1 = run_sk(hw, true, b2, len, iv1);
			if (r1 || memcmp(b2, b1, len) || memcmp(iv1, iv2, bs)) {
				pr_info("fsoc3-cp-test: %s %u bit len %u: decryption wrong (%d)\n",
					name, keylen * 8, len, r1);
				continue;
			}
			ok++;
		}
	}
	pr_info("fsoc3-cp-test: %-14s %3u bit: %u/%u ok (vs %s); us per 1504/16384 B: hw %lld/%lld sw %lld/%lld\n",
		name, keylen * 8, ok, tot, drv(crypto_skcipher_tfm(sw)),
		speed_sk(hw, 1504 / bs * bs), speed_sk(hw, 16384),
		speed_sk(sw, 1504 / bs * bs), speed_sk(sw, 16384));
out:
	if (!IS_ERR(sw))
		crypto_free_skcipher(sw);
	if (!IS_ERR(hw))
		crypto_free_skcipher(hw);
}

/* authenc key blob: rtattr(param), enckeylen, authkey, enckey */
static unsigned int authenc_key(u8 *out, const u8 *ak, unsigned int aklen,
				const u8 *ek, unsigned int eklen)
{
	struct rtattr *rta = (void *)out;
	struct crypto_authenc_key_param *p;

	rta->rta_type = CRYPTO_AUTHENC_KEYA_PARAM;
	rta->rta_len = RTA_LENGTH(sizeof(*p));
	p = RTA_DATA(rta);
	p->enckeylen = cpu_to_be32(eklen);
	memcpy(out + RTA_SPACE(sizeof(*p)), ak, aklen);
	memcpy(out + RTA_SPACE(sizeof(*p)) + aklen, ek, eklen);
	return RTA_SPACE(sizeof(*p)) + aklen + eklen;
}

static void test_aead(const char *hname, unsigned int icv, unsigned int aklen,
		      const char *cname, unsigned int eklen)
{
	static const unsigned int lens[] = { 64, 1504, 4096 };
	char hwname[96], swname[128];
	struct crypto_aead *hw, *sw;
	unsigned int bs, ivs, l, i, j, a, ok = 0, tot = 0, bad = 0, badtot = 0;
	u8 key[256], ak[64], ek[32], iv0[16], iv1[16], iv2[16];
	unsigned int klen;
	ktime_t t0;
	s64 thw, tsw;
	int r1, r2;

	snprintf(hwname, sizeof(hwname), "authenc-hmac-%s-cbc-%s-fsoc3", hname, cname);
	snprintf(swname, sizeof(swname), "authenc(hmac(%s),cbc(%s))", hname, cname);
	hw = crypto_alloc_aead(hwname, 0, 0);
	/* The software instance (the one the driver falls back to) */
	sw = crypto_alloc_aead(swname, 0, CRYPTO_ALG_NEED_FALLBACK);
	if (IS_ERR(hw) || IS_ERR(sw)) {
		pr_info("fsoc3-cp-test: %s: cannot allocate (%d, %d)\n", hwname,
			PTR_ERR_OR_ZERO(hw), PTR_ERR_OR_ZERO(sw));
		goto out;
	}
	if (crypto_aead_setauthsize(hw, icv) || crypto_aead_setauthsize(sw, icv))
		goto out;
	bs = crypto_aead_blocksize(hw);
	ivs = crypto_aead_ivsize(hw);
	for (a = 0; a < 2; a++) {
		unsigned int alen = a ? 8 + ivs : 8;

		for (l = 0; l < ARRAY_SIZE(lens); l++) {
			unsigned int len = lens[l] / bs * bs;

			for (i = 0; i < iters; i++) {
				tot++;
				get_random_bytes(ak, aklen);
				get_random_bytes(ek, eklen);
				klen = authenc_key(key, ak, aklen, ek, eklen);
				get_random_bytes(iv0, ivs);
				get_random_bytes(b1, alen + len);
				memcpy(b2, b1, alen + len);
				memcpy(b3, b1, alen + len);
				memcpy(iv1, iv0, ivs);
				memcpy(iv2, iv0, ivs);
				if (crypto_aead_setkey(hw, key, klen) ||
				    crypto_aead_setkey(sw, key, klen)) {
					tot--;
					i--;
					continue;
				}
				r1 = run_aead(hw, false, b2, alen, len, iv1);
				r2 = run_aead(sw, false, b3, alen, len, iv2);
				if (r1 || r2 || memcmp(b2, b3, alen + len + icv)) {
					pr_info("fsoc3-cp-test: %s alen %u len %u: encryption differs (%d, %d)\n",
						hwname, alen, len, r1, r2);
					continue;
				}
				memcpy(b4, b3, alen + len + icv);
				memcpy(iv1, iv0, ivs);
				r1 = run_aead(hw, true, b3, alen, len + icv, iv1);
				if (r1 || memcmp(b3, b1, alen + len)) {
					pr_info("fsoc3-cp-test: %s alen %u len %u: decryption wrong (%d)\n",
						hwname, alen, len, r1);
					continue;
				}
				ok++;
				/* One bit off in the ICV, the ciphertext, the AD: -EBADMSG */
				for (j = 0; j < 3; j++) {
					static const char * const what[] = { "ICV", "ciphertext", "AD" };
					unsigned int pos = j == 0 ? alen + len + icv - 1 :
							   j == 1 ? alen + len / 2 : 3;

					badtot++;
					memcpy(b4, b2, alen + len + icv);
					b4[pos] ^= 0x01;
					memcpy(iv1, iv0, ivs);
					r1 = run_aead(hw, true, b4, alen, len + icv, iv1);
					if (r1 == -EBADMSG)
						bad++;
					else
						pr_info("fsoc3-cp-test: %s alen %u len %u: bad %s gives %d\n",
							hwname, alen, len, what[j], r1);
				}
			}
		}
	}
	memset(iv1, 0, sizeof(iv1));
	t0 = ktime_get();
	for (i = 0; i < 50; i++)
		run_aead(hw, false, b1, 8, 1504 / bs * bs, iv1);
	thw = div_s64(ktime_us_delta(ktime_get(), t0), 50);
	t0 = ktime_get();
	for (i = 0; i < 50; i++)
		run_aead(sw, false, b1, 8, 1504 / bs * bs, iv1);
	tsw = div_s64(ktime_us_delta(ktime_get(), t0), 50);
	pr_info("fsoc3-cp-test: hmac(%s)+cbc(%s) %u bit: %u/%u ok, tampered %u/%u -EBADMSG (vs %s); us per 1504 B enc: hw %lld sw %lld\n",
		hname, cname, eklen * 8, ok, tot, bad, badtot,
		drv(crypto_aead_tfm(sw)), thw, tsw);
out:
	if (!IS_ERR(sw))
		crypto_free_aead(sw);
	if (!IS_ERR(hw))
		crypto_free_aead(hw);
}

/* rfc4106(gcm(aes)): key | salt, AD = ESP header (8) | IV (8), tag icv */
static void test_gcm(unsigned int klen, unsigned int icv)
{
	static const unsigned int lens[] = { 4, 60, 64, 1504, 4096 };
	struct crypto_aead *hw, *sw;
	unsigned int l, i, j, ok = 0, tot = 0, bad = 0, badtot = 0;
	u8 key[36], iv0[8], iv1[8], iv2[8];
	ktime_t t0;
	s64 thw, tsw;
	int r1, r2;

	hw = crypto_alloc_aead("rfc4106-gcm-aes-fsoc3", 0, 0);
	sw = crypto_alloc_aead("rfc4106(gcm(aes))", 0, CRYPTO_ALG_NEED_FALLBACK);
	if (IS_ERR(hw) || IS_ERR(sw)) {
		pr_info("fsoc3-cp-test: rfc4106: cannot allocate (%d, %d)\n",
			PTR_ERR_OR_ZERO(hw), PTR_ERR_OR_ZERO(sw));
		goto out;
	}
	if (crypto_aead_setauthsize(hw, icv) || crypto_aead_setauthsize(sw, icv))
		goto out;
	for (l = 0; l < ARRAY_SIZE(lens); l++) {
		unsigned int len = lens[l];

		for (i = 0; i < iters; i++) {
			tot++;
			get_random_bytes(key, klen + 4);
			get_random_bytes(iv0, 8);
			get_random_bytes(b1, 16 + len);
			memcpy(b1 + 8, iv0, 8);		/* the IV ends the AD */
			memcpy(b2, b1, 16 + len);
			memcpy(b3, b1, 16 + len);
			memcpy(iv1, iv0, 8);
			memcpy(iv2, iv0, 8);
			if (crypto_aead_setkey(hw, key, klen + 4) ||
			    crypto_aead_setkey(sw, key, klen + 4)) {
				pr_info("fsoc3-cp-test: rfc4106: setkey failed\n");
				goto out;
			}
			r1 = run_aead(hw, false, b2, 16, len, iv1);
			r2 = run_aead(sw, false, b3, 16, len, iv2);
			if (r1 || r2 || memcmp(b2, b3, 16 + len + icv)) {
				pr_info("fsoc3-cp-test: rfc4106 %u bit len %u: encryption differs (%d, %d)\n",
					klen * 8, len, r1, r2);
				continue;
			}
			memcpy(iv1, iv0, 8);
			r1 = run_aead(hw, true, b3, 16, len + icv, iv1);
			if (r1 || memcmp(b3, b1, 16 + len)) {
				pr_info("fsoc3-cp-test: rfc4106 %u bit len %u: decryption wrong (%d)\n",
					klen * 8, len, r1);
				continue;
			}
			ok++;
			for (j = 0; j < 3; j++) {
				unsigned int pos = j == 0 ? 16 + len + icv - 1 :
						   j == 1 ? 16 + len / 2 : 3;

				badtot++;
				memcpy(b4, b2, 16 + len + icv);
				b4[pos] ^= 0x01;
				memcpy(iv1, iv0, 8);
				r1 = run_aead(hw, true, b4, 16, len + icv, iv1);
				if (r1 == -EBADMSG)
					bad++;
				else
					pr_info("fsoc3-cp-test: rfc4106 %u bit len %u: tampered byte %u gives %d\n",
						klen * 8, len, pos, r1);
			}
		}
	}
	memset(iv1, 0, sizeof(iv1));
	t0 = ktime_get();
	for (i = 0; i < 50; i++)
		run_aead(hw, false, b1, 16, 1504, iv1);
	thw = div_s64(ktime_us_delta(ktime_get(), t0), 50);
	t0 = ktime_get();
	for (i = 0; i < 50; i++)
		run_aead(sw, false, b1, 16, 1504, iv1);
	tsw = div_s64(ktime_us_delta(ktime_get(), t0), 50);
	pr_info("fsoc3-cp-test: rfc4106(gcm(aes)) %u bit tag %u: %u/%u ok, tampered %u/%u -EBADMSG (vs %s); us per 1504 B enc: hw %lld sw %lld\n",
		klen * 8, icv, ok, tot, bad, badtot, drv(crypto_aead_tfm(sw)), thw, tsw);
out:
	if (!IS_ERR(sw))
		crypto_free_aead(sw);
	if (!IS_ERR(hw))
		crypto_free_aead(hw);
}

/* A buffer as one scatterlist entry, or split in three */
static void sg_buf(struct scatterlist *sg, u8 *buf, unsigned int len,
		   bool split)
{
	if (split && len >= 3) {
		sg_init_table(sg, 3);
		sg_set_buf(&sg[0], buf, len / 3);
		sg_set_buf(&sg[1], buf + len / 3, len / 3);
		sg_set_buf(&sg[2], buf + 2 * (len / 3), len - 2 * (len / 3));
	} else {
		sg_init_one(sg, buf, len);
	}
}

/* In place if src == dst, else out of place (split scatterlists) */
static int run_aead_x(struct crypto_aead *tfm, bool dec, u8 *src, u8 *dst,
		      unsigned int alen, unsigned int clen, u8 *iv)
{
	unsigned int icv = crypto_aead_authsize(tfm);
	unsigned int slen = alen + clen;
	unsigned int dlen = alen + (dec ? clen - icv : clen + icv);
	struct scatterlist s[3], d[3];
	struct aead_request *req;
	DECLARE_CRYPTO_WAIT(wait);
	int ret;

	if (src == dst)
		return run_aead(tfm, dec, src, alen, clen, iv);
	req = aead_request_alloc(tfm, GFP_KERNEL);
	if (!req)
		return -ENOMEM;
	sg_buf(s, src, slen, true);
	sg_buf(d, dst, dlen, true);
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_SLEEP |
				  CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);
	aead_request_set_crypt(req, s, d, clen, iv);
	aead_request_set_ad(req, alen);
	ret = crypto_wait_req(dec ? crypto_aead_decrypt(req) :
				    crypto_aead_encrypt(req), &wait);
	aead_request_free(req);
	return ret;
}

static s64 speed_gcm(struct crypto_aead *tfm, unsigned int len)
{
	u8 iv[12] = {};
	ktime_t t0 = ktime_get();
	unsigned int i;

	for (i = 0; i < 50; i++)
		run_aead(tfm, false, b1, 8, len, iv);
	return div_s64(ktime_us_delta(ktime_get(), t0), 50);
}

/* At most 16 failure lines (the matrix is large) */
static unsigned int nfail;
#define GCM_FAIL(fmt, ...)						\
	do {								\
		if (++nfail <= 16)					\
			pr_info(fmt, ##__VA_ARGS__);			\
	} while (0)

/*
 * gcm(aes): key, 12-byte IV, AD and text of any length. The driver takes
 * AD of up to 8 bytes, texts of 1-16384 bytes; the rest is its fallback.
 * Every case also out of place over split scatterlists (odd iterations).
 */
static void test_gcm_plain(unsigned int klen)
{
	static const unsigned int alens[] = { 0, 1, 5, 8, 12, 13, 20 };
	static const unsigned int lens[] = {
		0, 1, 2, 3, 4, 5, 15, 16, 17, 31, 61, 64, 1397, 1398, 1399,
		1400, 4093, 16381, 16384, 16385 };
	static const unsigned int icvs[] = { 16, 15, 13, 12, 8, 4 };
	unsigned int c, al, l, i, j, ok = 0, tot = 0, bad = 0, badtot = 0;
	struct crypto_aead *hw, *sw;
	u8 key[32], iv0[12], iv1[12], iv2[12];
	int r1, r2;

	hw = crypto_alloc_aead("gcm-aes-fsoc3", 0, 0);
	sw = crypto_alloc_aead("gcm(aes)", 0, CRYPTO_ALG_NEED_FALLBACK);
	if (IS_ERR(hw) || IS_ERR(sw)) {
		pr_info("fsoc3-cp-test: gcm: cannot allocate (%d, %d)\n",
			PTR_ERR_OR_ZERO(hw), PTR_ERR_OR_ZERO(sw));
		goto out;
	}
	for (c = 0; c < ARRAY_SIZE(icvs); c++) {
		unsigned int icv = icvs[c];

		if (crypto_aead_setauthsize(hw, icv) ||
		    crypto_aead_setauthsize(sw, icv)) {
			pr_info("fsoc3-cp-test: gcm: tag %u refused\n", icv);
			continue;
		}
		for (al = 0; al < ARRAY_SIZE(alens); al++) {
			unsigned int alen = alens[al];

			/* Other tag sizes: a few AD sizes */
			if (c && alen != 0 && alen != 8 && alen != 13)
				continue;
			for (l = 0; l < ARRAY_SIZE(lens); l++) {
				unsigned int len = lens[l];
				unsigned int n = alen + len + icv;

				if (c && len > 4096)
					continue;
				for (i = 0; i < iters; i++) {
					bool oop = i & 1;
					u8 *d2 = oop ? b4 : b2, *d3 = oop ? b4 + BUF_MAX / 2 : b3;

					if (n > BUF_MAX / 2)
						oop = false, d2 = b2, d3 = b3;
					tot++;
					get_random_bytes(key, klen);
					get_random_bytes(iv0, 12);
					get_random_bytes(b1, alen + len);
					memcpy(b2, b1, alen + len);
					memcpy(b3, b1, alen + len);
					if (oop) {
						memset(d2, 0xa5, n);
						memset(d3, 0xa5, n);
					}
					memcpy(iv1, iv0, 12);
					memcpy(iv2, iv0, 12);
					if (crypto_aead_setkey(hw, key, klen) ||
					    crypto_aead_setkey(sw, key, klen)) {
						pr_info("fsoc3-cp-test: gcm: setkey failed\n");
						goto out;
					}
					r1 = run_aead_x(hw, false, b2, d2, alen, len, iv1);
					r2 = run_aead_x(sw, false, b3, d3, alen, len, iv2);
					if (r1 || r2 || memcmp(d2, d3, n)) {
						GCM_FAIL("fsoc3-cp-test: gcm %u bit tag %u alen %u len %u%s: encryption differs (%d, %d)\n",
							klen * 8, icv, alen, len,
							oop ? " oop" : "", r1, r2);
						continue;
					}
					/*
					 * Out of place the AD place of the outputs kept
					 * the 0xa5 fill (as it must): put the AD there,
					 * for the decryption and the tampering below
					 */
					if (oop) {
						memcpy(d2, b1, alen);
						memcpy(d3, b1, alen);
					}
					/* d3: the software ciphertext; decrypt it into b2 */
					if (oop)
						memset(b2, 0x5a, alen + len);
					memcpy(iv1, iv0, 12);
					r1 = run_aead_x(hw, true, d3, oop ? b2 : d3, alen,
							len + icv, iv1);
					if (r1 || memcmp((oop ? b2 : d3) + alen, b1 + alen, len)) {
						GCM_FAIL("fsoc3-cp-test: gcm %u bit tag %u alen %u len %u%s: decryption wrong (%d)\n",
							klen * 8, icv, alen, len,
							oop ? " oop" : "", r1);
						continue;
					}
					ok++;
					/* One bit off in the tag, the ciphertext, the AD */
					for (j = 0; j < 3; j++) {
						unsigned int pos = j == 0 ? alen + len + icv - 1 :
								   j == 1 ? alen + len / 2 : alen / 2;

						if ((j == 1 && !len) || (j == 2 && !alen))
							continue;
						badtot++;
						memcpy(b3, d2, n);
						b3[pos] ^= 0x01;
						memcpy(iv1, iv0, 12);
						r1 = run_aead_x(hw, true, b3, b3, alen,
								len + icv, iv1);
						if (r1 == -EBADMSG)
							bad++;
						else
							GCM_FAIL("fsoc3-cp-test: gcm %u bit tag %u alen %u len %u: tampered byte %u gives %d\n",
								klen * 8, icv, alen, len, pos, r1);
					}
				}
			}
		}
	}
	crypto_aead_setauthsize(hw, 16);
	crypto_aead_setauthsize(sw, 16);
	pr_info("fsoc3-cp-test: gcm(aes) %u bit: %u/%u ok, tampered %u/%u -EBADMSG (vs %s); us per enc (AD 8) 64/1397/1504 B: hw %lld/%lld/%lld sw %lld/%lld/%lld\n",
		klen * 8, ok, tot, bad, badtot, drv(crypto_aead_tfm(sw)),
		speed_gcm(hw, 64), speed_gcm(hw, 1397), speed_gcm(hw, 1504),
		speed_gcm(sw, 64), speed_gcm(sw, 1397), speed_gcm(sw, 1504));
out:
	if (!IS_ERR(sw))
		crypto_free_aead(sw);
	if (!IS_ERR(hw))
		crypto_free_aead(hw);
}

/*
 * Time table: microseconds per request (200 requests), encryption and
 * decryption, in place, AD 8 (gcm, authenc) or 16 (rfc4106), random key.
 */
static void speed_table(const char *name, unsigned int klen, unsigned int alen,
			bool authenc)
{
	static const unsigned int lens[] = { 64, 512, 1396, 1397, 1504, 4096 };
	struct crypto_aead *tfm;
	unsigned int l, i, icv, ivs;
	u8 key[128], iv[16] = {};
	char line[256];
	int n = 0, r = 0;

	/* Generic names: the software instance (as the fallback) */
	tfm = crypto_alloc_aead(name, 0, strstr(name, "fsoc3") ? 0 :
				CRYPTO_ALG_NEED_FALLBACK);
	if (IS_ERR(tfm)) {
		pr_info("fsoc3-cp-test: speed %s: %ld\n", name, PTR_ERR(tfm));
		return;
	}
	get_random_bytes(key, sizeof(key));
	if (authenc) {
		u8 ak[32], ek[16];

		get_random_bytes(ak, sizeof(ak));
		get_random_bytes(ek, sizeof(ek));
		klen = authenc_key(key, ak, sizeof(ak), ek, sizeof(ek));
	}
	if (crypto_aead_setkey(tfm, key, klen) ||
	    (authenc && crypto_aead_setauthsize(tfm, 16)))
		goto out;
	icv = crypto_aead_authsize(tfm);
	ivs = crypto_aead_ivsize(tfm);
	n = scnprintf(line, sizeof(line), "%s:", crypto_tfm_alg_driver_name(crypto_aead_tfm(tfm)));
	for (l = 0; l < ARRAY_SIZE(lens); l++) {
		unsigned int len = lens[l];
		ktime_t t0;
		u32 te, td;	/* ns */

		if (authenc && len % 16)
			continue;
		get_random_bytes(b1, alen + len);
		t0 = ktime_get();
		for (i = 0; i < 200; i++) {
			memcpy(b2, b1, alen + len);
			run_aead(tfm, false, b2, alen, len, iv);
		}
		te = div_s64(ktime_to_ns(ktime_sub(ktime_get(), t0)), 200);
		memcpy(b3, b2, alen + len + icv);
		t0 = ktime_get();
		for (i = 0; i < 200; i++) {
			memcpy(b2, b3, alen + len + icv);
			r = run_aead(tfm, true, b2, alen, len + icv, iv);
		}
		td = div_s64(ktime_to_ns(ktime_sub(ktime_get(), t0)), 200);
		n += scnprintf(line + n, sizeof(line) - n, " %u %u.%u/%u.%u%s",
			       len, te / 1000, te % 1000 / 100, td / 1000,
			       td % 1000 / 100, r ? "!" : "");
	}
	pr_info("fsoc3-cp-test: speed (B enc/dec us) %s (ivs %u)\n", line, ivs);
out:
	crypto_free_aead(tfm);
}

static int __init fsoc3_cp_test_init(void)
{
	static const char * const aes_sw[] = { "cbc(aes-generic)", "cbc(aes-lib)", NULL };
	static const char * const des_sw[] = { "cbc(des-generic)", NULL };
	static const char * const des3_sw[] = { "cbc(des3_ede-generic)", NULL };
	static const struct { const char *h; unsigned int icv, ak; } hs[] = {
		{ "md5", 12, 16 }, { "sha1", 12, 20 }, { "sha256", 16, 32 },
		{ "sha384", 24, 48 }, { "sha512", 32, 64 },
	};
	unsigned int i;

	b1 = kmalloc(BUF_MAX, GFP_KERNEL);
	b2 = kmalloc(BUF_MAX, GFP_KERNEL);
	b3 = kmalloc(BUF_MAX, GFP_KERNEL);
	b4 = kmalloc(BUF_MAX, GFP_KERNEL);
	if (b1 && b2 && b3 && b4 && speed) {
		speed_table("rfc4106-gcm-aes-fsoc3", 20, 16, false);
		speed_table("gcm-aes-fsoc3", 16, 8, false);
		speed_table("authenc-hmac-sha256-cbc-aes-fsoc3", 0, 8, true);
		speed_table("rfc4106(gcm(aes))", 20, 16, false);
		speed_table("gcm(aes)", 16, 8, false);
	} else if (b1 && b2 && b3 && b4) {
		test_sk("cbc(aes)", "cbc-aes-fsoc3", aes_sw, 16);
		test_sk("cbc(aes)", "cbc-aes-fsoc3", aes_sw, 24);
		test_sk("cbc(aes)", "cbc-aes-fsoc3", aes_sw, 32);
		test_sk("cbc(des)", "cbc-des-fsoc3", des_sw, 8);
		test_sk("cbc(des3_ede)", "cbc-des3_ede-fsoc3", des3_sw, 24);
		for (i = 0; i < ARRAY_SIZE(hs); i++) {
			test_aead(hs[i].h, hs[i].icv, hs[i].ak, "aes", 16);
			test_aead(hs[i].h, hs[i].icv, hs[i].ak, "des3_ede", 24);
		}
		test_aead("sha1", 12, 20, "aes", 32);
		for (i = 0; i < 3; i++) {
			test_gcm(16 + 8 * i, 16);
			test_gcm(16 + 8 * i, 12);
			test_gcm(16 + 8 * i, 8);
			test_gcm_plain(16 + 8 * i);
		}
	}
	kfree(b4);
	kfree(b3);
	kfree(b2);
	kfree(b1);
	return 0;
}

static void __exit fsoc3_cp_test_exit(void)
{
}

module_init(fsoc3_cp_test_init);
module_exit(fsoc3_cp_test_exit);

MODULE_DESCRIPTION("Differential test of fsoc3-cp against software (bring-up)");
MODULE_LICENSE("GPL");
