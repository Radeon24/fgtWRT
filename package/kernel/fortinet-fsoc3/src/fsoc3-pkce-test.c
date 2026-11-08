// SPDX-License-Identifier: GPL-2.0-only
/*
 * Differential test of rsa-fsoc3 against rsa-generic (bring-up tool, not
 * loaded at boot).
 *
 * At load, with key= (hex of a PKCS#1 RSAPrivateKey, in parts of at most
 * 1024 digits separated by commas, the limit of a string parameter): sets
 * the key on both
 * implementations, then iters times takes a random m < n, encrypts it with
 * both (the results must match) and decrypts the ciphertext with both (both
 * must give m back). Then m = 1 with both: the return codes must match
 * (the payload checks of rsa-generic). With pub= (hex of a PKCS#1
 * RSAPublicKey of the same key): the same encryption test through
 * set_pub_key. Logs the counts and the mean times; nothing stays set up.
 */

#include <crypto/akcipher.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>

#define MAX_PARTS	8

static char *key[MAX_PARTS], *pub[MAX_PARTS];
static int key_n, pub_n;
static unsigned int iters = 10;
module_param_array(key, charp, &key_n, 0);
MODULE_PARM_DESC(key, "PKCS#1 RSAPrivateKey, hex, in parts (comma separated)");
module_param_array(pub, charp, &pub_n, 0);
MODULE_PARM_DESC(pub, "PKCS#1 RSAPublicKey of the same key, hex, in parts (optional)");
module_param(iters, uint, 0);
MODULE_PARM_DESC(iters, "random messages (default 10)");

/* The parts of a hex parameter, joined and decoded */
static int unhex(char **part, int nparts, u8 **out, unsigned int *len)
{
	size_t n = 0, pn;
	int i;

	for (i = 0; i < nparts; i++) {
		pn = strlen(part[i]);
		if (pn % 2)
			return -EINVAL;
		n += pn;
	}
	if (!n)
		return -EINVAL;
	*len = n / 2;
	*out = kmalloc(*len, GFP_KERNEL);
	if (!*out)
		return -ENOMEM;
	for (n = 0, i = 0; i < nparts; i++) {
		pn = strlen(part[i]) / 2;
		if (hex2bin(*out + n, part[i], pn)) {
			kfree(*out);
			return -EINVAL;
		}
		n += pn;
	}
	return 0;
}

static int run(struct crypto_akcipher *tfm, bool enc, const u8 *in,
	       unsigned int len, u8 *out, s64 *us)
{
	struct akcipher_request *req;
	struct scatterlist src, dst;
	DECLARE_CRYPTO_WAIT(wait);
	ktime_t t0;
	int ret;

	req = akcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req)
		return -ENOMEM;
	sg_init_one(&src, in, len);
	sg_init_one(&dst, out, len);
	akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
				      CRYPTO_TFM_REQ_MAY_SLEEP,
				      crypto_req_done, &wait);
	akcipher_request_set_crypt(req, &src, &dst, len, len);
	t0 = ktime_get();
	ret = crypto_wait_req(enc ? crypto_akcipher_encrypt(req) :
				    crypto_akcipher_decrypt(req), &wait);
	*us += ktime_us_delta(ktime_get(), t0);
	akcipher_request_free(req);
	return ret;
}

static void dump(const char *what, const u8 *b, unsigned int len)
{
	pr_info("fsoc3-pkce-test:   %s %*phN...\n", what, min(len, 16U), b);
}

static int test_pub(const u8 *pk, unsigned int pklen, unsigned int len)
{
	struct crypto_akcipher *hw, *sw;
	unsigned int i, ok = 0;
	u8 *m, *c1, *c2;
	s64 thw = 0, tsw = 0;
	int ret = -ENOMEM;

	hw = crypto_alloc_akcipher("rsa-fsoc3", 0, 0);
	sw = crypto_alloc_akcipher("rsa-generic", 0, 0);
	m = kmalloc(len, GFP_KERNEL);
	c1 = kmalloc(len, GFP_KERNEL);
	c2 = kmalloc(len, GFP_KERNEL);
	if (IS_ERR(hw) || IS_ERR(sw) || !m || !c1 || !c2) {
		ret = IS_ERR(hw) ? PTR_ERR(hw) : IS_ERR(sw) ? PTR_ERR(sw) : ret;
		goto out;
	}
	ret = crypto_akcipher_set_pub_key(hw, pk, pklen) ?:
	      crypto_akcipher_set_pub_key(sw, pk, pklen);
	if (ret)
		goto out;
	for (i = 0; i < iters; i++) {
		get_random_bytes(m, len);
		m[0] = 0;
		m[1] |= 1;
		if (run(hw, true, m, len, c1, &thw) ||
		    run(sw, true, m, len, c2, &tsw) || memcmp(c1, c2, len)) {
			pr_info("fsoc3-pkce-test: set_pub_key: encryption %u differs\n", i);
			dump("rsa-fsoc3  ", c1, len);
			dump("rsa-generic", c2, len);
			continue;
		}
		ok++;
	}
	pr_info("fsoc3-pkce-test: set_pub_key: %u/%u ok, mean rsa-fsoc3 %lld us, rsa-generic %lld us\n",
		ok, iters, iters ? div_s64(thw, iters) : 0,
		iters ? div_s64(tsw, iters) : 0);
	ret = 0;
out:
	kfree(c2);
	kfree(c1);
	kfree(m);
	if (!IS_ERR(sw))
		crypto_free_akcipher(sw);
	if (!IS_ERR(hw))
		crypto_free_akcipher(hw);
	return ret;
}

static int __init fsoc3_pkce_test_init(void)
{
	struct crypto_akcipher *hw, *sw;
	unsigned int klen, plen = 0, len, i, eok = 0, dok = 0;
	s64 ehw = 0, esw = 0, dhw = 0, dsw = 0;
	u8 *k, *p = NULL, *m = NULL, *c1 = NULL, *c2 = NULL, *m1 = NULL;
	int ret, r1, r2;

	ret = unhex(key, key_n, &k, &klen);
	if (ret) {
		pr_err("fsoc3-pkce-test: key= missing or not hex\n");
		return ret;
	}
	if (pub_n) {
		ret = unhex(pub, pub_n, &p, &plen);
		if (ret) {
			pr_err("fsoc3-pkce-test: pub= not hex\n");
			goto out_k;
		}
	}

	hw = crypto_alloc_akcipher("rsa-fsoc3", 0, 0);
	if (IS_ERR(hw)) {
		ret = PTR_ERR(hw);
		pr_err("fsoc3-pkce-test: no rsa-fsoc3 (%d)\n", ret);
		goto out_p;
	}
	sw = crypto_alloc_akcipher("rsa-generic", 0, 0);
	if (IS_ERR(sw)) {
		ret = PTR_ERR(sw);
		pr_err("fsoc3-pkce-test: no rsa-generic (%d)\n", ret);
		goto out_hw;
	}
	ret = crypto_akcipher_set_priv_key(hw, k, klen);
	r1 = crypto_akcipher_set_priv_key(sw, k, klen);
	if (ret || r1) {
		pr_err("fsoc3-pkce-test: set_priv_key: rsa-fsoc3 %d, rsa-generic %d\n",
		       ret, r1);
		ret = ret ?: r1;
		goto out_sw;
	}
	len = crypto_akcipher_maxsize(sw);
	ret = -ENOMEM;
	m = kmalloc(len, GFP_KERNEL);
	c1 = kmalloc(len, GFP_KERNEL);
	c2 = kmalloc(len, GFP_KERNEL);
	m1 = kmalloc(len, GFP_KERNEL);
	if (!m || !c1 || !c2 || !m1)
		goto out_sw;
	pr_info("fsoc3-pkce-test: %u-bit key, maxsize rsa-fsoc3 %u, rsa-generic %u\n",
		8 * len, crypto_akcipher_maxsize(hw), len);

	for (i = 0; i < iters; i++) {
		get_random_bytes(m, len);
		m[0] = 0;		/* m < n */
		m[1] |= 1;		/* m > 1 */
		r1 = run(hw, true, m, len, c1, &ehw);
		r2 = run(sw, true, m, len, c2, &esw);
		if (r1 || r2 || memcmp(c1, c2, len)) {
			pr_info("fsoc3-pkce-test: encryption %u differs (%d, %d)\n",
				i, r1, r2);
			dump("rsa-fsoc3  ", c1, len);
			dump("rsa-generic", c2, len);
		} else {
			eok++;
		}
		r1 = run(hw, false, c2, len, m1, &dhw);
		if (r1 || memcmp(m1, m, len)) {
			pr_info("fsoc3-pkce-test: decryption %u by rsa-fsoc3 wrong (%d)\n",
				i, r1);
			dump("m          ", m, len);
			dump("rsa-fsoc3  ", m1, len);
		} else {
			dok++;
		}
		r2 = run(sw, false, c2, len, m1, &dsw);
		if (r2 || memcmp(m1, m, len))
			pr_info("fsoc3-pkce-test: decryption %u by rsa-generic wrong (%d)\n",
				i, r2);
	}
	pr_info("fsoc3-pkce-test: encryption %u/%u ok, decryption %u/%u ok\n",
		eok, iters, dok, iters);
	if (iters)
		pr_info("fsoc3-pkce-test: mean rsa-fsoc3 enc %lld us dec %lld us, rsa-generic enc %lld us dec %lld us\n",
			div_s64(ehw, iters), div_s64(dhw, iters),
			div_s64(esw, iters), div_s64(dsw, iters));

	/* Payload checks: m = 1 is refused by rsa-generic */
	memset(m, 0, len);
	m[len - 1] = 1;
	r1 = run(hw, true, m, len, c1, &ehw);
	r2 = run(sw, true, m, len, c2, &esw);
	pr_info("fsoc3-pkce-test: m = 1: rsa-fsoc3 %d, rsa-generic %d: %s\n",
		r1, r2, r1 == r2 ? "same" : "DIFFERENT");

	ret = p ? test_pub(p, plen, len) : 0;
out_sw:
	kfree(m1);
	kfree(c2);
	kfree(c1);
	kfree(m);
	crypto_free_akcipher(sw);
out_hw:
	crypto_free_akcipher(hw);
out_p:
	kfree(p);
out_k:
	kfree_sensitive(k);
	return ret;
}

static void __exit fsoc3_pkce_test_exit(void)
{
}

module_init(fsoc3_pkce_test_init);
module_exit(fsoc3_pkce_test_exit);

MODULE_DESCRIPTION("Differential test of rsa-fsoc3 against rsa-generic (bring-up)");
MODULE_LICENSE("GPL");
