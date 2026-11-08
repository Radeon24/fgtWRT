// SPDX-License-Identifier: GPL-2.0-only
/*
 * Fortinet FortiSOC3 public key engine (PKCE): RSA ("rsa", raw RSA as
 * rsa-generic, with the same key checks and the same payload checks)
 *
 * Programming model, as established on the FortiGate 100E (bring-up
 * sessions 1-5; register names of the vendor firmware, FortiOS 6.4):
 *
 * Channel pketx_0 (0xf501a000, inside the NP6Lite window, whose driver
 * requests it: mapped, not requested). Registers 64 bits apart:
 *   +0x00 qba    physical address of the command list (32 bits)
 *   +0x08 qbah   upper DMA address byte: 0x27 (through the ACP)
 *   +0x10 qlen   number of commands
 *   +0x20 ctlst  busy 0, intsts 1, vclr 2, intena 3, errors 4-12 (ovferr,
 *                adrerr, ofserr, lenerr, fetcherr, queerr, wcerr, klerr,
 *                loaderr). Start: 0x9; end: busy clear, intsts set
 *                (interrupt GIC SPI 65 when intena); acknowledge:
 *                ctlst | 0x6, then 0x8.
 *
 * Commands: 8 bytes, opcode in bits 31:28 of the first word. Numbers are
 * arrays of 32-bit words, least significant first, read and written by
 * the engine in 64-bit beats.
 *   SET   0x60000000, wc << 16 | kl: kl = bit length (1-0x103e), wc = word
 *         count, even, 4-128 (else wcerr)
 *   LOAD  0x1000LLRR, address: register RR <- LL words (1-0x81)
 *   STORE 0x2000LLRR, address: LL words <- register RR
 *   EXP   0x50000000, 0: reg 0x00 := X^E mod N, with, before it,
 *         reg 0x00 = H = R^2 mod N, 0x08 = X, 0x10 = N, 0x18 = E and
 *         R = 2^(32 wc). N must be odd and 32 wc >= kl + 32 (one spare
 *         word; with one word less, the engine stops with ovferr).
 * One modular exponentiation is the list SET, LOAD 0x00/0x08/0x10/0x18
 * (wc words each), EXP, STORE 0x00. H is computed here (MPI).
 *
 * Cache coherency: the bring-up device trees leave the ACP profiles as the
 * boot loader set them, so the accesses with qbah 0x27 are not taken as
 * coherent. The buffer is coherent DMA memory (not cached by the CPU),
 * cleaned and invalidated from the outer cache (PL310) before the start
 * and after the end, as in the bring-up test that established all this.
 *
 * Interrupt: the end of a command list sets intsts, but on the 100E no
 * interrupt reaches the GIC (SPI 65, the line of the vendor firmware, which
 * does not use the engine either). The driver waits for it on the first
 * list only and polls ctlst from then on.
 *
 * Every private key result is checked (m^e mod n must give the input back)
 * before it is given out: a wrong CRT half would reveal the key. When the
 * engine fails (an error, a check that does not pass, a timeout after
 * which it is no longer used), the request goes to rsa-generic.
 *
 * Decryption uses the CRT (two exponentiations of half size, recombined
 * with MPI) when the key has its CRT parts (crt=1, the default), else d.
 * Keys whose moduli the engine cannot take (more than 4064 bits) go to
 * rsa-generic, as the encryption with a 4096-bit key does; the decryption
 * with such a key still runs on the engine through the CRT.
 */

#include <crypto/akcipher.h>
#include <crypto/internal/akcipher.h>
#include <crypto/internal/rsa.h>
#include <linux/completion.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mpi.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <asm/outercache.h>

#define PKCE_QBA		0x00
#define PKCE_QBAH		0x08
#define PKCE_QLEN		0x10
#define PKCE_CTLST		0x20
#define PKCE_REGS_SIZE		0x80

#define CTLST_BUSY		BIT(0)
#define CTLST_INTSTS		BIT(1)
#define CTLST_VCLR		BIT(2)
#define CTLST_INTENA		BIT(3)
#define CTLST_ERR		GENMASK(12, 4)

#define PKCE_QBAH_ACP		0x27

#define CMD_LOAD		0x10000000
#define CMD_STORE		0x20000000
#define CMD_EXP			0x50000000
#define CMD_SET			0x60000000
#define REG_H			0x00	/* H in, result out */
#define REG_X			0x08
#define REG_N			0x10
#define REG_E			0x18

#define PKCE_MIN_WC		4
#define PKCE_MAX_WC		128
#define PKCE_MAX_BITS		(32 * (PKCE_MAX_WC - 1))	/* 4064 */

/* Layout of the DMA buffer */
#define BUF_CMD			0x000
#define BUF_OPND(i)		(0x100 + (i) * 4 * PKCE_MAX_WC)	/* H, X, N, E */
#define BUF_RES			BUF_OPND(4)
#define BUF_SIZE		(BUF_RES + 4 * PKCE_MAX_WC)
#define PKCE_NCMDS		7

/* Longest operation: 4064-bit private exponent without the CRT, ~130 ms */
#define PKCE_TIMEOUT_MS		2000
/*
 * Wait for the interrupt of the first command list (the self-test, a few
 * microseconds): on the 100E the interrupt does not come (its routing is not
 * established), and the driver then polls.
 */
#define PKCE_IRQ_PROBE_MS	100

static bool crt = true;
module_param(crt, bool, 0644);
MODULE_PARM_DESC(crt, "decrypt with the CRT parts of the key (default 1)");

struct fsoc3_pkce {
	struct device *dev;
	void __iomem *regs;
	int irq;
	bool polling;
	bool dead;
	struct mutex lock;		/* one command list at a time */
	struct completion done;
	u32 ctlst;			/* ctlst at the end, from the IRQ */
	u32 *buf;
	dma_addr_t dma;
	u64 ops;
};

/* The engine behind the registered algorithm */
static struct fsoc3_pkce *fsoc3_pkce;

/* One modular exponentiation: modulus, H and exponent, wc words each */
struct fsoc3_mexp {
	unsigned int kl, wc;		/* wc 0: not for the engine */
	u32 *w;
};

struct fsoc3_rsa_ctx {
	struct crypto_akcipher *fallback;
	MPI n, e, d, p, q, dp, dq, qinv;
	struct fsoc3_mexp pub, priv, crtp, crtq;
};

/* --- engine ----------------------------------------------------------- */

static irqreturn_t fsoc3_pkce_irq(int irq, void *data)
{
	struct fsoc3_pkce *pk = data;
	u32 st = readl(pk->regs + PKCE_CTLST);

	if (!(st & CTLST_INTSTS))
		return IRQ_NONE;
	writel(st | CTLST_INTSTS | CTLST_VCLR, pk->regs + PKCE_CTLST);
	pk->ctlst = st;
	complete(&pk->done);
	return IRQ_HANDLED;
}

static void fsoc3_pkce_ack(struct fsoc3_pkce *pk, u32 st)
{
	writel(st | CTLST_INTSTS | CTLST_VCLR, pk->regs + PKCE_CTLST);
	writel(CTLST_INTENA, pk->regs + PKCE_CTLST);
}

static void fsoc3_pkce_cmd(struct fsoc3_pkce *pk, unsigned int i, u32 w0, u32 w1)
{
	pk->buf[BUF_CMD / 4 + 2 * i] = w0;
	pk->buf[BUF_CMD / 4 + 2 * i + 1] = w1;
}

/* Runs the command list of the buffer; called with pk->lock held */
static int fsoc3_pkce_run(struct fsoc3_pkce *pk, unsigned int ncmds)
{
	phys_addr_t pa = pk->dma;	/* no IOMMU, no DMA offset */
	u32 st;
	int ret;

	if (pk->dead)
		return -EIO;

	wmb();
	outer_flush_range(pa, pa + BUF_SIZE);

	reinit_completion(&pk->done);
	pk->ctlst = 0;
	writel(lower_32_bits(pk->dma) + BUF_CMD, pk->regs + PKCE_QBA);
	writel(ncmds, pk->regs + PKCE_QLEN);
	writel(CTLST_BUSY | CTLST_INTENA, pk->regs + PKCE_CTLST);

	if (!pk->polling) {
		if (wait_for_completion_timeout(&pk->done, msecs_to_jiffies(
				pk->ops ? PKCE_TIMEOUT_MS : PKCE_IRQ_PROBE_MS))) {
			st = pk->ctlst;
		} else {
			st = readl(pk->regs + PKCE_CTLST);
			if (try_wait_for_completion(&pk->done)) {
				st = pk->ctlst;
			} else if (!(st & CTLST_BUSY)) {
				/* Done, but no interrupt came */
				dev_info(pk->dev,
					 "no interrupt (ctlst %#x): polling\n", st);
				disable_irq(pk->irq);
				pk->polling = true;
				fsoc3_pkce_ack(pk, st);
			}
		}
	} else {
		ret = readl_poll_timeout(pk->regs + PKCE_CTLST, st,
					 !(st & CTLST_BUSY), 20,
					 PKCE_TIMEOUT_MS * 1000);
		if (!ret)
			fsoc3_pkce_ack(pk, st);
	}

	if (st & CTLST_BUSY) {
		dev_err(pk->dev, "still busy after %u ms (ctlst %#x), engine disabled\n",
			PKCE_TIMEOUT_MS, st);
		pk->dead = true;
		return -ETIMEDOUT;
	}
	if (!pk->polling)
		writel(CTLST_INTENA, pk->regs + PKCE_CTLST);

	outer_flush_range(pa, pa + BUF_SIZE);
	rmb();
	pk->ops++;

	if (st & CTLST_ERR) {
		dev_err_ratelimited(pk->dev, "command list failed, ctlst %#x\n",
				    st);
		return -EIO;
	}
	return 0;
}

/*
 * res := x^e mod n. All arrays have wc words (least significant first);
 * h = 2^(64 wc) mod n; x < n.
 */
static int fsoc3_pkce_exp(struct fsoc3_pkce *pk, unsigned int kl,
			  unsigned int wc, const u32 *h, const u32 *x,
			  const u32 *n, const u32 *e, u32 *res)
{
	const u32 *opnd[4] = { h, x, n, e };
	static const u8 reg[4] = { REG_H, REG_X, REG_N, REG_E };
	u32 base = lower_32_bits(pk->dma);
	unsigned int i;
	int ret;

	mutex_lock(&pk->lock);
	for (i = 0; i < 4; i++)
		memcpy(pk->buf + BUF_OPND(i) / 4, opnd[i], 4 * wc);
	fsoc3_pkce_cmd(pk, 0, CMD_SET, wc << 16 | kl);
	for (i = 0; i < 4; i++)
		fsoc3_pkce_cmd(pk, 1 + i, CMD_LOAD | wc << 8 | reg[i],
			       base + BUF_OPND(i));
	fsoc3_pkce_cmd(pk, 5, CMD_EXP, 0);
	fsoc3_pkce_cmd(pk, 6, CMD_STORE | wc << 8 | REG_H, base + BUF_RES);
	memset(pk->buf + BUF_RES / 4, 0, 4 * wc);

	ret = fsoc3_pkce_run(pk, PKCE_NCMDS);
	if (!ret)
		memcpy(res, pk->buf + BUF_RES / 4, 4 * wc);
	/* Operands (key parts among them) and result: not left behind */
	memzero_explicit((u8 *)pk->buf + BUF_OPND(0), BUF_SIZE - BUF_OPND(0));
	mutex_unlock(&pk->lock);
	return ret;
}

/*
 * Known answer at probe (measured in bring-up session 5): N = 2^96 - 17,
 * X = 0x0123456789abcdef01234567, E = 0x10001, wc = 4.
 */
static int fsoc3_pkce_selftest(struct fsoc3_pkce *pk)
{
	static const u32 n[4] = { 0xffffffef, 0xffffffff, 0xffffffff, 0 };
	static const u32 h[4] = { 0, 0, 0x121, 0 };
	static const u32 x[4] = { 0x01234567, 0x89abcdef, 0x01234567, 0 };
	static const u32 e[4] = { 0x10001, 0, 0, 0 };
	static const u32 y[4] = { 0x5d4b2414, 0xacf21e5b, 0x41c642ac, 0 };
	u32 r[4];
	int ret;

	ret = fsoc3_pkce_exp(pk, 96, 4, h, x, n, e, r);
	if (ret)
		return ret;
	if (memcmp(r, y, sizeof(y))) {
		dev_err(pk->dev, "self-test: %08x %08x %08x %08x, expected %08x %08x %08x %08x\n",
			r[3], r[2], r[1], r[0], y[3], y[2], y[1], y[0]);
		return -EIO;
	}
	return 0;
}

/* --- numbers ---------------------------------------------------------- */

/* w := a, wc words, least significant first */
static int fsoc3_mpi_to_words(u32 *w, unsigned int wc, MPI a)
{
	unsigned int nbytes, i;
	u8 *b;
	int ret;

	b = kmalloc(4 * wc, GFP_KERNEL);
	if (!b)
		return -ENOMEM;
	ret = mpi_read_buffer(a, b, 4 * wc, &nbytes, NULL);
	if (!ret) {
		memset(w, 0, 4 * wc);
		for (i = 0; i < nbytes; i++)
			w[i / 4] |= (u32)b[nbytes - 1 - i] << (8 * (i % 4));
	}
	kfree_sensitive(b);
	return ret;
}

static MPI fsoc3_words_to_mpi(const u32 *w, unsigned int wc)
{
	unsigned int i;
	MPI a;
	u8 *b;

	b = kmalloc(4 * wc, GFP_KERNEL);
	if (!b)
		return NULL;
	for (i = 0; i < 4 * wc; i++)
		b[4 * wc - 1 - i] = w[i / 4] >> (8 * (i % 4));
	a = mpi_read_raw_data(b, 4 * wc);
	kfree_sensitive(b);
	return a;
}

static void fsoc3_mexp_free(struct fsoc3_mexp *x)
{
	kfree_sensitive(x->w);
	x->w = NULL;
	x->wc = 0;
}

/*
 * Prepares x^e mod m for the engine. Leaves x->wc at 0 (the caller then
 * uses rsa-generic) when the engine cannot take it.
 */
static int fsoc3_mexp_init(struct fsoc3_mexp *x, MPI m, MPI e)
{
	unsigned int kl = mpi_get_nbits(m), wc;
	u8 two = 2, k[2];
	MPI h, base, exp;
	int ret;

	fsoc3_mexp_free(x);
	if (kl < 2 || kl > PKCE_MAX_BITS || !mpi_test_bit(m, 0) ||
	    !mpi_cmp_ui(e, 0) || mpi_get_nbits(e) > kl)
		return 0;

	wc = max_t(unsigned int, round_up(DIV_ROUND_UP(kl, 32) + 1, 2),
		   PKCE_MIN_WC);
	x->w = kcalloc(3 * wc, 4, GFP_KERNEL);
	if (!x->w)
		return -ENOMEM;

	/* H = R^2 mod m = 2^(64 wc) mod m */
	k[0] = (64 * wc) >> 8;
	k[1] = (64 * wc) & 0xff;
	h = mpi_alloc(0);
	base = mpi_read_raw_data(&two, 1);
	exp = mpi_read_raw_data(k, 2);
	ret = -ENOMEM;
	if (h && base && exp)
		ret = mpi_powm(h, base, exp, m) ?:
		      fsoc3_mpi_to_words(x->w, wc, m) ?:
		      fsoc3_mpi_to_words(x->w + wc, wc, h) ?:
		      fsoc3_mpi_to_words(x->w + 2 * wc, wc, e);
	mpi_free(exp);
	mpi_free(base);
	mpi_free(h);
	if (ret) {
		fsoc3_mexp_free(x);
		return ret;
	}
	x->kl = kl;
	x->wc = wc;
	return 0;
}

/* r := a^e mod m on the engine, a < m */
static MPI fsoc3_mexp_run(const struct fsoc3_mexp *x, MPI a, int *err)
{
	unsigned int wc = x->wc;
	MPI r = NULL;
	u32 *t;

	t = kcalloc(2 * wc, 4, GFP_KERNEL);
	if (!t) {
		*err = -ENOMEM;
		return NULL;
	}
	*err = fsoc3_mpi_to_words(t, wc, a) ?:
	       fsoc3_pkce_exp(fsoc3_pkce, x->kl, wc, x->w + wc, t, x->w,
			      x->w + 2 * wc, t + wc);
	if (!*err) {
		r = fsoc3_words_to_mpi(t + wc, wc);
		if (!r)
			*err = -ENOMEM;
	}
	kfree_sensitive(t);
	return r;
}

/* --- RSA -------------------------------------------------------------- */

/* As rsa-generic: 1 < x < n - 1 (SP 800-56Br2, 7.1.1 and 7.1.2) */
static int fsoc3_rsa_check_payload(MPI x, MPI n)
{
	MPI n1;
	int ret = 0;

	if (mpi_cmp_ui(x, 1) <= 0)
		return -EINVAL;
	n1 = mpi_alloc(0);
	if (!n1)
		return -ENOMEM;
	if (mpi_sub_ui(n1, n, 1) || mpi_cmp(x, n1) >= 0)
		ret = -EINVAL;
	mpi_free(n1);
	return ret;
}

static void fsoc3_rsa_free_key(struct fsoc3_rsa_ctx *ctx)
{
	MPI *m[] = { &ctx->n, &ctx->e, &ctx->d, &ctx->p, &ctx->q, &ctx->dp,
		     &ctx->dq, &ctx->qinv };
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(m); i++) {
		mpi_free(*m[i]);
		*m[i] = NULL;
	}
	fsoc3_mexp_free(&ctx->pub);
	fsoc3_mexp_free(&ctx->priv);
	fsoc3_mexp_free(&ctx->crtp);
	fsoc3_mexp_free(&ctx->crtq);
}

static int fsoc3_rsa_set_pub_key(struct crypto_akcipher *tfm, const void *key,
				 unsigned int keylen)
{
	struct fsoc3_rsa_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct rsa_key raw = {};
	int ret;

	fsoc3_rsa_free_key(ctx);
	/* Same checks as rsa-generic (lengths, FIPS), which also falls back */
	ret = crypto_akcipher_set_pub_key(ctx->fallback, key, keylen) ?:
	      rsa_parse_pub_key(&raw, key, keylen);
	if (ret)
		return ret;

	ctx->n = mpi_read_raw_data(raw.n, raw.n_sz);
	ctx->e = mpi_read_raw_data(raw.e, raw.e_sz);
	ret = -ENOMEM;
	if (ctx->n && ctx->e)
		ret = fsoc3_mexp_init(&ctx->pub, ctx->n, ctx->e);
	if (ret)
		fsoc3_rsa_free_key(ctx);
	return ret;
}

static int fsoc3_rsa_set_priv_key(struct crypto_akcipher *tfm, const void *key,
				  unsigned int keylen)
{
	struct fsoc3_rsa_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct rsa_key raw = {};
	int ret;

	fsoc3_rsa_free_key(ctx);
	ret = crypto_akcipher_set_priv_key(ctx->fallback, key, keylen) ?:
	      rsa_parse_priv_key(&raw, key, keylen);
	if (ret)
		return ret;

	ret = -ENOMEM;
	ctx->n = mpi_read_raw_data(raw.n, raw.n_sz);
	ctx->e = mpi_read_raw_data(raw.e, raw.e_sz);
	ctx->d = mpi_read_raw_data(raw.d, raw.d_sz);
	ctx->p = mpi_read_raw_data(raw.p, raw.p_sz);
	ctx->q = mpi_read_raw_data(raw.q, raw.q_sz);
	ctx->dp = mpi_read_raw_data(raw.dp, raw.dp_sz);
	ctx->dq = mpi_read_raw_data(raw.dq, raw.dq_sz);
	ctx->qinv = mpi_read_raw_data(raw.qinv, raw.qinv_sz);
	if (ctx->n && ctx->e && ctx->d && ctx->p && ctx->q && ctx->dp &&
	    ctx->dq && ctx->qinv)
		ret = fsoc3_mexp_init(&ctx->pub, ctx->n, ctx->e) ?:
		      fsoc3_mexp_init(&ctx->priv, ctx->n, ctx->d) ?:
		      fsoc3_mexp_init(&ctx->crtp, ctx->p, ctx->dp) ?:
		      fsoc3_mexp_init(&ctx->crtq, ctx->q, ctx->dq);
	if (ret)
		fsoc3_rsa_free_key(ctx);
	return ret;
}

static int fsoc3_rsa_fallback(struct akcipher_request *req, bool enc)
{
	struct fsoc3_rsa_ctx *ctx = akcipher_tfm_ctx(crypto_akcipher_reqtfm(req));
	struct akcipher_request *sub = akcipher_request_ctx(req);
	int ret;

	akcipher_request_set_tfm(sub, ctx->fallback);
	akcipher_request_set_callback(sub, req->base.flags, req->base.complete,
				      req->base.data);
	akcipher_request_set_crypt(sub, req->src, req->dst, req->src_len,
				   req->dst_len);
	ret = enc ? crypto_akcipher_encrypt(sub) : crypto_akcipher_decrypt(sub);
	req->dst_len = sub->dst_len;
	return ret;
}

static int fsoc3_rsa_write(struct akcipher_request *req, MPI r)
{
	int sign, ret;

	ret = mpi_write_to_sgl(r, req->dst, req->dst_len, &sign);
	if (!ret && sign < 0)
		ret = -EBADMSG;
	return ret;
}

static int fsoc3_rsa_enc(struct akcipher_request *req)
{
	struct fsoc3_rsa_ctx *ctx = akcipher_tfm_ctx(crypto_akcipher_reqtfm(req));
	MPI m, c;
	int ret;

	if (unlikely(!ctx->n || !ctx->e))
		return -EINVAL;
	if (!ctx->pub.wc || READ_ONCE(fsoc3_pkce->dead))
		return fsoc3_rsa_fallback(req, true);

	m = mpi_read_raw_from_sgl(req->src, req->src_len);
	if (!m)
		return -ENOMEM;
	ret = fsoc3_rsa_check_payload(m, ctx->n);
	if (!ret) {
		c = fsoc3_mexp_run(&ctx->pub, m, &ret);
		if (c)
			ret = fsoc3_rsa_write(req, c);
		mpi_free(c);
	}
	mpi_free(m);
	/* The engine failed: the software does it (the source is untouched) */
	if (ret == -EIO || ret == -ETIMEDOUT)
		return fsoc3_rsa_fallback(req, true);
	return ret;
}

/* m := c^d mod n by the CRT, as rsa-generic (RFC 8017, 5.1.2, 2b) */
static MPI fsoc3_rsa_dec_crt(struct fsoc3_rsa_ctx *ctx, MPI c, int *err)
{
	MPI cp, cq, m1 = NULL, m2 = NULL, h = NULL, t = NULL, one;
	u8 b1 = 1;

	*err = -ENOMEM;
	one = mpi_read_raw_data(&b1, 1);
	cp = mpi_alloc(0);
	cq = mpi_alloc(0);
	if (!one || !cp || !cq)
		goto out;

	/* c mod p, c mod q: the engine takes operands below the modulus */
	*err = mpi_mulm(cp, c, one, ctx->p) ?: mpi_mulm(cq, c, one, ctx->q);
	if (*err)
		goto out;

	/* m1 = c^dP mod p, m2 = c^dQ mod q */
	m1 = fsoc3_mexp_run(&ctx->crtp, cp, err);
	if (!m1)
		goto out;
	m2 = fsoc3_mexp_run(&ctx->crtq, cq, err);
	if (!m2)
		goto out;

	/* h = (m1 - m2) qInv mod p; m = m2 + q h (mod n) */
	*err = -ENOMEM;
	h = mpi_alloc(0);
	t = mpi_alloc(0);
	if (!h || !t)
		goto out;
	*err = mpi_sub(t, m1, m2) ?:
	       mpi_mulm(h, t, ctx->qinv, ctx->p) ?:
	       mpi_mul(t, ctx->q, h) ?:
	       mpi_addm(h, m2, t, ctx->n);
out:
	mpi_free(t);
	mpi_free(m2);
	mpi_free(m1);
	mpi_free(cq);
	mpi_free(cp);
	mpi_free(one);
	if (*err) {
		mpi_free(h);
		return NULL;
	}
	return h;
}

/* 0 if m^e mod n == c, -EIO if not (the result is not given out) */
static int fsoc3_rsa_verify(struct fsoc3_rsa_ctx *ctx, MPI m, MPI c)
{
	MPI v = NULL;
	int ret = 0;

	if (ctx->pub.wc) {
		v = fsoc3_mexp_run(&ctx->pub, m, &ret);
	} else {
		v = mpi_alloc(0);
		ret = v ? mpi_powm(v, m, ctx->e, ctx->n) : -ENOMEM;
	}
	if (!ret && mpi_cmp(v, c)) {
		dev_err_ratelimited(fsoc3_pkce->dev,
				    "private key operation gave a wrong result\n");
		ret = -EIO;
	}
	mpi_free(v);
	return ret;
}

static int fsoc3_rsa_dec(struct akcipher_request *req)
{
	struct fsoc3_rsa_ctx *ctx = akcipher_tfm_ctx(crypto_akcipher_reqtfm(req));
	bool use_crt = crt && ctx->crtp.wc && ctx->crtq.wc;
	MPI c, m = NULL;
	int ret;

	if (unlikely(!ctx->n || !ctx->d))
		return -EINVAL;
	if ((!use_crt && !ctx->priv.wc) || READ_ONCE(fsoc3_pkce->dead))
		return fsoc3_rsa_fallback(req, false);

	c = mpi_read_raw_from_sgl(req->src, req->src_len);
	if (!c)
		return -ENOMEM;
	ret = fsoc3_rsa_check_payload(c, ctx->n);
	if (!ret) {
		m = use_crt ? fsoc3_rsa_dec_crt(ctx, c, &ret) :
			      fsoc3_mexp_run(&ctx->priv, c, &ret);
		/*
		 * A wrong result of one CRT half would give the key away
		 * (signature fault attack): m^e must give c back.
		 */
		if (m)
			ret = fsoc3_rsa_verify(ctx, m, c);
		if (!ret)
			ret = fsoc3_rsa_write(req, m);
	}
	mpi_free(m);
	mpi_free(c);
	if (ret == -EIO || ret == -ETIMEDOUT)
		return fsoc3_rsa_fallback(req, false);
	return ret;
}

static unsigned int fsoc3_rsa_max_size(struct crypto_akcipher *tfm)
{
	struct fsoc3_rsa_ctx *ctx = akcipher_tfm_ctx(tfm);

	return ctx->n ? mpi_get_size(ctx->n) : 0;
}

static int fsoc3_rsa_init_tfm(struct crypto_akcipher *tfm)
{
	struct fsoc3_rsa_ctx *ctx = akcipher_tfm_ctx(tfm);

	ctx->fallback = crypto_alloc_akcipher("rsa", 0, CRYPTO_ALG_NEED_FALLBACK |
						       CRYPTO_ALG_ASYNC);
	if (IS_ERR(ctx->fallback))
		return PTR_ERR(ctx->fallback);
	akcipher_set_reqsize(tfm, sizeof(struct akcipher_request) +
				  crypto_akcipher_reqsize(ctx->fallback));
	return 0;
}

static void fsoc3_rsa_exit_tfm(struct crypto_akcipher *tfm)
{
	struct fsoc3_rsa_ctx *ctx = akcipher_tfm_ctx(tfm);

	fsoc3_rsa_free_key(ctx);
	crypto_free_akcipher(ctx->fallback);
}

static struct akcipher_alg fsoc3_rsa_alg = {
	.encrypt = fsoc3_rsa_enc,
	.decrypt = fsoc3_rsa_dec,
	.set_pub_key = fsoc3_rsa_set_pub_key,
	.set_priv_key = fsoc3_rsa_set_priv_key,
	.max_size = fsoc3_rsa_max_size,
	.init = fsoc3_rsa_init_tfm,
	.exit = fsoc3_rsa_exit_tfm,
	.base = {
		.cra_name = "rsa",
		.cra_driver_name = "rsa-fsoc3",
		.cra_priority = 300,
		.cra_flags = CRYPTO_ALG_NEED_FALLBACK,
		.cra_module = THIS_MODULE,
		.cra_ctxsize = sizeof(struct fsoc3_rsa_ctx),
	},
};

/* --- device ----------------------------------------------------------- */

/* Frees the buffer if the channel is idle; else leaves it (leaked) */
static void fsoc3_pkce_release(struct fsoc3_pkce *pk)
{
	if (readl(pk->regs + PKCE_CTLST) & CTLST_BUSY) {
		dev_err(pk->dev, "channel still busy: DMA buffer not freed\n");
		return;
	}
	memzero_explicit(pk->buf, BUF_SIZE);
	dma_free_coherent(pk->dev, BUF_SIZE, pk->buf, pk->dma);
}

static int fsoc3_pkce_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct fsoc3_pkce *pk;
	struct resource *res;
	ktime_t t0;
	u32 st;
	int ret;

	if (fsoc3_pkce)
		return -EBUSY;

	pk = devm_kzalloc(dev, sizeof(*pk), GFP_KERNEL);
	if (!pk)
		return -ENOMEM;
	pk->dev = dev;
	mutex_init(&pk->lock);
	init_completion(&pk->done);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res || resource_size(res) < PKCE_REGS_SIZE)
		return dev_err_probe(dev, -EINVAL, "no window of 0x%x bytes\n",
				     PKCE_REGS_SIZE);
	/* Inside the NP6Lite window, requested by its driver: not requested */
	pk->regs = devm_ioremap(dev, res->start, PKCE_REGS_SIZE);
	if (!pk->regs)
		return -ENOMEM;

	ret = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(32));
	if (ret)
		return ret;
	/* Not managed: freed only once the channel is known idle */
	pk->buf = dma_alloc_coherent(dev, BUF_SIZE, &pk->dma, GFP_KERNEL);
	if (!pk->buf)
		return -ENOMEM;

	st = readl(pk->regs + PKCE_CTLST);
	if (st & CTLST_BUSY) {
		dma_free_coherent(dev, BUF_SIZE, pk->buf, pk->dma);
		return dev_err_probe(dev, -EBUSY, "channel busy (ctlst %#x)\n", st);
	}

	pk->irq = platform_get_irq_optional(pdev, 0);
	if (pk->irq > 0) {
		ret = devm_request_irq(dev, pk->irq, fsoc3_pkce_irq, 0,
				       dev_name(dev), pk);
		if (ret) {
			dma_free_coherent(dev, BUF_SIZE, pk->buf, pk->dma);
			return dev_err_probe(dev, ret, "cannot request the interrupt\n");
		}
	} else {
		pk->polling = true;
	}

	writel(PKCE_QBAH_ACP, pk->regs + PKCE_QBAH);
	writel(CTLST_INTENA, pk->regs + PKCE_CTLST);

	t0 = ktime_get();
	ret = fsoc3_pkce_selftest(pk);
	if (ret) {
		fsoc3_pkce_release(pk);
		return dev_err_probe(dev, ret, "self-test failed\n");
	}

	platform_set_drvdata(pdev, pk);
	fsoc3_pkce = pk;
	ret = crypto_register_akcipher(&fsoc3_rsa_alg);
	if (ret) {
		fsoc3_pkce = NULL;
		fsoc3_pkce_release(pk);
		return dev_err_probe(dev, ret, "cannot register rsa\n");
	}

	dev_info(dev, "self-test passed in %lld us (%s), rsa-fsoc3 registered\n",
		 ktime_us_delta(ktime_get(), t0),
		 pk->polling ? "polling" : "interrupt");
	return 0;
}

static void fsoc3_pkce_remove(struct platform_device *pdev)
{
	struct fsoc3_pkce *pk = platform_get_drvdata(pdev);

	crypto_unregister_akcipher(&fsoc3_rsa_alg);
	fsoc3_pkce = NULL;
	dev_info(pk->dev, "%llu command lists run\n", pk->ops);
	fsoc3_pkce_release(pk);
}

static const struct of_device_id fsoc3_pkce_of_match[] = {
	{ .compatible = "fortinet,fsoc3-pkce" },
	{ }
};
MODULE_DEVICE_TABLE(of, fsoc3_pkce_of_match);

static struct platform_driver fsoc3_pkce_driver = {
	.probe = fsoc3_pkce_probe,
	.remove = fsoc3_pkce_remove,
	.driver = {
		.name = "fsoc3-pkce",
		.of_match_table = fsoc3_pkce_of_match,
		.suppress_bind_attrs = true,
	},
};
module_platform_driver(fsoc3_pkce_driver);

MODULE_DESCRIPTION("Fortinet FortiSOC3 public key engine (RSA)");
MODULE_LICENSE("GPL");
