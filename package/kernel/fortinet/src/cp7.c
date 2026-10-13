// SPDX-License-Identifier: GPL-2.0-only
/*
 * Fortinet CP7 crypto engine driver
 *
 * CP7: content processor (crypto engine) of the FortiSOC1 and FortiSOC2.
 *
 * The FortiSOC1 has a memory to memory crypto engine,
 * separate from its network processor. It is fed through a single ring of
 * 512 descriptors of 64 bytes each. A descriptor carries one source and one
 * destination buffer (no scatter-gather), the IV, and the address of a key
 * block. The engine does DES, 3DES and AES in CBC mode, optionally combined
 * with HMAC-MD5/SHA1. The plain CBC ciphers are exposed as skciphers, and
 * AES and 3DES with HMAC-SHA1/MD5 as authenc() AEADs.
 *
 * Up to CP7_JOBS requests are in flight at once, each with at most one
 * descriptor on the ring. A request that fits in one descriptor and whose
 * buffers are each one contiguous, suitably aligned segment is handed to
 * the engine as is. Any other request goes through a per-job bounce buffer,
 * in pieces of at most 64 KiB (the length field has 16 bits) which are
 * processed one after the other, the IV being chained between them.
 * Completions are handled in a BH workqueue, which also starts the next
 * queued requests.
 *
 * The engine expects the AES decryption key as the last two round keys of
 * the encryption key schedule, round Nr first, whatever the key size.
 *
 * Hardware gotcha: the engine remembers the address of the last key block
 * it loaded and does not fetch the key again when the next descriptor
 * points to the same address, even if the key stored there has changed.
 * Returning to an address after using another one does reload the key.
 * Each ring slot gets its own key block, so that two consecutive
 * descriptors never share a key address.
 *
 * An authenticated descriptor works in place, the ESP way: Src points to
 * the associated data, the offset field (in words) skips it, Dst points to
 * the text that follows, and Length covers both, the ICV excluded. The ICV
 * is written, or read and checked, right after the text. It is always
 * truncated to 96 bits, so only an authsize of 12 is done in hardware. The
 * authentication state does not chain across descriptors: an AEAD request
 * is one descriptor. It is processed in place when its source and
 * destination are the same single lowmem segment and the cache lines the
 * engine writes hold nothing else, but for the ends of the first and last
 * lines on encryption (see fcp7_aead_can_inplace()), through the
 * bounce buffer otherwise. When the ICV check fails, the engine
 * still writes the plaintext out; it is wiped.
 *
 * Hardware gotcha: the engine only takes 8 bytes of
 * associated data (ESP SPI | seq, as esp4/esp6 encrypt) or 8 + ivsize
 * (the IV included, as they decrypt). Any other length fails with a
 * cipher length error and/or an offset error, whatever the cipher, key and
 * text lengths: those requests go to the fallback. After any descriptor error the driver
 * resets the engine as soon as nothing is in flight, as a precaution: a
 * failed ICV check does not affect the descriptors behind it (checked on
 * hardware), the effect of a length error is not known. Should a
 * descriptor behind a failed one fail too, its request is held and
 * submitted again, once, after the reset. The engine is not known to leave
 * a rejected descriptor's destination untouched, so a direct in-place
 * skcipher piece is never queued behind an AEAD decryption: it goes
 * through the bounce buffer then. An AEAD request processed in place is
 * not held either: should its descriptor fail behind another one, it fails
 * (an ESP packet is dropped).
 *
 * The FortiSOC2 has a second generation of this engine,
 * inside the register window of its network processor. Its interrupt
 * reaches the SoC through the interrupt map of the network processor,
 * which the network processor driver programs: this driver waits for it.
 * The engine has four rings (0x40 apart, only the first one is used) of
 * 1024 descriptors. The descriptor is the same,
 * but for its first word: the length field has 15 bits, the offset field 6,
 * and the two bits freed (15 and 22) select SHA-256, SHA-384 or SHA-512 in
 * place of SHA1. The key block grows to 96 bytes: the two HMAC-SHA-256
 * states take 32 bytes each; for HMAC-SHA-384/512, the engine takes the raw
 * HMAC key (64 bytes at most). The ICV is truncated as in IPsec: 12 bytes
 * for MD5 and SHA1, 16 for SHA-256, 24 for SHA-384, 32 for SHA-512.
 * HMAC-SHA-384 gives wrong results on hardware: it is left to software.
 */

#include <crypto/aes.h>
#include <crypto/authenc.h>
#include <crypto/internal/aead.h>
#include <crypto/internal/des.h>
#include <crypto/internal/skcipher.h>
#include <crypto/md5.h>
#include <crypto/scatterwalk.h>
#include <crypto/sha1.h>
#include <crypto/sha2.h>
#include <linux/bits.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/property.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/soc/fortinet/cp-hmac.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/unaligned.h>
#include <linux/workqueue.h>

#define CP7_STATUS		0x00
#define CP7_STATUS_IRQ	BIT(0)
#define CP7_IRQ_CTRL	0x08
#define CP7_CTRL	0x10
#define CP7_CTRL_RUN	BIT(0)
#define CP7_CTRL_RESET	BIT(31)
#define CP7_RING_BASE		0x18
#define CP7_RING_SIZE		0x20
#define CP7_RING_HEAD		0x28
#define CP7_RING_ACK	0x30
#define CP7_RING_DONE		0x38

/* Descriptors per ring: 512 on the FortiSOC1, 1024 on the FortiSOC2. */
#define CP7_RING_MAX	1024
/* FortiSOC2: the four rings, 0x40 apart; the driver uses ring 0. */
#define CP7_RING_STRIDE	0x40

#define CP7_CMD_DECRYPT	BIT(0)
#define CP7_CMD_DES	0x04
#define CP7_CMD_3DES	0x06
#define CP7_CMD_AES128	0x22
#define CP7_CMD_AES192	0x24
#define CP7_CMD_AES256	0x26
#define CP7_CMD_HMAC_MD5	0x10
#define CP7_CMD_HMAC_SHA1	0x18

/*
 * FortiSOC2, first descriptor word: hash selector, with the SHA1 command.
 * 1 = SHA-256, 2 = SHA-384, 3 = SHA-512; its bit 0 goes to bit 15, its bit 1
 * to bit 22.
 */
#define CP7_HASH_SEL_LO	BIT(15)
#define CP7_HASH_SEL_HI	BIT(22)
#define CP7_HASH_SEL_SHA256	1
#define CP7_HASH_SEL_SHA384	2	/* wrong results: not used */
#define CP7_HASH_SEL_SHA512	3

#define CP7_DESC_ERR	GENMASK(10, 0)
#define CP7_DESC_ERR_AUTH	BIT(7)

/* Size of the ICV the engine writes and checks for MD5/SHA1 (HMAC-xxx-96). */
#define CP7_ICV_SIZE	12
/* Associated data the engine takes: SPI | seq, then that and the IV. */
#define CP7_ESP_HDR	8
/*
 * Above the authenc() instances built on top of the cbc() skciphers of
 * this driver (10 x 300 + 300).
 */
#define CP7_AEAD_PRIORITY	4000

/*
 * The key block holds the cipher key and the two HMAC states (72 bytes).
 * One per ring slot, 64-byte aligned. The states are those after one block
 * of key ^ ipad and key ^ opad: big-endian words for SHA1, little-endian
 * words for MD5, whose last word is left zero.
 *
 * FortiSOC2: 96 bytes. The SHA-256 states are big-endian words too, 32
 * bytes each, the outer one at 0x40; for SHA-384/512 the raw HMAC key
 * starts at 0x20, zero padded.
 */
#define CP7_KEY_BLOCK_SIZE	72
#define CP7_KEY_BLOCK_MAX	96
#define CP7_KEY_HMAC_IN	FCP_HMAC_KB_IN
#define CP7_KEY_RAW_MAX	(CP7_KEY_BLOCK_MAX - CP7_KEY_HMAC_IN)
#define CP7_KEY_STRIDE	128
#define CP7_KEY_MAX	32

/*
 * Requests in flight, and the software queue in front of them. The queue is
 * a list of requests, nothing is sized on its length. ESP does not allow
 * backlogging: a request that finds it full goes to the synchronous
 * fallback, which costs far more CPU than the engine. Transmitting a GSO
 * packet submits all its segments at once (up to ~45 for 64 KiB), and a
 * NAPI poll may carry several such packets: 64 was seen to overflow.
 */
#define CP7_JOBS		8
#define CP7_QUEUE_LEN	256
#define CP7_BOUNCE_SIZE	SZ_64K

/* The source of a direct request: the engine was only seen on such. */
#define CP7_SRC_ALIGN	16
/*
 * The start of an AEAD request processed in place: ESP headers are 32-bit
 * aligned, and the offset field of the descriptor counts 32-bit words.
 */
#define CP7_INPLACE_ALIGN	4
/*
 * D-cache line of the core: 16 bytes on the FA626TE (CACHE_DLINESIZE in
 * arch/arm/mm/cache-fa.S), finer than dma_get_cache_alignment(), which is
 * L1_CACHE_BYTES; 32 on the FA726TE of the FortiSOC2 (proc-arm926.S). Set
 * at probe time from the SoC data (one engine per SoC).
 */
static unsigned int fcp7_dline = 16;
/* Largest Length field of the engine, also set at probe time. */
static unsigned int fcp7_max_len = U16_MAX;

/* No progress for this long: the engine is declared dead. */
#define CP7_TIMEOUT	msecs_to_jiffies(1000)
/* Watchdog period; also the grace period before calling an IRQ lost. */
#define CP7_TICK		msecs_to_jiffies(100)

/*
 * IRQ control, both generations: the completion interrupt comes 3 us after
 * the completion (measured). Bits 16..23 hold the interrupt off after a
 * completion: larger values delay it by hundreds of microseconds, or past
 * the watchdog tick, on the FortiSOC2. The meaning of the other bits is
 * unknown.
 */
#define CP7_IRQ_CTRL_INIT	0x00010100

/*
 * Requests shorter than this go to the software fallback. Measured
 * (tcrypt, one synchronous request at a time), the CPU does ~30000 16-byte
 * operations per second and the engine ~5000, while the engine is faster
 * from 4 KiB on. Callers that do not wait for each request (IPsec) pay
 * less per request: 256 bytes is a guess to refine in that context.
 */
#define CP7_FALLBACK_BELOW	256

/* What differs between the engines of the FortiSOC1 and of the FortiSOC2. */
struct fcp7_variant {
	unsigned int ring_size;		/* descriptors per ring (RING_SIZE) */
	unsigned int max_len;		/* largest Length field */
	unsigned int key_block;		/* bytes of key block the engine reads */
	unsigned int dline;		/* D-cache line of the core */
	/* Hash selector in the descriptor, HMAC-SHA-256/384/512 */
	bool sha2;
	/* Interrupt routed by the network processor (fortinet,fsoc2-np) */
	bool np_irq;
	/* Rings besides ring 0, left alone but for a pending interrupt */
	unsigned int extra_queues;
	/*
	 * Stop by the self-clearing reset at shutdown: CONTROL = 0 does not
	 * stop the descriptors already on the ring.
	 */
	bool reset_on_shutdown;
};

struct fcp7_desc {
	__le32 ctrl;		/* length | offset << 16 | command << 24 */
	__le32 status;
	__le32 src;
	__le32 dst;
	u8 iv[AES_BLOCK_SIZE];
	__le32 key;
	__le32 reserved[7];
};

static_assert(sizeof(struct fcp7_desc) == 64);
static_assert(CP7_KEY_STRIDE >= CP7_KEY_BLOCK_MAX);
static_assert(CP7_KEY_BLOCK_MAX >= FCP_HMAC_KB_SIZE);

struct fcp7_job {
	/* One of the two is set. */
	struct skcipher_request *req;
	struct aead_request *aead_req;
	void *bounce;
	bool busy;
	bool decrypt;
	bool direct;
	/* Held during an engine reset, to be submitted after it. */
	bool pending;
	/* Already submitted again once after a reset. */
	bool retried;
	/* AEAD: size of the ICV the engine computes or checks */
	unsigned int icv;
	int src_nents;
	int dst_nents;
	dma_addr_t src_dma;
	dma_addr_t dst_dma;
	unsigned int offset;
	unsigned int len;
	u8 iv[AES_BLOCK_SIZE];
	u8 next_iv[AES_BLOCK_SIZE];
};

struct fcp7 {
	struct device *dev;
	const struct fcp7_variant *soc;
	void __iomem *base;
	unsigned int ring_mask;
	int irq;
	bool polling;
	bool broken;
	/* A descriptor failed: reset the engine once it is idle. */
	bool needs_reset;
	/* AEAD decryptions on the ring, which may fail authentication. */
	unsigned int aead_dec_inflight;

	struct fcp7_desc *ring;
	dma_addr_t ring_dma;
	u8 *keys;
	dma_addr_t keys_dma;
	struct fcp7_job *slot_job[CP7_RING_MAX];
	u16 slot_key[CP7_RING_MAX];
	unsigned int key_next;
	unsigned int head;
	unsigned int tail;
	unsigned int inflight;

	struct fcp7_job jobs[CP7_JOBS];
	unsigned int active_jobs;
	struct crypto_queue queue;

	struct work_struct done_work;
	struct work_struct poll_work;
	struct work_struct drain_work;
	struct timer_list watchdog;
	unsigned long last_progress;
	unsigned int irq_misses;
};

/* Requests to complete once the lock is released. */
struct fcp7_batch {
	unsigned int nr_done;
	struct crypto_async_request *done[2 * CP7_JOBS];
	int err[2 * CP7_JOBS];
	unsigned int nr_backlog;
	struct crypto_async_request *backlog[CP7_JOBS];
};

struct fcp7_tfm_ctx {
	struct crypto_skcipher *fallback;
	u8 cmd;
	u8 key_enc[CP7_KEY_MAX];
	u8 key_dec[CP7_KEY_MAX];
};

struct fcp7_req_ctx {
	bool decrypt;
	/* Must be last: the fallback request context follows. */
	struct skcipher_request fallback_req;
};

struct fcp7_aead_ctx {
	struct crypto_aead *fallback;
	u8 cmd;
	u8 hsel;
	/* The key fits the key block: the engine can do it. */
	bool hw_key;
	u8 key_enc[CP7_KEY_BLOCK_MAX];
	u8 key_dec[CP7_KEY_BLOCK_MAX];
};

struct fcp7_aead_req_ctx {
	bool decrypt;
	/* Must be last: the fallback request context follows. */
	struct aead_request fallback_req;
};

struct fcp7_aead_alg {
	struct aead_alg alg;
	u8 cipher_cmd;		/* 0 for AES: set by the key size */
	u8 hash_cmd;
	u8 hsel;		/* FortiSOC2 hash selector, 0 for MD5/SHA1 */
	u8 icv;			/* the only authsize the engine does */
};

/*
 * Only one engine exists in the SoC. The lock protects the pointer, and all
 * the ring and queue state of the device it points to.
 */
static DEFINE_SPINLOCK(fcp7_lock);
static struct fcp7 *fcp7_dev;

/*
 * Writing RING_DONE back to RING_ACK clears STATUS bit 0, and with it the
 * interrupt. A descriptor that completes between the read of RING_DONE and
 * the write of RING_ACK has its interrupt cleared too; this is harmless because
 * the handler always schedules the completion work after acknowledging, and
 * that work reads RING_DONE afresh. A descriptor that completes after the write
 * raises STATUS bit 0 again: acknowledge again. Returns false only if STATUS
 * bit 0 does not go down.
 */
static bool fcp7_ack(struct fcp7 *ce)
{
	unsigned int i;

	for (i = 0; i < 8; i++) {
		writel(readl(ce->base + CP7_RING_DONE),
		       ce->base + CP7_RING_ACK);
		if (!(readl(ce->base + CP7_STATUS) & CP7_STATUS_IRQ))
			return true;
	}

	return false;
}

static unsigned int fcp7_ring_done(struct fcp7 *ce)
{
	return readl(ce->base + CP7_RING_DONE) & ce->ring_mask;
}

static void fcp7_hw_init(struct fcp7 *ce)
{
	/* Self-clearing: stops the engine and resets the ring pointers. */
	writel(CP7_CTRL_RESET, ce->base + CP7_CTRL);
	writel(CP7_IRQ_CTRL_INIT, ce->base + CP7_IRQ_CTRL);
	writel(lower_32_bits(ce->ring_dma), ce->base + CP7_RING_BASE);
	writel(ce->soc->ring_size, ce->base + CP7_RING_SIZE);
	ce->head = fcp7_ring_done(ce);
	ce->tail = ce->head;
}

static void fcp7_hw_start(struct fcp7 *ce)
{
	writel(CP7_CTRL_RUN, ce->base + CP7_CTRL);
}

static void fcp7_hw_stop(struct fcp7 *ce)
{
	writel(0, ce->base + CP7_CTRL);
}

/*
 * Pieces are whole blocks and whole cache lines, so that the pieces of a
 * direct request never share a cache line. On the FortiSOC1, 65504-byte
 * pieces work on hardware.
 */
static unsigned int fcp7_piece_max(struct fcp7 *ce,
				       struct crypto_skcipher *tfm)
{
	unsigned int step = max_t(unsigned int, crypto_skcipher_blocksize(tfm),
				  dma_get_cache_alignment());

	return max(round_down(ce->soc->max_len, step), step);
}

/*
 * Fills the descriptor at the ring head and returns its index. Key blocks
 * are taken in turn, independently of the ring index and across engine
 * resets, so that two consecutive descriptors never point to the same key
 * block (see the hardware gotcha above).
 */
static unsigned int fcp7_put_desc_hsel(struct fcp7 *ce, u8 cmd,
					   u8 hsel, u8 offset, dma_addr_t src,
					   dma_addr_t dst, unsigned int len,
					   const u8 *iv, unsigned int ivsize,
					   const u8 *key, unsigned int keylen)
{
	unsigned int idx = ce->head;
	unsigned int kidx = ce->key_next;
	struct fcp7_desc *desc = &ce->ring[idx];
	dma_addr_t key_dma = ce->keys_dma + kidx * CP7_KEY_STRIDE;

	ce->key_next = (kidx + 1) & ce->ring_mask;

	memcpy(ce->keys + kidx * CP7_KEY_STRIDE, key, keylen);
	ce->slot_key[idx] = kidx;

	memset(desc, 0, sizeof(*desc));
	/* hsel is 0 on the FortiSOC1, whose Length field has 16 bits. */
	desc->ctrl = cpu_to_le32(len | (u32)offset << 16 | (u32)cmd << 24 |
				 (hsel & 1 ? CP7_HASH_SEL_LO : 0) |
				 (hsel & 2 ? CP7_HASH_SEL_HI : 0));
	desc->src = cpu_to_le32(lower_32_bits(src));
	desc->dst = cpu_to_le32(lower_32_bits(dst));
	memcpy(desc->iv, iv, ivsize);
	desc->key = cpu_to_le32(lower_32_bits(key_dma));

	dev_dbg(ce->dev, "d%03u w0 %08x src %pad dst %pad key %u\n",
		idx, le32_to_cpu(desc->ctrl), &src, &dst, kidx);

	ce->head = (idx + 1) & ce->ring_mask;

	return idx;
}

static unsigned int fcp7_put_desc(struct fcp7 *ce, u8 cmd, u8 offset,
				      dma_addr_t src, dma_addr_t dst,
				      unsigned int len, const u8 *iv,
				      unsigned int ivsize, const u8 *key,
				      unsigned int keylen)
{
	return fcp7_put_desc_hsel(ce, cmd, 0, offset, src, dst, len, iv,
				      ivsize, key, keylen);
}

static void fcp7_kick(struct fcp7 *ce)
{
	/* The descriptors must be visible before the engine is kicked. */
	dma_wmb();
	writel(ce->head, ce->base + CP7_RING_HEAD);
}

/* Lock held. Hands descriptor @idx, just filled for @job, to the engine. */
static void fcp7_submit(struct fcp7 *ce, struct fcp7_job *job,
			    unsigned int idx)
{
	ce->slot_job[idx] = job;
	if (!ce->inflight++) {
		ce->last_progress = jiffies;
		mod_timer(&ce->watchdog, jiffies + CP7_TICK);
	}
	fcp7_kick(ce);

	if (ce->polling)
		queue_work(system_wq, &ce->poll_work);
}

/* Maps the current piece of a direct job, in place or not. */
static int fcp7_map_piece(struct fcp7 *ce, struct fcp7_job *job)
{
	struct skcipher_request *req = job->req;
	struct scatterlist *src = req->src, *dst = req->dst;

	if (src == dst) {
		job->src_dma = dma_map_page(ce->dev, sg_page(src),
					    src->offset + job->offset, job->len,
					    DMA_BIDIRECTIONAL);
		if (dma_mapping_error(ce->dev, job->src_dma))
			return -ENOMEM;
		job->dst_dma = job->src_dma;
		return 0;
	}

	job->src_dma = dma_map_page(ce->dev, sg_page(src),
				    src->offset + job->offset, job->len,
				    DMA_TO_DEVICE);
	if (dma_mapping_error(ce->dev, job->src_dma))
		return -ENOMEM;
	job->dst_dma = dma_map_page(ce->dev, sg_page(dst),
				    dst->offset + job->offset, job->len,
				    DMA_FROM_DEVICE);
	if (dma_mapping_error(ce->dev, job->dst_dma)) {
		dma_unmap_page(ce->dev, job->src_dma, job->len, DMA_TO_DEVICE);
		return -ENOMEM;
	}

	return 0;
}

static void fcp7_unmap_piece(struct fcp7 *ce, struct fcp7_job *job)
{
	struct skcipher_request *req = job->req;

	if (!job->direct) {
		dma_unmap_single(ce->dev, job->src_dma, job->len,
				 DMA_BIDIRECTIONAL);
	} else if (req->src == req->dst) {
		dma_unmap_page(ce->dev, job->src_dma, job->len,
			       DMA_BIDIRECTIONAL);
	} else {
		dma_unmap_page(ce->dev, job->src_dma, job->len, DMA_TO_DEVICE);
		dma_unmap_page(ce->dev, job->dst_dma, job->len,
			       DMA_FROM_DEVICE);
	}
}

/* Lock held. Queues the next piece of @job on the ring. */
static int fcp7_job_next(struct fcp7 *ce, struct fcp7_job *job)
{
	struct skcipher_request *req = job->req;
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct fcp7_tfm_ctx *ctx = crypto_skcipher_ctx(tfm);
	unsigned int ivsize = crypto_skcipher_ivsize(tfm);
	const u8 *key = job->decrypt ? ctx->key_dec : ctx->key_enc;
	u8 cmd = ctx->cmd | (job->decrypt ? CP7_CMD_DECRYPT : 0);
	unsigned int idx;
	int err;

	job->len = min(req->cryptlen - job->offset, fcp7_piece_max(ce, tfm));

	/* See the header: nothing to lose if the engine rejects the piece. */
	if (job->direct && req->src == req->dst && ce->aead_dec_inflight)
		job->direct = false;

	if (job->direct) {
		/*
		 * In place, the engine overwrites the last ciphertext block
		 * of the piece: read it while the CPU still owns it.
		 */
		if (job->decrypt)
			memcpy_from_sglist(job->next_iv, req->src,
					   job->offset + job->len - ivsize,
					   ivsize);
		err = fcp7_map_piece(ce, job);
		if (err)
			return err;
	} else {
		sg_pcopy_to_buffer(req->src, job->src_nents, job->bounce,
				   job->len, job->offset);
		if (job->decrypt)
			memcpy(job->next_iv, job->bounce + job->len - ivsize,
			       ivsize);
		job->src_dma = dma_map_single(ce->dev, job->bounce, job->len,
					      DMA_BIDIRECTIONAL);
		if (dma_mapping_error(ce->dev, job->src_dma))
			return -ENOMEM;
		job->dst_dma = job->src_dma;
	}

	idx = fcp7_put_desc(ce, cmd, 0, job->src_dma, job->dst_dma,
				job->len, job->iv, ivsize, key,
				CP7_KEY_MAX);
	fcp7_submit(ce, job, idx);

	return 0;
}

/*
 * Direct DMA needs each buffer in one segment. The engine writes the
 * destination, which must start a cache line and must not share its last
 * one with anything else, unless the request is in place; the source
 * alignment is the one the engine was seen working with.
 */
static bool fcp7_can_direct(struct skcipher_request *req)
{
	unsigned int align = dma_get_cache_alignment();

	if (req->src->length < req->cryptlen || req->dst->length < req->cryptlen)
		return false;
	if (!IS_ALIGNED(req->src->offset, CP7_SRC_ALIGN) ||
	    !IS_ALIGNED(req->dst->offset, align))
		return false;
	if (IS_ALIGNED(req->cryptlen, align))
		return true;

	/*
	 * In place, the last line may run past the request. The engine
	 * writes nothing after the request, and mapping the buffer cleans
	 * and invalidates that line, so the bytes after it are kept; the
	 * caller must not touch them meanwhile, as for any DMA buffer.
	 * Only the last piece can end inside a line (fcp7_piece_max()).
	 */
	return req->src == req->dst;
}

/* Lock held. */
static int fcp7_job_start(struct fcp7 *ce, struct fcp7_job *job,
			      struct skcipher_request *req)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct fcp7_req_ctx *rctx = skcipher_request_ctx(req);

	job->req = req;
	job->decrypt = rctx->decrypt;
	job->offset = 0;
	memcpy(job->iv, req->iv, crypto_skcipher_ivsize(tfm));

	job->src_nents = sg_nents_for_len(req->src, req->cryptlen);
	job->dst_nents = sg_nents_for_len(req->dst, req->cryptlen);
	if (job->src_nents < 0 || job->dst_nents < 0)
		return -EINVAL;

	job->direct = fcp7_can_direct(req);

	return fcp7_job_next(ce, job);
}

/*
 * What an AEAD job maps: the associated data, the text and the ICV after
 * it; in whole cache lines in the bounce buffer.
 */
static unsigned int fcp7_aead_map_len(struct fcp7_job *job)
{
	if (job->direct)
		return job->len + job->icv;

	return round_up(job->len + job->icv, dma_get_cache_alignment());
}

/* The buffer the engine works on: the request's own, or the bounce one. */
static u8 *fcp7_aead_buf(struct fcp7_job *job)
{
	return job->direct ? sg_virt(job->aead_req->src) : job->bounce;
}

/*
 * An AEAD request can be processed in place when its source and
 * destination are the same single lowmem segment (the ESP case).
 *
 * The engine writes from Dst on: the text, then the ICV on encryption. The
 * cache is not coherent, and the unmap does not invalidate on this CPU. A
 * line the engine writes must hold nothing but the request, which no one
 * touches until it completes: were the CPU to access a neighbour in that
 * line meanwhile, it would load the line and hide what the engine wrote,
 * or write the line back over it. The lines the engine only reads (the
 * associated data, the ICV to check) may be shared: the engine leaves
 * their memory unchanged, so whatever the CPU does with the neighbours
 * there is harmless. The map cleans and invalidates all of them.
 *
 * One exception, on encryption: the line holding the end of the computed
 * ICV may run past the request. The engine writes the 12 ICV bytes and
 * nothing after them (tested on hardware: a guard there is left
 * intact). ESP puts the
 * ICV at skb->tail, so the rest of that line is tailroom of the same skb,
 * never skb_shared_info, which starts on a cache line; no one touches the
 * tailroom of an skb while it is being encrypted. The map covers that
 * partial line too (fa_dma_flush_range() cleans and invalidates every line
 * from the one of the start to the one of the last byte), so what the CPU
 * wrote there is not lost, and the CPU does not load the line again unless
 * it accesses those bytes while the request is in flight. A caller doing
 * so would corrupt its ICV (its peer would drop the packet); the DMA API
 * does not allow it anyway. Decryption writes no ICV, and its last written
 * line always ends within the ICV it reads when the start is aligned.
 *
 * Likewise, on encryption, the line holding the start of the text may
 * begin before the request: with 8 bytes of associated data starting 4
 * bytes into a line (ESP in tunnel mode, on a gateway), the 4 bytes before
 * the ESP header, the end of the outer IP header (or of the UDP header of
 * NAT-T), share the line of the first text bytes. The engine reads from
 * Src and writes from Dst only (tested on hardware: a guard before the
 * request is left intact). The CPU writes those header bytes before the request, and the
 * map cleans them to memory; it touches them again only once the request
 * has completed: esp_output_tail() returns -EINPROGRESS and
 * xfrm_output_one() gives the skb up, and the outer header is completed
 * (length, checksum) by xfrm_output_resume(), from esp_output_done().
 * Decryption keeps the strict rule: its associated data are longer than a
 * line, so its first written line never begins before the request.
 */
static bool fcp7_aead_can_inplace(struct aead_request *req, bool decrypt)
{
	unsigned int icv = crypto_aead_authsize(crypto_aead_reqtfm(req));
	struct scatterlist *sg = req->src;
	unsigned int len = req->assoclen + req->cryptlen + (decrypt ? 0 : icv);
	unsigned long start, end;

	if (req->src != req->dst || sg->length < len ||
	    PageHighMem(sg_page(sg)))
		return false;

	start = (unsigned long)sg_virt(sg);
	end = start + len;
	if (!IS_ALIGNED(start, CP7_INPLACE_ALIGN))
		return false;
	/* Encryption: the first and last lines written may be shared. */
	if (!decrypt)
		return true;

	return round_down(start + req->assoclen, fcp7_dline) >= start &&
	       round_up(end - icv, fcp7_dline) <= end;
}

/*
 * Lock held. An AEAD request is one descriptor, in place or through the
 * bounce buffer.
 */
static int fcp7_aead_job_start(struct fcp7 *ce,
				   struct fcp7_job *job,
				   struct aead_request *req)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct fcp7_aead_ctx *ctx = crypto_aead_ctx(tfm);
	struct fcp7_aead_req_ctx *rctx = aead_request_ctx(req);
	unsigned int assoclen = req->assoclen;
	unsigned int idx;
	u8 cmd;

	job->aead_req = req;
	job->decrypt = rctx->decrypt;
	job->icv = crypto_aead_authsize(tfm);
	job->direct = fcp7_aead_can_inplace(req, job->decrypt);
	job->offset = 0;
	/* What the engine authenticates: the ICV is not part of it. */
	job->len = assoclen + req->cryptlen - (job->decrypt ? job->icv : 0);

	for (;;) {
		/* The ICV to check comes along; the one to compute goes after. */
		if (!job->direct)
			memcpy_from_sglist(job->bounce, req->src, 0,
					   assoclen + req->cryptlen);
		job->src_dma = dma_map_single(ce->dev, fcp7_aead_buf(job),
					      fcp7_aead_map_len(job),
					      DMA_BIDIRECTIONAL);
		if (!dma_mapping_error(ce->dev, job->src_dma))
			break;
		if (!job->direct)
			return -ENOMEM;
		job->direct = false;
	}
	job->dst_dma = job->src_dma + assoclen;

	cmd = ctx->cmd | (job->decrypt ? CP7_CMD_DECRYPT : 0);
	if (job->decrypt)
		ce->aead_dec_inflight++;
	idx = fcp7_put_desc_hsel(ce, cmd, ctx->hsel, assoclen / 4,
				     job->src_dma, job->dst_dma, job->len,
				     req->iv, crypto_aead_ivsize(tfm),
				     job->decrypt ? ctx->key_dec : ctx->key_enc,
				     ce->soc->key_block);
	fcp7_submit(ce, job, idx);

	return 0;
}

/*
 * Lock held. Accounts for the completion of the current piece of @job.
 * Returns true when the whole request is over, with *@err set.
 */
static bool fcp7_job_piece_done(struct fcp7 *ce,
				    struct fcp7_job *job, int *err)
{
	struct skcipher_request *req = job->req;
	unsigned int ivsize = crypto_skcipher_ivsize(crypto_skcipher_reqtfm(req));

	fcp7_unmap_piece(ce, job);
	if (*err)
		return true;

	if (job->direct) {
		if (!job->decrypt)
			memcpy_from_sglist(job->next_iv, req->dst,
					   job->offset + job->len - ivsize,
					   ivsize);
	} else {
		if (!job->decrypt)
			memcpy(job->next_iv, job->bounce + job->len - ivsize,
			       ivsize);
		sg_pcopy_from_buffer(req->dst, job->dst_nents, job->bounce,
				     job->len, job->offset);
	}

	memcpy(job->iv, job->next_iv, ivsize);
	job->offset += job->len;
	if (job->offset < req->cryptlen) {
		/* It would fail: the next piece waits for the reset. */
		if (ce->needs_reset) {
			job->pending = true;
			return false;
		}
		*err = fcp7_job_next(ce, job);
		return *err != 0;
	}

	memcpy(req->iv, job->iv, ivsize);

	return true;
}

/* Lock held. Accounts for the completion of the descriptor of an AEAD job. */
static void fcp7_aead_job_done(struct fcp7 *ce,
				   struct fcp7_job *job, unsigned int idx,
				   int err)
{
	struct aead_request *req = job->aead_req;
	unsigned int assoclen = req->assoclen;

	dma_unmap_single(ce->dev, job->src_dma, fcp7_aead_map_len(job),
			 DMA_BIDIRECTIONAL);
	if (job->direct) {
		/*
		 * Done in place, nothing to copy. A failed decryption may
		 * have left plaintext in the request's own buffer.
		 */
		if (err && job->decrypt)
			memzero_explicit(sg_virt(req->dst) + assoclen,
					 job->len - assoclen);
		return;
	}
	if (err) {
		/* A failed ICV check still leaves the plaintext here. */
		memzero_explicit(job->bounce, fcp7_aead_map_len(job));
		return;
	}

	/* Like authenc(): the associated data is copied on encryption only. */
	if (job->decrypt) {
		memcpy_to_sglist(req->dst, assoclen, job->bounce + assoclen,
				 job->len - assoclen);
		memzero_explicit(job->bounce, fcp7_aead_map_len(job));
	} else {
		memcpy_to_sglist(req->dst, 0, job->bounce, job->len + job->icv);
	}
}

/* Lock held. fcp7_job_piece_done() for any kind of job. */
static bool fcp7_job_done(struct fcp7 *ce, struct fcp7_job *job,
			      unsigned int idx, int *err)
{
	if (job->aead_req) {
		fcp7_aead_job_done(ce, job, idx, *err);
		return true;
	}

	return fcp7_job_piece_done(ce, job, err);
}

static struct crypto_async_request *fcp7_job_areq(struct fcp7_job *job)
{
	return job->aead_req ? &job->aead_req->base : &job->req->base;
}

static bool fcp7_is_aead(struct crypto_async_request *areq)
{
	return crypto_tfm_alg_type(areq->tfm) == CRYPTO_ALG_TYPE_AEAD;
}

static void fcp7_batch_add(struct fcp7_batch *b,
			       struct crypto_async_request *areq, int err)
{
	b->done[b->nr_done] = areq;
	b->err[b->nr_done++] = err;
}

static void fcp7_job_release(struct fcp7 *ce, struct fcp7_job *job)
{
	job->busy = false;
	job->pending = false;
	job->retried = false;
	job->req = NULL;
	job->aead_req = NULL;
	ce->active_jobs--;
}

/* Lock held. Starts queued requests while jobs are available. */
static void fcp7_pump(struct fcp7 *ce, struct fcp7_batch *b)
{
	while (ce->active_jobs < CP7_JOBS && !ce->broken &&
	       !ce->needs_reset) {
		struct crypto_async_request *backlog, *areq;
		struct fcp7_job *job = NULL;
		unsigned int i;
		int err;

		/*
		 * Requests that fail to start free their job again: bound the
		 * batch, and let the completion work carry on.
		 */
		if (b->nr_done == ARRAY_SIZE(b->done) ||
		    b->nr_backlog == ARRAY_SIZE(b->backlog)) {
			queue_work(system_bh_wq, &ce->done_work);
			break;
		}

		backlog = crypto_get_backlog(&ce->queue);
		areq = crypto_dequeue_request(&ce->queue);
		if (!areq)
			break;
		if (backlog)
			b->backlog[b->nr_backlog++] = backlog;

		for (i = 0; i < CP7_JOBS; i++) {
			if (!ce->jobs[i].busy) {
				job = &ce->jobs[i];
				break;
			}
		}
		job->busy = true;
		ce->active_jobs++;

		if (fcp7_is_aead(areq))
			err = fcp7_aead_job_start(ce, job,
						      aead_request_cast(areq));
		else
			err = fcp7_job_start(ce, job,
						 skcipher_request_cast(areq));
		if (err) {
			fcp7_batch_add(b, areq, err);
			fcp7_job_release(ce, job);
		}
	}
}

static int fcp7_fallback(struct skcipher_request *req)
{
	struct fcp7_tfm_ctx *ctx =
		crypto_skcipher_ctx(crypto_skcipher_reqtfm(req));
	struct fcp7_req_ctx *rctx = skcipher_request_ctx(req);

	skcipher_request_set_tfm(&rctx->fallback_req, ctx->fallback);
	skcipher_request_set_callback(&rctx->fallback_req, req->base.flags,
				      req->base.complete, req->base.data);
	skcipher_request_set_crypt(&rctx->fallback_req, req->src, req->dst,
				   req->cryptlen, req->iv);

	return rctx->decrypt ? crypto_skcipher_decrypt(&rctx->fallback_req) :
			       crypto_skcipher_encrypt(&rctx->fallback_req);
}

static int fcp7_aead_fallback(struct aead_request *req)
{
	struct fcp7_aead_ctx *ctx = crypto_aead_ctx(crypto_aead_reqtfm(req));
	struct fcp7_aead_req_ctx *rctx = aead_request_ctx(req);

	aead_request_set_tfm(&rctx->fallback_req, ctx->fallback);
	aead_request_set_callback(&rctx->fallback_req, req->base.flags,
				  req->base.complete, req->base.data);
	aead_request_set_crypt(&rctx->fallback_req, req->src, req->dst,
			       req->cryptlen, req->iv);
	aead_request_set_ad(&rctx->fallback_req, req->assoclen);

	return rctx->decrypt ? crypto_aead_decrypt(&rctx->fallback_req) :
			       crypto_aead_encrypt(&rctx->fallback_req);
}

static int fcp7_fallback_any(struct crypto_async_request *areq)
{
	if (fcp7_is_aead(areq))
		return fcp7_aead_fallback(aead_request_cast(areq));

	return fcp7_fallback(skcipher_request_cast(areq));
}

/*
 * Lock not held. Runs the completions collected in @b. Does not touch the
 * device, which may be gone by now.
 */
static void fcp7_batch_finish(struct fcp7_batch *b)
{
	unsigned int i;

	local_bh_disable();
	for (i = 0; i < b->nr_backlog; i++)
		crypto_request_complete(b->backlog[i], -EINPROGRESS);
	for (i = 0; i < b->nr_done; i++)
		crypto_request_complete(b->done[i], b->err[i]);
	local_bh_enable();
}

/*
 * A dead engine hands what is still queued to the fallback. This runs in
 * process context: the fallback may sleep if the caller allowed it.
 */
static void fcp7_drain(struct fcp7 *ce)
{
	for (;;) {
		struct crypto_async_request *backlog, *areq;
		int err;

		spin_lock_bh(&fcp7_lock);
		backlog = crypto_get_backlog(&ce->queue);
		areq = crypto_dequeue_request(&ce->queue);
		spin_unlock_bh(&fcp7_lock);

		if (backlog) {
			local_bh_disable();
			crypto_request_complete(backlog, -EINPROGRESS);
			local_bh_enable();
		}
		if (!areq)
			break;

		err = fcp7_fallback_any(areq);
		if (err != -EINPROGRESS && err != -EBUSY) {
			local_bh_disable();
			crypto_request_complete(areq, err);
			local_bh_enable();
		}
	}
}

static void fcp7_drain_work(struct work_struct *work)
{
	fcp7_drain(container_of(work, struct fcp7, drain_work));
}

/*
 * Lock held. The descriptor of @job failed behind another failed one: undo
 * it and hold the job until the engine is reset. Returns false if the job
 * cannot be submitted again: already done once, or a direct in-place piece
 * whose buffer the engine may have written.
 */
static bool fcp7_job_hold(struct fcp7 *ce, struct fcp7_job *job)
{
	if (job->retried)
		return false;

	if (job->aead_req) {
		/* In place, the engine may have written the request's buffer. */
		if (job->direct)
			return false;
		dma_unmap_single(ce->dev, job->src_dma,
				 fcp7_aead_map_len(job), DMA_BIDIRECTIONAL);
	} else {
		if (job->direct && job->req->src == job->req->dst)
			return false;
		fcp7_unmap_piece(ce, job);
	}

	job->pending = true;
	job->retried = true;

	return true;
}

/* Lock held. Submits the jobs held during the reset of the engine. */
static void fcp7_resubmit(struct fcp7 *ce, struct fcp7_batch *b)
{
	unsigned int i;

	for (i = 0; i < CP7_JOBS; i++) {
		struct fcp7_job *job = &ce->jobs[i];
		int err;

		if (!job->busy || !job->pending)
			continue;
		job->pending = false;
		if (job->aead_req)
			err = fcp7_aead_job_start(ce, job, job->aead_req);
		else
			err = fcp7_job_next(ce, job);
		if (err) {
			fcp7_batch_add(b, fcp7_job_areq(job), err);
			fcp7_job_release(ce, job);
		}
	}
}

/* Lock held. Retires the descriptors the engine is done with. */
static void fcp7_reap(struct fcp7 *ce, struct fcp7_batch *b)
{
	unsigned int rd = fcp7_ring_done(ce);

	/* Descriptor status words are read after the pointer. */
	dma_rmb();
	while (ce->tail != rd) {
		unsigned int idx = ce->tail;
		struct fcp7_job *job = ce->slot_job[idx];
		u32 status = le32_to_cpu(ce->ring[idx].status);
		int err = 0;

		dev_dbg(ce->dev, "d%03u status %08x\n", idx, status);
		memzero_explicit(ce->keys +
				 ce->slot_key[idx] * CP7_KEY_STRIDE,
				 ce->soc->key_block);
		ce->slot_job[idx] = NULL;
		ce->tail = (idx + 1) & ce->ring_mask;
		ce->last_progress = jiffies;

		/* The engine went past what we gave it: resynchronize. */
		if (WARN_ONCE(!job || !ce->inflight,
			      "fortinet-cp7: stray completion at %u\n", idx))
			continue;
		ce->inflight--;
		if (job->aead_req && job->decrypt)
			ce->aead_dec_inflight--;

		status &= CP7_DESC_ERR;
		/*
		 * The first failed descriptor is the request's own failure;
		 * the ones after it fail because of it (see the header).
		 */
		if (status && ce->needs_reset && fcp7_job_hold(ce, job))
			continue;
		if (status)
			ce->needs_reset = true;
		if (job->aead_req && job->decrypt &&
		    status == CP7_DESC_ERR_AUTH) {
			err = -EBADMSG;
		} else if (status) {
			dev_err_ratelimited(ce->dev, "descriptor error %#05x\n",
					    status);
			err = -EIO;
		}
		if (fcp7_job_done(ce, job, idx, &err)) {
			fcp7_batch_add(b, fcp7_job_areq(job), err);
			fcp7_job_release(ce, job);
		}
	}
	/* Only the interrupt handler and the poller acknowledge. */
	if (ce->polling)
		fcp7_ack(ce);

	/*
	 * After a descriptor error, reset the engine as a precaution once
	 * nothing is in flight, then submit what was held; the queue waits
	 * for it.
	 */
	if (ce->needs_reset && !ce->inflight) {
		dev_dbg(ce->dev, "resetting the engine after an error\n");
		fcp7_hw_init(ce);
		fcp7_hw_start(ce);
		ce->needs_reset = false;
		fcp7_resubmit(ce, b);
	}
}

static void fcp7_process(struct fcp7 *ce)
{
	struct fcp7_batch b = { };
	bool again;

	spin_lock_bh(&fcp7_lock);
	fcp7_reap(ce, &b);
	fcp7_pump(ce, &b);
	again = ce->polling && ce->inflight;
	if (again)
		queue_work(system_wq, &ce->poll_work);
	/*
	 * A descriptor done while this ran (seen once on the FortiSOC2, after
	 * a reset: acknowledged, never reaped): do not wait for the watchdog.
	 */
	else if (ce->inflight && fcp7_ring_done(ce) != ce->tail)
		queue_work(system_bh_wq, &ce->done_work);
	spin_unlock_bh(&fcp7_lock);

	fcp7_batch_finish(&b);
}

static void fcp7_done_work(struct work_struct *work)
{
	fcp7_process(container_of(work, struct fcp7, done_work));
}

/*
 * Polling mode. HZ is low on this platform and a sleep lasts at least one
 * tick, far more than a descriptor takes: requeue, letting others run.
 */
static void fcp7_poll_work(struct work_struct *work)
{
	fcp7_process(container_of(work, struct fcp7, poll_work));
	cond_resched();
}

/* Lock held. Stops the engine for good and fails what it was doing. */
static void fcp7_kill(struct fcp7 *ce, struct fcp7_batch *b)
{
	unsigned int i;

	fcp7_hw_init(ce);
	ce->broken = true;

	for (i = 0; i < CP7_JOBS; i++) {
		struct fcp7_job *job = &ce->jobs[i];
		int err = -ETIMEDOUT;

		if (!job->busy)
			continue;
		/* A held job has nothing mapped. */
		if (!job->pending)
			fcp7_job_done(ce, job, ce->soc->ring_size, &err);
		fcp7_batch_add(b, fcp7_job_areq(job), err);
		fcp7_job_release(ce, job);
	}
	memset(ce->slot_job, 0, sizeof(ce->slot_job));
	memzero_explicit(ce->keys, ce->soc->ring_size * CP7_KEY_STRIDE);
	ce->inflight = 0;
	ce->aead_dec_inflight = 0;
	ce->needs_reset = false;
	queue_work(system_wq, &ce->drain_work);
}

static void fcp7_watchdog(struct timer_list *t)
{
	struct fcp7 *ce = timer_container_of(ce, t, watchdog);
	struct fcp7_batch b = { };
	bool poll_now = false;

	spin_lock_bh(&fcp7_lock);
	if (!ce->inflight) {
		spin_unlock_bh(&fcp7_lock);
		return;
	}

	if (fcp7_ring_done(ce) != ce->tail) {
		/* Work done and not reaped for a whole tick: IRQ lost. */
		if (!ce->polling &&
		    time_after(jiffies, ce->last_progress + CP7_TICK)) {
			if (++ce->irq_misses < 8) {
				dev_warn_ratelimited(ce->dev,
						     "completion interrupt missed (STATUS %#x, RING_DONE %u, RING_ACK %u, RING_HEAD %u, tail %u)\n",
						     readl(ce->base + CP7_STATUS),
						     readl(ce->base + CP7_RING_DONE),
						     readl(ce->base + CP7_RING_ACK),
						     readl(ce->base + CP7_RING_HEAD),
						     ce->tail);
				queue_work(system_bh_wq, &ce->done_work);
			} else {
				dev_warn(ce->dev,
					 "no completion interrupt, switching to polling\n");
				disable_irq_nosync(ce->irq);
				ce->polling = true;
			}
		}
		poll_now = ce->polling;
	} else if (time_after(jiffies, ce->last_progress + CP7_TIMEOUT)) {
		dev_err(ce->dev,
			"descriptor %u timed out, using the software fallback\n",
			ce->tail);
		fcp7_kill(ce, &b);
	}

	if (ce->inflight)
		mod_timer(&ce->watchdog, jiffies + CP7_TICK);
	if (poll_now)
		queue_work(system_wq, &ce->poll_work);
	spin_unlock_bh(&fcp7_lock);

	fcp7_batch_finish(&b);
}

static irqreturn_t fcp7_irq(int irq, void *data)
{
	struct fcp7 *ce = data;
	bool acked;

	if (!(readl(ce->base + CP7_STATUS) & CP7_STATUS_IRQ))
		return IRQ_NONE;

	acked = fcp7_ack(ce);
	WRITE_ONCE(ce->irq_misses, 0);

	if (!acked) {
		/* A level interrupt that does not go away would lock us up. */
		dev_err(ce->dev, "interrupt stuck, switching to polling\n");
		disable_irq_nosync(irq);
		WRITE_ONCE(ce->polling, true);
		queue_work(system_wq, &ce->poll_work);
		return IRQ_HANDLED;
	}

	queue_work(system_bh_wq, &ce->done_work);

	return IRQ_HANDLED;
}

/* Queues @areq for the engine, or hands it to the fallback. */
static int fcp7_enqueue(struct crypto_async_request *areq)
{
	struct fcp7_batch b = { };
	struct fcp7 *ce;
	int ret;

	spin_lock_bh(&fcp7_lock);
	ce = fcp7_dev;
	if (!ce || ce->broken) {
		spin_unlock_bh(&fcp7_lock);
		return fcp7_fallback_any(areq);
	}
	ret = crypto_enqueue_request(&ce->queue, areq);
	fcp7_pump(ce, &b);
	spin_unlock_bh(&fcp7_lock);

	/* Only the batch from here on: the device may be gone. */
	fcp7_batch_finish(&b);

	/*
	 * Queue full and no backlog allowed: do it in software. A caller
	 * that allows backlogging gets -EBUSY instead, its request queued.
	 */
	if (ret == -ENOSPC)
		return fcp7_fallback_any(areq);

	return ret;
}

static int fcp7_queue(struct skcipher_request *req, bool decrypt)
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct fcp7_req_ctx *rctx = skcipher_request_ctx(req);

	if (!req->cryptlen)
		return 0;
	if (!IS_ALIGNED(req->cryptlen, crypto_skcipher_blocksize(tfm)))
		return -EINVAL;

	/* Refuse bad scatterlists before queueing, not on completion. */
	if (sg_nents_for_len(req->src, req->cryptlen) < 0 ||
	    sg_nents_for_len(req->dst, req->cryptlen) < 0)
		return -EINVAL;

	rctx->decrypt = decrypt;
	if (req->cryptlen < CP7_FALLBACK_BELOW)
		return fcp7_fallback(req);

	return fcp7_enqueue(&req->base);
}

static int fcp7_encrypt(struct skcipher_request *req)
{
	return fcp7_queue(req, false);
}

static int fcp7_decrypt(struct skcipher_request *req)
{
	return fcp7_queue(req, true);
}

static int fcp7_set_fallback_key(struct crypto_skcipher *tfm,
				     const u8 *key, unsigned int keylen)
{
	struct fcp7_tfm_ctx *ctx = crypto_skcipher_ctx(tfm);

	crypto_skcipher_clear_flags(ctx->fallback, CRYPTO_TFM_REQ_MASK);
	crypto_skcipher_set_flags(ctx->fallback,
				  crypto_skcipher_get_flags(tfm) &
				  CRYPTO_TFM_REQ_MASK);

	return crypto_skcipher_setkey(ctx->fallback, key, keylen);
}

static u8 fcp7_aes_cmd(unsigned int keylen)
{
	switch (keylen) {
	case AES_KEYSIZE_128:
		return CP7_CMD_AES128;
	case AES_KEYSIZE_192:
		return CP7_CMD_AES192;
	default:
		return CP7_CMD_AES256;
	}
}

/*
 * Decryption key: round key Nr then round key Nr - 1. key_enc[] holds
 * little-endian words, so storing them back as such yields the FIPS-197
 * byte order the engine wants.
 */
static void fcp7_aes_dec_key(const struct crypto_aes_ctx *aes,
				 unsigned int keylen, u8 *out)
{
	unsigned int nr = 6 + keylen / 4, i;

	for (i = 0; i < 4; i++) {
		put_unaligned_le32(aes->key_enc[4 * nr + i], &out[4 * i]);
		put_unaligned_le32(aes->key_enc[4 * (nr - 1) + i],
				   &out[16 + 4 * i]);
	}
}

static int fcp7_aes_setkey(struct crypto_skcipher *tfm, const u8 *key,
			       unsigned int keylen)
{
	struct fcp7_tfm_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct crypto_aes_ctx *aes;
	int err;

	aes = kmalloc_obj(*aes, GFP_KERNEL);
	if (!aes)
		return -ENOMEM;

	err = aes_expandkey(aes, key, keylen);
	if (err)
		goto out;
	/* First, so that a failure leaves the context untouched. */
	err = fcp7_set_fallback_key(tfm, key, keylen);
	if (err)
		goto out;

	ctx->cmd = fcp7_aes_cmd(keylen);
	memset(ctx->key_enc, 0, sizeof(ctx->key_enc));
	memcpy(ctx->key_enc, key, keylen);
	fcp7_aes_dec_key(aes, keylen, ctx->key_dec);
out:
	kfree_sensitive(aes);
	return err;
}

static int fcp7_des_setkey_common(struct crypto_skcipher *tfm,
				      const u8 *key, unsigned int keylen,
				      u8 cmd)
{
	struct fcp7_tfm_ctx *ctx = crypto_skcipher_ctx(tfm);

	int err;

	err = fcp7_set_fallback_key(tfm, key, keylen);
	if (err)
		return err;

	/* DES keys are used as is, in both directions. */
	ctx->cmd = cmd;
	memset(ctx->key_enc, 0, sizeof(ctx->key_enc));
	memcpy(ctx->key_enc, key, keylen);
	memcpy(ctx->key_dec, ctx->key_enc, sizeof(ctx->key_dec));

	return 0;
}

static int fcp7_des_setkey(struct crypto_skcipher *tfm, const u8 *key,
			       unsigned int keylen)
{
	int err;

	err = verify_skcipher_des_key(tfm, key);
	if (err)
		return err;

	return fcp7_des_setkey_common(tfm, key, keylen, CP7_CMD_DES);
}

static int fcp7_des3_setkey(struct crypto_skcipher *tfm, const u8 *key,
				unsigned int keylen)
{
	int err;

	err = verify_skcipher_des3_key(tfm, key);
	if (err)
		return err;

	return fcp7_des_setkey_common(tfm, key, keylen, CP7_CMD_3DES);
}

static int fcp7_init_tfm(struct crypto_skcipher *tfm)
{
	struct fcp7_tfm_ctx *ctx = crypto_skcipher_ctx(tfm);
	const char *name = crypto_tfm_alg_name(crypto_skcipher_tfm(tfm));

	ctx->fallback = crypto_alloc_skcipher(name, 0, CRYPTO_ALG_NEED_FALLBACK);
	if (IS_ERR(ctx->fallback))
		return PTR_ERR(ctx->fallback);

	crypto_skcipher_set_reqsize(tfm, sizeof(struct fcp7_req_ctx) +
				    crypto_skcipher_reqsize(ctx->fallback));

	return 0;
}

static void fcp7_exit_tfm(struct crypto_skcipher *tfm)
{
	struct fcp7_tfm_ctx *ctx = crypto_skcipher_ctx(tfm);

	crypto_free_skcipher(ctx->fallback);
	memzero_explicit(ctx->key_enc, sizeof(ctx->key_enc));
	memzero_explicit(ctx->key_dec, sizeof(ctx->key_dec));
}

static struct skcipher_alg fcp7_algs[] = {
	{
		.base = {
			.cra_name = "cbc(aes)",
			.cra_driver_name = "cbc-aes-cp7",
			.cra_priority = 300,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY |
				     CRYPTO_ALG_NEED_FALLBACK,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct fcp7_tfm_ctx),
			.cra_module = THIS_MODULE,
		},
		.min_keysize = AES_MIN_KEY_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE,
		.ivsize = AES_BLOCK_SIZE,
		.setkey = fcp7_aes_setkey,
		.encrypt = fcp7_encrypt,
		.decrypt = fcp7_decrypt,
		.init = fcp7_init_tfm,
		.exit = fcp7_exit_tfm,
	},
	{
		.base = {
			.cra_name = "cbc(des3_ede)",
			.cra_driver_name = "cbc-des3-cp7",
			.cra_priority = 300,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY |
				     CRYPTO_ALG_NEED_FALLBACK,
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct fcp7_tfm_ctx),
			.cra_module = THIS_MODULE,
		},
		.min_keysize = DES3_EDE_KEY_SIZE,
		.max_keysize = DES3_EDE_KEY_SIZE,
		.ivsize = DES3_EDE_BLOCK_SIZE,
		.setkey = fcp7_des3_setkey,
		.encrypt = fcp7_encrypt,
		.decrypt = fcp7_decrypt,
		.init = fcp7_init_tfm,
		.exit = fcp7_exit_tfm,
	},
	{
		.base = {
			.cra_name = "cbc(des)",
			.cra_driver_name = "cbc-des-cp7",
			.cra_priority = 300,
			.cra_flags = CRYPTO_ALG_ASYNC |
				     CRYPTO_ALG_KERN_DRIVER_ONLY |
				     CRYPTO_ALG_NEED_FALLBACK,
			.cra_blocksize = DES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct fcp7_tfm_ctx),
			.cra_module = THIS_MODULE,
		},
		.min_keysize = DES_KEY_SIZE,
		.max_keysize = DES_KEY_SIZE,
		.ivsize = DES_BLOCK_SIZE,
		.setkey = fcp7_des_setkey,
		.encrypt = fcp7_encrypt,
		.decrypt = fcp7_decrypt,
		.init = fcp7_init_tfm,
		.exit = fcp7_exit_tfm,
	},
};

/*
 * The engine does authsize 12 only, the two ESP associated data lengths
 * only, and one descriptor per request. Anything else
 * goes to the fallback, which also rejects what is invalid.
 */
static int fcp7_aead_queue(struct aead_request *req, bool decrypt)
{
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct fcp7_aead_ctx *ctx = crypto_aead_ctx(tfm);
	struct fcp7_aead_alg *alg = container_of(crypto_aead_alg(tfm),
						     struct fcp7_aead_alg,
						     alg);
	struct fcp7_aead_req_ctx *rctx = aead_request_ctx(req);
	unsigned int authsize = crypto_aead_authsize(tfm);
	unsigned int icv = decrypt ? authsize : 0;
	unsigned int assoclen = req->assoclen;
	unsigned int textlen, len;

	rctx->decrypt = decrypt;

	if (!ctx->hw_key || authsize != alg->icv ||
	    (assoclen != CP7_ESP_HDR &&
	     assoclen != CP7_ESP_HDR + crypto_aead_ivsize(tfm)) ||
	    req->cryptlen < icv)
		goto unsupported;

	textlen = req->cryptlen - icv;
	len = assoclen + textlen;
	if (!textlen || !IS_ALIGNED(textlen, crypto_aead_blocksize(tfm)) ||
	    len > fcp7_max_len ||
	    len + authsize > CP7_BOUNCE_SIZE)
		goto unsupported;
	if (textlen < CP7_FALLBACK_BELOW)
		return fcp7_aead_fallback(req);

	/* Refuse bad scatterlists before queueing, not on completion. */
	if (sg_nents_for_len(req->src, assoclen + req->cryptlen) < 0 ||
	    sg_nents_for_len(req->dst, len + authsize - icv) < 0)
		return -EINVAL;

	return fcp7_enqueue(&req->base);

unsupported:
	return fcp7_aead_fallback(req);
}

static int fcp7_aead_encrypt(struct aead_request *req)
{
	return fcp7_aead_queue(req, false);
}

static int fcp7_aead_decrypt(struct aead_request *req)
{
	return fcp7_aead_queue(req, true);
}

/*
 * FortiSOC2, HMAC-SHA-384/512: the engine takes the raw key, zero padded,
 * and has room for 64 bytes. HMAC pads the key with zeroes to the block
 * size (128 bytes) anyway, so the padding changes nothing. A longer key
 * would not fit: the requests of such a tfm go to the fallback.
 */
static bool fcp7_hmac_raw_key(u8 *kb, const u8 *key, unsigned int keylen)
{
	if (keylen > CP7_KEY_RAW_MAX)
		return false;
	memcpy(kb + CP7_KEY_HMAC_IN, key, keylen);

	return true;
}

static int fcp7_aead_setkey(struct crypto_aead *tfm, const u8 *key,
				unsigned int keylen)
{
	struct fcp7_aead_ctx *ctx = crypto_aead_ctx(tfm);
	struct fcp7_aead_alg *alg = container_of(crypto_aead_alg(tfm),
						     struct fcp7_aead_alg,
						     alg);
	struct crypto_aes_ctx *aes = NULL;
	struct crypto_authenc_keys keys;
	u8 cmd = alg->cipher_cmd;
	int err;

	err = crypto_authenc_extractkeys(&keys, key, keylen);
	if (err)
		goto out;

	if (cmd == CP7_CMD_3DES) {
		err = verify_aead_des3_key(tfm, keys.enckey, keys.enckeylen);
		if (err)
			goto out;
	} else {
		aes = kmalloc_obj(*aes, GFP_KERNEL);
		if (!aes) {
			err = -ENOMEM;
			goto out;
		}
		err = aes_expandkey(aes, keys.enckey, keys.enckeylen);
		if (err)
			goto out;
		cmd = fcp7_aes_cmd(keys.enckeylen);
	}

	/* First, so that a failure leaves the context untouched. */
	crypto_aead_clear_flags(ctx->fallback, CRYPTO_TFM_REQ_MASK);
	crypto_aead_set_flags(ctx->fallback,
			      crypto_aead_get_flags(tfm) & CRYPTO_TFM_REQ_MASK);
	err = crypto_aead_setkey(ctx->fallback, key, keylen);
	if (err)
		goto out;

	ctx->cmd = cmd | alg->hash_cmd;
	ctx->hsel = alg->hsel;
	ctx->hw_key = true;
	memset(ctx->key_enc, 0, sizeof(ctx->key_enc));
	memset(ctx->key_dec, 0, sizeof(ctx->key_dec));
	memcpy(ctx->key_enc, keys.enckey, keys.enckeylen);
	/* DES keys are used as is, in both directions. */
	if (aes)
		fcp7_aes_dec_key(aes, keys.enckeylen, ctx->key_dec);
	else
		memcpy(ctx->key_dec, ctx->key_enc, CP7_KEY_MAX);

	if (alg->hsel == CP7_HASH_SEL_SHA256)
		fcp_hmac_sha256_states(ctx->key_enc, keys.authkey,
					 keys.authkeylen);
	else if (alg->hsel)
		ctx->hw_key = fcp7_hmac_raw_key(ctx->key_enc, keys.authkey,
						    keys.authkeylen);
	else if (alg->hash_cmd == CP7_CMD_HMAC_SHA1)
		fcp_hmac_sha1_states(ctx->key_enc, keys.authkey,
				       keys.authkeylen);
	else
		fcp_hmac_md5_states(ctx->key_enc, keys.authkey,
				      keys.authkeylen);
	memcpy(ctx->key_dec + CP7_KEY_HMAC_IN,
	       ctx->key_enc + CP7_KEY_HMAC_IN,
	       CP7_KEY_BLOCK_MAX - CP7_KEY_HMAC_IN);
out:
	kfree_sensitive(aes);
	memzero_explicit(&keys, sizeof(keys));
	return err;
}

/* Any size the fallback takes; only alg->icv is done by the engine. */
static int fcp7_aead_setauthsize(struct crypto_aead *tfm,
				     unsigned int authsize)
{
	struct fcp7_aead_ctx *ctx = crypto_aead_ctx(tfm);

	return crypto_aead_setauthsize(ctx->fallback, authsize);
}

static int fcp7_aead_init_tfm(struct crypto_aead *tfm)
{
	struct fcp7_aead_ctx *ctx = crypto_aead_ctx(tfm);
	const char *name = crypto_tfm_alg_name(crypto_aead_tfm(tfm));

	ctx->fallback = crypto_alloc_aead(name, 0, CRYPTO_ALG_NEED_FALLBACK);
	if (IS_ERR(ctx->fallback))
		return PTR_ERR(ctx->fallback);

	crypto_aead_set_reqsize(tfm, sizeof(struct fcp7_aead_req_ctx) +
				crypto_aead_reqsize(ctx->fallback));

	return 0;
}

static void fcp7_aead_exit_tfm(struct crypto_aead *tfm)
{
	struct fcp7_aead_ctx *ctx = crypto_aead_ctx(tfm);

	crypto_free_aead(ctx->fallback);
	memzero_explicit(ctx->key_enc, sizeof(ctx->key_enc));
	memzero_explicit(ctx->key_dec, sizeof(ctx->key_dec));
}

/*
 * An AEAD of the FortiSOC2: HMAC-SHA-2 on top of the SHA1 command, the
 * hash selector choosing the variant. The driver names spell des3_ede
 * "des3", as for the other algorithms of this driver.
 */
#define CP7_FSOC2_AEAD(name, drv, CIPHER, ccmd, HASH, icvsize)		\
	{								\
		.alg = {						\
			.base = {					\
				.cra_name = name,			\
				.cra_driver_name = drv,			\
				.cra_priority = CP7_AEAD_PRIORITY,	\
				.cra_flags = CRYPTO_ALG_ASYNC |		\
					     CRYPTO_ALG_KERN_DRIVER_ONLY | \
					     CRYPTO_ALG_NEED_FALLBACK,	\
				.cra_blocksize = CIPHER##_BLOCK_SIZE,	\
				.cra_ctxsize = sizeof(struct fcp7_aead_ctx), \
				.cra_module = THIS_MODULE,		\
			},						\
			.ivsize = CIPHER##_BLOCK_SIZE,			\
			.maxauthsize = HASH##_DIGEST_SIZE,		\
			.setkey = fcp7_aead_setkey,			\
			.setauthsize = fcp7_aead_setauthsize,	\
			.encrypt = fcp7_aead_encrypt,		\
			.decrypt = fcp7_aead_decrypt,		\
			.init = fcp7_aead_init_tfm,			\
			.exit = fcp7_aead_exit_tfm,			\
		},							\
		.cipher_cmd = ccmd,					\
		.hash_cmd = CP7_CMD_HMAC_SHA1,			\
		.hsel = CP7_HASH_SEL_##HASH,				\
		.icv = icvsize,						\
	}

static struct fcp7_aead_alg fcp7_aead_algs[] = {
	{
		.alg = {
			.base = {
				.cra_name = "authenc(hmac(sha1),cbc(aes))",
				.cra_driver_name =
					"authenc-hmac-sha1-cbc-aes-cp7",
				.cra_priority = CP7_AEAD_PRIORITY,
				.cra_flags = CRYPTO_ALG_ASYNC |
					     CRYPTO_ALG_KERN_DRIVER_ONLY |
					     CRYPTO_ALG_NEED_FALLBACK,
				.cra_blocksize = AES_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct fcp7_aead_ctx),
				.cra_module = THIS_MODULE,
			},
			.ivsize = AES_BLOCK_SIZE,
			.maxauthsize = SHA1_DIGEST_SIZE,
			.setkey = fcp7_aead_setkey,
			.setauthsize = fcp7_aead_setauthsize,
			.encrypt = fcp7_aead_encrypt,
			.decrypt = fcp7_aead_decrypt,
			.init = fcp7_aead_init_tfm,
			.exit = fcp7_aead_exit_tfm,
		},
		.cipher_cmd = 0,
		.hash_cmd = CP7_CMD_HMAC_SHA1,
		.icv = CP7_ICV_SIZE,
	},
	{
		.alg = {
			.base = {
				.cra_name = "authenc(hmac(md5),cbc(aes))",
				.cra_driver_name =
					"authenc-hmac-md5-cbc-aes-cp7",
				.cra_priority = CP7_AEAD_PRIORITY,
				.cra_flags = CRYPTO_ALG_ASYNC |
					     CRYPTO_ALG_KERN_DRIVER_ONLY |
					     CRYPTO_ALG_NEED_FALLBACK,
				.cra_blocksize = AES_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct fcp7_aead_ctx),
				.cra_module = THIS_MODULE,
			},
			.ivsize = AES_BLOCK_SIZE,
			.maxauthsize = MD5_DIGEST_SIZE,
			.setkey = fcp7_aead_setkey,
			.setauthsize = fcp7_aead_setauthsize,
			.encrypt = fcp7_aead_encrypt,
			.decrypt = fcp7_aead_decrypt,
			.init = fcp7_aead_init_tfm,
			.exit = fcp7_aead_exit_tfm,
		},
		.cipher_cmd = 0,
		.hash_cmd = CP7_CMD_HMAC_MD5,
		.icv = CP7_ICV_SIZE,
	},
	{
		.alg = {
			.base = {
				.cra_name = "authenc(hmac(sha1),cbc(des3_ede))",
				.cra_driver_name =
					"authenc-hmac-sha1-cbc-des3-cp7",
				.cra_priority = CP7_AEAD_PRIORITY,
				.cra_flags = CRYPTO_ALG_ASYNC |
					     CRYPTO_ALG_KERN_DRIVER_ONLY |
					     CRYPTO_ALG_NEED_FALLBACK,
				.cra_blocksize = DES3_EDE_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct fcp7_aead_ctx),
				.cra_module = THIS_MODULE,
			},
			.ivsize = DES3_EDE_BLOCK_SIZE,
			.maxauthsize = SHA1_DIGEST_SIZE,
			.setkey = fcp7_aead_setkey,
			.setauthsize = fcp7_aead_setauthsize,
			.encrypt = fcp7_aead_encrypt,
			.decrypt = fcp7_aead_decrypt,
			.init = fcp7_aead_init_tfm,
			.exit = fcp7_aead_exit_tfm,
		},
		.cipher_cmd = CP7_CMD_3DES,
		.hash_cmd = CP7_CMD_HMAC_SHA1,
		.icv = CP7_ICV_SIZE,
	},
	{
		.alg = {
			.base = {
				.cra_name = "authenc(hmac(md5),cbc(des3_ede))",
				.cra_driver_name =
					"authenc-hmac-md5-cbc-des3-cp7",
				.cra_priority = CP7_AEAD_PRIORITY,
				.cra_flags = CRYPTO_ALG_ASYNC |
					     CRYPTO_ALG_KERN_DRIVER_ONLY |
					     CRYPTO_ALG_NEED_FALLBACK,
				.cra_blocksize = DES3_EDE_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct fcp7_aead_ctx),
				.cra_module = THIS_MODULE,
			},
			.ivsize = DES3_EDE_BLOCK_SIZE,
			.maxauthsize = MD5_DIGEST_SIZE,
			.setkey = fcp7_aead_setkey,
			.setauthsize = fcp7_aead_setauthsize,
			.encrypt = fcp7_aead_encrypt,
			.decrypt = fcp7_aead_decrypt,
			.init = fcp7_aead_init_tfm,
			.exit = fcp7_aead_exit_tfm,
		},
		.cipher_cmd = CP7_CMD_3DES,
		.hash_cmd = CP7_CMD_HMAC_MD5,
		.icv = CP7_ICV_SIZE,
	},
	/* FortiSOC2 only (fcp7_variant.sha2) */
	CP7_FSOC2_AEAD("authenc(hmac(sha256),cbc(aes))",
		      "authenc-hmac-sha256-cbc-aes-cp7", AES, 0, SHA256, 16),
	CP7_FSOC2_AEAD("authenc(hmac(sha512),cbc(aes))",
		      "authenc-hmac-sha512-cbc-aes-cp7", AES, 0, SHA512, 32),
	CP7_FSOC2_AEAD("authenc(hmac(sha256),cbc(des3_ede))",
		      "authenc-hmac-sha256-cbc-des3-cp7", DES3_EDE,
		      CP7_CMD_3DES, SHA256, 16),
	CP7_FSOC2_AEAD("authenc(hmac(sha512),cbc(des3_ede))",
		      "authenc-hmac-sha512-cbc-des3-cp7", DES3_EDE,
		      CP7_CMD_3DES, SHA512, 32),
};

/* The algorithms the engine of @soc does: SHA-2 on the FortiSOC2 only. */
static bool fcp7_aead_supported(const struct fcp7_variant *soc,
				    unsigned int i)
{
	return !fcp7_aead_algs[i].hsel || soc->sha2;
}

static void fcp7_unregister_aeads(const struct fcp7_variant *soc,
				      unsigned int count)
{
	while (count--)
		if (fcp7_aead_supported(soc, count))
			crypto_unregister_aead(&fcp7_aead_algs[count].alg);
}

static int fcp7_register_aeads(const struct fcp7_variant *soc)
{
	unsigned int i;
	int err;

	for (i = 0; i < ARRAY_SIZE(fcp7_aead_algs); i++) {
		if (!fcp7_aead_supported(soc, i))
			continue;
		err = crypto_register_aead(&fcp7_aead_algs[i].alg);
		if (err) {
			fcp7_unregister_aeads(soc, i);
			return err;
		}
	}

	return 0;
}

/* Stops the engine and everything that could still touch it. */
static void fcp7_quiesce(struct fcp7 *ce)
{
	fcp7_hw_stop(ce);
	disable_irq(ce->irq);
	cancel_work_sync(&ce->done_work);
	cancel_work_sync(&ce->poll_work);
	timer_delete_sync(&ce->watchdog);
	/* Nothing is queued any more, or it went to the fallback below. */
	fcp7_drain(ce);
	cancel_work_sync(&ce->drain_work);
}

/*
 * FortiSOC2: the interrupt of the engine reaches the SoC through the
 * interrupt map of the network processor, which its driver programs at
 * probe time. Wait for that driver to be bound (it may be a module loaded
 * after this one); without a network processor, poll.
 *
 * The bound state is read under the device lock of the network processor,
 * and a managed device link is made while that lock is held: should the
 * network processor driver ever be unbound, the driver core unbinds this
 * device first, so the interrupt route never disappears under it. The link
 * also orders suspend and shutdown (this device first).
 */
static int fcp7_np_irq(struct fcp7 *ce)
{
	struct platform_device *np_pdev;
	struct device_node *np_node;
	struct device_link *link = NULL;
	bool bound = false;
	int err = 0;

	np_node = of_find_compatible_node(NULL, NULL, "fortinet,fsoc2-np");
	if (!np_node || !of_device_is_available(np_node)) {
		dev_warn(ce->dev,
			 "no network processor to route the interrupt, polling\n");
		ce->polling = true;
		goto out;
	}

	np_pdev = of_find_device_by_node(np_node);
	if (np_pdev) {
		device_lock(&np_pdev->dev);
		bound = device_is_bound(&np_pdev->dev);
		if (bound)
			link = device_link_add(ce->dev, &np_pdev->dev,
					       DL_FLAG_AUTOREMOVE_CONSUMER);
		device_unlock(&np_pdev->dev);
		put_device(&np_pdev->dev);
	}

	if (!bound)
		err = dev_err_probe(ce->dev, -EPROBE_DEFER,
				    "waiting for the network processor to route the interrupt\n");
	else if (!link)
		err = dev_err_probe(ce->dev, -EINVAL,
				    "cannot link to the network processor\n");
out:
	of_node_put(np_node);

	return err;
}

/*
 * Reset ring 0, and check that the reset took: self-clearing, pointers
 * back to 0. The other rings of the FortiSOC2 are not used: only
 * one left with its interrupt pending (by a previous kernel) is reset, as
 * it would hold the shared line up.
 */
static int fcp7_hw_reset(struct fcp7 *ce)
{
	unsigned int q;

	writel(CP7_CTRL_RESET, ce->base + CP7_CTRL);
	if ((readl(ce->base + CP7_CTRL) & CP7_CTRL_RESET) ||
	    readl(ce->base + CP7_RING_DONE))
		return dev_err_probe(ce->dev, -ENODEV,
				     "engine reset failed (CONTROL %#x, RING_DONE %#x)\n",
				     readl(ce->base + CP7_CTRL),
				     readl(ce->base + CP7_RING_DONE));

	for (q = 1; q <= ce->soc->extra_queues; q++) {
		void __iomem *base = ce->base + q * CP7_RING_STRIDE;

		if (!(readl(base + CP7_STATUS) & CP7_STATUS_IRQ))
			continue;
		dev_warn(ce->dev, "ring %u: interrupt pending, resetting it\n", q);
		writel(CP7_CTRL_RESET, base + CP7_CTRL);
	}

	return 0;
}

static int fcp7_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct fcp7 *ce;
	unsigned int i;
	int err;

	if (fcp7_dev)
		return -EBUSY;

	ce = devm_kzalloc(dev, sizeof(*ce), GFP_KERNEL);
	if (!ce)
		return -ENOMEM;
	ce->dev = dev;
	ce->soc = device_get_match_data(dev);
	if (!ce->soc)
		return -ENODEV;
	ce->ring_mask = ce->soc->ring_size - 1;
	if (ce->soc->np_irq) {
		err = fcp7_np_irq(ce);
		if (err)
			return err;
	}
	fcp7_dline = ce->soc->dline;
	fcp7_max_len = ce->soc->max_len;
	crypto_init_queue(&ce->queue, CP7_QUEUE_LEN);
	INIT_WORK(&ce->done_work, fcp7_done_work);
	INIT_WORK(&ce->poll_work, fcp7_poll_work);
	INIT_WORK(&ce->drain_work, fcp7_drain_work);
	timer_setup(&ce->watchdog, fcp7_watchdog, 0);
	platform_set_drvdata(pdev, ce);

	ce->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(ce->base))
		return PTR_ERR(ce->base);

	/* Stop whatever the boot loader or a previous kernel left running. */
	err = fcp7_hw_reset(ce);
	if (err)
		return err;

	err = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(32));
	if (err)
		return err;

	ce->ring = dmam_alloc_coherent(dev, ce->soc->ring_size * sizeof(*ce->ring),
				       &ce->ring_dma, GFP_KERNEL);
	if (!ce->ring)
		return -ENOMEM;
	/* The engine is only known to work with a naturally aligned ring. */
	if (!IS_ALIGNED(ce->ring_dma, ce->soc->ring_size * sizeof(*ce->ring)))
		return dev_err_probe(dev, -EINVAL, "ring at %pad is misaligned\n",
				     &ce->ring_dma);

	ce->keys = dmam_alloc_coherent(dev, ce->soc->ring_size *
				       CP7_KEY_STRIDE, &ce->keys_dma,
				       GFP_KERNEL);
	if (!ce->keys)
		return -ENOMEM;

	for (i = 0; i < CP7_JOBS; i++) {
		unsigned long page;

		page = devm_get_free_pages(dev, GFP_KERNEL,
					   get_order(CP7_BOUNCE_SIZE));
		if (!page)
			return -ENOMEM;
		ce->jobs[i].bounce = (void *)page;
	}

	fcp7_hw_init(ce);
	fcp7_hw_start(ce);

	ce->irq = platform_get_irq(pdev, 0);
	if (ce->irq < 0) {
		err = ce->irq;
		goto err_stop;
	}
	err = devm_request_irq(dev, ce->irq, fcp7_irq, 0, dev_name(dev), ce);
	if (err) {
		dev_err_probe(dev, err, "cannot request IRQ %d\n", ce->irq);
		goto err_stop;
	}
	if (ce->polling)
		disable_irq(ce->irq);

	spin_lock_bh(&fcp7_lock);
	fcp7_dev = ce;
	spin_unlock_bh(&fcp7_lock);

	err = crypto_register_skciphers(fcp7_algs, ARRAY_SIZE(fcp7_algs));
	if (err) {
		dev_err(dev, "cannot register algorithms: %d\n", err);
		goto err_dev;
	}
	err = fcp7_register_aeads(ce->soc);
	if (err) {
		dev_err(dev, "cannot register AEAD algorithms: %d\n", err);
		goto err_skciphers;
	}

	dev_info(dev, "crypto engine ready (%s)\n",
		 ce->polling ? "polling" : "interrupt");

	return 0;

err_skciphers:
	crypto_unregister_skciphers(fcp7_algs, ARRAY_SIZE(fcp7_algs));
err_dev:
	spin_lock_bh(&fcp7_lock);
	fcp7_dev = NULL;
	spin_unlock_bh(&fcp7_lock);
	/* The engine may have been used meanwhile. */
	fcp7_quiesce(ce);
	return err;
err_stop:
	fcp7_hw_stop(ce);
	return err;
}

/*
 * Runs on module removal only (no unbind through sysfs). Every tfm of this
 * driver holds a reference to the module, so none is left by then; the
 * instances built on top of the algorithms (authenc(), echainiv()...) are
 * torn down by crypto_unregister_*().
 */
static void fcp7_remove(struct platform_device *pdev)
{
	struct fcp7 *ce = platform_get_drvdata(pdev);
	struct fcp7_batch b = { };
	unsigned long deadline = jiffies + CP7_TIMEOUT;
	unsigned int i;
	bool busy;

	/*
	 * New requests go to the software fallback from now on. The tfms
	 * that still exist keep working after the device is gone: they only
	 * reach it through fcp7_dev.
	 */
	spin_lock_bh(&fcp7_lock);
	fcp7_dev = NULL;
	spin_unlock_bh(&fcp7_lock);

	/* Let the engine finish what it has, the queue included. */
	for (;;) {
		spin_lock_bh(&fcp7_lock);
		busy = ce->active_jobs || ce->queue.qlen;
		if (busy && time_after(jiffies, deadline)) {
			fcp7_kill(ce, &b);
			busy = false;
		}
		spin_unlock_bh(&fcp7_lock);
		if (!busy)
			break;
		msleep(20);
	}
	/* Fails the jobs killed above; quiesce runs what is still queued. */
	fcp7_batch_finish(&b);
	fcp7_quiesce(ce);
	/* The ring and the key blocks are freed next: leave the engine reset. */
	writel(CP7_CTRL_RESET, ce->base + CP7_CTRL);

	/* The bounce buffers may still hold plaintext. */
	for (i = 0; i < CP7_JOBS; i++)
		memzero_explicit(ce->jobs[i].bounce, CP7_BOUNCE_SIZE);

	fcp7_unregister_aeads(ce->soc, ARRAY_SIZE(fcp7_aead_algs));
	crypto_unregister_skciphers(fcp7_algs, ARRAY_SIZE(fcp7_algs));
}

static void fcp7_shutdown(struct platform_device *pdev)
{
	struct fcp7 *ce = platform_get_drvdata(pdev);

	/* Do not leave the engine fetching descriptors across a reboot. */
	if (ce->soc->reset_on_shutdown)
		writel(CP7_CTRL_RESET, ce->base + CP7_CTRL);
	else
		fcp7_hw_stop(ce);
}

static const struct fcp7_variant fcp7_fsoc1_data = {
	.ring_size = 512,
	.max_len = U16_MAX,
	.key_block = CP7_KEY_BLOCK_SIZE,
	.dline = 16,
};

/*
 * FortiSOC2: the engine sits in the register window of the network
 * processor, which routes its interrupt.
 */
static const struct fcp7_variant fcp7_fsoc2_data = {
	.ring_size = 1024,
	.max_len = 0x7fff,
	.key_block = CP7_KEY_BLOCK_MAX,
	.dline = 32,
	.sha2 = true,
	.np_irq = true,
	.extra_queues = 3,
	.reset_on_shutdown = true,
};

static const struct of_device_id fcp7_of_match[] = {
	{ .compatible = "fortinet,fsoc1-crypto", .data = &fcp7_fsoc1_data },
	{ .compatible = "fortinet,fsoc2-crypto", .data = &fcp7_fsoc2_data },
	{ }
};
MODULE_DEVICE_TABLE(of, fcp7_of_match);

static struct platform_driver fcp7_driver = {
	.probe = fcp7_probe,
	.remove = fcp7_remove,
	.shutdown = fcp7_shutdown,
	.driver = {
		.name = "fortinet-cp7",
		.of_match_table = fcp7_of_match,
		/*
		 * Unbinding through sysfs would unregister algorithms that
		 * live tfms still use; module removal is refused while any
		 * exists.
		 */
		.suppress_bind_attrs = true,
	},
};
module_platform_driver(fcp7_driver);

MODULE_DESCRIPTION("Fortinet CP7 crypto engine driver");
MODULE_LICENSE("GPL");
