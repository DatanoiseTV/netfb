// SPDX-License-Identifier: GPL-2.0-only
/*
 * VNC (RFB, RFC 6143) session for netfb.
 *
 * Protocol versions 3.3, 3.7 and 3.8; security type "None" (loopback, no
 * password) or "VNC Authentication" (DES challenge/response); Raw and ZRLE
 * encodings; any true-colour client pixel format; key events (through the netfb
 * input device when keyboard=1). Pointer and cut-text messages are accepted
 * and ignored. The framebuffer size never changes.
 *
 * RFB is pull based: an update is sent only while a FramebufferUpdateRequest
 * is outstanding. Dirty rows are found with the same per-row versions the
 * WebSocket path uses, kept per connection in sent[] so that a request for part
 * of the screen does not lose damage elsewhere.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <crypto/des.h>
#if __has_include(<crypto/utils.h>)
#include <crypto/utils.h>
#else
#include <crypto/algapi.h>
#endif
#if __has_include(<linux/unaligned.h>)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif
#include <linux/bitops.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/zlib.h>
#include <net/sock.h>

#include "netfb.h"

#define HANDSHAKE_DEADLINE	(15 * HZ)
#define AUTH_FAIL_DELAY_MS	1500	/* slows down password guessing */
#define WAIT_MS			200
#define RX_MAX			512
#define MAX_ENCODINGS		64
#define CUTTEXT_MAX		(1u << 20)
#define MERGE_GAP		8
#define MAX_RUNS		32
#define RAW_CHUNK_BYTES		(128 * 1024)
#define ZRLE_CHUNK_BYTES	(120 * 1000)
#define ZBUF_SIZE		(192 * 1024)	/* > deflate bound of one ZRLE chunk */
#define TILE			64
#define MAX_ACTIVE		32

#define ENC_RAW			0
#define ENC_ZRLE		16

#define SEC_NONE		1
#define SEC_VNC			2

enum { K_SHIFT, K_CTRL, K_ALT, K_META, K_NKINDS };

/* Linux key codes of the modifiers: [kind][left, right]. */
static const u8 mod_code[K_NKINDS][2] = {
	{ 42, 54 }, { 29, 97 }, { 56, 100 }, { 125, 126 },
};

struct pixfmt {
	u8 bpp;			/* 8, 16 or 32 */
	bool be;
	u16 max[3];		/* red, green, blue: 2^n - 1 */
	u8 shift[3];
	u32 lut[3][256];	/* 8-bit channel value -> client value, already shifted */
	bool native;		/* identical to the framebuffer's memory layout */
	u8 cpix;		/* ZRLE CPIXEL size in bytes */
	u8 cpix_off;		/* where the CPIXEL sits in a wire pixel */
};

struct vkey {
	u32 sym;
	u8 code;
};

struct vnc {
	struct netfb_conn *c;
	struct netfb *nf;
	int ver;			/* 3, 7 or 8 */

	struct pixfmt pf;
	struct pixfmt pf_new;		/* scratch for SetPixelFormat: the tables are too big for the stack */
	bool zrle;
	bool pending;			/* a FramebufferUpdateRequest is outstanding */
	bool scan;			/* rescan even if the generation did not move */
	struct { u32 x, y, w, h; } req;
	u64 seen_gen;
	u64 *sent;			/* per row: framebuffer version last sent */
	unsigned long interval;

	u8 rx[RX_MAX];
	size_t rxlen;
	u32 skip;			/* bytes of ClientCutText still to discard */

	u8 *tx;
	u8 *stage;			/* one ZRLE tile */
	u8 *zbuf;
	z_stream zs;
	bool zinit;

	struct vkey active[MAX_ACTIVE];
	unsigned int nactive;
	u8 guest_mods[K_NKINDS];	/* bit 0/1: left/right held in the guest */
	u8 client_mods[K_NKINDS];	/* bit 0/1: left/right held by the client */
};

/* ---- socket helpers ----------------------------------------------------- */

static int vnc_read(struct netfb_conn *c, void *buf, size_t n, unsigned long deadline)
{
	u8 *p = buf;

	while (n) {
		struct msghdr msg = {};
		struct kvec iov = { .iov_base = p, .iov_len = n };
		int r;

		if (kthread_should_stop() || netfb_srv_stopping(c->srv))
			return -ECANCELED;
		if (time_after(jiffies, deadline))
			return -ETIMEDOUT;
		r = kernel_recvmsg(c->sock, &msg, &iov, 1, n, 0);
		if (r == -EAGAIN)
			continue;		/* receive timeout: re-check the deadline */
		if (r < 0)
			return r;
		if (!r)
			return -ECONNRESET;
		p += r;
		n -= r;
	}
	return 0;
}

static int vnc_u32(struct netfb_conn *c, u32 v)
{
	__be32 be = cpu_to_be32(v);

	return netfb_send_all(c->sock, &be, sizeof(be));
}

/* ---- pixel formats ------------------------------------------------------ */

static u8 bitrev(u8 b)
{
	b = (b & 0xf0) >> 4 | (b & 0x0f) << 4;
	b = (b & 0xcc) >> 2 | (b & 0x33) << 2;
	b = (b & 0xaa) >> 1 | (b & 0x55) << 1;
	return b;
}

static bool pf_native_layout(const struct vnc *v, const struct pixfmt *pf)
{
	const struct netfb *nf = v->nf;
	bool host_be = IS_ENABLED(CONFIG_CPU_BIG_ENDIAN);

	if (pf->bpp != nf->bpp || pf->be != host_be)
		return false;
	if (nf->bpp == 32)
		return pf->max[0] == 255 && pf->max[1] == 255 && pf->max[2] == 255 &&
		       pf->shift[0] == 16 && pf->shift[1] == 8 && pf->shift[2] == 0;
	return pf->max[0] == 31 && pf->max[1] == 63 && pf->max[2] == 31 &&
	       pf->shift[0] == 11 && pf->shift[1] == 5 && pf->shift[2] == 0;
}

/* Validates a client format and derives the lookup tables from it. */
static int pf_setup(struct vnc *v, struct pixfmt *pf)
{
	u32 mask = 0;
	int ch, i;

	if (pf->bpp != 8 && pf->bpp != 16 && pf->bpp != 32)
		return -EPROTO;
	for (ch = 0; ch < 3; ch++) {
		u32 m = pf->max[ch];
		unsigned int bits = fls(m);

		if (!m || (m & (m + 1)))		/* must be 2^n - 1 */
			return -EPROTO;
		if (pf->shift[ch] + bits > pf->bpp)
			return -EPROTO;
		for (i = 0; i < 256; i++)
			pf->lut[ch][i] = ((u32)((i * m + 127) / 255)) << pf->shift[ch];
		mask |= m << pf->shift[ch];
	}

	pf->cpix = pf->bpp / 8;
	pf->cpix_off = 0;
	if (pf->bpp == 32) {
		/* RFC 6143 7.7.5: three bytes if the colour bits fit in the low or high three. */
		if (!(mask & 0xff000000u)) {
			pf->cpix = 3;
			pf->cpix_off = pf->be ? 1 : 0;
		} else if (!(mask & 0x000000ffu)) {
			pf->cpix = 3;
			pf->cpix_off = pf->be ? 0 : 1;
		}
	}
	pf->native = pf_native_layout(v, pf);
	return 0;
}

static void pf_set_native(struct vnc *v)
{
	struct pixfmt *pf = &v->pf;

	memset(pf, 0, sizeof(*pf));
	pf->bpp = v->nf->bpp;
	pf->be = IS_ENABLED(CONFIG_CPU_BIG_ENDIAN);
	if (pf->bpp == 32) {
		pf->max[0] = pf->max[1] = pf->max[2] = 255;
		pf->shift[0] = 16; pf->shift[1] = 8; pf->shift[2] = 0;
	} else {
		pf->max[0] = 31; pf->max[1] = 63; pf->max[2] = 31;
		pf->shift[0] = 11; pf->shift[1] = 5; pf->shift[2] = 0;
	}
	pf_setup(v, pf);
}

/* Framebuffer pixel at @src, in the client's pixel format, as a value. */
static inline u32 pix_value(const struct vnc *v, const u8 *src)
{
	const struct pixfmt *pf = &v->pf;
	u32 r, g, b;

	if (v->nf->bpp == 32) {
		u32 p = *(const u32 *)src;

		r = (p >> 16) & 0xff; g = (p >> 8) & 0xff; b = p & 0xff;
	} else {
		u32 p = *(const u16 *)src;

		r = (p >> 11) & 31; r = (r << 3) | (r >> 2);
		g = (p >> 5) & 63;  g = (g << 2) | (g >> 4);
		b = p & 31;         b = (b << 3) | (b >> 2);
	}
	return pf->lut[0][r] | pf->lut[1][g] | pf->lut[2][b];
}

/* Writes @val as one client pixel (bpp/8 bytes) at @dst. */
static inline void pix_pack(const struct pixfmt *pf, u32 val, u8 *dst)
{
	if (pf->bpp == 32) {
		if (pf->be) put_unaligned_be32(val, dst); else put_unaligned_le32(val, dst);
	} else if (pf->bpp == 16) {
		if (pf->be) put_unaligned_be16(val, dst); else put_unaligned_le16(val, dst);
	} else {
		dst[0] = val;
	}
}

static inline u8 *cpix_pack(const struct pixfmt *pf, u32 val, u8 *dst)
{
	u8 tmp[4];

	pix_pack(pf, val, tmp);
	memcpy(dst, tmp + pf->cpix_off, pf->cpix);
	return dst + pf->cpix;
}

/* ---- keyboard ----------------------------------------------------------- */

static const char us_base[] = "`1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./";
static const char us_shift[] = "~!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:\"ZXCVBNM<>?";
static const u8 us_code[] = {
	41, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
	16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 43,
	30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	44, 45, 46, 47, 48, 49, 50, 51, 52, 53,
};

static const struct { u32 sym; u8 code; } special_keys[] = {
	{ 0xff08, 14 }, { 0xff09, 15 }, { 0xff0d, 28 }, { 0xff1b, 1 },
	{ 0xff50, 102 }, { 0xff51, 105 }, { 0xff52, 103 }, { 0xff53, 106 },
	{ 0xff54, 108 }, { 0xff55, 104 }, { 0xff56, 109 }, { 0xff57, 107 },
	{ 0xff63, 110 }, { 0xffff, 111 }, { 0xff13, 119 }, { 0xff61, 99 },
	{ 0xff67, 127 }, { 0xff7f, 69 }, { 0xff14, 70 },
	{ 0xffbe, 59 }, { 0xffbf, 60 }, { 0xffc0, 61 }, { 0xffc1, 62 },
	{ 0xffc2, 63 }, { 0xffc3, 64 }, { 0xffc4, 65 }, { 0xffc5, 66 },
	{ 0xffc6, 67 }, { 0xffc7, 68 }, { 0xffc8, 87 }, { 0xffc9, 88 },
	{ 0xffb0, 82 }, { 0xffb1, 79 }, { 0xffb2, 80 }, { 0xffb3, 81 },
	{ 0xffb4, 75 }, { 0xffb5, 76 }, { 0xffb6, 77 }, { 0xffb7, 71 },
	{ 0xffb8, 72 }, { 0xffb9, 73 }, { 0xffae, 83 }, { 0xffab, 78 },
	{ 0xffad, 74 }, { 0xffaa, 55 }, { 0xffaf, 98 }, { 0xff8d, 96 },
};

/* X11 keysym -> modifier slot (kind * 2 + right), or -1. */
static int mod_slot(u32 sym)
{
	switch (sym) {
	case 0xffe1: return K_SHIFT * 2;
	case 0xffe2: return K_SHIFT * 2 + 1;
	case 0xffe3: return K_CTRL * 2;
	case 0xffe4: return K_CTRL * 2 + 1;
	case 0xffe9: return K_ALT * 2;
	case 0xffea: return K_ALT * 2 + 1;
	case 0xffe7: case 0xffeb: return K_META * 2;
	case 0xffe8: case 0xffec: return K_META * 2 + 1;
	}
	return -1;
}

/*
 * Keysym -> Linux key code. For printable characters *shift says whether the US
 * layout needs Shift for it; for other keys it is left at -1 (do not care).
 */
static bool sym_to_code(u32 sym, u8 *code, int *shift)
{
	size_t i;

	*shift = -1;
	if (sym == ' ') {
		*code = 57; *shift = 0;
		return true;
	}
	if (sym > 0x20 && sym < 0x7f) {
		for (i = 0; i < sizeof(us_code); i++) {
			if (us_base[i] == sym) { *code = us_code[i]; *shift = 0; return true; }
			if (us_shift[i] == sym) { *code = us_code[i]; *shift = 1; return true; }
		}
		return false;
	}
	for (i = 0; i < ARRAY_SIZE(special_keys); i++) {
		if (special_keys[i].sym == sym) { *code = special_keys[i].code; return true; }
	}
	return false;
}

static void k_emit(struct vnc *v, u8 code, bool down)
{
	int k, s;

	netfb_key(v->nf, code, down);
	for (k = 0; k < K_NKINDS; k++) {
		for (s = 0; s < 2; s++) {
			if (mod_code[k][s] == code) {
				if (down) v->guest_mods[k] |= BIT(s); else v->guest_mods[k] &= ~BIT(s);
			}
		}
	}
}

static void k_set_kind(struct vnc *v, int kind, bool want)
{
	bool has = v->guest_mods[kind];
	int s;

	if (want && !has) {
		s = (v->client_mods[kind] & BIT(1)) && !(v->client_mods[kind] & BIT(0)) ? 1 : 0;
		k_emit(v, mod_code[kind][s], true);
	} else if (!want && has) {
		for (s = 0; s < 2; s++)
			if (v->guest_mods[kind] & BIT(s))
				k_emit(v, mod_code[kind][s], false);
	}
}

static void k_sync_mods(struct vnc *v)
{
	int k;

	for (k = 0; k < K_NKINDS; k++)
		k_set_kind(v, k, v->client_mods[k]);
}

static void k_release_all(struct vnc *v)
{
	unsigned int i;
	int k, s;

	for (i = 0; i < v->nactive; i++)
		k_emit(v, v->active[i].code, false);
	v->nactive = 0;
	for (k = 0; k < K_NKINDS; k++)
		for (s = 0; s < 2; s++)
			if (v->guest_mods[k] & BIT(s))
				k_emit(v, mod_code[k][s], false);
}

static void vnc_key(struct vnc *v, u32 sym, bool down)
{
	u8 code;
	int shift, slot, k;
	unsigned int i;

	if (!v->nf->kbd)
		return;

	slot = mod_slot(sym);
	if (slot >= 0) {
		k = slot / 2;
		if (down) {
			v->client_mods[k] |= BIT(slot & 1);
			k_emit(v, mod_code[k][slot & 1], true);
		} else {
			v->client_mods[k] &= ~BIT(slot & 1);
			k_emit(v, mod_code[k][slot & 1], false);
			k_sync_mods(v);
		}
		return;
	}
	if (sym == 0xffe5)		/* Caps Lock: case comes from the keysyms themselves */
		return;

	for (i = 0; i < v->nactive; i++)
		if (v->active[i].sym == sym)
			break;

	if (!down) {
		if (i < v->nactive) {
			k_emit(v, v->active[i].code, false);
			v->active[i] = v->active[--v->nactive];
			k_sync_mods(v);
		}
		return;
	}
	if (i < v->nactive)		/* auto-repeat from the client: the guest repeats itself */
		return;
	if (v->nactive == MAX_ACTIVE || !sym_to_code(sym, &code, &shift))
		return;

	/* The keysym names the character, so the guest's Shift must match what that
	 * character needs on a US layout, whatever Shift the client is holding. */
	k_set_kind(v, K_SHIFT, shift >= 0 ? shift : !!v->client_mods[K_SHIFT]);
	k_set_kind(v, K_CTRL, v->client_mods[K_CTRL]);
	k_set_kind(v, K_ALT, v->client_mods[K_ALT]);
	k_set_kind(v, K_META, v->client_mods[K_META]);
	k_emit(v, code, true);
	v->active[v->nactive].sym = sym;
	v->active[v->nactive].code = code;
	v->nactive++;
}

/* ---- handshake ---------------------------------------------------------- */

static int vnc_auth(struct vnc *v)
{
	struct netfb_conn *c = v->c;
	const char *pw = netfb_srv_vnc_password(c->srv);
	u8 challenge[16], resp[16], want[16], key[8] = {};
	struct des_ctx ctx;
	unsigned int i;
	int ret;
	bool ok;

	get_random_bytes(challenge, sizeof(challenge));
	ret = netfb_send_all(c->sock, challenge, sizeof(challenge));
	if (ret)
		return ret;
	ret = vnc_read(c, resp, sizeof(resp), jiffies + HANDSHAKE_DEADLINE);
	if (ret)
		return ret;

	/* RFB: the password, NUL padded to 8 bytes, with every byte bit-reversed, is the DES key. */
	for (i = 0; i < 8 && pw[i]; i++)
		key[i] = bitrev(pw[i]);
	ok = !des_expand_key(&ctx, key, sizeof(key));
	if (ok) {
		des_encrypt(&ctx, want, challenge);
		des_encrypt(&ctx, want + 8, challenge + 8);
		ok = !crypto_memneq(resp, want, sizeof(want));
	}
	memzero_explicit(&ctx, sizeof(ctx));
	memzero_explicit(key, sizeof(key));
	memzero_explicit(want, sizeof(want));
	return ok ? 0 : -EACCES;
}

static int vnc_handshake(struct vnc *v)
{
	struct netfb_conn *c = v->c;
	unsigned long deadline = jiffies + HANDSHAKE_DEADLINE;
	const bool need_auth = !!netfb_srv_vnc_password(c->srv);
	const u8 sec = need_auth ? SEC_VNC : SEC_NONE;
	char ver[12];
	u8 sel, init;
	unsigned int major, minor;
	int ret;

	ret = netfb_send_all(c->sock, "RFB 003.008\n", 12);
	if (ret)
		return ret;
	ret = vnc_read(c, ver, sizeof(ver), deadline);
	if (ret)
		return ret;
	if (memcmp(ver, "RFB ", 4) || ver[7] != '.' || ver[11] != '\n' ||
	    !isdigit(ver[4]) || !isdigit(ver[5]) || !isdigit(ver[6]) ||
	    !isdigit(ver[8]) || !isdigit(ver[9]) || !isdigit(ver[10]))
		return -EPROTO;
	major = (ver[4] - '0') * 100 + (ver[5] - '0') * 10 + (ver[6] - '0');
	minor = (ver[8] - '0') * 100 + (ver[9] - '0') * 10 + (ver[10] - '0');
	if (major != 3)
		return -EPROTO;
	/* Some clients announce 3.889 (Apple); anything >= 3.8 is spoken as 3.8. */
	v->ver = minor >= 8 ? 8 : minor == 7 ? 7 : 3;

	if (v->ver >= 7) {
		u8 offer[2] = { 1, sec };

		ret = netfb_send_all(c->sock, offer, sizeof(offer));
		if (ret)
			return ret;
		ret = vnc_read(c, &sel, 1, deadline);
		if (ret)
			return ret;
		if (sel != sec) {
			if (v->ver == 8) {
				static const char why[] = "security type not offered";

				vnc_u32(c, 1);
				vnc_u32(c, sizeof(why) - 1);
				netfb_send_all(c->sock, why, sizeof(why) - 1);
			}
			return -EPROTO;
		}
	} else {
		ret = vnc_u32(c, sec);
		if (ret)
			return ret;
	}

	if (need_auth) {
		ret = vnc_auth(v);
		if (ret == -EACCES) {
			static const char why[] = "authentication failed";

			netfb_auth_failed(c->srv, c->peer);
			msleep(AUTH_FAIL_DELAY_MS);
			vnc_u32(c, 1);
			if (v->ver == 8) {
				vnc_u32(c, sizeof(why) - 1);
				netfb_send_all(c->sock, why, sizeof(why) - 1);
			}
			return -EACCES;
		}
		if (ret)
			return ret;
		netfb_auth_ok(c->srv, c->peer);
		ret = vnc_u32(c, 0);
		if (ret)
			return ret;
	} else if (v->ver == 8) {
		ret = vnc_u32(c, 0);	/* SecurityResult for "None" exists only in 3.8 */
		if (ret)
			return ret;
	}

	ret = vnc_read(c, &init, 1, deadline);	/* ClientInit: shared flag, ignored */
	if (ret)
		return ret;

	{
		u8 si[24 + 5];
		const struct pixfmt *pf = &v->pf;
		const u8 depth = pf->bpp == 32 ? 24 : 16;

		put_unaligned_be16(v->nf->width, si);
		put_unaligned_be16(v->nf->height, si + 2);
		si[4] = pf->bpp; si[5] = depth; si[6] = pf->be; si[7] = 1;
		put_unaligned_be16(pf->max[0], si + 8);
		put_unaligned_be16(pf->max[1], si + 10);
		put_unaligned_be16(pf->max[2], si + 12);
		si[14] = pf->shift[0]; si[15] = pf->shift[1]; si[16] = pf->shift[2];
		si[17] = si[18] = si[19] = 0;
		put_unaligned_be32(5, si + 20);
		memcpy(si + 24, "netfb", 5);
		return netfb_send_all(c->sock, si, sizeof(si));
	}
}

/* ---- updates ------------------------------------------------------------ */

static void rect_header(u8 *p, u32 w, u32 y, u32 h, s32 enc)
{
	put_unaligned_be16(0, p);
	put_unaligned_be16(y, p + 2);
	put_unaligned_be16(w, p + 4);
	put_unaligned_be16(h, p + 6);
	put_unaligned_be32(enc, p + 8);
}

/* Records the version of each row about to be read; must precede the pixel reads. */
static void mark_sent(struct vnc *v, u32 y, u32 h)
{
	u32 i;

	for (i = y; i < y + h; i++)
		v->sent[i] = READ_ONCE(v->nf->row_ver[i]);
}

static int send_raw(struct vnc *v, u32 y, u32 h)
{
	struct netfb *nf = v->nf;
	const struct pixfmt *pf = &v->pf;
	u8 *out = v->tx + 12;
	u32 row, x;

	rect_header(v->tx, nf->width, y, h, ENC_RAW);
	mark_sent(v, y, h);
	if (pf->native) {
		memcpy(out, nf->vmem + (size_t)y * nf->rowbytes, (size_t)h * nf->rowbytes);
		out += (size_t)h * nf->rowbytes;
	} else {
		for (row = y; row < y + h; row++) {
			const u8 *src = nf->vmem + (size_t)row * nf->rowbytes;

			for (x = 0; x < nf->width; x++, src += nf->bpp / 8, out += pf->bpp / 8)
				pix_pack(pf, pix_value(v, src), out);
		}
	}
	return netfb_send_all(v->c->sock, v->tx, out - v->tx);
}

/* One 64x64 (or smaller) tile as ZRLE data: solid (1) when uniform, else raw (0). */
static size_t zrle_tile(struct vnc *v, u32 tx, u32 ty, u32 tw, u32 th)
{
	struct netfb *nf = v->nf;
	const struct pixfmt *pf = &v->pf;
	const u32 bytes = nf->bpp / 8;
	u8 *o = v->stage + 1;
	u32 first = 0, x, y;
	bool solid = true;

	for (y = 0; y < th; y++) {
		const u8 *src = nf->vmem + (size_t)(ty + y) * nf->rowbytes + (size_t)tx * bytes;

		for (x = 0; x < tw; x++, src += bytes) {
			u32 val = pix_value(v, src);

			if (!x && !y)
				first = val;
			else if (val != first)
				solid = false;
			o = cpix_pack(pf, val, o);
		}
	}
	if (solid) {
		v->stage[0] = 1;
		cpix_pack(pf, first, v->stage + 1);
		return 1 + pf->cpix;
	}
	v->stage[0] = 0;
	return o - v->stage;
}

static int send_zrle(struct vnc *v, u32 y, u32 h)
{
	struct netfb *nf = v->nf;
	z_stream *zs = &v->zs;
	u32 tx, ty, tw, th, clen;
	int ret;

	mark_sent(v, y, h);
	zs->next_out = v->zbuf + 16;		/* 12 byte rect header + 4 byte length in front */
	zs->avail_out = ZBUF_SIZE - 16;
	for (ty = y; ty < y + h; ty += TILE) {
		th = min_t(u32, TILE, y + h - ty);
		for (tx = 0; tx < nf->width; tx += TILE) {
			tw = min_t(u32, TILE, nf->width - tx);
			zs->next_in = v->stage;
			zs->avail_in = zrle_tile(v, tx, ty, tw, th);
			ret = zlib_deflate(zs, Z_NO_FLUSH);
			if (ret != Z_OK || zs->avail_in || !zs->avail_out)
				return -EIO;
		}
	}
	zs->next_in = NULL;
	zs->avail_in = 0;
	ret = zlib_deflate(zs, Z_SYNC_FLUSH);
	if (ret != Z_OK || !zs->avail_out)
		return -EIO;

	clen = ZBUF_SIZE - 16 - zs->avail_out;
	rect_header(v->zbuf, nf->width, y, h, ENC_ZRLE);
	put_unaligned_be32(clen, v->zbuf + 12);
	return netfb_send_all(v->c->sock, v->zbuf, 16 + clen);
}

static u32 rows_per_chunk(const struct vnc *v)
{
	const struct netfb *nf = v->nf;
	u32 per;

	if (v->zrle) {
		per = max_t(u32, 1, ZRLE_CHUNK_BYTES / (nf->width * v->pf.cpix));
		if (per >= TILE)
			per &= ~(TILE - 1);	/* keep tiles aligned across chunks */
	} else {
		per = max_t(u32, 1, RAW_CHUNK_BYTES / (nf->width * (v->pf.bpp / 8)));
	}
	return per;
}

/* Sends the rows inside the requested area that changed. Returns <0 on error. */
static int vnc_send_update(struct vnc *v)
{
	struct netfb *nf = v->nf;
	u32 ry0[MAX_RUNS], ry1[MAX_RUNS];
	u32 y, y0 = v->req.y, y1 = min(nf->height, v->req.y + v->req.h);
	u32 per = rows_per_chunk(v), nrects = 0, nruns = 0, i, a;
	unsigned long flags;
	u8 hdr[4];
	u64 g;
	int ret;

	/* Sample under the lock so every version <= g is already in row_ver. */
	spin_lock_irqsave(&nf->lock, flags);
	g = nf->gen;
	spin_unlock_irqrestore(&nf->lock, flags);
	v->seen_gen = g;
	v->scan = false;

	for (y = y0; y < y1;) {
		u32 start, end, gap = 0;

		if (READ_ONCE(nf->row_ver[y]) <= v->sent[y]) {
			y++;
			continue;
		}
		start = end = y;
		for (; y < y1 && gap <= MERGE_GAP; y++) {
			if (READ_ONCE(nf->row_ver[y]) > v->sent[y]) {
				end = y;
				gap = 0;
			} else {
				gap++;
			}
		}
		if (nruns == MAX_RUNS) {
			ry1[nruns - 1] = end;		/* too fragmented: merge into the last run */
		} else {
			ry0[nruns] = start;
			ry1[nruns] = end;
			nruns++;
		}
		y = end + 1;
	}
	if (!nruns)
		return 0;			/* nothing new: keep the request pending */

	for (i = 0; i < nruns; i++)
		nrects += DIV_ROUND_UP(ry1[i] - ry0[i] + 1, per);

	hdr[0] = 0; hdr[1] = 0;
	put_unaligned_be16(nrects, hdr + 2);
	ret = netfb_send_all(v->c->sock, hdr, sizeof(hdr));
	if (ret)
		return ret;
	for (i = 0; i < nruns; i++) {
		for (a = ry0[i]; a <= ry1[i]; a += per) {
			u32 h = min(per, ry1[i] - a + 1);

			ret = v->zrle ? send_zrle(v, a, h) : send_raw(v, a, h);
			if (ret)
				return ret;
		}
	}
	v->pending = false;
	return 1;
}

/* ---- client messages ---------------------------------------------------- */

static int zlib_start(struct vnc *v)
{
	int ret;

	if (v->zinit)
		return 0;
	v->zs.workspace = vzalloc(zlib_deflate_workspacesize(MAX_WBITS, DEF_MEM_LEVEL));
	v->stage = kmalloc(1 + TILE * TILE * 4, GFP_KERNEL);
	v->zbuf = kvmalloc(ZBUF_SIZE, GFP_KERNEL);
	if (!v->zs.workspace || !v->stage || !v->zbuf)
		return -ENOMEM;
	ret = zlib_deflateInit2(&v->zs, Z_BEST_SPEED, Z_DEFLATED, MAX_WBITS,
				DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY);
	if (ret != Z_OK)
		return -EIO;
	v->zinit = true;
	return 0;
}

static int vnc_message(struct vnc *v, const u8 *m, size_t len)
{
	struct netfb *nf = v->nf;
	u32 x, y, w, h, i;
	unsigned int n;

	switch (m[0]) {
	case 0: {			/* SetPixelFormat */
		struct pixfmt *pf = &v->pf_new;

		memset(pf, 0, sizeof(*pf));
		pf->bpp = m[4];
		pf->be = m[6];
		if (!m[7])		/* colour-map formats are not supported */
			return -EPROTO;
		pf->max[0] = get_unaligned_be16(m + 8);
		pf->max[1] = get_unaligned_be16(m + 10);
		pf->max[2] = get_unaligned_be16(m + 12);
		pf->shift[0] = m[14]; pf->shift[1] = m[15]; pf->shift[2] = m[16];
		if (pf_setup(v, pf))
			return -EPROTO;
		v->pf = *pf;
		v->scan = true;
		for (i = 0; i < nf->height; i++)	/* the client's picture is stale now */
			v->sent[i] = 0;
		break;
	}
	case 2:				/* SetEncodings */
		n = get_unaligned_be16(m + 2);
		v->zrle = false;
		for (i = 0; i < n; i++)
			if ((s32)get_unaligned_be32(m + 4 + 4 * i) == ENC_ZRLE)
				v->zrle = true;
		if (v->zrle && zlib_start(v))
			return -ENOMEM;
		break;
	case 3:				/* FramebufferUpdateRequest */
		x = get_unaligned_be16(m + 2);
		y = get_unaligned_be16(m + 4);
		w = get_unaligned_be16(m + 6);
		h = get_unaligned_be16(m + 8);
		if (x >= nf->width || y >= nf->height || !w || !h)
			break;
		v->req.x = x;
		v->req.y = y;
		v->req.w = min(w, nf->width - x);
		v->req.h = min(h, nf->height - y);
		v->pending = true;
		v->scan = true;
		if (!m[1])		/* not incremental: the client wants this area again */
			for (i = y; i < y + v->req.h; i++)
				v->sent[i] = 0;
		break;
	case 4:				/* KeyEvent */
		vnc_key(v, get_unaligned_be32(m + 4), m[1]);
		break;
	case 5:				/* PointerEvent: there is no pointer device */
		break;
	case 6:				/* ClientCutText: header only, the text is skipped */
		n = get_unaligned_be32(m + 4);
		if (n > CUTTEXT_MAX)
			return -EPROTO;
		v->skip = n;
		break;
	}
	return 0;
}

static int vnc_parse(struct vnc *v)
{
	for (;;) {
		size_t need;

		if (v->skip) {
			size_t k = min_t(size_t, v->skip, v->rxlen);

			v->skip -= k;
			v->rxlen -= k;
			memmove(v->rx, v->rx + k, v->rxlen);
			if (v->skip)
				return 0;
		}
		if (!v->rxlen)
			return 0;
		switch (v->rx[0]) {
		case 0: need = 20; break;
		case 2:
			if (v->rxlen < 4)
				return 0;
			if (get_unaligned_be16(v->rx + 2) > MAX_ENCODINGS)
				return -EPROTO;
			need = 4 + 4 * (size_t)get_unaligned_be16(v->rx + 2);
			break;
		case 3: need = 10; break;
		case 4: need = 8; break;
		case 5: need = 6; break;
		case 6: need = 8; break;
		default: return -EPROTO;
		}
		if (v->rxlen < need)
			return 0;
		if (vnc_message(v, v->rx, need))
			return -EPROTO;
		v->rxlen -= need;
		memmove(v->rx, v->rx + need, v->rxlen);
	}
}

static int vnc_poll_rx(struct vnc *v)
{
	int round, ret;

	WRITE_ONCE(v->c->rx_pending, false);
	for (round = 0; round < 16; round++) {
		struct msghdr msg = {};
		struct kvec iov;
		int n;

		if (v->rxlen == RX_MAX)
			return -EPROTO;
		iov.iov_base = v->rx + v->rxlen;
		iov.iov_len = RX_MAX - v->rxlen;
		n = kernel_recvmsg(v->c->sock, &msg, &iov, 1, iov.iov_len, MSG_DONTWAIT);
		if (n == -EAGAIN)
			return 0;
		if (n < 0)
			return n;
		if (!n)
			return -ECONNRESET;
		v->rxlen += n;
		ret = vnc_parse(v);
		if (ret)
			return ret;
	}
	WRITE_ONCE(v->c->rx_pending, true);
	return 0;
}

/* ---- session ------------------------------------------------------------ */

void netfb_vnc_run(struct netfb_conn *c)
{
	struct netfb *nf = c->nf;
	struct vnc *v;
	int ret;

	v = kzalloc(sizeof(*v), GFP_KERNEL);
	if (!v)
		return;
	v->c = c;
	v->nf = nf;
	if (netfb_auth_locked(c->srv, c->peer)) {
		pr_info_ratelimited("%pI4 vnc refused: locked out after failed logins\n", &c->peer);
		goto out;
	}
	v->interval = max(1ul, msecs_to_jiffies(1000 / netfb_srv_max_fps(c->srv)));
	pf_set_native(v);

	ret = vnc_handshake(v);
	if (ret) {
		if (ret != -ECANCELED && ret != -ECONNRESET)
			pr_info("%pI4 vnc handshake failed: %d\n", &c->peer, ret);
		goto out;
	}

	v->sent = kvcalloc(nf->height, sizeof(*v->sent), GFP_KERNEL);
	v->tx = kvmalloc(12 + RAW_CHUNK_BYTES, GFP_KERNEL);
	if (!v->sent || !v->tx)
		goto out;

	pr_info("%pI4 vnc connected\n", &c->peer);
	netfb_conn_hook_rx(c);

	while (!kthread_should_stop() && !netfb_srv_stopping(c->srv)) {
		wait_event_interruptible_timeout(nf->wq,
			(v->pending && (v->scan || READ_ONCE(nf->gen) != v->seen_gen)) ||
			READ_ONCE(c->rx_pending) ||
			kthread_should_stop() || netfb_srv_stopping(c->srv),
			msecs_to_jiffies(WAIT_MS));
		if (kthread_should_stop() || netfb_srv_stopping(c->srv))
			break;
		if (vnc_poll_rx(v))
			break;

		if (v->pending && (v->scan || READ_ONCE(nf->gen) != v->seen_gen)) {
			ret = vnc_send_update(v);
			if (ret < 0)
				break;
			if (ret > 0)	/* rate limit; client input still cuts it short */
				wait_event_interruptible_timeout(nf->wq,
					READ_ONCE(c->rx_pending) || kthread_should_stop() ||
					netfb_srv_stopping(c->srv), v->interval);
		}
	}
	pr_info("%pI4 vnc disconnected\n", &c->peer);
out:
	netfb_conn_unhook_rx(c);
	k_release_all(v);
	if (v->zinit)
		zlib_deflateEnd(&v->zs);
	vfree(v->zs.workspace);
	kfree(v->stage);
	kvfree(v->zbuf);
	kvfree(v->tx);
	kvfree(v->sent);
	kfree(v);
}
