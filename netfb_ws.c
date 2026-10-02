// SPDX-License-Identifier: GPL-2.0-only
/*
 * WebSocket session for netfb (RFC 6455, server side).
 *
 * The session is a polling loop on one thread: wait for framebuffer damage,
 * send the changed rows, then drain whatever control frames the browser has
 * sent. There is no per-client queue: every update is read from the live
 * framebuffer at send time, so a slow client simply receives fewer, larger
 * updates instead of building a backlog.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#if __has_include(<linux/unaligned.h>)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <net/sock.h>

#include "netfb.h"

/* Unchanged rows between two dirty rows that are still sent in one message. */
#define MERGE_GAP	8
#define WAIT_MS		200
#define RX_BUF		256
#define WS_HDR_LEN	4	/* every pixel message uses the 16 bit length form */

#define WS_OP_CONT	0x0
#define WS_OP_TEXT	0x1
#define WS_OP_BIN	0x2
#define WS_OP_CLOSE	0x8
#define WS_OP_PING	0x9
#define WS_OP_PONG	0xa

struct ws {
	struct netfb_conn *c;
	struct netfb *nf;
	u8 *tx;			/* WS_HDR_LEN + NETFB_MSG_HDR_LEN + pixels */
	u8 rx[RX_BUF];
	size_t rxlen;
	u64 last;		/* last generation sent to this client */
	bool paused;
	unsigned long interval;	/* min jiffies between updates */
	unsigned int fps_cap;
	DECLARE_BITMAP(keys, NETFB_MAX_KEYCODE);	/* keys this client holds down */
};

/* ---- sending ------------------------------------------------------------ */

/* Control and small text frames. Server frames are never masked. */
static int ws_send_small(struct socket *sock, u8 opcode, const void *p, size_t n)
{
	u8 buf[4 + 512];
	size_t hl;

	if (n > 512)
		return -EMSGSIZE;
	buf[0] = 0x80 | opcode;
	if (n < 126) {
		buf[1] = n;
		hl = 2;
	} else {
		buf[1] = 126;
		put_unaligned_be16(n, buf + 2);
		hl = 4;
	}
	memcpy(buf + hl, p, n);
	return netfb_send_all(sock, buf, hl + n);
}

static int ws_close(struct netfb_conn *c, u16 code)
{
	__be16 be = cpu_to_be16(code);

	ws_send_small(c->sock, WS_OP_CLOSE, &be, sizeof(be));
	return -ECONNRESET;
}

/* One contiguous band of rows, which must fit one message. */
static int ws_send_rows(struct ws *w, u32 y, u32 h)
{
	struct netfb *nf = w->nf;
	u8 *msg = w->tx + WS_HDR_LEN;
	size_t plen = NETFB_MSG_HDR_LEN + (size_t)h * nf->rowbytes;

	w->tx[0] = 0x80 | WS_OP_BIN;
	w->tx[1] = 126;
	put_unaligned_be16(plen, w->tx + 2);

	msg[0] = NETFB_MSG_PIXELS;
	msg[1] = 0;
	put_unaligned_le16(y, msg + 2);
	put_unaligned_le16(h, msg + 4);
	put_unaligned_le16(0, msg + 6);
	memcpy(msg + NETFB_MSG_HDR_LEN, nf->vmem + (size_t)y * nf->rowbytes,
	       (size_t)h * nf->rowbytes);

	return netfb_send_all(w->c->sock, w->tx, WS_HDR_LEN + plen);
}

/* Send every row whose version is newer than w->last, in bounded chunks. */
static int ws_send_dirty(struct ws *w)
{
	struct netfb *nf = w->nf;
	u32 per_msg = (NETFB_WS_PAYLOAD_MAX - NETFB_MSG_HDR_LEN) / nf->rowbytes;
	u32 y = 0;
	int ret;

	while (y < nf->height) {
		u32 y0, yend, gap = 0;

		if (READ_ONCE(nf->row_ver[y]) <= w->last) {
			y++;
			continue;
		}

		y0 = yend = y;
		for (; y < nf->height && gap <= MERGE_GAP; y++) {
			if (READ_ONCE(nf->row_ver[y]) > w->last) {
				yend = y;
				gap = 0;
			} else {
				gap++;
			}
		}

		for (y = y0; y <= yend; y += per_msg) {
			u32 h = min(per_msg, yend - y + 1);

			ret = ws_send_rows(w, y, h);
			if (ret)
				return ret;
		}
		y = yend + 1;
	}
	return 0;
}

/* ---- receiving ---------------------------------------------------------- */

static void ws_set_interval(struct ws *w, unsigned int fps)
{
	w->fps_cap = clamp(fps, 1u, netfb_srv_max_fps(w->c->srv));
	w->interval = max(1ul, msecs_to_jiffies(1000 / w->fps_cap));
}

/* Text commands: "pause", "resume", "full", "fps <n>", "key <code> <0|1>". */
static void ws_command(struct ws *w, const char *cmd)
{
	unsigned int n;

	if (!strcmp(cmd, "pause")) {
		w->paused = true;
	} else if (!strcmp(cmd, "resume")) {
		w->paused = false;
	} else if (!strcmp(cmd, "full")) {
		w->last = 0;
	} else if (!strncmp(cmd, "key ", 4)) {
		unsigned int code, down;

		if (sscanf(cmd + 4, "%u %u", &code, &down) != 2 ||
		    code == 0 || code >= NETFB_MAX_KEYCODE || down > 1)
			return;
		/* Track holds so a dropped connection cannot leave a key stuck. */
		__assign_bit(code, w->keys, down);
		netfb_key(w->nf, code, down);
	} else if (!strncmp(cmd, "fps ", 4) && !kstrtouint(cmd + 4, 10, &n)) {
		ws_set_interval(w, n);
	}
	/* Unknown commands are ignored so the UI can be newer than the module. */
}

/* Parse every complete frame in w->rx. Returns <0 to end the session. */
static int ws_parse_rx(struct ws *w)
{
	struct netfb_conn *c = w->c;

	while (w->rxlen >= 2) {
		u8 b0 = w->rx[0], b1 = w->rx[1];
		u8 op = b0 & 0xf;
		bool fin = b0 & 0x80;
		size_t plen = b1 & 0x7f, hl = 2, total, i;
		u8 *mask, *data;
		char cmd[64];

		if ((b0 & 0x70) || !(b1 & 0x80))	/* RSV bits / unmasked */
			return ws_close(c, 1002);
		if (plen == 127)
			return ws_close(c, 1009);
		if (plen == 126) {
			if (w->rxlen < 4)
				break;
			plen = get_unaligned_be16(w->rx + 2);
			hl = 4;
		}
		if (op >= WS_OP_CLOSE && (plen > 125 || !fin))
			return ws_close(c, 1002);

		total = hl + 4 + plen;
		if (total > RX_BUF)
			return ws_close(c, 1009);
		if (w->rxlen < total)
			break;

		mask = w->rx + hl;
		data = mask + 4;
		for (i = 0; i < plen; i++)
			data[i] ^= mask[i & 3];

		switch (op) {
		case WS_OP_CLOSE:
			ws_send_small(c->sock, WS_OP_CLOSE, data, min_t(size_t, plen, 2));
			return -ECONNRESET;
		case WS_OP_PING:
			if (ws_send_small(c->sock, WS_OP_PONG, data, plen))
				return -EPIPE;
			break;
		case WS_OP_PONG:
			break;
		case WS_OP_TEXT:
			if (!fin)
				return ws_close(c, 1003);
			/*
			 * Copy out: terminating in place would clobber the first
			 * byte of the next frame when several share one recv().
			 */
			if (plen < sizeof(cmd)) {
				memcpy(cmd, data, plen);
				cmd[plen] = '\0';
				ws_command(w, cmd);
			}
			break;
		case WS_OP_BIN:
		case WS_OP_CONT:
			return ws_close(c, 1003);	/* data we do not accept */
		default:				/* reserved opcode */
			return ws_close(c, 1002);
		}

		w->rxlen -= total;
		memmove(w->rx, w->rx + total, w->rxlen);
	}
	return 0;
}

static int ws_poll_rx(struct ws *w)
{
	struct msghdr msg = {};
	struct kvec iov;
	int n;

	if (w->rxlen == RX_BUF)
		return ws_close(w->c, 1009);

	iov.iov_base = w->rx + w->rxlen;
	iov.iov_len = RX_BUF - w->rxlen;
	n = kernel_recvmsg(w->c->sock, &msg, &iov, 1, iov.iov_len, MSG_DONTWAIT);
	if (n == -EAGAIN)
		return 0;
	if (n < 0)
		return n;
	if (!n)
		return -ECONNRESET;
	w->rxlen += n;
	return ws_parse_rx(w);
}

/* ---- session ------------------------------------------------------------ */

void netfb_ws_run(struct netfb_conn *c)
{
	struct netfb *nf = c->nf;
	struct ws *w;
	char json[320];
	unsigned long flags;
	int n;

	w = kzalloc(sizeof(*w), GFP_KERNEL);
	if (!w)
		return;
	w->tx = kvmalloc(WS_HDR_LEN + NETFB_WS_PAYLOAD_MAX, GFP_KERNEL);
	if (!w->tx)
		goto out;
	w->c = c;
	w->nf = nf;
	ws_set_interval(w, netfb_srv_max_fps(c->srv));

	n = netfb_info_json(nf, netfb_srv_max_fps(c->srv), json, sizeof(json));
	if (ws_send_small(c->sock, WS_OP_TEXT, json, n))
		goto out;

	while (!kthread_should_stop() && !netfb_srv_stopping(c->srv)) {
		if (w->paused) {
			schedule_timeout_interruptible(msecs_to_jiffies(100));
		} else {
			wait_event_interruptible_timeout(nf->wq,
				READ_ONCE(nf->gen) != w->last ||
				kthread_should_stop() || netfb_srv_stopping(c->srv),
				msecs_to_jiffies(WAIT_MS));
			if (kthread_should_stop() || netfb_srv_stopping(c->srv))
				break;
		}
		if (ws_poll_rx(w))
			goto out;

		if (!w->paused && READ_ONCE(nf->gen) != w->last) {
			u64 g;

			/* Sample under the lock so every version <= g is in row_ver. */
			spin_lock_irqsave(&nf->lock, flags);
			g = nf->gen;
			spin_unlock_irqrestore(&nf->lock, flags);

			if (ws_send_dirty(w))
				goto out;
			w->last = g;
			/* Rate limit; also coalesces bursts of small damage. */
			schedule_timeout_interruptible(w->interval);
		}
	}
	ws_close(c, 1001);	/* going away: module unload */
out:
	for_each_set_bit(n, w->keys, NETFB_MAX_KEYCODE)
		netfb_key(nf, n, false);
	kvfree(w->tx);
	kfree(w);
}
