/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NETFB_H
#define NETFB_H

#include <linux/fb.h>
#include <linux/list.h>
#include <linux/net.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>

/*
 * Wire format of a pixel update (WebSocket binary message payload):
 *
 *   u8     type      1 = pixel rows
 *   u8     flags     bit 0: data[] is one LZ4 block (kernel LZ4_compress_default
 *                    output, i.e. the standard LZ4 block format, no frame) that
 *                    decompresses to exactly h * width * bytes_per_pixel bytes.
 *                    Cleared: data[] is the raw rows.
 *   __le16 y         first row
 *   __le16 h         number of rows
 *   __le16 reserved  0
 *   u8     data[]    h * width * bytes_per_pixel, rows tightly packed, native
 *                    framebuffer pixel format (see the "info" text message)
 *
 * Width, height and format are fixed for the lifetime of the module.
 * Limits enforced at load time so that every message payload fits the 16 bit
 * WebSocket length form and a row never exceeds a message.
 */
#define NETFB_MSG_PIXELS	1
#define NETFB_MSG_F_LZ4		0x01
#define NETFB_MSG_HDR_LEN	8
#define NETFB_MAX_DIM		8192
#define NETFB_MAX_ROWBYTES	32768
#define NETFB_MAX_VMEM		(64u << 20)
#define NETFB_WS_PAYLOAD_MAX	60000

struct netfb_server;
struct sock;

struct netfb {
	struct fb_info *info;
	void *vmem;
	size_t vmem_len;
	u32 width, height, bpp;
	u32 rowbytes;
	u32 palette[16];

	/*
	 * Damage tracking. row_ver[y] holds the value of @gen at the last
	 * change of row y. Both are written under @lock, and a reader samples
	 * @gen under @lock before scanning, so any row with a version <= the
	 * sampled generation is guaranteed to be visible in row_ver.
	 */
	spinlock_t lock;
	u64 gen;
	u64 *row_ver;
	wait_queue_head_t wq;

	struct input_dev *kbd;	/* NULL unless keyboard=1 */

	struct netfb_server *srv;
};

#define NETFB_MAX_KEYCODE	256

enum netfb_proto {
	NETFB_PROTO_HTTP,
	NETFB_PROTO_VNC,
	NETFB_PROTO_MAX,
};

struct netfb_net_cfg {
	__be32 addr;
	u16 port;
	const char *token;	/* NULL or empty: no authentication */
	u16 vnc_port;		/* 0: no VNC listener */
	const char *vnc_password; /* NULL: RFB security type "None" */
	unsigned int vnc_lockout; /* seconds a source is locked out after repeated failed logins; 0: off */
	unsigned int max_clients;
	unsigned int max_fps;
};

struct netfb_conn {
	struct netfb *nf;
	struct netfb_server *srv;
	struct socket *sock;
	struct task_struct *task;
	struct list_head node;
	__be32 peer;
	atomic_t done;
	enum netfb_proto proto;
	bool rx_pending;	/* set by sk_data_ready: the client sent something */
	void (*old_data_ready)(struct sock *sk);
};

/* netfb_fb.c */
void netfb_damage_rows(struct netfb *nf, u32 y0, u32 y1);
void netfb_key(struct netfb *nf, unsigned int code, bool down);

/* netfb_net.c */
int netfb_net_start(struct netfb *nf, const struct netfb_net_cfg *cfg);
void netfb_net_stop(struct netfb *nf);
int netfb_send_all(struct socket *sock, const void *buf, size_t len);
int netfb_info_json(const struct netfb *nf, unsigned int max_fps, char *buf,
		    size_t size);
unsigned int netfb_srv_max_fps(const struct netfb_server *srv);
const char *netfb_srv_vnc_password(const struct netfb_server *srv);
bool netfb_auth_locked(struct netfb_server *srv, __be32 ip);
void netfb_auth_failed(struct netfb_server *srv, __be32 ip);
void netfb_auth_ok(struct netfb_server *srv, __be32 ip);
void netfb_conn_hook_rx(struct netfb_conn *c);
void netfb_conn_unhook_rx(struct netfb_conn *c);
bool netfb_srv_stopping(const struct netfb_server *srv);

/* netfb_ws.c */
void netfb_ws_run(struct netfb_conn *c);

/* netfb_vnc.c */
void netfb_vnc_run(struct netfb_conn *c);

/* netfb_web.c */
extern const u8 netfb_web_gz[];
extern const u8 netfb_web_gz_end[];

#endif /* NETFB_H */
