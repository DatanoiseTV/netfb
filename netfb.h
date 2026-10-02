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
 *   u8     flags     0
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
#define NETFB_MSG_HDR_LEN	8
#define NETFB_MAX_DIM		8192
#define NETFB_MAX_ROWBYTES	32768
#define NETFB_MAX_VMEM		(64u << 20)
#define NETFB_WS_PAYLOAD_MAX	60000

struct netfb_server;

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

	struct netfb_server *srv;
};

struct netfb_net_cfg {
	__be32 addr;
	u16 port;
	const char *token;	/* NULL or empty: no authentication */
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
};

/* netfb_fb.c */
void netfb_damage_rows(struct netfb *nf, u32 y0, u32 y1);

/* netfb_net.c */
int netfb_net_start(struct netfb *nf, const struct netfb_net_cfg *cfg);
void netfb_net_stop(struct netfb *nf);
int netfb_send_all(struct socket *sock, const void *buf, size_t len);
int netfb_info_json(const struct netfb *nf, unsigned int max_fps, char *buf,
		    size_t size);
unsigned int netfb_srv_max_fps(const struct netfb_server *srv);

/* netfb_ws.c */
void netfb_ws_run(struct netfb_conn *c);

/* netfb_web.c */
extern const u8 netfb_web_gz[];
extern const u8 netfb_web_gz_end[];

#endif /* NETFB_H */
