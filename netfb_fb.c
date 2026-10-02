// SPDX-License-Identifier: GPL-2.0-only
/*
 * netfb - a virtual fbdev framebuffer that is exported over the network
 *
 * This file is the framebuffer side: a vmalloc'ed, mmap-able fbdev device
 * with deferred I/O so that every way of drawing (write(), mmap(), fbcon,
 * fillrect/copyarea/imageblit) is turned into per-row damage records. The
 * HTTP/WebSocket side lives in netfb_net.c and netfb_ws.c.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fb.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "netfb.h"

static unsigned int width = 800;
module_param(width, uint, 0444);
MODULE_PARM_DESC(width, "Framebuffer width in pixels (default 800)");

static unsigned int height = 600;
module_param(height, uint, 0444);
MODULE_PARM_DESC(height, "Framebuffer height in pixels (default 600)");

static unsigned int bpp = 32;
module_param(bpp, uint, 0444);
MODULE_PARM_DESC(bpp, "Bits per pixel: 16 (RGB565) or 32 (XRGB8888), default 32");

static char *bind_addr = "127.0.0.1";
module_param(bind_addr, charp, 0444);
MODULE_PARM_DESC(bind_addr, "IPv4 address to listen on (default 127.0.0.1)");

static unsigned short port = 8080;
module_param(port, ushort, 0444);
MODULE_PARM_DESC(port, "TCP port to listen on (default 8080)");

/* Permission 0: not exported in sysfs, so the token is not world-readable. */
static char *token;
module_param(token, charp, 0);
MODULE_PARM_DESC(token, "Access token, 16-128 chars of [A-Za-z0-9._~-]. Required unless bind_addr is loopback");

static bool allow_insecure;
module_param(allow_insecure, bool, 0444);
MODULE_PARM_DESC(allow_insecure, "Permit a non-loopback bind_addr without a token");

static unsigned int max_clients = 8;
module_param(max_clients, uint, 0444);
MODULE_PARM_DESC(max_clients, "Maximum concurrent connections, 1-64 (default 8)");

static unsigned int max_fps = 30;
module_param(max_fps, uint, 0444);
MODULE_PARM_DESC(max_fps, "Maximum update rate per client, 1-120 (default 30)");

static struct netfb *netfb_dev;
static struct platform_device *netfb_pdev;

/* ---- damage tracking ---------------------------------------------------- */

void netfb_damage_rows(struct netfb *nf, u32 y0, u32 y1)
{
	unsigned long flags;
	u64 g;
	u32 y;

	if (y0 >= nf->height)
		return;
	if (y1 >= nf->height)
		y1 = nf->height - 1;
	if (y1 < y0)
		return;

	spin_lock_irqsave(&nf->lock, flags);
	g = ++nf->gen;
	for (y = y0; y <= y1; y++)
		nf->row_ver[y] = g;
	spin_unlock_irqrestore(&nf->lock, flags);

	wake_up_interruptible(&nf->wq);
}

static void netfb_damage_range(struct fb_info *info, off_t off, size_t len)
{
	struct netfb *nf = info->par;

	if (off < 0 || !len)
		return;
	netfb_damage_rows(nf, off / nf->rowbytes,
			  (off + len - 1) / nf->rowbytes);
}

static void netfb_damage_area(struct fb_info *info, u32 x, u32 y, u32 w, u32 h)
{
	if (!w || !h)
		return;
	netfb_damage_rows(info->par, y, y + h - 1);
}

/* mmap() writers: called from the deferred-io worker with the dirty pages. */
static void netfb_deferred_io(struct fb_info *info, struct list_head *pagereflist)
{
	struct fb_deferred_io_pageref *ref;

	list_for_each_entry(ref, pagereflist, list)
		netfb_damage_range(info, ref->offset, PAGE_SIZE);
}

static struct fb_deferred_io netfb_defio = {
	.delay		= HZ / 60 ? HZ / 60 : 1,
	.deferred_io	= netfb_deferred_io,
};

/* ---- fb_ops ------------------------------------------------------------- */

FB_GEN_DEFAULT_DEFERRED_SYSMEM_OPS(netfb, netfb_damage_range, netfb_damage_area)

static int netfb_setcolreg(unsigned int regno, unsigned int red,
			   unsigned int green, unsigned int blue,
			   unsigned int transp, struct fb_info *info)
{
	u32 *pal = info->pseudo_palette;

	if (regno >= 16)
		return -EINVAL;

	pal[regno] = ((red >> (16 - info->var.red.length)) << info->var.red.offset) |
		     ((green >> (16 - info->var.green.length)) << info->var.green.offset) |
		     ((blue >> (16 - info->var.blue.length)) << info->var.blue.offset);
	return 0;
}

/* The mode is fixed: the network protocol announces it once per connection. */
static int netfb_check_var(struct fb_var_screeninfo *var, struct fb_info *info)
{
	if (var->xres != info->var.xres || var->yres != info->var.yres ||
	    var->bits_per_pixel != info->var.bits_per_pixel)
		return -EINVAL;

	var->xres_virtual = var->xres;
	var->yres_virtual = var->yres;
	var->xoffset = 0;
	var->yoffset = 0;
	var->red = info->var.red;
	var->green = info->var.green;
	var->blue = info->var.blue;
	var->transp = info->var.transp;
	return 0;
}

static const struct fb_ops netfb_ops = {
	.owner		= THIS_MODULE,
	FB_DEFAULT_DEFERRED_OPS(netfb),
	.fb_setcolreg	= netfb_setcolreg,
	.fb_check_var	= netfb_check_var,
};

/* ---- module ------------------------------------------------------------- */

static bool netfb_token_valid(const char *t)
{
	size_t n = strlen(t);

	if (n < 16 || n > 128)
		return false;
	for (; *t; t++) {
		if (!isalnum(*t) && !strchr("._~-", *t))
			return false;
	}
	return true;
}

static int netfb_check_params(struct netfb_net_cfg *cfg)
{
	u8 a[4];

	if (width < 16 || width > NETFB_MAX_DIM ||
	    height < 16 || height > NETFB_MAX_DIM) {
		pr_err("width/height must be 16..%d\n", NETFB_MAX_DIM);
		return -EINVAL;
	}
	if (bpp != 16 && bpp != 32) {
		pr_err("bpp must be 16 or 32\n");
		return -EINVAL;
	}
	if (width * bpp / 8 > NETFB_MAX_ROWBYTES ||
	    (u64)width * height * bpp / 8 > NETFB_MAX_VMEM) {
		pr_err("mode too large (max row %d bytes, max %u MiB)\n",
		       NETFB_MAX_ROWBYTES, NETFB_MAX_VMEM >> 20);
		return -EINVAL;
	}
	if (max_clients < 1 || max_clients > 64 || max_fps < 1 || max_fps > 120) {
		pr_err("max_clients must be 1..64 and max_fps 1..120\n");
		return -EINVAL;
	}
	if (!in4_pton(bind_addr, -1, a, -1, NULL)) {
		pr_err("bind_addr '%s' is not an IPv4 address\n", bind_addr);
		return -EINVAL;
	}
	memcpy(&cfg->addr, a, 4);

	if (token && *token) {
		if (!netfb_token_valid(token)) {
			pr_err("token must be 16-128 chars of [A-Za-z0-9._~-]\n");
			return -EINVAL;
		}
		cfg->token = token;
	} else {
		cfg->token = NULL;
	}

	if (!cfg->token && !ipv4_is_loopback(cfg->addr) && !allow_insecure) {
		pr_err("refusing to expose the framebuffer on %s without a token (set token=, or allow_insecure=1)\n",
		       bind_addr);
		return -EPERM;
	}

	cfg->port = port;
	cfg->max_clients = max_clients;
	cfg->max_fps = max_fps;
	return 0;
}

static void netfb_setup_var(struct fb_var_screeninfo *var)
{
	var->xres = var->xres_virtual = width;
	var->yres = var->yres_virtual = height;
	var->bits_per_pixel = bpp;
	var->activate = FB_ACTIVATE_NOW;
	var->height = var->width = -1;
	var->vmode = FB_VMODE_NONINTERLACED;
	var->pixclock = 0;

	if (bpp == 16) {
		var->red = (struct fb_bitfield){ .offset = 11, .length = 5 };
		var->green = (struct fb_bitfield){ .offset = 5, .length = 6 };
		var->blue = (struct fb_bitfield){ .offset = 0, .length = 5 };
	} else {
		var->red = (struct fb_bitfield){ .offset = 16, .length = 8 };
		var->green = (struct fb_bitfield){ .offset = 8, .length = 8 };
		var->blue = (struct fb_bitfield){ .offset = 0, .length = 8 };
	}
}

static int __init netfb_init(void)
{
	struct netfb_net_cfg cfg;
	struct fb_info *info;
	struct netfb *nf;
	int ret;

	ret = netfb_check_params(&cfg);
	if (ret)
		return ret;

	nf = kzalloc(sizeof(*nf), GFP_KERNEL);
	if (!nf)
		return -ENOMEM;
	spin_lock_init(&nf->lock);
	init_waitqueue_head(&nf->wq);
	nf->width = width;
	nf->height = height;
	nf->bpp = bpp;
	nf->rowbytes = width * bpp / 8;
	nf->vmem_len = PAGE_ALIGN((size_t)nf->rowbytes * height);

	ret = -ENOMEM;
	nf->vmem = vzalloc(nf->vmem_len);
	nf->row_ver = kvcalloc(height, sizeof(*nf->row_ver), GFP_KERNEL);
	if (!nf->vmem || !nf->row_ver)
		goto err_free;

	/* A new client must receive the whole (initially black) frame. */
	nf->gen = 1;
	memset64(nf->row_ver, 1, height);

	netfb_pdev = platform_device_register_simple(KBUILD_MODNAME,
						     PLATFORM_DEVID_NONE, NULL, 0);
	if (IS_ERR(netfb_pdev)) {
		ret = PTR_ERR(netfb_pdev);
		goto err_free;
	}

	info = framebuffer_alloc(0, &netfb_pdev->dev);
	if (!info) {
		ret = -ENOMEM;
		goto err_pdev;
	}
	nf->info = info;
	info->par = nf;
	info->fbops = &netfb_ops;
	info->screen_buffer = nf->vmem;
	info->screen_size = nf->vmem_len;
	info->pseudo_palette = nf->palette;
	info->flags = FBINFO_VIRTFB;
	info->fbdefio = &netfb_defio;

	strscpy(info->fix.id, "netfb", sizeof(info->fix.id));
	info->fix.type = FB_TYPE_PACKED_PIXELS;
	info->fix.visual = FB_VISUAL_TRUECOLOR;
	info->fix.accel = FB_ACCEL_NONE;
	info->fix.line_length = nf->rowbytes;
	info->fix.smem_len = nf->vmem_len;
	netfb_setup_var(&info->var);

	ret = fb_deferred_io_init(info);
	if (ret)
		goto err_info;

	ret = register_framebuffer(info);
	if (ret < 0)
		goto err_defio;

	ret = netfb_net_start(nf, &cfg);
	if (ret)
		goto err_unreg;

	netfb_dev = nf;
	pr_info("fb%d: %ux%u@%u, serving on http://%pI4:%u/%s\n", info->node,
		width, height, bpp, &cfg.addr, cfg.port,
		cfg.token ? " (token required)" : "");
	return 0;

err_unreg:
	unregister_framebuffer(info);
err_defio:
	fb_deferred_io_cleanup(info);
err_info:
	framebuffer_release(info);
err_pdev:
	platform_device_unregister(netfb_pdev);
err_free:
	kvfree(nf->row_ver);
	vfree(nf->vmem);
	kfree(nf);
	return ret;
}

static void __exit netfb_exit(void)
{
	struct netfb *nf = netfb_dev;
	struct fb_info *info = nf->info;

	/* No connection may touch the framebuffer once it is torn down. */
	netfb_net_stop(nf);
	unregister_framebuffer(info);
	fb_deferred_io_cleanup(info);
	framebuffer_release(info);
	platform_device_unregister(netfb_pdev);
	kvfree(nf->row_ver);
	vfree(nf->vmem);
	kfree(nf);
}

module_init(netfb_init);
module_exit(netfb_exit);

MODULE_DESCRIPTION("fbdev framebuffer exported over HTTP/WebSocket with a web UI");
MODULE_AUTHOR("DatanoiseTV");
MODULE_LICENSE("GPL");
