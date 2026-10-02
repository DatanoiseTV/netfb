// SPDX-License-Identifier: GPL-2.0-only
/*
 * Minimal HTTP/1.1 server for netfb: one accept thread, one kthread per
 * connection, no keep-alive. Routes:
 *
 *   GET /          the embedded web UI (public, static)
 *   GET /api/info  JSON description of the framebuffer      (token)
 *   GET /ws        WebSocket pixel stream                   (token + Origin)
 *
 * Everything here parses bytes from the network, so every length is bounded
 * before use, every blocking call has a timeout, and the request head is
 * limited both in size and in wall-clock time.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <crypto/hash.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/in.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/version.h>
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#if __has_include(<crypto/utils.h>)
#include <crypto/utils.h>
#else
#include <crypto/algapi.h>
#endif

#include "netfb.h"

#define HTTP_HEAD_MAX		4096
#define HTTP_TARGET_MAX		512
#define HTTP_HEAD_DEADLINE	(10 * HZ)
#define HTTP_RCV_TIMEOUT	(5 * HZ)
#define HTTP_SND_TIMEOUT	(10 * HZ)
#define ACCEPT_POLL		(HZ / 2)

/* Linux 6.19 changed kernel_bind() to take struct sockaddr_unsized. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)
#define netfb_sockaddr struct sockaddr_unsized
#else
#define netfb_sockaddr struct sockaddr
#endif

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/*
 * Sent with every response. The UI is one self-contained document, so the
 * policy can be strict: no third-party origins, no framing, no sniffing.
 */
#define SEC_HEADERS \
	"X-Content-Type-Options: nosniff\r\n" \
	"X-Frame-Options: DENY\r\n" \
	"Referrer-Policy: no-referrer\r\n" \
	"Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; " \
	"style-src 'unsafe-inline'; img-src data: blob:; connect-src 'self' ws: wss:; " \
	"base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n"

struct netfb_server {
	struct netfb *nf;
	struct netfb_net_cfg cfg;
	char *token;
	size_t toklen;
	struct crypto_shash *sha1;
	struct socket *listen;
	struct task_struct *accept_task;
	struct mutex lock;		/* protects conns, nconns */
	struct list_head conns;
	unsigned int nconns;
};

unsigned int netfb_srv_max_fps(const struct netfb_server *srv)
{
	return srv->cfg.max_fps;
}

/* ---- socket helpers ----------------------------------------------------- */

int netfb_send_all(struct socket *sock, const void *buf, size_t len)
{
	struct msghdr msg = { .msg_flags = MSG_NOSIGNAL };
	struct kvec iov;
	int n;

	while (len) {
		iov.iov_base = (void *)buf;
		iov.iov_len = len;
		n = kernel_sendmsg(sock, &msg, &iov, 1, len);
		if (n < 0)
			return n;
		if (!n)
			return -EPIPE;
		buf += n;
		len -= n;
	}
	return 0;
}

int netfb_info_json(const struct netfb *nf, unsigned int max_fps, char *buf,
		    size_t size)
{
	const struct fb_var_screeninfo *v = &nf->info->var;

	return scnprintf(buf, size,
		"{\"type\":\"info\",\"name\":\"netfb\",\"width\":%u,\"height\":%u,"
		"\"bpp\":%u,\"stride\":%u,\"red\":[%u,%u],\"green\":[%u,%u],"
		"\"blue\":[%u,%u],\"max_fps\":%u}",
		nf->width, nf->height, nf->bpp, nf->rowbytes,
		v->red.offset, v->red.length, v->green.offset, v->green.length,
		v->blue.offset, v->blue.length, max_fps);
}

/* ---- HTTP request parsing ----------------------------------------------- */

struct http_req {
	char *method;
	char *path;
	char *query;	/* NULL if the target has no '?' */
	char *hdrs;	/* first header line, headers end at the blank line */
};

/*
 * Receive until the blank line that ends the head. Bounded in size, in time
 * (so a slow-loris client cannot hold a slot) and aborted on module unload.
 */
static int http_read_head(struct socket *sock, char *buf, size_t max)
{
	unsigned long deadline = jiffies + HTTP_HEAD_DEADLINE;
	size_t len = 0;

	while (len < max) {
		struct msghdr msg = {};
		struct kvec iov = { .iov_base = buf + len, .iov_len = max - len };
		size_t from = len > 3 ? len - 3 : 0;
		int n;

		if (kthread_should_stop())
			return -ECANCELED;
		n = kernel_recvmsg(sock, &msg, &iov, 1, iov.iov_len, 0);
		if (n == -EAGAIN)
			return -ETIMEDOUT;
		if (n < 0)
			return n;
		if (!n)
			return -ECONNRESET;
		len += n;
		buf[len] = '\0';
		if (strstr(buf + from, "\r\n\r\n"))
			return 0;
		if (time_after(jiffies, deadline))
			return -ETIMEDOUT;
	}
	return -E2BIG;
}

static int http_parse(char *buf, struct http_req *r)
{
	char *sp, *eol;

	eol = strstr(buf, "\r\n");
	if (!eol)
		return -EINVAL;
	*eol = '\0';
	r->hdrs = eol + 2;

	r->method = buf;
	sp = strchr(buf, ' ');
	if (!sp)
		return -EINVAL;
	*sp++ = '\0';
	r->path = sp;
	sp = strchr(sp, ' ');
	if (!sp)
		return -EINVAL;
	*sp++ = '\0';
	if (strncmp(sp, "HTTP/1.", 7))
		return -EINVAL;
	if (strlen(r->path) > HTTP_TARGET_MAX || r->path[0] != '/')
		return -EINVAL;

	r->query = strchr(r->path, '?');
	if (r->query)
		*r->query++ = '\0';
	return 0;
}

/* Value of header @name (case-insensitive), not NUL-terminated. */
static const char *hdr_find(const struct http_req *r, const char *name,
			    size_t *vlen)
{
	size_t nlen = strlen(name);
	const char *p = r->hdrs;

	while (*p && !(p[0] == '\r' && p[1] == '\n')) {
		const char *eol = strstr(p, "\r\n");
		const char *v, *e;

		if (!eol)
			break;
		if (!strncasecmp(p, name, nlen) && p[nlen] == ':') {
			v = p + nlen + 1;
			while (v < eol && (*v == ' ' || *v == '\t'))
				v++;
			e = eol;
			while (e > v && (e[-1] == ' ' || e[-1] == '\t'))
				e--;
			*vlen = e - v;
			return v;
		}
		p = eol + 2;
	}
	return NULL;
}

static bool hdr_has_token(const char *v, size_t n, const char *tok)
{
	size_t tl = strlen(tok), i;

	for (i = 0; i + tl <= n; i++) {
		if (!strncasecmp(v + i, tok, tl))
			return true;
	}
	return false;
}

/* Value of @key in an application/x-www-form-urlencoded query, undecoded. */
static const char *query_get(const char *q, const char *key, size_t *vlen)
{
	size_t kl = strlen(key);

	while (q && *q) {
		const char *amp = strchr(q, '&');
		size_t n = amp ? (size_t)(amp - q) : strlen(q);

		if (n > kl && !strncmp(q, key, kl) && q[kl] == '=') {
			*vlen = n - kl - 1;
			return q + kl + 1;
		}
		q = amp ? amp + 1 : NULL;
	}
	return NULL;
}

static bool token_eq(const struct netfb_server *s, const char *v, size_t n)
{
	/* The length is not secret; the content is compared in constant time. */
	return n == s->toklen && !crypto_memneq(v, s->token, n);
}

static bool http_authorized(const struct netfb_server *s,
			    const struct http_req *r)
{
	const char *v;
	size_t n;

	if (!s->token)
		return true;

	v = query_get(r->query, "token", &n);
	if (v && token_eq(s, v, n))
		return true;

	v = hdr_find(r, "Authorization", &n);
	if (v && n > 7 && !strncasecmp(v, "Bearer ", 7) &&
	    token_eq(s, v + 7, n - 7))
		return true;
	return false;
}

/*
 * Browsers attach no CORS policy to WebSocket handshakes, so any web page the
 * user visits could otherwise reach a loopback-only server. A request carrying
 * an Origin must come from the page this server itself delivered.
 */
static bool http_origin_ok(const struct http_req *r)
{
	const char *o, *h, *sep;
	size_t on, hn, i;

	o = hdr_find(r, "Origin", &on);
	if (!o)
		return true;
	h = hdr_find(r, "Host", &hn);
	if (!h || !hn)
		return false;

	for (sep = NULL, i = 0; i + 3 <= on; i++) {
		if (!memcmp(o + i, "://", 3)) {
			sep = o + i + 3;
			break;
		}
	}
	if (!sep)
		return false;
	on -= sep - o;
	return on == hn && !strncasecmp(sep, h, hn);
}

/* ---- HTTP responses ----------------------------------------------------- */

static int http_respond(struct socket *sock, int code, const char *reason,
			const char *ctype, const char *extra,
			const void *body, size_t blen)
{
	char hdr[768];
	int n, ret;

	n = scnprintf(hdr, sizeof(hdr),
		      "HTTP/1.1 %d %s\r\n"
		      "Content-Type: %s\r\n"
		      "Content-Length: %zu\r\n"
		      "Cache-Control: no-store\r\n"
		      "Connection: close\r\n"
		      "%s" SEC_HEADERS "\r\n",
		      code, reason, ctype, blen, extra ? extra : "");
	ret = netfb_send_all(sock, hdr, n);
	if (!ret && blen)
		ret = netfb_send_all(sock, body, blen);
	return ret;
}

static int http_error(struct socket *sock, int code, const char *reason)
{
	char body[64];
	int n = scnprintf(body, sizeof(body), "%d %s\n", code, reason);

	return http_respond(sock, code, reason, "text/plain; charset=utf-8",
			    NULL, body, n);
}

static void b64_encode(const u8 *in, size_t n, char *out)
{
	static const char tab[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t i;

	for (i = 0; i + 2 < n; i += 3) {
		*out++ = tab[in[i] >> 2];
		*out++ = tab[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
		*out++ = tab[((in[i + 1] & 15) << 2) | (in[i + 2] >> 6)];
		*out++ = tab[in[i + 2] & 63];
	}
	if (i < n) {
		*out++ = tab[in[i] >> 2];
		if (i + 1 < n) {
			*out++ = tab[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
			*out++ = tab[(in[i + 1] & 15) << 2];
		} else {
			*out++ = tab[(in[i] & 3) << 4];
			*out++ = '=';
		}
		*out++ = '=';
	}
	*out = '\0';
}

/* RFC 6455 section 4.2.2: base64(SHA-1(key + GUID)). @key must be 24 chars. */
static int ws_accept_key(struct netfb_server *s, const char *key, char out[29])
{
	u8 in[24 + sizeof(WS_GUID) - 1];
	u8 sha[20];
	int ret;

	memcpy(in, key, 24);
	memcpy(in + 24, WS_GUID, sizeof(WS_GUID) - 1);
	ret = crypto_shash_tfm_digest(s->sha1, in, sizeof(in), sha);
	if (ret)
		return ret;
	b64_encode(sha, sizeof(sha), out);
	return 0;
}

static bool ws_key_valid(const char *k, size_t n)
{
	size_t i;

	if (n != 24 || k[22] != '=' || k[23] != '=')
		return false;
	for (i = 0; i < 22; i++) {
		if (!isalnum(k[i]) && k[i] != '+' && k[i] != '/')
			return false;
	}
	return true;
}

static int handle_ws(struct netfb_conn *c, const struct http_req *r)
{
	struct netfb_server *s = c->srv;
	const char *v;
	char resp[160], acc[29];
	size_t n;
	int len, ret;

	v = hdr_find(r, "Upgrade", &n);
	if (!v || !hdr_has_token(v, n, "websocket"))
		return http_error(c->sock, 400, "Bad Request");
	v = hdr_find(r, "Connection", &n);
	if (!v || !hdr_has_token(v, n, "upgrade"))
		return http_error(c->sock, 400, "Bad Request");
	v = hdr_find(r, "Sec-WebSocket-Version", &n);
	if (!v || n != 2 || memcmp(v, "13", 2))
		return http_respond(c->sock, 426, "Upgrade Required",
				    "text/plain; charset=utf-8",
				    "Sec-WebSocket-Version: 13\r\n", NULL, 0);
	v = hdr_find(r, "Sec-WebSocket-Key", &n);
	if (!v || !ws_key_valid(v, n))
		return http_error(c->sock, 400, "Bad Request");

	ret = ws_accept_key(s, v, acc);
	if (ret)
		return http_error(c->sock, 500, "Internal Server Error");

	len = scnprintf(resp, sizeof(resp),
			"HTTP/1.1 101 Switching Protocols\r\n"
			"Upgrade: websocket\r\n"
			"Connection: Upgrade\r\n"
			"Sec-WebSocket-Accept: %s\r\n\r\n", acc);
	ret = netfb_send_all(c->sock, resp, len);
	if (ret)
		return ret;

	pr_info("%pI4 connected\n", &c->peer);
	netfb_ws_run(c);
	pr_info("%pI4 disconnected\n", &c->peer);
	return 0;
}

static int handle_request(struct netfb_conn *c, char *buf)
{
	struct netfb_server *s = c->srv;
	struct http_req r;
	char json[320];
	int ret, n;

	ret = http_read_head(c->sock, buf, HTTP_HEAD_MAX);
	if (ret == -E2BIG)
		return http_error(c->sock, 431, "Request Header Fields Too Large");
	if (ret == -ETIMEDOUT)
		return http_error(c->sock, 408, "Request Timeout");
	if (ret)
		return ret;

	if (http_parse(buf, &r))
		return http_error(c->sock, 400, "Bad Request");
	if (strcmp(r.method, "GET"))
		return http_respond(c->sock, 405, "Method Not Allowed",
				    "text/plain; charset=utf-8",
				    "Allow: GET\r\n", "405 Method Not Allowed\n", 23);

	if (!strcmp(r.path, "/") || !strcmp(r.path, "/index.html"))
		return http_respond(c->sock, 200, "OK", "text/html; charset=utf-8",
				    "Content-Encoding: gzip\r\n", netfb_web_gz,
				    netfb_web_gz_end - netfb_web_gz);

	if (!strcmp(r.path, "/favicon.ico"))
		return http_respond(c->sock, 204, "No Content", "image/x-icon",
				    NULL, NULL, 0);

	if (!strcmp(r.path, "/api/info") || !strcmp(r.path, "/ws")) {
		if (!http_origin_ok(&r))
			return http_error(c->sock, 403, "Forbidden");
		if (!http_authorized(s, &r))
			return http_respond(c->sock, 401, "Unauthorized",
					    "text/plain; charset=utf-8",
					    "WWW-Authenticate: Bearer\r\n",
					    "401 Unauthorized\n", 17);
		if (!strcmp(r.path, "/ws"))
			return handle_ws(c, &r);

		n = netfb_info_json(s->nf, s->cfg.max_fps, json, sizeof(json));
		return http_respond(c->sock, 200, "OK", "application/json", NULL,
				    json, n);
	}

	return http_error(c->sock, 404, "Not Found");
}

static int netfb_conn_fn(void *data)
{
	struct netfb_conn *c = data;
	char *buf = kmalloc(HTTP_HEAD_MAX + 1, GFP_KERNEL);

	if (buf) {
		handle_request(c, buf);
		kfree(buf);
	}
	atomic_set(&c->done, 1);
	return 0;
}

/* ---- connection management ---------------------------------------------- */

static void reap_conns(struct netfb_server *srv, bool all)
{
	struct netfb_conn *c, *tmp;
	LIST_HEAD(dead);

	mutex_lock(&srv->lock);
	list_for_each_entry_safe(c, tmp, &srv->conns, node) {
		if (!all && !atomic_read(&c->done))
			continue;
		if (all)
			kernel_sock_shutdown(c->sock, SHUT_RDWR);
		list_move(&c->node, &dead);
		srv->nconns--;
	}
	mutex_unlock(&srv->lock);

	list_for_each_entry_safe(c, tmp, &dead, node) {
		/* We hold a task reference, so this is valid after self-exit. */
		kthread_stop(c->task);
		put_task_struct(c->task);
		sock_release(c->sock);
		kfree(c);
	}
}

static void reject_busy(struct socket *sock)
{
	sock->sk->sk_sndtimeo = HZ;
	http_error(sock, 503, "Service Unavailable");
	sock_release(sock);
}

static void spawn_conn(struct netfb_server *srv, struct socket *sock)
{
	struct netfb_conn *c;

	tcp_sock_set_nodelay(sock->sk);
	sock->sk->sk_rcvtimeo = HTTP_RCV_TIMEOUT;
	sock->sk->sk_sndtimeo = HTTP_SND_TIMEOUT;

	mutex_lock(&srv->lock);
	if (srv->nconns >= srv->cfg.max_clients) {
		mutex_unlock(&srv->lock);
		reject_busy(sock);
		return;
	}

	c = kzalloc(sizeof(*c), GFP_KERNEL);
	if (!c)
		goto err;
	c->nf = srv->nf;
	c->srv = srv;
	c->sock = sock;
	c->peer = inet_sk(sock->sk)->inet_daddr;
	atomic_set(&c->done, 0);
	c->task = kthread_create(netfb_conn_fn, c, "netfb-conn");
	if (IS_ERR(c->task)) {
		kfree(c);
		goto err;
	}
	get_task_struct(c->task);
	list_add_tail(&c->node, &srv->conns);
	srv->nconns++;
	mutex_unlock(&srv->lock);

	wake_up_process(c->task);
	return;
err:
	mutex_unlock(&srv->lock);
	sock_release(sock);
}

static int netfb_accept_fn(void *data)
{
	struct netfb_server *srv = data;

	while (!kthread_should_stop()) {
		struct socket *ns;
		int err;

		reap_conns(srv, false);
		err = kernel_accept(srv->listen, &ns, 0);
		if (err == -EAGAIN || err == -EINTR || err == -ERESTARTSYS)
			continue;	/* rcvtimeo expired: re-check for stop */
		if (err < 0) {
			pr_warn_ratelimited("accept failed: %d\n", err);
			schedule_timeout_interruptible(HZ / 10);
			continue;
		}
		spawn_conn(srv, ns);
	}
	return 0;
}

/* ---- start / stop ------------------------------------------------------- */

int netfb_net_start(struct netfb *nf, const struct netfb_net_cfg *cfg)
{
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = cfg->addr,
		.sin_port = htons(cfg->port),
	};
	struct netfb_server *srv;
	int ret;

	srv = kzalloc(sizeof(*srv), GFP_KERNEL);
	if (!srv)
		return -ENOMEM;
	srv->nf = nf;
	srv->cfg = *cfg;
	mutex_init(&srv->lock);
	INIT_LIST_HEAD(&srv->conns);

	if (cfg->token) {
		srv->token = kstrdup(cfg->token, GFP_KERNEL);
		if (!srv->token) {
			ret = -ENOMEM;
			goto err_free;
		}
		srv->toklen = strlen(srv->token);
	}

	srv->sha1 = crypto_alloc_shash("sha1", 0, 0);
	if (IS_ERR(srv->sha1)) {
		ret = PTR_ERR(srv->sha1);
		pr_err("sha1 unavailable (CONFIG_CRYPTO_SHA1): %d\n", ret);
		goto err_token;
	}

	ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP,
			       &srv->listen);
	if (ret)
		goto err_sha;
	sock_set_reuseaddr(srv->listen->sk);
	ret = kernel_bind(srv->listen, (netfb_sockaddr *)&sin, sizeof(sin));
	if (ret) {
		pr_err("bind %pI4:%u failed: %d\n", &cfg->addr, cfg->port, ret);
		goto err_sock;
	}
	ret = kernel_listen(srv->listen, 16);
	if (ret)
		goto err_sock;
	/* Makes kernel_accept() time out so the thread can notice a stop. */
	srv->listen->sk->sk_rcvtimeo = ACCEPT_POLL;

	srv->accept_task = kthread_run(netfb_accept_fn, srv, "netfb-accept");
	if (IS_ERR(srv->accept_task)) {
		ret = PTR_ERR(srv->accept_task);
		goto err_sock;
	}
	nf->srv = srv;
	return 0;

err_sock:
	sock_release(srv->listen);
err_sha:
	crypto_free_shash(srv->sha1);
err_token:
	kfree(srv->token);
err_free:
	kfree(srv);
	return ret;
}

void netfb_net_stop(struct netfb *nf)
{
	struct netfb_server *srv = nf->srv;

	kthread_stop(srv->accept_task);
	reap_conns(srv, true);
	sock_release(srv->listen);
	crypto_free_shash(srv->sha1);
	kfree_sensitive(srv->token);
	kfree(srv);
	nf->srv = NULL;
}
