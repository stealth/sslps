/*
 * Copyright (C) 2013 Sebastian Krahmer.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Sebastian Krahmer.
 * 4. The name Sebastian Krahmer may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include "sslps_priv.h"

static int ps_inited = 0;
static int priv_sock = -1;
extern int priv_server(int sock);


int sslps_readn(int fd, void *buf, size_t len)
{
	int o = 0, n;
	char *ptr = (char*)buf;
	size_t cs = sizeof(cmd_t);

	while (len > 0) {
		if (len < cs)
			cs = len;
		if ((n = read(fd, ptr + o, cs)) <= 0)
			return n;
		len -= n;
		o += n;
	}
	return o;
}


int sslps_writen(int fd, const void *buf, size_t len)
{
	int o = 0, n;
	char *ptr = (char*)buf;
	size_t cs = sizeof(cmd_t);

	while (len > 0) {
		if (len < cs)
			cs = len;
		if ((n = write(fd, ptr + o, cs)) <= 0)
			return n;
		len -= n;
		o += n;
	}
	return o;
}


static int sslps_init()
{
	int socks[2] = {-1, -1};

	if (ps_inited)
		return 0;

	// must be datagram, to preserve message boundaries
	if (socketpair(PF_UNIX, SOCK_DGRAM, 0, socks) < 0)
		return -1;

	ps_inited = 1;
	if (fork() > 0) {
		close(socks[0]);
		priv_sock = socks[1];
		return 0;
	}

	close(socks[1]);
	priv_server(socks[0]);
	exit(0);

	return 0;
}


void ps_OpenSSL_add_all_algorithms()
{
	sslps_init();
}


void ps_OpenSSL_add_all_ciphers()
{
	sslps_init();
}


void ps_OpenSSL_add_all_digests()
{
	sslps_init();
}


void ps_SSL_library_init()
{
	sslps_init();
}


void ps_SSL_load_error_strings()
{
	sslps_init();
}


int SSL_privsep_ctrl(int m)
{
	int r = -1;
	cmd_t snd_buf;

	if (m != PRIVSEP_DROP_PRIV && m != PRIVSEP_EXIT)
		return -1;

	memset(&snd_buf, 0, sizeof(snd_buf));
	snd_buf.cmd = m;

	if (sslps_writen(priv_sock, &snd_buf, sizeof(snd_buf)) < 0)
		return -1;
	sslps_readn(priv_sock, &r, sizeof(r));
	return r;
}


int ps_SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *path, int m)
{
	int r = -1;
	cmd_t snd_buf;

	if (strlen(path) >= sizeof(snd_buf.path))
		return -1;

	memset(&snd_buf, 0, sizeof(snd_buf));
	snd_buf.cmd = SSL_CTX_USE_CERTIFICATE_FILE;
	snd_buf.ctx = *(sslps_SSL_CTX *)ctx;
	strcpy(snd_buf.path, path);
	snd_buf.i = m;

	if (sslps_writen(priv_sock, &snd_buf, sizeof(snd_buf)) < 0)
		return -1;
	sslps_readn(priv_sock, &r, sizeof(r));
	return r;
}


int ps_SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *path)
{
	int r = -1;
	cmd_t snd_buf;

	if (strlen(path) >= sizeof(snd_buf.path))
		return -1;

	memset(&snd_buf, 0, sizeof(snd_buf));
	snd_buf.cmd = SSL_CTX_USE_CERTIFICATE_CHAIN_FILE;
	snd_buf.ctx = *(sslps_SSL_CTX *)ctx;
	strcpy(snd_buf.path, path);

	if (sslps_writen(priv_sock, &snd_buf, sizeof(snd_buf)) < 0)
		return -1;
	sslps_readn(priv_sock, &r, sizeof(r));
	return r;

}


int ps_SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *path, int m)
{
	int r = -1;
	cmd_t snd_buf;

	if (strlen(path) >= sizeof(snd_buf.path))
		return -1;

	memset(&snd_buf, 0, sizeof(snd_buf));
	snd_buf.cmd = SSL_CTX_USE_PRIVATE_KEY_FILE;
	snd_buf.ctx = *(sslps_SSL_CTX *)ctx;
	strcpy(snd_buf.path, path);
	snd_buf.i = m;

	if (sslps_writen(priv_sock, &snd_buf, sizeof(snd_buf)) < 0)
		return -1;
	sslps_readn(priv_sock, &r, sizeof(r));
	return r;
}


int ps_SSL_CTX_check_private_key(SSL_CTX *ctx)
{
	int r = -1;
	cmd_t snd_buf;

	memset(&snd_buf, 0, sizeof(snd_buf));
	snd_buf.cmd = SSL_CTX_CHECK_PRIVATE_KEY;
	snd_buf.ctx = *(sslps_SSL_CTX *)ctx;

	if (sslps_writen(priv_sock, &snd_buf, sizeof(snd_buf)) < 0)
		return -1;
	sslps_readn(priv_sock, &r, sizeof(r));
	return r;
}


int ps_SSL_set_fd(SSL *ssl, int fd)
{
	int r = -1;
	char buf1[1024];
	cmd_t snd_buf;
	struct iovec iov = { &snd_buf, sizeof(snd_buf)};
	struct cmsghdr *cmsg = (struct cmsghdr *)buf1;
	struct msghdr msg = { NULL, 0, &iov, 1, cmsg, CMSG_LEN(sizeof(int)), 0};

	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
	cmsg->cmsg_len = CMSG_LEN(sizeof(fd));

	memset(&snd_buf, 0, sizeof(snd_buf));
	snd_buf.cmd = SSL_SET_FD;
	snd_buf.ssl = *(sslps_SSL *)ssl;
	if (sendmsg(priv_sock, &msg, 0) <= 0)
		return -1;
	sslps_readn(priv_sock, &r, sizeof(r));

	if (r == 1)
		((sslps_SSL *)ssl)->fd = fd;
	return r;
}


int ps_SSL_get_fd(SSL *ssl)
{
	return ((sslps_SSL *)ssl)->fd;
}


int ps_SSL_accept(SSL *ssl)
{
	int r = -1;
	cmd_t snd_buf;

	memset(&snd_buf, 0, sizeof(snd_buf));
	snd_buf.cmd = SSL_ACCEPT;
	snd_buf.ssl = *(sslps_SSL *)ssl;

	if (sslps_writen(priv_sock, &snd_buf, sizeof(snd_buf)) < 0)
		return -1;
	sslps_readn(priv_sock, &r, sizeof(r));
	return r;
}


int ps_SSL_connect(SSL *ssl)
{
	int r = -1;
	cmd_t snd_buf;

	memset(&snd_buf, 0, sizeof(snd_buf));
	snd_buf.cmd = SSL_CONNECT;
	snd_buf.ssl = *(sslps_SSL *)ssl;

	if (sslps_writen(priv_sock, &snd_buf, sizeof(snd_buf)) < 0)
		return -1;
	sslps_readn(priv_sock, &r, sizeof(r));
	return r;
}


int ps_SSL_get_error(SSL *ssl, int n)
{
	int r = -1;
	cmd_t snd_buf;

	memset(&snd_buf, 0, sizeof(snd_buf));
	snd_buf.cmd = SSL_GET_ERROR;
	snd_buf.ssl = *(sslps_SSL *)ssl;
	snd_buf.i = n;

	if (sslps_writen(priv_sock, &snd_buf, sizeof(snd_buf)) < 0)
		return -1;
	sslps_readn(priv_sock, &r, sizeof(r));
	return r;
}


int ps_SSL_shutdown(SSL *ssl)
{
	int r = -1;
	cmd_t snd_buf;

	memset(&snd_buf, 0, sizeof(snd_buf));
	snd_buf.cmd = SSL_SHUTDOWN;
	snd_buf.ssl = *(sslps_SSL *)ssl;

	if (sslps_writen(priv_sock, &snd_buf, sizeof(snd_buf)) < 0)
		return -1;
	sslps_readn(priv_sock, &r, sizeof(r));
	return r;
}


SSL *ps_SSL_new(SSL_CTX *ctx)
{
	sslps_SSL *ssl = (sslps_SSL *)calloc(1, sizeof(sslps_SSL));
	cmd_t snd_buf;

	memset(&snd_buf, 0, sizeof(snd_buf));
	snd_buf.cmd = SSL_NEW;
	snd_buf.ctx = *(sslps_SSL_CTX *)ctx;

	if (sslps_writen(priv_sock, &snd_buf, sizeof(snd_buf)) < 0)
		return NULL;
	if (sslps_readn(priv_sock, ssl, sizeof(*ssl)) < 0) {
		free(ssl);
		return NULL;
	}
	ssl->fd = -1;
	return (SSL *)ssl;
}


SSL_CTX *ps_SSL_CTX_new(const SSL_METHOD *m)
{
	sslps_SSL_CTX *ctx = (sslps_SSL_CTX *)calloc(1, sizeof(sslps_SSL_CTX));
	cmd_t snd_buf;

	memset(&snd_buf, 0, sizeof(snd_buf));
	snd_buf.cmd = SSL_CTX_NEW;
	snd_buf.i = ((const sslps_SSL_METHOD *)m)->m;

	if (sslps_writen(priv_sock, &snd_buf, sizeof(snd_buf)) < 0)
		return NULL;
	if (sslps_readn(priv_sock, ctx, sizeof(*ctx)) < 0) {
		free(ctx);
		return NULL;
	}
	return (SSL_CTX *)ctx;
}


void ps_SSL_free(SSL *ssl)
{
	cmd_t snd_buf;

	memset(&snd_buf, 0, sizeof(snd_buf));
	snd_buf.cmd = SSL_FREE;
	snd_buf.ssl = *(sslps_SSL *)ssl;

	sslps_writen(priv_sock, &snd_buf, sizeof(snd_buf));
	free(ssl);
}


void ps_SSL_CTX_free(SSL_CTX *ctx)
{
	cmd_t snd_buf;

	memset(&snd_buf, 0, sizeof(snd_buf));
	snd_buf.cmd = SSL_CTX_FREE;
	snd_buf.ctx = *(sslps_SSL_CTX *)ctx;

	sslps_writen(priv_sock, &snd_buf, sizeof(snd_buf));
	free(ctx);
}


int ps_SSL_peek(SSL *ssl, void *buf, int n)
{
	int r = -1;
	cmd_t snd_buf;

	memset(&snd_buf, 0, sizeof(snd_buf));
	snd_buf.cmd = SSL_PEEK;
	snd_buf.ssl = *(sslps_SSL *)ssl;
	snd_buf.i = n;

	if (sslps_writen(priv_sock, &snd_buf, sizeof(snd_buf)) < 0)
		return -1;

	if (sslps_readn(priv_sock, &r, sizeof(r)) < 0 || r > n)
		return -1;
	if (sslps_readn(priv_sock, buf, r) != r)
		return -1;
	return r;

}


int ps_SSL_read(SSL *ssl, void *buf, int n)
{
	int r = -1;
	cmd_t snd_buf;

	memset(&snd_buf, 0, sizeof(snd_buf));
	snd_buf.cmd = SSL_READ;
	snd_buf.ssl = *(sslps_SSL *)ssl;
	snd_buf.i = n;

	if (sslps_writen(priv_sock, &snd_buf, sizeof(snd_buf)) < 0)
		return -1;

	if (sslps_readn(priv_sock, &r, sizeof(r)) < 0 || r > n)
		return -1;
	if (sslps_readn(priv_sock, buf, r) != r)
		return -1;
	return r;
}


int ps_SSL_write(SSL *ssl, const void *buf, int n)
{
	int r = -1;
	cmd_t snd_buf;

	memset(&snd_buf, 0, sizeof(snd_buf));
	snd_buf.cmd = SSL_WRITE;
	snd_buf.ssl = *(sslps_SSL *)ssl;
	snd_buf.i = n;

	if (sslps_writen(priv_sock, &snd_buf, sizeof(snd_buf)) < 0)
		return -1;
	if (sslps_writen(priv_sock, buf, n) < 0)
		return -1;
	sslps_readn(priv_sock, &r, sizeof(r));
	return r;
}


long ps_SSL_CTX_set_options(SSL_CTX *ctx, long o)
{
	long r = -1;
	cmd_t snd_buf;

	memset(&snd_buf, 0, sizeof(snd_buf));
	snd_buf.cmd = SSL_CTX_SET_OPTIONS;
	snd_buf.ctx = *(sslps_SSL_CTX *)ctx;
	snd_buf.l = o;
	if (sslps_writen(priv_sock, &snd_buf, sizeof(snd_buf)) < 0)
		return -1;
	sslps_readn(priv_sock, &r, sizeof(r));
	return r;
}


long ps_SSL_CTX_get_options(SSL_CTX *ctx)
{
	long r = -1;
	cmd_t snd_buf;

	memset(&snd_buf, 0, sizeof(snd_buf));
	snd_buf.cmd = SSL_CTX_GET_OPTIONS;
	snd_buf.ctx = *(sslps_SSL_CTX *)ctx;
	if (sslps_writen(priv_sock, &snd_buf, sizeof(snd_buf)) < 0)
		return -1;
	sslps_readn(priv_sock, &r, sizeof(r));
	return r;
}


long ps_SSL_CTX_clear_options(SSL_CTX *ctx, long o)
{
	long r = -1;
	cmd_t snd_buf;

	memset(&snd_buf, 0, sizeof(snd_buf));
	snd_buf.cmd = SSL_CTX_CLEAR_OPTIONS;
	snd_buf.ctx = *(sslps_SSL_CTX *)ctx;
	snd_buf.l = o;
	if (sslps_writen(priv_sock, &snd_buf, sizeof(snd_buf)) < 0)
		return -1;
	sslps_readn(priv_sock, &r, sizeof(r));
	return r;
}


long ps_SSL_set_options(SSL *ssl, long o)
{
	long r = -1;
	cmd_t snd_buf;

	memset(&snd_buf, 0, sizeof(snd_buf));
	snd_buf.cmd = SSL_SET_OPTIONS;
	snd_buf.ssl = *(sslps_SSL *)ssl;
	snd_buf.l = o;
	if (sslps_writen(priv_sock, &snd_buf, sizeof(snd_buf)) < 0)
		return -1;
	sslps_readn(priv_sock, &r, sizeof(r));
	return r;
}


long ps_SSL_get_options(SSL *ssl)
{
	long r = -1;
	cmd_t snd_buf;

	memset(&snd_buf, 0, sizeof(snd_buf));
	snd_buf.cmd = SSL_GET_OPTIONS;
	snd_buf.ssl = *(sslps_SSL *)ssl;
	if (sslps_writen(priv_sock, &snd_buf, sizeof(snd_buf)) < 0)
		return -1;
	sslps_readn(priv_sock, &r, sizeof(r));
	return r;
}


long ps_SSL_clear_options(SSL *ssl, long o)
{
	long r = -1;
	cmd_t snd_buf;

	memset(&snd_buf, 0, sizeof(snd_buf));
	snd_buf.cmd = SSL_CLEAR_OPTIONS;
	snd_buf.ssl = *(sslps_SSL *)ssl;
	snd_buf.l = o;
	if (sslps_writen(priv_sock, &snd_buf, sizeof(snd_buf)) < 0)
		return -1;
	sslps_readn(priv_sock, &r, sizeof(r));
	return r;
}


long ps_SSL_CTX_set_session_cache_mode(SSL_CTX *ctx, long m)
{
	long r = -1;
	cmd_t snd_buf;

	memset(&snd_buf, 0, sizeof(snd_buf));
	snd_buf.cmd = SSL_CTX_SET_SESSION_CACHE_MODE;
	snd_buf.ctx = *(sslps_SSL_CTX *)ctx;
	snd_buf.l = m;
	if (sslps_writen(priv_sock, &snd_buf, sizeof(snd_buf)) < 0)
		return -1;
	sslps_readn(priv_sock, &r, sizeof(r));
	return r;

}


long ps_SSL_CTX_get_session_cache_mode(SSL_CTX *ctx)
{
	long r = -1;
	cmd_t snd_buf;

	memset(&snd_buf, 0, sizeof(snd_buf));
	snd_buf.cmd = SSL_CTX_GET_SESSION_CACHE_MODE;
	snd_buf.ctx = *(sslps_SSL_CTX *)ctx;
	if (sslps_writen(priv_sock, &snd_buf, sizeof(snd_buf)) < 0)
		return -1;
	sslps_readn(priv_sock, &r, sizeof(r));
	return r;
}


int ps_SSL_CTX_set_session_id_context(SSL_CTX *ctx, const unsigned char *sid, unsigned int len)
{
	int r = -1;
	cmd_t snd_buf;

	if (len >= sizeof(snd_buf.path))
		return -1;

	memset(&snd_buf, 0, sizeof(snd_buf));
	snd_buf.cmd = SSL_CTX_SET_SESSION_ID_CONTEXT;
	snd_buf.ctx = *(sslps_SSL_CTX *)ctx;
	memcpy(snd_buf.path, sid, len);
	snd_buf.i = (int)len;

	if (sslps_writen(priv_sock, &snd_buf, sizeof(snd_buf)) < 0)
		return -1;
	sslps_readn(priv_sock, &r, sizeof(r));
	return r;
}


int ps_SSL_set_session_id_context(SSL *ssl, const unsigned char *sid, unsigned int len)
{
	int r = -1;
	cmd_t snd_buf;

	if (len >= sizeof(snd_buf.path))
		return -1;

	memset(&snd_buf, 0, sizeof(snd_buf));
	snd_buf.cmd = SSL_SET_SESSION_ID_CONTEXT;
	snd_buf.ssl = *(sslps_SSL *)ssl;
	memcpy(snd_buf.path, sid, len);
	snd_buf.i = (int)len;

	if (sslps_writen(priv_sock, &snd_buf, sizeof(snd_buf)) < 0)
		return -1;
	sslps_readn(priv_sock, &r, sizeof(r));
	return r;
}


SSL_METHOD *ps_SSLv3_method(void)
{
	static sslps_SSL_METHOD sslps_m_v3 = {SSL3_METHOD};
	return (SSL_METHOD *)&sslps_m_v3;
}


SSL_METHOD *ps_SSLv3_client_method(void)
{
	static sslps_SSL_METHOD sslps_m_v3 = {SSL3_CLIENT_METHOD};
	return (SSL_METHOD *)&sslps_m_v3;
}


SSL_METHOD *ps_SSLv3_server_method(void)
{
	static sslps_SSL_METHOD sslps_m_v3 = {SSL3_SERVER_METHOD};
	return (SSL_METHOD *)&sslps_m_v3;
}


 SSL_METHOD *ps_SSLv23_method(void)
{
	static sslps_SSL_METHOD sslps_m_v23 = {SSL23_METHOD};
	return (SSL_METHOD *)&sslps_m_v23;
}


SSL_METHOD *ps_SSLv23_client_method(void)
{
	static sslps_SSL_METHOD sslps_m_v23 = {SSL23_CLIENT_METHOD};
	return (SSL_METHOD *)&sslps_m_v23;
}


SSL_METHOD *ps_SSLv23_server_method(void)
{
	static sslps_SSL_METHOD sslps_m_v23 = {SSL23_SERVER_METHOD};
	return (SSL_METHOD *)&sslps_m_v23;
}


SSL_METHOD *ps_TLSv1_method(void)
{
	static sslps_SSL_METHOD sslps_m_v1 = {TLS1_METHOD};
	return (SSL_METHOD *)&sslps_m_v1;
}


SSL_METHOD *ps_TLSv1_client_method(void)
{
	static sslps_SSL_METHOD sslps_m_v1 = {TLS1_CLIENT_METHOD};
	return (SSL_METHOD *)&sslps_m_v1;
}


SSL_METHOD *ps_TLSv1_server_method(void)
{
	static sslps_SSL_METHOD sslps_m_v1 = {TLS1_SERVER_METHOD};
	return (SSL_METHOD *)&sslps_m_v1;
}


SSL_METHOD *ps_TLSv1_1_method(void)
{
	static sslps_SSL_METHOD sslps_m_v11 = {TLS11_METHOD};
	return (SSL_METHOD *)&sslps_m_v11;
}


SSL_METHOD *ps_TLSv1_1_client_method(void)
{
	static sslps_SSL_METHOD sslps_m_v11 = {TLS11_CLIENT_METHOD};
	return (SSL_METHOD *)&sslps_m_v11;
}


SSL_METHOD *ps_TLSv1_1_server_method(void)
{
	static sslps_SSL_METHOD sslps_m_v11 = {TLS11_SERVER_METHOD};
	return (SSL_METHOD *)&sslps_m_v11;
}


