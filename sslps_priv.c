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

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include "sslps_priv.h"


static SSL *SSL_array[4096];
static SSL_CTX *SSL_CTX_array[4096];

extern int privsep_init();


#ifdef USE_SECCOMP

#include <linux/audit.h>
#include <linux/filter.h>
#include <sys/prctl.h>
#include <asm/unistd.h>

/* structures and filter with help from OpenSSH 6.0 code and "fancy seccomp-bpf.h" */


#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER	2 /* uses user-supplied filter. */
#define SECCOMP_RET_KILL	0x00000000U /* kill the task immediately */
#define SECCOMP_RET_TRAP	0x00030000U /* disallow and force a SIGSYS */
#define SECCOMP_RET_ALLOW	0x7fff0000U /* allow */

struct seccomp_data {
	int nr;
	uint32_t arch;
	uint64_t instruction_pointer;
	uint64_t args[6];
};

#endif

#if defined(__i386__)
#define REG_SYSCALL REG_EAX
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_I386
#elif defined(__x86_64__)
#define REG_SYSCALL REG_RAX
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_X86_64
#else
#warning "Platform does not support seccomp filter yet"
#define REG_SYSCALL 0
#define SECCOMP_AUDIT_ARCH 0
#endif

#define SC_DENY(_nr, _errno) \
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_ ## _nr, 0, 1), \
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ERRNO|(_errno))
#define SC_ALLOW(_nr) \
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_ ## _nr, 0, 1), \
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)


#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif


static const struct sock_filter filter_insns[] = {
	/* validate arch */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, arch)),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),

	/* load syscall nr */
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),

	SC_ALLOW(gettimeofday),
	SC_ALLOW(read),
	SC_ALLOW(write),
	SC_ALLOW(recvmsg),
	SC_ALLOW(mmap),
	SC_ALLOW(munmap),
	SC_ALLOW(brk),
	SC_ALLOW(close),
	SC_ALLOW(exit_group),

	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)
};


static const struct sock_fprog filter = {
	.len = (unsigned short)(sizeof(filter_insns)/sizeof(filter_insns[0])),
	.filter = (struct sock_filter *)filter_insns
};

#endif


SSL *get_SSL(const sslps_SSL *ssl)
{
	if (ssl->id >= sizeof(SSL_array)/sizeof(SSL_array[0]))
		return NULL;
	return SSL_array[ssl->id];
}


sslps_SSL new_SSL(SSL_CTX *ctx)
{
	uint32_t i = 0, can = 0;
	SSL *ssl = NULL;
	sslps_SSL sslps_ssl;

	memset(&sslps_ssl, 0, sizeof(sslps_ssl));
	sslps_ssl.id = (uint32_t)-1;

	for (i = 0; i < sizeof(SSL_array)/sizeof(SSL_array[0]); ++i) {
		if (!SSL_array[i]) {
			can = 1;
			break;
		}
	}

	if (!can)
		return sslps_ssl;

	if (!(ssl = SSL_new(ctx)))
		return sslps_ssl;

	sslps_ssl.id = i;
	SSL_array[i] = ssl;
	return sslps_ssl;
}


void free_SSL(const sslps_SSL *ssl)
{
	if (ssl->id >= sizeof(SSL_array)/sizeof(SSL_array[0]))
		return;

	if (SSL_array[ssl->id]) {
		close(SSL_get_fd(SSL_array[ssl->id]));
		SSL_free(SSL_array[ssl->id]);
		SSL_array[ssl->id] = NULL;
	}
}


SSL_CTX *get_SSL_CTX(const sslps_SSL_CTX *ctx)
{
	if (ctx->id >= sizeof(SSL_CTX_array)/sizeof(SSL_CTX_array[0]))
		return NULL;
	return SSL_CTX_array[ctx->id];

}


void free_SSL_CTX(const sslps_SSL_CTX *ctx)
{
	if (ctx->id >= sizeof(SSL_CTX_array)/sizeof(SSL_CTX_array[0]))
		return;

	if (SSL_CTX_array[ctx->id]) {
		SSL_CTX_free(SSL_CTX_array[ctx->id]);
		SSL_CTX_array[ctx->id] = NULL;
	}
}


sslps_SSL_CTX new_SSL_CTX(int m)
{
	uint32_t i = 0, can = 0;
	SSL_CTX *ssl_ctx = NULL;
	sslps_SSL_CTX sslps_ssl_ctx;
	const SSL_METHOD *ssl_m = NULL;

	memset(&sslps_ssl_ctx, 0, sizeof(sslps_ssl_ctx));
	sslps_ssl_ctx.id = (uint32_t)-1;

	for (i = 0; i < sizeof(SSL_CTX_array)/sizeof(SSL_CTX_array[0]); ++i) {
		if (!SSL_CTX_array[i]) {
			can = 1;
			break;
		}
	}

	if (!can)
		return sslps_ssl_ctx;

	switch (m) {
	case SSL3_METHOD:
		ssl_m = SSLv3_method();
		break;
	case SSL3_CLIENT_METHOD:
		ssl_m = SSLv3_client_method();
		break;
	case SSL3_SERVER_METHOD:
		ssl_m = SSLv3_server_method();
		break;
	case SSL23_METHOD:
		ssl_m = SSLv23_method();
		break;
	case SSL23_CLIENT_METHOD:
		ssl_m = SSLv23_client_method();
		break;
	case SSL23_SERVER_METHOD:
		ssl_m = SSLv23_server_method();
		break;
	case TLS1_METHOD:
		ssl_m = TLSv1_method();
		break;
	case TLS1_CLIENT_METHOD:
		ssl_m = TLSv1_client_method();
		break;
	case TLS1_SERVER_METHOD:
		ssl_m = TLSv1_server_method();
		break;
/* sometimes not supported */
#if 0
	case TLS11_METHOD:
		ssl_m = TLSv1_1_method();
		break;
	case TLS11_CLIENT_METHOD:
		ssl_m = TLSv1_1_client_method();
		break;
	case TLS11_SERVER_METHOD:
		ssl_m = TLSv1_1_server_method();
		break;
#endif
	}
	if (!(ssl_ctx = SSL_CTX_new(ssl_m))) {
		return sslps_ssl_ctx;
	}
	sslps_ssl_ctx.id = i;
	SSL_CTX_array[i] = ssl_ctx;
	return sslps_ssl_ctx;
}


int priv_server(int fd)
{
	char buf[4096], anc[1024], *tbuf = NULL;
	struct cmsghdr *cmsg = NULL;
	struct iovec iov = { buf, sizeof(buf)};
	struct msghdr msg;
	ssize_t n = -1;
	int r = -1, fd2 = -1;
	long lr = -1;

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();

	cmd_t *cmd_buf = NULL;
	SSL *ssl = NULL;
	SSL_CTX *ctx = NULL;
	sslps_SSL sslps_ssl;
	sslps_SSL_CTX sslps_ssl_ctx;

	signal(SIGPIPE, SIG_IGN);

	for (;;) {
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = anc;
		msg.msg_controllen = sizeof(anc);
		msg.msg_flags = 0;
		if ((n = recvmsg(fd, &msg, 0)) <= 0) {
			exit(0);
		}

		cmd_buf = (cmd_t *)iov.iov_base;

		if (n < sizeof(cmd_t))
			continue;

		r = -1;
		lr = -1;

		switch (cmd_buf->cmd) {
		case PRIVSEP_DROP_PRIV:
			r = privsep_init();
#ifdef USE_SECCOMP
			if (r == 0)
				r = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
			if (r == 0)
				r = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter);
#endif
			sslps_writen(fd, &r, sizeof(r));
			break;
		case PRIVSEP_EXIT:
			r = cmd_buf->i;
			sslps_writen(fd, &r, sizeof(r));
			exit(r);
			break;
		case SSL_CTX_USE_CERTIFICATE_FILE:
			ctx = get_SSL_CTX(&cmd_buf->ctx);
			if (ctx)
				r = SSL_CTX_use_certificate_file(ctx, cmd_buf->path, cmd_buf->i);
			sslps_writen(fd, &r, sizeof(r));
			break;
		case SSL_CTX_USE_CERTIFICATE_CHAIN_FILE:
			ctx = get_SSL_CTX(&cmd_buf->ctx);
			if (ctx)
				r = SSL_CTX_use_certificate_chain_file(ctx, cmd_buf->path);
			sslps_writen(fd, &r, sizeof(r));
			break;
		case SSL_CTX_USE_PRIVATE_KEY_FILE:
			ctx = get_SSL_CTX(&cmd_buf->ctx);
			if (ctx)
				r = SSL_CTX_use_PrivateKey_file(ctx, cmd_buf->path, cmd_buf->i);
			sslps_writen(fd, &r, sizeof(r));
			break;
		case SSL_CTX_CHECK_PRIVATE_KEY:
			ctx = get_SSL_CTX(&cmd_buf->ctx);
			if (ctx)
				r = SSL_CTX_check_private_key(ctx);
			sslps_writen(fd, &r, sizeof(r));
			break;
		case SSL_SET_FD:
			ssl = get_SSL(&cmd_buf->ssl);
			if (ssl) {
				cmsg = CMSG_FIRSTHDR(&msg);
				if (cmsg && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS &&
				    cmsg->cmsg_len >= CMSG_LEN(sizeof(int))) {
					memcpy(&fd2, CMSG_DATA(cmsg), sizeof(fd2));
					r = SSL_set_fd(ssl, fd2);
				}
			}
			sslps_writen(fd, &r, sizeof(r));
			break;
		case SSL_ACCEPT:
			ssl = get_SSL(&cmd_buf->ssl);
			if (ssl)
				r = SSL_accept(ssl);
			sslps_writen(fd, &r, sizeof(r));
			break;
		case SSL_CONNECT:
			ssl = get_SSL(&cmd_buf->ssl);
			if (ssl)
				r = SSL_connect(ssl);
			sslps_writen(fd, &r, sizeof(r));
			break;
		case SSL_GET_ERROR:
			ssl = get_SSL(&cmd_buf->ssl);
			if (ssl)
				r = SSL_get_error(ssl, cmd_buf->i);
			sslps_writen(fd, &r, sizeof(r));
			break;
		case SSL_SHUTDOWN:
			ssl = get_SSL(&cmd_buf->ssl);
			if (ssl)
				r = SSL_shutdown(ssl);
			sslps_writen(fd, &r, sizeof(r));
			break;
		case SSL_NEW:
			ctx = get_SSL_CTX(&cmd_buf->ctx);
			if (ctx)
				sslps_ssl = new_SSL(ctx);
			sslps_writen(fd, &sslps_ssl, sizeof(sslps_ssl));
			break;
		case SSL_CTX_NEW:
			sslps_ssl_ctx = new_SSL_CTX(cmd_buf->i);
			sslps_writen(fd, &sslps_ssl_ctx, sizeof(sslps_ssl_ctx));
			break;
		case SSL_READ:
			ssl = get_SSL(&cmd_buf->ssl);
			if (ssl) {
				tbuf = (char *)calloc(1, cmd_buf->i);
				if (tbuf) {
					r = SSL_read(ssl, tbuf, cmd_buf->i);
					sslps_writen(fd, &r, sizeof(r));
					if (r > 0)
						sslps_writen(fd, tbuf, r);
					free(tbuf);
				} else
					sslps_writen(fd, &r, sizeof(r));
			} else
				sslps_writen(fd, &r, sizeof(r));
			break;
		case SSL_PEEK:
			ssl = get_SSL(&cmd_buf->ssl);
			if (ssl) {
				tbuf = (char *)calloc(1, cmd_buf->i);
				if (tbuf) {
					r = SSL_peek(ssl, tbuf, cmd_buf->i);
					sslps_writen(fd, &r, sizeof(r));
					if (r > 0)
						sslps_writen(fd, tbuf, r);
					free(tbuf);
				} else
					sslps_writen(fd, &r, sizeof(r));
			} else
				sslps_writen(fd, &r, sizeof(r));
			break;
		case SSL_WRITE:
			ssl = get_SSL(&cmd_buf->ssl);
			if (ssl) {
				tbuf = (char *)calloc(1, cmd_buf->i);
				if (tbuf) {
					if ((r = sslps_readn(fd, tbuf, cmd_buf->i)) > 0) {
						r = SSL_write(ssl, tbuf, r);
					}
					free(tbuf);
				}
				sslps_writen(fd, &r, sizeof(r));
			} else
				sslps_writen(fd, &r, sizeof(r));
			break;
		case SSL_FREE:
			free_SSL(&cmd_buf->ssl);
			break;
		case SSL_CTX_FREE:
			free_SSL_CTX(&cmd_buf->ctx);
			break;
		case SSL_SET_OPTIONS:
			ssl = get_SSL(&cmd_buf->ssl);
			if (ssl) {
				lr = SSL_set_options(ssl, cmd_buf->l);
			}
			sslps_writen(fd, &lr, sizeof(lr));
			break;
		case SSL_GET_OPTIONS:
			ssl = get_SSL(&cmd_buf->ssl);
			if (ssl) {
				lr = SSL_get_options(ssl);
			}
			sslps_writen(fd, &lr, sizeof(lr));
			break;
		case SSL_CLEAR_OPTIONS:
			ssl = get_SSL(&cmd_buf->ssl);
			if (ssl) {
				lr = SSL_clear_options(ssl, cmd_buf->l);
			}
			sslps_writen(fd, &lr, sizeof(lr));
			break;
		case SSL_CTX_SET_OPTIONS:
			ctx = get_SSL_CTX(&cmd_buf->ctx);
			if (ctx) {
				lr = SSL_CTX_set_options(ctx, cmd_buf->l);
			}
			sslps_writen(fd, &lr, sizeof(lr));
			break;
		case SSL_CTX_GET_OPTIONS:
			ctx = get_SSL_CTX(&cmd_buf->ctx);
			if (ctx) {
				lr = SSL_CTX_get_options(ctx);
			}
			sslps_writen(fd, &lr, sizeof(lr));
			break;
		case SSL_CTX_CLEAR_OPTIONS:
			ctx = get_SSL_CTX(&cmd_buf->ctx);
			if (ctx) {
				lr = SSL_CTX_clear_options(ctx, cmd_buf->l);
			}
			sslps_writen(fd, &lr, sizeof(lr));
			break;
		case SSL_CTX_SET_SESSION_CACHE_MODE:
			ctx = get_SSL_CTX(&cmd_buf->ctx);
			if (ctx) {
				lr = SSL_CTX_set_session_cache_mode(ctx, cmd_buf->l);
			}
			sslps_writen(fd, &lr, sizeof(lr));
			break;
		case SSL_CTX_GET_SESSION_CACHE_MODE:
			ctx = get_SSL_CTX(&cmd_buf->ctx);
			if (ctx) {
				lr = SSL_CTX_get_session_cache_mode(ctx);
			}
			sslps_writen(fd, &lr, sizeof(lr));
			break;
		case SSL_CTX_SET_SESSION_ID_CONTEXT:
			ctx = get_SSL_CTX(&cmd_buf->ctx);
			if (ctx) {
				r = SSL_CTX_set_session_id_context(ctx, (unsigned char *)cmd_buf->path, (unsigned int)cmd_buf->i);
			}
			sslps_writen(fd, &r, sizeof(r));
			break;
		case SSL_SET_SESSION_ID_CONTEXT:
			ssl = get_SSL(&cmd_buf->ssl);
			if (ssl) {
				r = SSL_set_session_id_context(ssl, (unsigned char *)cmd_buf->path, (unsigned int)cmd_buf->i);
			}
			sslps_writen(fd, &r, sizeof(r));
			break;
		default:
			;
		}

	}

	return -1;
}

