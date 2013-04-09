#ifndef __sslps_h__
#define __sslps_h__

#include <openssl/ssl.h>

void ps_OpenSSL_add_all_algorithms();

void ps_OpenSSL_add_all_ciphers();

void ps_OpenSSL_add_all_digests();

void ps_SSL_library_init();

void ps_SSL_load_error_strings();

int SSL_privsep_ctrl(int);

int ps_SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *path, int m);

int ps_SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *path);

int ps_SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *path, int m);

int ps_SSL_CTX_check_private_key(SSL_CTX *ctx);

int ps_SSL_set_fd(SSL *ssl, int fd);

int ps_SSL_get_fd(SSL *);

int ps_SSL_accept(SSL *ssl);

int ps_SSL_connect(SSL *ssl);

int ps_SSL_get_error(SSL *ssl, int r);

int ps_SSL_shutdown(SSL *ssl);

SSL *ps_SSL_new(SSL_CTX *);

SSL_CTX *ps_SSL_CTX_new(const SSL_METHOD *m);

void ps_SSL_free(SSL *ssl);

void ps_SSL_CTX_free(SSL_CTX *ctx);

int ps_SSL_read(SSL *ssl, void *buf, int n);

int ps_SSL_peek(SSL *ssl, void *buf, int n);

int ps_SSL_write(SSL *ssl, const void *buf, int n);

long ps_SSL_CTX_set_options(SSL_CTX *ctx, long o);

long ps_SSL_CTX_get_options(SSL_CTX *ctx);

long ps_SSL_CTX_clear_options(SSL_CTX *ctx, long o);

long ps_SSL_set_options(SSL *ssl, long o);

long ps_SSL_get_options(SSL *ssl);

long ps_SSL_clear_options(SSL *ssl, long o);

long ps_SSL_CTX_set_session_cache_mode(SSL_CTX *ctx, long m);

long ps_SSL_CTX_get_session_cache_mode(SSL_CTX *ctx);

int ps_SSL_CTX_set_session_id_context(SSL_CTX *ctx, const unsigned char *sid, unsigned int len);

int ps_SSL_set_session_id_context(SSL *ssl, const unsigned char *sid, unsigned int len);

SSL_METHOD *ps_SSLv3_method(void);

SSL_METHOD *ps_SSLv3_client_method(void);

SSL_METHOD *ps_SSLv3_server_method(void);

SSL_METHOD *ps_SSLv23_method(void);

SSL_METHOD *ps_SSLv23_client_method(void);

SSL_METHOD *ps_SSLv23_server_method(void);

SSL_METHOD *ps_TLSv1_method(void);

SSL_METHOD *ps_TLSv1_client_method(void);

SSL_METHOD *ps_TLSv1_server_method(void);

SSL_METHOD *ps_TLSv1_1_method(void);

SSL_METHOD *ps_TLSv1_1_client_method(void);

SSL_METHOD *ps_TLSv1_1_server_method(void);


#define OpenSSL_add_all_algorithms ps_OpenSSL_add_all_algorithms
#define OpenSSL_add_all_digests ps_OpenSSL_add_all_digests
#define SSL_library_init ps_SSL_library_init
#define SSL_load_error_strings ps_SSL_load_error_strings
#define SSL_CTX_use_certificate_file ps_SSL_CTX_use_certificate_file
#define SSL_CTX_use_certificate_chain_file ps_SSL_CTX_use_certificate_chain_file
#define SSL_CTX_use_PrivateKey_file ps_SSL_CTX_use_PrivateKey_file
#define SSL_CTX_check_private_key ps_SSL_CTX_check_private_key

#define SSL_set_fd ps_SSL_set_fd
#define SSL_get_fd ps_SSL_get_fd
#define SSL_accept ps_SSL_accept
#define SSL_connect ps_SSL_connect
#define SSL_get_error ps_SSL_get_error
#define SSL_shutdown ps_SSL_shutdown
#define SSL_new ps_SSL_new
#define SSL_free ps_SSL_free
#define SSL_CTX_new ps_SSL_CTX_new
#define SSL_CTX_free ps_SSL_CTX_free
#define SSL_set_fd ps_SSL_set_fd
#define SSL_read ps_SSL_read
#define SSL_peek ps_SSL_peek
#define SSL_write ps_SSL_write
#define SSL_set_options ps_SSL_set_options
#define SSL_get_options ps_SSL_get_options
#define SSL_clear_options ps_SSL_clear_options
#define SSL_CTX_set_options ps_SSL_CTX_set_options
#define SSL_CTX_get_options ps_SSL_CTX_get_options
#define SSL_CTX_clear_options ps_SSL_CTX_clear_options
#define SSL_CTX_set_session_cache_mode ps_SSL_CTX_set_session_cache_mode
#define SSL_CTX_get_session_cache_mode ps_SSL_CTX_get_session_cache_mode
#define SSL_CTX_set_session_id_context ps_SSL_CTX_set_session_id_context
#define SSL_set_session_id_context ps_SSL_set_session_id_context

#define SSLv3_method ps_SSLv3_method
#define SSLv3_client_method ps_SSLv3_client_method
#define SSLv3_server_method ps_SSLv3_server_method
#define SSLv23_method ps_SSLv23_method
#define SSLv23_client_method ps_SSLv23_client_method
#define SSLv23_server_method ps_SSLv23_server_method
#define TLSv1_method ps_TLSv1_method
#define TLSv1_client_method ps_TLSv1_client_method
#define TLSv1_server_method ps_TLSv1_server_method
#define TLSv1_1_method ps_TLSv1_1_method
#define TLSv1_1_client_method ps_TLSv1_1_client_method
#define TLSv1_1_server_method ps_TLSv1_1_server_method


#endif

