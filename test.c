/* cc test.c sslps.c sslps_priv.c -lssl -lcrypto */

#include <unistd.h>
#include <fcntl.h>
#include <openssl/ssl.h>

/* Include this, all required SSL_ functions are shadowed by
 * macros, calling corresponding privsep SSL functions. Do not mind
 * the redefinition warnings during compilation.
 */
#include "sslps.h"
#include "sslps_priv.h"

/* You need to provide this function. Its called upon  
 * PRIVSEP_DROP_PRIV ctrl from privseped process in order to
 * lose its privileges.
 */
int privsep_init()
{
	/* chroot, setuid etc */
	printf("privset_init() called\n");
	return 0;
}


int main()
{
	int fd = -1;
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;

	OpenSSL_add_all_algorithms();

	/* dummy FD, wont really work for SSL handshake */
	fd = open("/etc/passwd", O_RDONLY);

	/* call this when you loaded the certificates etc */
	SSL_privsep_ctrl(PRIVSEP_DROP_PRIV);

	/* ... */
	ctx = SSL_CTX_new(SSLv3_server_method());
	ssl = SSL_new(ctx);

	SSL_set_fd(ssl, fd);

	/* ... more SSL client/server code here, but functions requiring
	 * callbacks or handling X509 directly as parameters, are not implemented yet ...
	 */

	SSL_free(ssl);
	SSL_CTX_free(ctx);

	/* call this upon exit, so the privsep process exits too */
	SSL_privsep_ctrl(PRIVSEP_EXIT);

	return 0;
}

