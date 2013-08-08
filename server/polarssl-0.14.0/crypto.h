#ifndef	_CRYPTO_H
#define _CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

//*******************************************************
// used by client and server
#include "../function_strings.h"
#include "include/polarssl/net.h"
#include "include/polarssl/ssl.h"
#include "include/polarssl/havege.h"

#define CLIENT 1
#define SERVER 2

int crypt_setup_client( havege_state *hs, ssl_context *ssl, ssl_session *ssn, int *sockfd );
int crypt_setup_server( havege_state *hs, ssl_context *ssl, ssl_session *ssn, int *sockfd );
int crypt_handshake( ssl_context *ssl );
int crypt_read( ssl_context *ssl, unsigned char *buf, int bufsz );
int crypt_write( ssl_context *ssl, unsigned char *buf, int size );
int	crypt_close_notify( ssl_context *ssl );
int crypt_cleanup( ssl_context *ssl);

#ifdef __cplusplus
}
#endif

#endif	//_CRYPTO_H
