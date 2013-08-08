#ifndef	_CRYPTO_H
#define _CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

//*******************************************************
// used by client and server
#include "polarssl/include/polarssl/net.h"
#include "polarssl/include/polarssl/ssl.h"
#include "polarssl/include/polarssl/havege.h"
#include "polarssl/include/polarssl/x509.h"
#include "../crypto_proj_strings.h"

#define CLIENT 1
#define SERVER 2
#define SSL_SERVER

#define SRV_CERT_FILE	"./server.crt"
#define CA_CERT_FILE	"./ca.crt"
#define SRV_KEY_FILE	"./server.key"

int crypt_setup_client( havege_state *hs, ssl_context *ssl, ssl_session *ssn, int *sockfd );
int crypt_setup_server( havege_state *hs, ssl_context *ssl, ssl_session *ssn, int *sockfd );
int crypt_handshake( ssl_context *ssl );
int crypt_read( ssl_context *ssl, unsigned char *buf, int bufsz );
int crypt_write( ssl_context *ssl, unsigned char *buf, int size );
int crypt_close_notify( ssl_context *ssl );
int crypt_cleanup( ssl_context *ssl);
void print_ssl_errors(int error);

// Load_file definition from poloarssl/include/polarssl/x509.c
int load_file(const char *, unsigned char **, size_t * );

#ifdef __cplusplus
}
#endif

#endif	//_CRYPTO_H
