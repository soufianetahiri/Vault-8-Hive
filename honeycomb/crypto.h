#ifndef	_CRYPTO_H
#define _CRYPTO_H

#define CLIENT 1
#define SERVER 2

int crypt_setup_client( int *sockfd );
int crypt_setup_server( int *sockfd );
int crypt_handshake( void );
int crypt_read( unsigned char *buf, int bufsz );
int crypt_write( unsigned char *buf, int size );
int	crypt_close_notify( void );
int crypt_cleanup( void );

#endif	//_CRYPTO_H
