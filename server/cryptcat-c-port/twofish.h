#ifndef	__TWOFISH_H
#define	__TWOFISH_H

#include <stdio.h>
#include "port.h"

#define BLOCK_SIZE  16 // bytes in a data-block
#define ROUNDS      16
#define TOTAL_SUBKEYS  4 + 4 + 2*ROUNDS
#define SK_BUMP  0x01010101
#define SK_ROTL  9
#define P_00 1
#define P_01 0
#define P_02 0
#define P_03 (P_01 ^ 1)
#define P_04 1
#define P_10 0
#define P_11 0
#define P_12 1
#define P_13 (P_11 ^ 1)
#define P_14 0
#define P_20 1
#define P_21 1
#define P_22 0
#define P_23 (P_21 ^ 1)
#define P_24 0
#define P_30 0
#define P_31 1
#define P_32 1
#define P_33 ( P_31 ^ 1 )
#define P_34 1
#define GF256_FDBK    0x169
#define GF256_FDBK_2  0x169 / 2
#define GF256_FDBK_4  0x169 / 4
#define RS_GF_FDBK  0x14D // field generator
#define MDS_GF_FDBK  0x169	/* primitive polynomial for GF(256)*/

struct tf_context
{
    /** mode: encrypt (false) or decrypt (true) */
    bool decrypt;
    bool outputIsFile;
    bool outputIsBuffer;
    bool outputIsSocket;

    /** Key dependent S-box */
    int sBox[4 * 256];

    /** Subkeys */
    int subKeys[TOTAL_SUBKEYS];

    // output areas
    FILE* fpout;
    unsigned char* outputBuffer;
    int sockfd;
	char qBlockPlain[16];
	char qBlockCrypt[16];
	char prevCipher[16];
	bool qBlockDefined;
};

char* generateKey( char* kstr );

void tf_init( struct tf_context *ctx, char* userkey, bool _decrypt, FILE* fpout, unsigned char* outbuf );
void tf_setDecrypt( struct tf_context *ctx, bool d );
void tf_setFp( struct tf_context *ctx, FILE* fp );
void tf_setOutputBuffer( struct tf_context *ctx, unsigned char* obuf );
void tf_setSocket( struct tf_context *ctx, int sfd );
void tf_blockCrypt( struct tf_context *ctx, char* in, char* out, int size );
void tf_blockCrypt16( struct tf_context *ctx, char* in, char* out );
void tf_flush( struct tf_context *ctx );
void tf_resetCBC( struct tf_context *ctx );

void tf_encryptAscii( struct tf_context *ctx, char* in, char* out, int outBufferSize );
void tf_decryptAscii( struct tf_context *ctx, char* in, char* out );

#endif
