#ifndef _BLTH_H
#define _BLTH_H

#define PACK_FOR_LINUX __attribute__((packed))

typedef struct _BthpHdr_T
{
	unsigned char 	version;
	unsigned char 	type;
	unsigned short 	hdrLen;
	unsigned int 	dataLen;
	unsigned int 	proxyId;
}
PACK_FOR_LINUX BthpHdr_T, *PBthpHdr_T;

struct addl_hdr_field
{
	unsigned char	type;
	unsigned char	len;
	unsigned char	data[6];
} PACK_FOR_LINUX;

struct beacon_field
{
	char		mac[20];
	unsigned long	uptime;
	unsigned long 	tool_id;
};

struct rsi_args
{
	struct beacon_field* 	bfptr;
	unsigned int 		dataLen;
	char*		path;
	char		dst_ip[15];
	char		proxy_ip[15];
	char		beacon_ip[15];
};

#endif	//_BLTH_H
