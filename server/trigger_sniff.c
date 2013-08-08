#if defined LINUX || defined SOLARIS
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "unpifi.h"
#endif

#if defined LINUX
#include <features.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#endif

#if defined SOLARIS
#include <sys/dlpi.h>
#include <stropts.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif

#include <string.h>
#include <stdlib.h>

#include "trigger_sniff.h"
#include "trigger_listen.h"
#include "compat.h"
#include "debug.h"

#ifdef WIN32
#include <Mstcpip.h>
#endif


//*************************************************************************
/*  This is the only external function in the file,
 *  all other funcs are private static helpers to this.
 */
int dt_get_socket_fd( char *iface )
{
  int fd;

  fd = dt_create_raw_socket( iface );

  if ( fd == -1 )
  {
    return FAILURE;
  } 

  // TODO: does ETH_P_IP need to be part of the function definition???
//  if ( dt_find_interface_and_bind(fd, ETH_P_IP) != SUCCESS )
  if ( dt_find_interface_and_bind(fd, 0) != SUCCESS )
  {
      return FAILURE;
  }

  return fd;
}

//*************************************************************************
#if defined LINUX
int dt_find_interface_and_bind(int fd, int proto)
{
	// to silence compiler warnings
	fd = fd;
	proto = proto;

	// listen on all interfaces
	return SUCCESS;
}

//************************************************************************
int dt_create_raw_socket( char *iface )
{
	int raw_fd;
	iface = iface;
  
	if ( ( raw_fd = socket( PF_PACKET, SOCK_RAW, htons( ETH_P_IP ) ) ) == -1 )
	{
		return FAILURE;
	}

	return raw_fd;
}

#endif  //_#if defined LINUX


//************************************************************************
//************************************************************************
//************************************************************************
#ifdef WIN32
int dt_create_raw_socket( char *iface ) {
 
  int raw_fd;
  iface = iface;
  
  if((raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_IP)) == -1) {

    return FAILURE;

  }

  return raw_fd;
}

//************************************************************************
 //Gets a list of mac addresses and interface names
void GetIPInterfaceList(PIP_ADAPTER_INFO* pAdapterList,unsigned long* size)
{
	unsigned long status;

	*pAdapterList = (IP_ADAPTER_INFO*) malloc(sizeof(IP_ADAPTER_INFO));
	*size = sizeof(IP_ADAPTER_INFO);

	status = GetAdaptersInfo(*pAdapterList, size);

	if(status != ERROR_SUCCESS)
	{
		if(status == ERROR_BUFFER_OVERFLOW)
		{
			free(*pAdapterList);
			*pAdapterList = (IP_ADAPTER_INFO*) malloc (*size);
			status = GetAdaptersInfo(*pAdapterList,size);
			if(status != ERROR_SUCCESS)
			{
				pAdapterList = NULL;
				return;
			}
		}
		else
		{
			pAdapterList = NULL;
			return;
		}
	}
}

//************************************************************************
/*
Gets the Local IP Address.
*/
void getLocalIP(char* retIP)
{
	char host_name[128]; //
	struct hostent *hp;
	struct in_addr in;

	memset(host_name,0,sizeof(host_name));
	gethostname(host_name,128);
	hp = gethostbyname(host_name);

	memcpy(&in, hp->h_addr, hp->h_length);
	strcpy(retIP,inet_ntoa(in));
}

//************************************************************************
 int
dt_find_interface_and_bind(int fd, 
			   int proto)
{
	char localIP[20];
	struct sockaddr_in sock_sniff;
	int optval = RCVALL_ON;
	unsigned long dwLen = 0;
	//PIP_ADAPTER_INFO pAdapterList = NULL;
	//unsigned long ulALS;
	int count = 1;
	char response = 0;


	/*
	TODO: We need to decide later how to handle multiple interfaces on windows
	*This is code to help determine that

	//get the list of interfaces
	GetIPInterfaceList(&pAdapterList, &ulALS);

	if(pAdapterList != NULL)
	{
		PIP_ADAPTER_INFO temp = NULL;
		temp = pAdapterList;
		while(temp)
		{
			printf("%d. -  %s\n",count,temp->Description);
			++count;
			temp = temp->Next;
		}

		response = getchar();

		temp = pAdapterList;
		count = 1;

		while(temp)
		{
			if(count == atoi(&response))
			{
				memset(localIP,0,sizeof(localIP));
				strcpy(localIP,temp->IpAddressList.IpAddress.String);
				break;
			}

			++count;
			temp = temp->Next;
		}
	}
	else
	{ */
		memset(localIP,0,sizeof(localIP));
		getLocalIP(localIP);
	//}

	//bind the raw socket
	sock_sniff.sin_family = AF_INET;
	sock_sniff.sin_port = htons(0);
	sock_sniff.sin_addr.s_addr = inet_addr(localIP);

	if(bind(fd,(struct sockaddr*)&sock_sniff,sizeof(sock_sniff)) == SOCKET_ERROR)
	{
		closesocket(fd);
		return FAILURE;
	}


	//set the socket to promiscuous mode
	if(WSAIoctl(fd, SIO_RCVALL, &optval, sizeof(optval), NULL, 0, &dwLen, NULL, NULL) == SOCKET_ERROR)
	{
		closesocket(fd);
		return FAILURE;
	}

  return SUCCESS;

}

#endif //_#if defined WIN32
//************************************************************************

#if defined SOLARIS

#include <unistd.h>		// for ioctl()
#include <stropts.h>	// for ioctl opts.

#include "dlcommon.h"

//************************************************************************
int sniff_read_solaris( int fd, void *out, int outlen )
{
	struct strbuf		data;
	char				buffer[ MAXDLBUF ];		//8k x sizeof( long )
	int					ret = 0, flags = 0;

	// initialize the incoming packet buffer
	memset( &data, 0, sizeof(data) );
	data.buf = buffer;

	// only request the minimum size of our buffer here,
	// or the destination buffer. Saves us some logic at
	// memcpy() below - when we go to fill the callers buffer
	data.maxlen = MIN( outlen, MAXDLBUF );
	data.len = 0;

	/* Upon successful completion, a non-negative value is
     returned. A return value of 0 indicates that a full message
     was read successfully. A return value of MORECTL indicates
     that more control information is waiting for retrieval. A
     return value of MOREDATA indicates that more data are wait-
     ing for retrieval. A return value of MORECTL | MOREDATA
     indicates that both types of information remain.  */
	if ( ( ret = getmsg( fd, NULL, &data, &flags ) ) < 0 )
	{	// ERROR
		D( printf( " ERROR: getmsg() failed\n" ); )
		return FAILURE;
	}

	if ( data.len > 0 )
	{
		memcpy( out, data.buf, data.len );
		return( data.len );
	}

	// not reached
	return FAILURE;
}

//************************************************************************

static int sniff_make_promiscuous_solaris( int fd )
{
	char		buf[ MAXDLBUF ];

//	dlpromisconreq( fd, DL_PROMISC_PHYS );	// TODO - to get all packets?
	dlpromisconreq( fd, DL_PROMISC_SAP );
	dlokack( fd, buf );

	return 0;
}


//************************************************************************
int sniff_start_solaris( char *devname )
{
	char			device[16], buf[MAXDLBUF];
	int				device_len;
	uint32_t		ppa = 0, sap = 0;
	int				fd;
	
	// create logical device path, ppa#, sap# = 0 for ethernet.
	device_len = strlen( devname );
	ppa = atoi( &(devname[device_len - 1]) );
	snprintf( device, 16, "/dev/%s", devname );
	D( printf( " DEBUG: devname = %s\n", devname ); )
	device_len = strlen( device );
	device[ device_len - 1 ] = 0;	// nul terminate off the number.
	
	D( printf( " DEBUG: Solaris logical network device: ==> %s\n", device ); )
	D( printf( " DEBUG: PPA: ==> %d\t\tSAP: ==> %d\n", ppa, sap ); )
	fd = open( device, 2 ); // 2 = O_RDWR?

	// attach logical device fd to ppa.
	dlattachreq( fd, ppa );
	dlokack( fd, buf );

	sniff_make_promiscuous_solaris( fd );

	// bind logical device to sap.
	dlbindreq( fd, sap, 0, DL_CLDLS, 0, 0 );
	dlbindack( fd, buf );

	// issue DLIOCRAW.
	if ( strioctl( fd, DLIOCRAW, -1, 0, NULL ) < 0 )
	{
		D( perror( " strioctl() setting DLIOCRAW" ); )
		goto cleanup;
	}

	// flush the read side of the stream. 
	if ( ioctl( fd, I_FLUSH, FLUSHR ) < 0 )
	{
		D( perror( " ioctl() flushing read stream" ); )
		goto cleanup;
	}

	return( fd );

cleanup:
	D( printf( " ERROR: starting Solaris raw link-layer socket.\n" );)
	close( fd );
	return( -1 );
}

/* TODO: Add this loopback interface check.
	if (( ctx->name ) && ( strncmp( ctx->name, "lo", 2 ) == 0 ))
	{
		debug_error("Solaris cannot be set to sniff on loopback device.\n" );
		free( ctx->name );
		ctx->name = NULL;
		return( -1 );
	}
*/

//************************************************************************
int dt_find_interface_and_bind( int fd, int proto )
{
	// to silence compiler warnings
	fd = fd;
	proto = proto;

	return 0;
}

//************************************************************************
int dt_create_raw_socket( char *iface )
{
	int		raw_fd;

	D( printf( " DEBUG: Starting dt_create_raw_socket\n" ); )

	if ( ( raw_fd = sniff_start_solaris( iface ) ) == -1 )
	{
	    return FAILURE;
	}

	return raw_fd;
}
#endif //_#if defined SOLARIS

