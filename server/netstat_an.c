// netan. c
//
//     Uses a lot of the features specified in busybox's 1_18_stable version
//     of the networking/netstat.c file.  We have changed some of the function
//     names and variables based upon a breif review of the code.  We will
//     use several of the function names when possible but reserve the right
//     to change accordingly since the libbb.h file will not be used.

#include "debug.h"
#include "proj_strings.h"
#include "netstat_an.h"

#if !defined _NETSTAT_AN && defined LINUX
#include <unistd.h>
#include <stdlib.h>
#include "get_data.h"

unsigned char* get_netstat_an(int* size)
{
	return get_data(size, GD_NETSTAT_AN);
}

void release_netstat_an(unsigned char* netstat_an)
{
	if(netstat_an != NULL)
	{
		free(netstat_an);
	}
}
#endif

#if defined SOLARIS
#include "get_data.h"
#include <stdlib.h>

unsigned char* get_netstat_an(int* size)
{
	return get_data(size, GD_NETSTAT_AN);
}

void release_netstat_an(unsigned char* netstat_an)
{
	if(netstat_an != NULL)
	{
		free(netstat_an);
	}
}
#endif

#if defined _NETSTAT_AN
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <sys/param.h>
#include <pwd.h>
#include <grp.h>
#include <arpa/inet.h>

#define defaultOutputSize 16384 
static int sizeIncrementCount;
static char *outputBuffer=NULL;

//Set to 1 to read tcp6, udp6, and raw6
#define ENABLE_FEATURE_IPV6 1

//disable busybox's FAST_FUNC and other variables... 
typedef int smallint;
struct globals {
	smallint flags;
	unsigned addr_width;
};
struct globals *ptr_to_globals;
#define G (*ptr_to_globals)
#define flags            (G.flags           )

#define barrier() __asm__ __volatile__("":::"memory")

#define SET_PTR_TO_GLOBALS(x) do { \
	(*(struct globals**)&ptr_to_globals) = (void*)(x); \
	barrier(); \
} while (0)

// TODO: it appears there is memory allocated here. 
// where is it freed???
#define INIT_G() do { \
        SET_PTR_TO_GLOBALS(malloc(sizeof(G))); \
        flags = NETSTAT_CONNECTED | NETSTAT_ALLPROTO; \
} while (0)

 
#define NETSTAT_CONNECTED 0x01
#define NETSTAT_LISTENING 0x02
#define NETSTAT_NUMERIC   0x04
/* Must match getopt32 option string */
#define NETSTAT_TCP       0x10
#define NETSTAT_UDP       0x20
#define NETSTAT_RAW       0x40
#define NETSTAT_UNIX      0x80
#define NETSTAT_ALLPROTO  (NETSTAT_TCP|NETSTAT_UDP|NETSTAT_RAW|NETSTAT_UNIX)

//Note that there is a 1 to 1 mapping between the following enumeration
//  and the following tcp_state which seems to imply the following
// logic...     if (state==TCP_LISTEN) printf("%s", tcp_state[state]; 

enum {
        TCP_ESTABLISHED = 1,
        TCP_SYN_SENT,
        TCP_SYN_RECV,
        TCP_FIN_WAIT1,
        TCP_FIN_WAIT2,
        TCP_TIME_WAIT,
        TCP_CLOSE,
        TCP_CLOSE_WAIT,
        TCP_LAST_ACK,
        TCP_LISTEN,
        TCP_CLOSING, /* now a valid state */
};


//  Used to add the 6 to tcp, udp, and raw via the main routine...
static int ipv6File;

typedef enum {
        SS_FREE = 0,     /* not allocated                */
        SS_UNCONNECTED,  /* unconnected to any socket    */
        SS_CONNECTING,   /* in process of connecting     */
        SS_CONNECTED,    /* connected to socket          */
        SS_DISCONNECTING /* in process of disconnecting  */
} socket_state;

#define SO_ACCEPTCON (1<<16)  /* performed a listen           */
#define SO_WAITDATA  (1<<17)  /* wait data to read            */
#define SO_NOSPACE   (1<<18)  /* no space to write            */

#define ADDR_NORMAL_WIDTH        23
/* When there are IPv6 connections the IPv6 addresses will be
 * truncated to none-recognition. The '-W' option makes the
 * address columns wide enough to accomodate for longest possible
 * IPv6 addresses, i.e. addresses of the form
 * xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:ddd.ddd.ddd.ddd
 */
#define ADDR_WIDE                51  /* INET6_ADDRSTRLEN + 5 for the port number */
#endif
