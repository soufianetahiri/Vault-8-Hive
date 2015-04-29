#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "dns_protocol.h"
#include "decode_dns.h"
#include "debug.h"

enum {WAITING = 0, TIMED_OUT = 1} response_timeout;

/*!
 * @brief Perform DNS lookup
 *
 * @param ip - IP address or domain name of host
 * @param serverIP - DNS server IP address (e.g. "192.168.1.53")
 * @returns a pointer to the dotted quad address string (malloc'd memory that must be freed)
 */
char *dns_resolv(char *ip, char *serverIP)
{
	uint8_t buf[MAX_MSG_LENGTH] = {0};
	DNS_header *header;
	DNS_response *response;

	struct sockaddr_in sin;
	int sin_len = sizeof(sin);
	int sock;

	struct sigaction response_timer;
	void *qp;
	size_t buflen = 0;
	char *p;
	int n;
	uint16_t queryID = 0;

	DLX(5,printf("Attempting to resolve %s\n", ip));
	if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		DLX(4, perror("Could not create socket"));
		return NULL;
	}
	memset((char *) &sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(53);							// DNS UDP port number
	inet_aton(serverIP, &sin.sin_addr);					// DNS server address

	header = (DNS_header *)buf;
	queryID = htons((uint16_t)rand());
	header->id = htons(queryID);
	header->qdcount = htons(1);

	// Generate the query
	{
		char *tbuf;	// Temporary buffer for parsing domain name

		if ((tbuf = malloc(strlen(ip)+1)) ==  NULL)
			return NULL;

		memcpy(tbuf, ip, strlen(ip));
		qp = (char *) (buf + sizeof(DNS_header));			// Start of question
		p = strtok(tbuf, ".");
		while (p) {
			*((uint8_t *)qp++) = (uint8_t)strlen(p);
			memcpy((char *)qp, p, strlen(p));
			qp += strlen(p);
			p = strtok(NULL, ".");
		}
		*(char *)qp++ = '\0';							// Null byte terminates Qname field
		*(uint16_t *)qp = htons(1), qp += 2;			//  Qtype = 1 (A record)
		*(uint16_t *)qp++ = htons(1), qp += 2;			// Qclass = 1 (IN ==> INTERNET)
		free(tbuf);
	}
	// Send DNS query
	buflen = (size_t)qp - (size_t)buf;
	n = sendto(sock, buf, buflen, 0, (struct sockaddr *) &sin, sin_len);
	if (n < 0) {
		DLX(4, perror("Could not send DNS query"));
		return NULL;
	}

//*************************************************************************************************

	// Wait for DNS server response
	response_timer.sa_handler = timeout_handler;
	alarm(DNS_TIMEOUT);
	response = (DNS_response *)buf;
	do {
		n = recv(sock, buf, MAX_MSG_LENGTH, 0);
		if (n < 0) {
			DLX(4, perror("Error receiving DNS response"));
			return NULL;
		}
		if (n < (int)sizeof(DNS_header))					// Must at least see a DNS-sized header
			continue;
		header = (DNS_header *)buf;
	} while (header->id != queryID && !header->qr && response_timeout == WAITING);		// QR must be set and the header ID must match the queryID
	alarm(0); // Kill timer

	if (response_timeout == TIMED_OUT) {
		DLX(4, printf("No response from DNS server\n"));
		return NULL;
	}

	if (header->ancount == 0) {
		DLX(4, printf("%s did not resolve\n", ip));
		return NULL;
	}

#if 0
	response = (DNS_response *)(buf + sizeof(DNS_header));
	DPB(6, "DNS response: ", response, n - sizeof(DNS_header));
	DLX(4, printf("RR Type: %d\n", ntohs(response->type)));
	if (ntohs(response->type) != A_RECORD) {
		DLX(4, printf("Response was not an A record.\n"));
		return NULL;
	}

	if ((resolved_ip = (char *)malloc(16)) == NULL) {
		DLX(4, printf("Failed to malloc resolved IP buffer.\n"));
		return NULL;
	}
	// Convert decimal IP address back to a character string
	if ((inet_ntop(AF_INET, response->rdata, resolved_ip, 16)) == NULL) {
		DLX(4, printf("inet_ntop() failed to convert IP to string.\n"));
		return NULL;
	}

	return resolved_ip;								// Return IP address
#endif

	return (decode_dns(response));
}

void timeout_handler(int signal)
{
	if (signal == SIGALRM) {
		DLX(4, printf("DNS lookup timed out."));
		response_timeout = TIMED_OUT;
	}
}
