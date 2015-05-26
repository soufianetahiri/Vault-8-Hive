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
 * 		See RFC 1035 section 4 for DNS message details.
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
		char *tbuf;	// Pointer to temporary buffer for parsing domain name
		D(char *x;)

		if ((tbuf = calloc(strlen(ip)+1, 1)) ==  NULL) {	// Create temporary buffer
			close(sock);
			return NULL;
		}

		memcpy(tbuf, ip, strlen(ip));
		qp = (char *) (buf + sizeof(DNS_header));		// Skip over header and build DNS formatted name
		D(x = qp;)
		p = strtok(tbuf, ".");							// p points to first part of name
		while (p) {
			*((uint8_t *)qp++) = (uint8_t)strlen(p);	// Add length encoding
			memcpy((char *)qp, p, strlen(p));			// Copy portion of name
			qp += strlen(p);							// Reposition pointer to next part of name
			p = strtok(NULL, ".");						// Repeat until entire domain name encoded
		}
		*(char *)qp++ = '\0';							// Null byte terminates Qname field
		DLX(5, printf("Query Buffer: %s\n", x));
		*(uint16_t *)qp = htons(1), qp += 2;			//  Qtype = 1 (A record)
		*(uint16_t *)qp++ = htons(1), qp += 2;			// Qclass = 1 (IN ==> INTERNET)
		free(tbuf);
	}
	// Send DNS query
	DLX(5,printf("Sending DNS query...\n"));
	buflen = (size_t)qp - (size_t)buf;
	n = sendto(sock, buf, buflen, 0, (struct sockaddr *) &sin, sin_len);
	if (n < 0) {
		close(sock);
		DLX(4, perror("Could not send DNS query"));
		return NULL;
	}

//*************************************************************************************************

	// Wait for DNS server response
	response_timer.sa_handler = timeout_handler;
	if ((sigaction(SIGALRM, &response_timer, NULL)) != 0) {
		DLX(4, perror("Timeout setup"));
	}
	response_timeout = WAITING;
	alarm(DNS_TIMEOUT);
	response = (DNS_response *)buf;
	DLX(4,printf("Waiting for response from DNS server...\n"));
	do {
		n = recv(sock, buf, MAX_MSG_LENGTH, 0);
		if (n < 0) {
			DLX(4, perror("Error receiving DNS response"));
			close(sock);
			return NULL;
		}
		if (n < (int)sizeof(DNS_header))					// Must at least see a DNS-sized header
			DLX(4, printf("Packet received is %i bytes -- too small for a DNS response\n", n));
			continue;
		header = (DNS_header *)buf;
	} while (ntohs(header->id) != queryID && !header->qr && response_timeout == WAITING);		// QR must be set and the header ID must match the queryID
	close(sock);
	alarm(0); // Kill timer

	if (response_timeout == TIMED_OUT) {
		DLX(4, printf("No response from DNS server\n"));
		return NULL;
	}

	if (header->ancount == 0) {
		DLX(4, printf("%s did not resolve\n", ip));
		return NULL;
	}

	return (decode_dns(response));
}

void timeout_handler(int signal)
{
	if (signal == SIGALRM) {
		DLX(4, printf("DNS lookup timed out.\n"));
		response_timeout = TIMED_OUT;
	}
}
