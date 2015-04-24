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
#include "debug.h"

enum {WAITING = 0, TIMED_OUT = 1} response_timeout;

/*!
 * @brief Perform DNS lookup
 *
 * @param ip - IP address or domain name of host
 * @param serverIP - DNS server IP address (e.g. "192.168.1.53")
 * @return
 */
uint32_t dns_resolv(char *ip, char *serverIP)
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

	if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		DLX(4, perror("Could not create socket"));
		return -1;
	}
	memset((char *) &sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(53);							// DNS UDP port number
	inet_aton(serverIP, &sin.sin_addr);					// DNS server address

	header = (DNS_header *)buf;
	queryID = (uint16_t)rand();
	header->id = queryID;
	header->qdcount = 1;

	// Generate the query
	qp = (char *) (buf + sizeof(DNS_header));			// Start of question
	p = strtok(ip, ".");
	while (p) {
		uint16_t size;

		size = (uint16_t)strlen(p);
		memcpy((uint16_t *)qp, &size, sizeof(size));
		qp += (uint16_t)sizeof(size);
		memcpy((char *)qp, p, strlen(p));
		qp += strlen(p);
		p = strtok(NULL, ".");
	}
	*(char *)qp++ = '\0';
	*(uint16_t *)qp++ = 1;								//  Qtype = 1 (A record)
	*(uint16_t *)qp++ = 1;								// Qclass = 1 (IN ==> INTERNET)

	// Send DNS query
	buflen = (size_t)qp - (size_t)buf;
	n = sendto(sock, buf, buflen, 0, (struct sockaddr *) &sin, sin_len);
	if (n < 0) {
		DLX(4, perror("Could not send DNS query"));
		return -1;
	}

	// Wait for DNS server response
	response_timer.sa_handler = timeout_handler;
	alarm(DNS_TIMEOUT);
	response = (DNS_response *)buf;
	do {
		n = recv(sock, buf, MAX_MSG_LENGTH, 0);
		if (n < 0) {
			DLX(4, perror("Error receiving DNS response"));
			return -1;
		}
		if (n < (int)sizeof(DNS_header))						// Must at least see a DNS-sized header
			continue;
		header = (DNS_header *)buf;
	} while (header->id != queryID && !header->qr && response_timeout == WAITING);		// QR must be set and the header ID must match the queryID
	if (response_timeout == TIMED_OUT) {
		DLX(4, printf("No response from DNS server\n"));
		return -1;
	}
	if (header->ancount == 0) {
		DLX(4, printf("%s did not resolve\n", ip));
		return -1;
	}
	response = (DNS_response *)(buf + sizeof(DNS_header));
	if (response->type != A_RECORD) {
		DLX(4, printf("Response was not an A record.\n"));
		return -1;
	}
	return (uint32_t)response->rdata;								// Return IP address
}

void timeout_handler(int signal)
{
	if (signal == SIGALRM)
		response_timeout = TIMED_OUT;
}
