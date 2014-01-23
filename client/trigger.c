/*!
 * dieselt.c
 *
 * @version 0.1 (October 1, 2007)
 *
 * Trigger component of the DieSel project.
 *
 * @author Matt Bravo
 *
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <pthread.h>

#include "trigger_network.h"
#include "trigger_protocols.h"
#include "trigger_utils.h"
#include "trigger_debug.h"
#include "trigger.h"
#include "debug.h"
#include "colors.h"

#include "proj_strings.h"

//************************************************************
extern pthread_mutex_t tlock;
//************************************************************
static void print_usage ();
static void parse_options (struct trigger_params *t_info, trigger_info * ti);
static void print_input_args (trigger_info * ti);
int trigger_info_to_payload (payload * p, trigger_info * ti);
//************************************************************
void *
trigger_start (void *arg)
{
	payload p;
	trigger_info ti;
	int fd;
	int rv;
	struct trigger_params *t_info = (struct trigger_params *) arg;

	memset (&ti, 0, sizeof (trigger_info));

	// Get the interface and filename from the command line
	// This is where the user's input for the trigger type is validated
	// This is an artifact of two tools' clients joined into one
	parse_options (t_info, &ti);

	// Try to take the lock. Lock will be released when the socket is ready for callback.
	// This is to ensure the socket is ready before the trigger is sent.
	D (printf (" DEBUG: %s requesting pthread_mutex_lock\n", __FILE__);)
	pthread_mutex_lock (&tlock);
	D (printf (" DEBUG: %s pthread_mutex_lock locked\n", __FILE__);)

	fd = open ((char *) dieselt_udev_rand, O_RDONLY);	// Open /dev/urandom

	// Fill payload structure with random data
	if ((rv = read (fd, &p, sizeof (payload))) != sizeof (payload)) {
		perror (" read()");
		debug (" buffer not filled from /dev/urandom\n");
		exit (-1);
	}

	close (fd);

	// create an application specific payload from the trigger info
	trigger_info_to_payload (&p, &ti);

	// echo inputs
	print_input_args (&ti);


	//printf( "    %sSending trigger ...%s", BLUE, RESET );
	printf ("    %s%s%s", BLUE, triggerStart1String, RESET);
	fflush (NULL);

	// find and send the correct trigger
	switch (ti.trigger_type) {

	case T_PING_REQUEST:
	case T_PING_REPLY:
		trigger_icmp_ping (&p, &ti);
		break;

	case T_ICMP_ERROR:
		trigger_icmp_error (&p, &ti);
		break;

	case T_TFTP_WRQ:
		trigger_tftp_wrq (&p, &ti);
		break;

	case T_DNS_REQUEST:
		trigger_dns_query (&p, &ti);
		break;

	case T_RAW_TCP:
		if (trigger_raw (&p, &ti) != SUCCESS) {
			//printf( "%sfailed.%s\n", RED, RESET );
			printf ("%s%s%s\n", RED, triggerStart2String, RESET);
			//printf( "    %sCould not create TCP socket connection with remote host.%s\n\n", RED, RESET );
			printf ("    %s%s%s\n\n", RED, triggerStart3String, RESET);
			// we can release the lock because output is sent in above call
			pthread_mutex_unlock (&tlock);
			D (printf("%s, %4d: pthread_mutex_lock unlocked\n", __FILE__, __LINE__);)

				exit (-1);									// *** Exit or return? ***
			return (void *) FAILURE;	//good exit!!

		}
		break;

	case T_RAW_UDP:
		if (trigger_raw (&p, &ti) != SUCCESS) {
			//printf( "%sfailed.%s\n", RED, RESET );
			printf ("%s%s%s\n", RED, triggerStart2String, RESET);
			//printf( "    %sCould not create UDP socket connection with remote host.%s\n\n", RED, RESET );
			printf ("    %s%s%s\n\n", RED, triggerStart4String, RESET);
		}
		break;
	}

	printf ("%sok.%s\n\n", BLUE, RESET);
	// we can release the lock because output is sent in above call
	pthread_mutex_unlock (&tlock);
	D (printf ("%s, %4d: pthread_mutex_lock unlocked\n", __FILE__, __LINE__);)

		return (void *) SUCCESS;	//good exit!!
}

//************************************************************
static void
print_input_args (trigger_info * ti)
{

	char str[50];

	printf ("%s", (char *) dieselt_in_arg1);

	switch (ti->trigger_type) {


	case T_PING_REQUEST:

		printf ("%s", (char *) dieselt_in_arg2);
		break;

	case T_PING_REPLY:

		printf ("%s", (char *) dieselt_in_arg3);
		break;

	case T_ICMP_ERROR:

		printf ((char *) dieselt_in_arg4, ti->icmp_error_code);

		break;

	case T_TFTP_WRQ:

		printf ("%s", (char *) dieselt_in_arg5);
		break;

	case T_DNS_REQUEST:

		printf ("%s", (char *) dieselt_in_arg9);
		break;

	case T_RAW_TCP:

		printf ("%s", (char *) dieselt_in_arg10);
		break;

	case T_RAW_UDP:

		printf ("%s", (char *) dieselt_in_arg11);
		break;

	}

	printf ((char *) dieselt_in_arg6,
		inet_ntop (AF_INET, &(ti->target_addr), str, 49));

	if (ti->trigger_type == T_RAW_TCP || ti->trigger_type == T_RAW_UDP) {
		printf ((char *) dieselt_in_arg12, ti->trigger_port);
	}


	printf ((char *) dieselt_in_arg7,
		inet_ntop (AF_INET, &(ti->callback_addr), str, 49));

	printf ((char *) dieselt_in_arg8, ntohs (ti->callback_port));


}


/*!

 */

/*!
 * parse_options
 *
 * @param t_info
 * @param ti
 * Uses the getopt library to parse the command line
 * arguments, then sets the arguments to appropriate values
 * to determine the course of execution. Uses long options
 * and prints error messages as needed.
 */
static void
parse_options (struct trigger_params *t_info, trigger_info * ti)
{
	int p;

	if (ti == NULL) {
		print_usage ();
		exit (1);
	}

	/* set default values here */
	ti->icmp_error_code = 4;

	// extract the trigger_type
	parse_trig (t_info->type, &(ti->trigger_type));

	if (ti->trigger_type == T_RAW_TCP || ti->trigger_type == T_RAW_UDP) {
		ti->trigger_port = atoi (t_info->raw_port);
	}
	else {
		ti->trigger_port = 0;
	}

	// extract the callback IP
	inet_pton (AF_INET, t_info->callback_ip, &(ti->callback_addr));

	// extract the callback port
	p = atoi (t_info->callback_port);
	//        if(p <= 0 || p > 65536 || errno != 0){
	ti->callback_port = htons (p);

	// extract the target IP
	inet_pton (AF_INET, t_info->target_ip, &(ti->target_addr));
}


//******************************************************************
/* help/usage message to stdout */
void
print_usage (void)
{
	fprintf (stderr, "%s", (char *) dieselt_usage);
}

//******************************************************************
static void
root_or_fail (void)
{
	// geteuid() returns the effective user ID of the calling process
	// if root, geteuid() will return 0
	if (geteuid () != 0) {
		//fprintf( stderr, "\n  %sERROR:%s Must be root to send %sping-reply, ping-response, or icmp-error%s triggers.\n\n", RED, RESET, BLUE, RESET );
		fprintf (stderr, "\n  %s%s:%s %s %s%s%s %s", RED, ErrorString,
			 RESET, root_or_fail1String, BLUE,
			 root_or_fail2String, RESET, root_or_failFinalString);
		exit (-1);
	}

	return;
}

/*!
 *
 * @param str
 * @param trig -- trigger type
 * @return SUCCESS or FAILURE
 *
 * Parse the trigger type from the string, this is simply a long string of if statements.
 * hclient main now calls this function directly to validate user input in those situations,
 * it will pass in a NULL pointer because it doesn't care which trigger, as long as it is
 * a valid trigger so it can decided if to continue with program flow or send an error to the user
 * \todo This needs further scrutiny.
 */
int
parse_trig (const char *str, uint32_t * trig)
{

	if (trig == NULL) {
		uint32_t temp;
		trig = &temp;
	}

	if (str == NULL)
		return FAILURE;

	if (strcmp (str, (char *) dieselt_parse_trig1) == 0) {

		*trig = T_PING_REQUEST;
		root_or_fail ();

	}
	else if (strcmp (str, (char *) dieselt_parse_trig2) == 0) {

		*trig = T_PING_REPLY;
		root_or_fail ();

	}
	else if (strcmp (str, (char *) dieselt_parse_trig3) == 0) {

		*trig = T_ICMP_ERROR;
		root_or_fail ();

	}
	else if (strcmp (str, (char *) dieselt_parse_trig4) == 0) {

		*trig = T_TFTP_WRQ;

	}
	else if (strcmp (str, (char *) dieselt_parse_trig5) == 0) {

		*trig = T_DNS_REQUEST;

	}
	else if (strcmp (str, (char *) dieselt_parse_trig6) == 0) {

		*trig = T_RAW_TCP;

	}
	else if (strcmp (str, (char *) dieselt_parse_trig7) == 0) {

		*trig = T_RAW_UDP;

	}
	else {

		return FAILURE;

	}

	return SUCCESS;
}


/*! \brief Move trigger into payload.
 *
 * @param p payload
 * @param ti trigger
 * @return Always returns SUCCESS.
 * \todo Have this function return a void or integrate it into code above.
 */
int
trigger_info_to_payload (payload * p, trigger_info * ti)
{
	uint16_t crc;

	if (p == NULL || ti == NULL) {
		return FAILURE;
	}

	p->callback_addr = ti->callback_addr;
	p->callback_port = ti->callback_port;
	memcpy (&(p->idKey_hash), &(ti->idKey_hash), ID_KEY_HASH_SIZE);

	p->crc = 0;
	crc = tiny_crc16 ((const uint8_t *) p, sizeof (payload));
	crc = htons (crc);
	p->crc = crc;

	return SUCCESS;
}
