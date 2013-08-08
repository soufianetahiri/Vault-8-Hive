/* Getopt for GNU.
   NOTE: getopt is now part of the C library, so if you don't know what
   "Keep this file name-space clean" means, talk to roland@gnu.ai.mit.edu
   before changing it!

Copyright (C) 1987, 88, 89, 90, 91, 92, 93, 94
Free Software Foundation, Inc.

This file is part of the GNU C Library.  Its master source is NOT part of
the C library, however.  The master source lives in /gd/gnu/lib.

Modifications:
- Changed the calling convention to fit C++ compiler.
- Removed all code concerning order.  The library modifies the order
  of the arguments so that non-option arguments can be interspersed with
  option arguments.
- Simplified ifdefs and compiling options to optimize for Windows.
- Removed all calls that need stdlib.h
*/
#ifndef __GETOPT_H
#define __GETOPT_H

#ifdef WIN32

#ifdef	__cplusplus
extern "C" {
#endif

/* For communication from `getopt' to the caller.
   When `getopt' finds an option that takes an argument,
   the argument value is returned here.
   Also, when `ordering' is RETURN_IN_ORDER,
   each non-option ARGV-element is returned here.  */
extern LPTSTR optarg;

/* Index in ARGV of the next element to be scanned.
   This is used for communication to and from the caller
   and for communication between successive calls to `getopt'.

   On entry to `getopt', zero means this is the first call; initialize.

   When `getopt' returns EOF, this is the index of the first of the
   non-option elements that the caller should itself scan.

   Otherwise, `optind' communicates from one call to the next
   how much of ARGV has been scanned so far.  */
extern int optind;

/* Callers store zero here to inhibit the error message `getopt' prints
   for unrecognized options.  */
extern int opterr;

/* Set to an option character which was unrecognized.  */
extern TCHAR optopt;

// defined so we don't have to include stdio.h
#ifndef EOF
#define EOF -1
#endif

extern int getopt (int argc, LPTSTR *argv, LPCTSTR shortopts);
extern void getopt_reset();

#ifdef	__cplusplus
}
#endif

#endif // WIN32

#if defined LINUX 
#include <getopt.h>
#endif

#if defined SOLARIS
#include <unistd.h>
#endif

#endif
