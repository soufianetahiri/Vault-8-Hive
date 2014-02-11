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

#if defined LINUX 
#include <getopt.h>
#endif

#if defined SOLARIS
#include <unistd.h>
#endif

#endif
