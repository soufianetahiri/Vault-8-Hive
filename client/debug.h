#ifndef __DEBUG_H
#define __DEBUG_H

#ifdef DEBUG
#include <stdio.h>
#include <errno.h>
#define D(x)	x
#else
#define D(x)
#endif

#endif //__DEBUG_H
