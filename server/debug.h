#ifndef DEBUG_H
#define DEBUG_H

#ifdef DEBUG
#define D(x) x
#include <stdio.h>
#include <errno.h>

#define sprintf_s(x, ...) snprintf(x, __VA_ARGS__)
//#define	debug_error(x, ...) fprintf( stderr, x, __VA_ARGS__ )
#define	debug_error(x, ...)
//#define debug_msg(x, ...) fprintf( stderr,x,__VA_ARGS__ )
#define debug_msg(x, ...)
#define	xs(x)	x
#define DBG D(printf(" DEBUG: %s:%i\n", __FILE__, __LINE__);)

#else
#define D(x)
#define	debug_error(x, ...)
#define debug_msg(x, ...)
#define xs(x) "%x"
#endif

#endif //_DEBUG_H
