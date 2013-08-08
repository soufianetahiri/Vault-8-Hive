#ifndef __THREADS_H
#define __THREADS_H

#include "function_strings.h"

#ifdef WIN32
int make_thread( void (*func)(void *), void *args );
int fork_process( void (*func)(void *), void *args );
#else
int make_thread( void *(*func)(void *), void *args );
int fork_process( void *(*func)(void *), void *args );
#endif
int terminate_thread( void );

#endif //__THREADS_H
