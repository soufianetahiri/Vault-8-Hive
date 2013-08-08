#ifndef TIMEOUT_H
#define TIMEOUT_H

#include "function_strings.h"

#ifdef WIN32
int timeoutSetup(int waittime, int* socket);
int endTimeout();
#endif

#endif
