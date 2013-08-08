#ifndef __PERSISTENCE_H
#define __PERSISTENCE_H

#include "function_strings.h"

#ifdef _WINDLL
int EnablePersistence();
#else
int EnablePersistence(char* beaconIP, int beaconPort);
#endif

#endif //__PERSISTENCE_H

