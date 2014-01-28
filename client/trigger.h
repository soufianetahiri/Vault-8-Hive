#ifndef __TRIGGER_H
#define __TRIGGER_H

#include "trigger_protocols.h"
#include "trigger_utils.h"

struct trigger_params 
{
	int		padding;
	char		*callback_ip;
	char		*callback_port;
	char		*target_ip;
	char		*raw_port;
	char		*type;
	unsigned char	triggerKey[ID_KEY_HASH_SIZE];
};

int
trigger_info_to_payload( Payload * p, trigger_info * ti);

void * trigger_start( void * );
int parse_trig( const char * str, uint32_t* trig);

#endif
