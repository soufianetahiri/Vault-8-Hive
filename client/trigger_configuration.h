#ifndef _DIESELT_CONFIG_H
#define _DIESELT_CONFIG_H

#include "trigger_utils.h"
#include "trigger_protocols.h"

// OPCODES
#define _DIESEL_OPCODE_TBOT 0

/* int  */
/* application_to_opcode( char * optarg, */
/* 		       uint8_t * ti ); */

int 
trigger_info_to_payload( payload * p, 
			 trigger_info * ti);


#endif
