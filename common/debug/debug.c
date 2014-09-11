/*
 * debug.c
 *
 */
#include "debug.h"

void debug_print_buffer(const char *line_preface, const unsigned char *buf, const size_t len)
{
    size_t i;

	for( i = 0; i < len; i++ ) {

        if( i >= 4096 )
            break;

        if (i % 16 == 0)
        	fprintf(stdout, "\n%s%4x: ", line_preface, i);
        else
        	fprintf(stdout, " ");

        fprintf (stdout, "%02x", buf[i]);

    }
	fprintf(stdout, "\n");
    if( len % 16 )
        fprintf(stdout, "\n");
}
