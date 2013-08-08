#include "cry_strings_main.h"

extern unsigned char my_dhm_P_String[257];
extern unsigned char my_dhm_G_String[2];
extern unsigned char test_ca_crt_String[1531];
extern unsigned char test_srv_crt_String[1707];
extern unsigned char test_srv_key_String[1703];

void cl_cry_string(unsigned char *str, int len);
 
void cl_cry_string(unsigned char *str, int len) 
{
    int i;
    for (i = 0; i< len; i++) {
        str[i] = ~str[i];
    }
}

void init_cry_strings(void)
{
    printf("\n\n Running init_cry_strings\n\n");
	cl_cry_string(my_dhm_P_String, 257);
	cl_cry_string(my_dhm_G_String, 2);
	cl_cry_string(test_ca_crt_String, 1531);
	cl_cry_string(test_srv_crt_String, 1707);
	cl_cry_string(test_srv_key_String, 1703);
    return;
}

