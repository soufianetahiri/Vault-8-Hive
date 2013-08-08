/*
* Adapted from linux xxd
*/

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "bzlib.h"

//for compression use this
#define USING_COMPRESSION

#ifdef USING_COMPRESSION
void bz_internal_error(int errcode)
{
	(void)errcode;
	return;
}
#endif

int main( int argc, char **argv )
{
	FILE *fd_in, *fd_out, *fd_comp;
	int cnt = 0;
	char c;
	char *array_name = *(argv+1);
#ifdef USING_COMPRESSION
	int ret = 0;
	int fdinsize =0;
	unsigned char* compressionbuff = NULL;
	unsigned int* compressedSize = NULL;
	char* needtocompressbuff = NULL;
#endif

	if ( argc != 3 )
	{
		printf( " USAGE: %s <infile> <outfile>\n", *argv );
		return -1;
	}

	if ( ( fd_in = fopen( *(argv + 1), "rb" ) ) < 0 )
	{
		perror( "open()" );
		return -1;
	}

	if ( ( fd_out = fopen( *(argv + 2), "wb" ) ) < 0 )
	{
		perror( "open()" );
		return -1;
	}

	//compression
#ifdef USING_COMPRESSION

	compressedSize = (unsigned int*) malloc(sizeof(unsigned int));
	fseek(fd_in,0,SEEK_END );
	fdinsize = ftell(fd_in);
	fseek(fd_in, 0, SEEK_SET);
	*compressedSize = fdinsize;
	compressionbuff = (unsigned char*) malloc(*compressedSize);
	memset(compressionbuff,0,*compressedSize);

	needtocompressbuff = (char *) malloc(fdinsize);

	memset(needtocompressbuff,0,*compressedSize);

	fread(needtocompressbuff, sizeof(char),fdinsize,fd_in);

	ret = BZ2_bzBuffToBuffCompress((char*)compressionbuff,compressedSize,needtocompressbuff,fdinsize,9,0,30);
	if(ret != BZ_OK)
	{
		return NULL;
	}


	//createfile
	fd_comp = fopen( "test", "wb" );
	fwrite(compressionbuff, sizeof(char),*compressedSize, fd_comp);
	fclose(fd_in);
	fflush(fd_comp);
	fclose(fd_comp);
	fd_in = fopen( "test", "rb");
	//writetoit the compressed buffer
	//now change everything to that compressed file (file pointers and ish)

	free(needtocompressbuff);
	free(compressionbuff);
	free(compressedSize);
#endif

	fprintf( fd_out, "unsigned char util[] = {", array_name );//"unsigned char %s[] = {", array_name );

	while ( fread( &c, 1, 1, fd_in ) > 0 )
	{
		if ( cnt != 0 )
		{
			fprintf( fd_out, ", " );
		}

		if ( cnt % 12 == 0 )
		{
			fprintf( fd_out, "\n " );
		}

		cnt++;

		fprintf( fd_out, "0x%.2X", (unsigned char)c );
	}
	fprintf( fd_out, "\n};\n" );
	fprintf( fd_out, "unsigned int util_len = %i;\n", cnt );//"unsigned int %s_len = %i;\n", array_name, cnt );

#ifdef USING_COMPRESSION
	fprintf( fd_out, "unsigned int decompr_len = %i;\n", fdinsize);
#endif

	fclose( fd_in );
	fclose( fd_out );

	return 0;
} 