/* zpipe.c: example of proper use of zlib's inflate() and deflate()
   Not copyrighted -- provided to the public domain
   Version 1.4  11 December 2005  Mark Adler */


#include <stdio.h>
#include <string.h>
#include <assert.h>
// #include <sys/stat.h>

#include "zlib.h"
#include "file2pcap.h"


#if defined(MSDOS) || defined(OS2) || defined(WIN32) || defined(__CYGWIN__)
#  include <fcntl.h>
#  include <io.h>
#  define SET_BINARY_MODE(file) setmode(fileno(file), O_BINARY)
#else
#  define SET_BINARY_MODE(file)
#endif

#define CHUNK 16384

int compressGzip(struct handover *ho)
{
	int ret, flush;
	int level = Z_DEFAULT_COMPRESSION;
	unsigned have;
	z_stream strm;
	unsigned char in[CHUNK];
	unsigned char out[CHUNK];
	FILE *source, *dest;
	struct stat fileStat;


	source=ho->inFile;

	if((ho->tmpFile=fopen(TMP_FILE, "w+"))==NULL)
	{
		printf("Error: Failed to create temporary file %s!", TMP_FILE);
		return -1;
	}
	dest = ho->tmpFile;



	SET_BINARY_MODE(source);
	SET_BINARY_MODE(dest);

	
	if(source != NULL)
		rewind(source);

	/* allocate deflate state */
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;

	ret = deflateInit(&strm, level);

	if (ret != Z_OK)
		return ret;

	/* compress until end of file */
	do 
	{
		strm.avail_in = fread(in, 1, CHUNK, source);
		if (ferror(source)) 
		{
			(void)deflateEnd(&strm);
			return Z_ERRNO;
		}
		flush = feof(source) ? Z_FINISH : Z_NO_FLUSH;
		strm.next_in = in;

		/* run deflate() on input until output buffer not full, finish
		compression if all of source has been read in */
		
		do 
		{
			strm.avail_out = CHUNK;
			strm.next_out = out;
			ret = deflate(&strm, flush);    /* no bad return value */
			assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
			have = CHUNK - strm.avail_out;
			
			if (fwrite(out, 1, have, dest) != have || ferror(dest)) 
			{
				(void)deflateEnd(&strm);
				return Z_ERRNO;
			}
		} while (strm.avail_out == 0);

		assert(strm.avail_in == 0);     /* all input will be used */

		/* done when last data in file processed */
	} while (flush != Z_FINISH);

	assert(ret == Z_STREAM_END);        /* stream will be complete */

	/* clean up and return */
	(void)deflateEnd(&strm);



	//That code above writes 2 bytes header into the file as well as 4 trailing bytes(checksum), which I don't need
	//I get rid of the checksum here(and read past the first 2 bytes in the file transfer function)
	rewind(ho->tmpFile);
	if(fstat(fileno(ho->tmpFile), &fileStat)==-1)
	{
		printf("Error: Could not determine file size of temporary file\n");
		return -1;
	}

	if((ret = ftruncate(fileno(ho->tmpFile), (int)fileStat.st_size-4)) < 0)
	{
		printf("Error: Failed to truncate temporary file\n");
		return -1;
	}




return Z_OK;
}

/***********************************************************************************************************/

