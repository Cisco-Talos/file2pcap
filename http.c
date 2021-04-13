#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define  __FAVOR_BSD
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdlib.h>


#include "file2pcap.h"
#include "helpers.h"
#include "crc32.h"
#include "http.h"

extern int packetLen4, packetLen6;

/**************************************************************************/


int httpGetRequest(struct handover *ho) {
	char *encoded=NULL;


        char requestEnd[] =	"Host: wrl\r\n"
				"User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.17) Gecko/20081007 Firefox/2.0.0.17\r\n"
                                "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
                                "Accept-Language: en-us,en;q=0.5\r\n"
                                "Accept-Encoding: gzip,deflate\r\n"
                                "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
                                "Keep-Alive: 300\r\n"
                                "Connection: keep-alive\r\n\r\n";
        char tmp[700];


	encoded=URLencoder(ho->srcFile);

	if(encoded==NULL)
		exit(-1);


        snprintf(tmp, sizeof(tmp)-1,"GET /file2pcap/%s HTTP/1.1\r\n%s", encoded, requestEnd);

	tcpSendString(ho, tmp, TO_SERVER);


return(0);
}

/**************************************************************************/


int httpPostRequest(struct handover *ho) {
	char tmp[850];
	int fullSize=0;
        char requestStart[] =  	"POST /file2pcap.cgi HTTP/1.1\r\n"
				"Host: wrl\r\n"
                                "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.17) Gecko/20081007 Firefox/2.0.0.17\r\n"
                                "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
                                "Accept-Language: en-us,en;q=0.5\r\n"
				"Content-Length: ";
				
	char requestCenter[] =	"\r\nContent-Type: multipart/form-data; boundary=---------------------------8173728711543081858379436204\r\n"
                                "Accept-Encoding: gzip,deflate\r\n"
                                "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
                                "Keep-Alive: 300\r\n"
                                "Connection: keep-alive\r\n\r\n"
				"-----------------------------8173728711543081858379436204\r\n"
				"Content-Disposition: form-data; name=\"file\"; filename=\"";

	char requestEnd[] =	"\"\r\nContent-Type: application/octet-stream\r\n\r\n";


	//Calculating the content-length: everything after the http header
	fullSize = 	strlen("-----------------------------8173728711543081858379436204\r\n") +
			strlen("Content-Disposition: form-data; name=\"file\"; filename=\"") + 
			strlen(ho->srcFile) + 
			strlen("\"\r\nContent-Type: application/octet-stream\r\n\r\n") + 
			(int)ho->inFileSize +
			strlen("\r\n-----------------------------8173728711543081858379436204--\r\n");


        snprintf(tmp, sizeof(tmp)-1,"%s%d%s%s%s", requestStart, fullSize, requestCenter, ho->srcFile, requestEnd);

	tcpSendString(ho, tmp, TO_SERVER);


return(0);
}


/**************************************************************************************************/

int httpPostFinalBoundary(struct handover *ho) {
	char finalBoundary[] =	"\r\n-----------------------------8173728711543081858379436204--\r\n";

	tcpSendString(ho, finalBoundary, TO_SERVER);   

return 0;
}

/************************************************************************************************************************/

int httpGetRequestAcknowledge(struct handover *ho) {
	char http_header_default[] =	"HTTP/1.1 200 Ok\r\n"
                                	"Date: Fri, 21 Sep 2018 13:35:26 GMT\r\n"
                                	"Server: Apache/2.2.3 (Debian) PHP/5.2.0-8+etch10 mod_ssl/2.2.3 OpenSSL/0.9.8c\r\n"
                                	"Last-Modified: Sat, 20 Jan 2018 12:01:21 GMT\r\n"
                                	"ETag: \"a801c-1bbd1c-22416640\"\r\n"
                                	"Accept-Ranges: bytes\r\n"
                                	"Content-Length: ";
	char http_header_chunked[] =	"HTTP/1.1 200 Ok\r\n"
                                	"Date: Fri, 21 Sep 2018 13:35:26 GMT\r\n"
                                	"Server: Apache/2.2.3 (Debian) PHP/5.2.0-8+etch10 mod_ssl/2.2.3 OpenSSL/0.9.8c\r\n"
                                	"Last-Modified: Sat, 20 Jan 2018 12:01:21 GMT\r\n"
                                	"ETag: \"a801c-1bbd1c-22416640\"\r\n"
                                	"Accept-Ranges: bytes\r\n"
					"Connection: close\r\n"
					"Content-Type: text/html\r\n"
                                	"Transfer-Encoding: chunked\r\n\r\n";
	char http_header_gzip_chunked[] =	"HTTP/1.1 200 Ok\r\n"
                                		"Date: Fri, 21 Sep 2018 13:35:26 GMT\r\n"
                                		"Server: Apache/2.2.3 (Debian) PHP/5.2.0-8+etch10 mod_ssl/2.2.3 OpenSSL/0.9.8c\r\n"
                                		"Last-Modified: Sat, 20 Jan 2018 12:01:21 GMT\r\n"
                                		"ETag: \"a801c-1bbd1c-22416640\"\r\n"
                                		"Accept-Ranges: bytes\r\n"
                                		"Transfer-Encoding: chunked\r\n";
        char http_tail_default[] =  	"\r\n"
                                	"Keep-Alive: timeout=15, max=99\r\n"
                                	"Connection: Keep-Alive\r\n"
                                	"Content-Type: application/octet-stream\r\n\r\n";

	char http_tail_gzip[] =		"\r\n"
					"Vary: Accept-Encoding\r\n"
					"Content-Encoding: gzip\r\n"
					"Connection: close\r\n"
					"Content-Type: text/html; charset=UTF-8\r\n\r\n"
					"\x1F\x8B\x08\x00\x00\x00\x00\x00\x00\x03";
	char http_tail_gzip_chunked[] =	"Vary: Accept-Encoding\r\n"
					"Content-Encoding: gzip\r\n"
					"Connection: close\r\n"
					"Content-Type: text/html\r\n\r\n";
	char http_tail_gzip_chunked2[] = "\x1F\x8B\x08\x00\x00\x00\x00\x00\x00\x03";
        char headerBuffer[500];



	if(ho->httpEncoder == ENC_HTTP_DEFAULT)
	{
	        snprintf(headerBuffer,sizeof(headerBuffer)-1,"%s%d%s", http_header_default, (unsigned int)ho->inFileSize, http_tail_default);
		tcpSendString(ho, headerBuffer, FROM_SERVER);
	}
	else if (ho->httpEncoder == ENC_HTTP_GZIP)
	{
		char zipSize[33];
		memset(zipSize, 0, sizeof(zipSize));
		snprintf(zipSize, sizeof(zipSize)-1,"%d", ((unsigned int)ho->inFileSize)+12); //12 = 10 bytes gzip header + 8 bytes tail - 6 bytes we skip from temp file
		snprintf(headerBuffer, sizeof(headerBuffer)-1,"%s%s", http_header_default, zipSize); 
		memcpy(headerBuffer + sizeof(http_header_default) + strlen(zipSize)-1, &http_tail_gzip, sizeof(http_tail_gzip));
		tcpSendData(ho, headerBuffer, sizeof(http_header_default)-1 + 4 + sizeof(http_tail_gzip)-1 - 1, FROM_SERVER); 
	}
	else if (ho->httpEncoder == ENC_HTTP_CHUNKED)
	{
		tcpSendData(ho, http_header_chunked, sizeof(http_header_chunked)-1, FROM_SERVER); 
	}
	else if (ho->httpEncoder == ENC_HTTP_GZIP_CHUNKED)
	{
		snprintf(headerBuffer, sizeof(headerBuffer)-1,"%s", http_header_gzip_chunked);
		memcpy(headerBuffer + sizeof(http_header_gzip_chunked)-1, &http_tail_gzip_chunked, sizeof(http_tail_gzip_chunked)-1);
		tcpSendData(ho, headerBuffer, sizeof(http_header_gzip_chunked) - 1 + sizeof(http_tail_gzip_chunked) - 1, FROM_SERVER); 
		tcpSendHttpChunked(ho, http_tail_gzip_chunked2, sizeof(http_tail_gzip_chunked2)-1, FROM_SERVER);
	}



return(0);
}

/**************************************************************************************************************/


int httpTransferFile(struct handover *ho) {
        int packetLen, checksum = -1, chunkLen;
        unsigned int count;
        char buffer[1500], temp[10];
	struct pcap_packet_header ph;
	FILE *sourceFile=NULL;


	sourceFile = ho->inFile;

	if(ho->httpEncoder == ENC_HTTP_GZIP || ho->httpEncoder == ENC_HTTP_GZIP_CHUNKED)
		sourceFile = ho->tmpFile;
	
	if(sourceFile != NULL)
		rewind(sourceFile);


	//skip the first 2 bytes, the 'magic' in the temp file created by lib z
	if(ho->httpEncoder == ENC_HTTP_GZIP || ho->httpEncoder == ENC_HTTP_GZIP_CHUNKED)
		count=read(fileno(sourceFile), buffer, 2);
 

	if(ho->ipV == 4)
		packetLen = packetLen4;
	else
		packetLen = packetLen6;



        while(!(feof(sourceFile)))
        {
                count=read(fileno(sourceFile), buffer, ho->blockSize);

		if(count<=0)
		{
			if(ho->httpEncoder == ENC_HTTP_GZIP || ho->httpEncoder == ENC_HTTP_GZIP_CHUNKED) 
			{
				httpGzipTail(ho);
			}
			else if(ho->httpEncoder == ENC_HTTP_CHUNKED) 
			{
				tcpSendHttpChunked(ho, NULL, 0, TO_SERVER);
			}

                        return 0;
                }

		if(ho->httpEncoder == ENC_HTTP_CHUNKED || ho->httpEncoder == ENC_HTTP_GZIP_CHUNKED)
		{
			tcpSendHttpChunked(ho, buffer, count, TO_SERVER);
		}
		else
		{
			tcpSendData(ho, buffer, count, TO_SERVER);
		}

        }

return(0);
}

/************************************************************************************************************************/

//sends checksum and file size after the gzipped file
int httpGzipTail(struct handover *ho) {
        char buffer[10];
	int checksum=-1;

	checksum = crc32(ho);


	memcpy(buffer, &checksum, 4);
	memcpy(buffer+4, &ho->inFileSize, 4);

	if(ho->httpEncoder == ENC_HTTP_GZIP_CHUNKED)
	{
		tcpSendHttpChunked(ho, buffer, 8, FROM_SERVER);
		tcpSendHttpChunked(ho, NULL, 0, FROM_SERVER);
	}
	else
		tcpSendData(ho, buffer, 8, FROM_SERVER);


return(0);
}

/**************************************************************************************************************************/

int tcpSendHttpChunked(struct handover *ho, char *buffer, int length, char direction) {
	char chunkTail[] = "\x30\x0d\x0a\x0d\x0a";
	static char sendBuffer[3000];
	char buildBuffer[1600];
	static int bufferLength=0;
	char *bufferIndex=NULL;
	int buildBufferLength,i;

	if(length != 0)
	{
		bufferIndex = (char*)sendBuffer + bufferLength;
	
		if((bufferLength + length) < sizeof(sendBuffer))
		{
			memcpy(bufferIndex, buffer, length);
			bufferLength += length;
		}
		else
		{
			printf("Error: Sendbuffer too small\n");
			return -1;
		}

		bufferIndex = sendBuffer;

		while((bufferLength / length) > 0)
		{
			if(ho->blockSize > (sizeof(sendBuffer)-20))	
			{
				printf("Error: Block size too big\n");
				return -1;
			}

			snprintf(buildBuffer, sizeof(buildBuffer)-1,"%x\r\n", length);
			buildBufferLength = strlen(buildBuffer);
			memcpy((char*)buildBuffer + buildBufferLength, bufferIndex, length);
		       	buildBuffer[buildBufferLength + length] = 0x0d;
		       	buildBuffer[buildBufferLength + length+1] = 0x0a;

			tcpSendData(ho, buildBuffer, buildBufferLength + length + 2, FROM_SERVER);
			bufferLength -= length;
			bufferIndex += length;
		}

		//copy the unsent remainder to the start of the buffer
		if((bufferLength % length)!= 0)
			memcpy(sendBuffer, bufferIndex, bufferLength % length);
	}
	else
	{
		bufferIndex = sendBuffer;
		if(bufferLength != 0)
		{
			snprintf(buildBuffer, sizeof(buildBuffer)-1,"%x\r\n", bufferLength);
			buildBufferLength = strlen(buildBuffer);
			memcpy((char*)buildBuffer + buildBufferLength, bufferIndex, bufferLength);
		       	buildBuffer[buildBufferLength + bufferLength] = 0x0d;
		       	buildBuffer[buildBufferLength + bufferLength+1] = 0x0a;

			tcpSendData(ho, buildBuffer, buildBufferLength + bufferLength + 2, FROM_SERVER);
			bufferLength = 0;
			bufferIndex = sendBuffer;
		}
		tcpSendData(ho, chunkTail, sizeof(chunkTail)-1, FROM_SERVER);
	}
return 0;
}
