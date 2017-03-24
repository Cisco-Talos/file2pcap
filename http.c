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


extern int packetLen4, packetLen6;
extern struct stat fileStat;

/**************************************************************************/


int httpGetRequest(struct handover *ho) {
	char *encoded=NULL;


        char requestEnd[] =   "Host: wrl\r\n"
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
			(int)fileStat.st_size +
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
        char http_header[] =    "HTTP/1.1 200 Ok\r\n"
                                "Date: Wed, 29 Jul 2009 13:35:26 GMT\r\n"
                                "Server: Apache/2.2.3 (Debian) PHP/5.2.0-8+etch10 mod_ssl/2.2.3 OpenSSL/0.9.8c\r\n"
                                "Last-Modified: Sun, 20 Jan 2008 12:01:21 GMT\r\n"
                                "ETag: \"a801c-1bbd1c-22416640\"\r\n"
                                "Accept-Ranges: bytes\r\n"
                                "Content-Length: ";
        char http_header_2[] =  "\r\n"
                                "Keep-Alive: timeout=15, max=99\r\n"
                                "Connection: Keep-Alive\r\n"
                                "Content-Type: application/octet-stream\r\n\r\n";
        char headerBuffer[500];

        snprintf(headerBuffer,sizeof(headerBuffer)-1,"%s%d%s", http_header, (unsigned int)fileStat.st_size, http_header_2);

	//this line replaces all the old code below. And it also gets the ethernet addresses right, unlike before
	tcpSendString(ho, headerBuffer, FROM_SERVER);

return(0);
}

/**************************************************************************************************************/


int httpTransferFile(struct handover *ho) {
        int packetLen;
        unsigned int count;
        char buffer[1500];
	struct pcap_packet_header ph;


        if(ho->inFile != NULL)
                rewind(ho->inFile);

        //initialize ph with the current values
	ph.time = ho->time;
	ph.usec = ho->usec;



	if(ho->ipV == 4)
		packetLen = packetLen4;
	else
		packetLen = packetLen6;



        while(!(feof(ho->inFile)))
        {
                count=read(fileno(ho->inFile), buffer, 1200);

                if(count<=0)
                {
			ho->time = ph.time;
			ho->usec = ph.usec;
                        return 0;	//FIXME ??
                }


                ph.usec += INTERVAL;
                if((ph.usec + INTERVAL) >= 1000000)
                {
                        ph.time+=1;
                        ph.usec=0;
                }


                ph.length1 = packetLen + count;
                ph.length2 = packetLen + count;


                write(fileno(ho->outFile), &ph, sizeof(struct pcap_packet_header));

		if(ho->direction == FROM_SERVER)
	                write(fileno(ho->outFile), ho->fromEther, sizeof(ho->fromEther)-1);
		else
			write(fileno(ho->outFile), ho->toEther, sizeof(ho->toEther)-1);
		


                craftTcp(buffer, count, ho->direction == FROM_SERVER ? FROM_SERVER : TO_SERVER, TH_ACK|TH_PUSH, ho);  

                //and now send the ack
                ph.usec+=INTERVAL;
                ph.length1=packetLen;
                ph.length2=packetLen;
                write(fileno(ho->outFile), &ph, sizeof(struct pcap_packet_header));

		if(ho->direction == FROM_SERVER)
	                write(fileno(ho->outFile), ho->toEther, sizeof(ho->toEther)-1);
		else
	                write(fileno(ho->outFile), ho->fromEther, sizeof(ho->fromEther)-1);



                craftTcp(NULL,0, ho->direction == FROM_SERVER ? TO_SERVER : FROM_SERVER, TH_ACK, ho);    //direction - client to server
        }

	ho->time = ph.time;
	ho->usec = ph.usec;	



return(0);
}

