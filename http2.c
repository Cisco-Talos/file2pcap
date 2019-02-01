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

/**************************************************************************/

int http2ConnectionUpgrade(struct handover *ho) {
	char *encoded=NULL;
	char requestEnd[] = 	"Host: wrl\r\n"
                                "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.17) Gecko/20081007 Firefox/2.0.0.17\r\n"
				"Accept: */*\r\n"
				"Connection: Upgrade, HTTP2-Settings\r\n"
				"Upgrade: h2c\r\n"
				"HTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n";

        char tmp[700];


	encoded=URLencoder(ho->srcFile);

	if(encoded==NULL)
		exit(-1);


        snprintf(tmp, sizeof(tmp)-1,"GET /file2pcap/%s HTTP/1.1\r\n%s", encoded, requestEnd);

	tcpSendString(ho, tmp, TO_SERVER);


return(0);
}



/***************************************************************************/

int http2SwitchingProtocols(struct handover *ho) {

	char switchingProtocols[] = 	"HTTP/1.1 101 Switching Protocols\r\n"
					"Connection: Upgrade\r\n"
					"Upgrade: h2c\r\n\r\n";

	tcpSendString(ho, switchingProtocols, FROM_SERVER);

return 0;
}


/***************************************************************************/

int http2ClientMagic(struct handover *ho) {
	char http2Magic[] = 	{	"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
				};
	

	struct pcap_packet_header ph;
	int len, packetLen;


	
	len = strlen(http2Magic);


	ph.time = ho->time;
	ph.usec = ho->usec;

        if(ho->ipV == 4)
                packetLen = packetLen4;
        else
                packetLen = packetLen6;


	ph.length1 = packetLen + len;
	ph.length2 = packetLen + len;


	write(fileno(ho->outFile), &ph, sizeof(struct pcap_packet_header));

	if(ho->direction == FROM_SERVER)
		write(fileno(ho->outFile), ho->fromEther, sizeof(ho->fromEther)-1);
	else
		write(fileno(ho->outFile), ho->toEther, sizeof(ho->toEther)-1);
	
	craftTcp(http2Magic, len, ho->direction == FROM_SERVER ? FROM_SERVER : TO_SERVER, TH_ACK|TH_PUSH, ho);


	//and now send the tcp ack
	ph.usec+=INTERVAL;
	ph.length1=packetLen;
	ph.length2=packetLen;
	write(fileno(ho->outFile), &ph, sizeof(struct pcap_packet_header));

	if(ho->direction == FROM_SERVER)
		write(fileno(ho->outFile), ho->toEther, sizeof(ho->toEther)-1);
	else
		write(fileno(ho->outFile), ho->fromEther, sizeof(ho->fromEther)-1);


	craftTcp(NULL,0, ho->direction == FROM_SERVER ? TO_SERVER : FROM_SERVER, TH_ACK, ho);    


return 0;
}


/***************************************************************************/

int http2ClientSettings(struct handover *ho) {
	char http2Settings[] = {        0x00, 0x00, 0x0c, 			//Length: 12
					0x04, 					//Type: Headers
					0x00, 					//Flags: 0x00
					0x00, 0x00, 0x00, 0x00, 		//Stream identifier: 0x00
					0x00, 0x03, 0x00, 0x00, 0x00, 0x64, 	//Max concurrent streams: 100
					0x00, 0x04, 0x00, 0x00, 0xff, 0xff 	//Initial window size: 0x00, 0x00, 0xff, 0xff
					};	



	struct pcap_packet_header ph;
	int len, packetLen;


	
	len = sizeof(http2Settings);


	ph.time = ho->time;
	ph.usec = ho->usec;

        if(ho->ipV == 4)
                packetLen = packetLen4;
        else
                packetLen = packetLen6;


	ph.length1 = packetLen + len;
	ph.length2 = packetLen + len;


	write(fileno(ho->outFile), &ph, sizeof(struct pcap_packet_header));

	if(ho->direction == FROM_SERVER)
		write(fileno(ho->outFile), ho->fromEther, sizeof(ho->fromEther)-1);
	else
		write(fileno(ho->outFile), ho->toEther, sizeof(ho->toEther)-1);
	
	craftTcp(http2Settings, len, ho->direction == FROM_SERVER ? FROM_SERVER : TO_SERVER, TH_ACK|TH_PUSH, ho);


	//and now send the tcp ack
	ph.usec+=INTERVAL;
	ph.length1=packetLen;
	ph.length2=packetLen;
	write(fileno(ho->outFile), &ph, sizeof(struct pcap_packet_header));

	if(ho->direction == FROM_SERVER)
		write(fileno(ho->outFile), ho->toEther, sizeof(ho->toEther)-1);
	else
		write(fileno(ho->outFile), ho->fromEther, sizeof(ho->fromEther)-1);


	craftTcp(NULL,0, ho->direction == FROM_SERVER ? TO_SERVER : FROM_SERVER, TH_ACK, ho);    



return 0;
}


/***************************************************************************/

int http2ClientGetRequest(struct handover *ho) {
	char *encoded = NULL;	
	char http2HeaderStart[] = {     0x01,   //stream id 1
                                	0x05,   //flags end headers && end stream
                                	0x00, 0x00, 0x00, 0x01, //reserved
                                	0x01, 0x06, 'w','r','l',':','8','0', //authority wrl:80
					0x82,   //method: GET, hufman
                                	0x04
				  }; 
	char http2HeaderCenter[] = {	 '/','f','i','l','e','2','p','c','a','p','/' //path
                          	   };
	char http2HeaderEnd[] =  {      0x86,   //scheme:http
                                	0x53, 0x03, 0x2a, 0x2f, 0x2a,
                                	0x58, 0x08, 'n', 'o', '-', 'c', 'a', 'c', 'h', 'e'   //cache-control: no cache
				  };
	char request[500];
	struct pcap_packet_header ph;
	int len, packetLen;




	memset(request, 0, sizeof(request));
        encoded=URLencoder(ho->srcFile);
        if(encoded==NULL)
                exit(-1);



	request[2]=(char)(sizeof(http2HeaderStart) - 6 + 1 + strlen(encoded) + strlen("/file2pcap/") + sizeof(http2HeaderEnd)); 
        memcpy(request + 3, &http2HeaderStart, sizeof(http2HeaderStart));
        request[3 + sizeof(http2HeaderStart) ]=(char)(strlen(encoded) + strlen("/file2pcap/"));
        memcpy(request + 3 + sizeof(http2HeaderStart) + 1, &http2HeaderCenter, sizeof(http2HeaderCenter));
        memcpy(request + 3 + sizeof(http2HeaderStart) + 1 + strlen("/file2pcap/"), encoded, strlen(encoded));
	memcpy(request + 3 + sizeof(http2HeaderStart) + 1 + strlen("/file2pcap/") + strlen(encoded), http2HeaderEnd, sizeof(http2HeaderEnd));


	len = 3 + sizeof(http2HeaderStart) + 1 + strlen("/file2pcap/") + strlen(encoded) + strlen(http2HeaderEnd);



	
	ph.time = ho->time;
	ph.usec = ho->usec;

        if(ho->ipV == 4)
                packetLen = packetLen4;
        else
                packetLen = packetLen6;


	ph.length1 = packetLen + len;
	ph.length2 = packetLen + len;


	write(fileno(ho->outFile), &ph, sizeof(struct pcap_packet_header));

	if(ho->direction == FROM_SERVER)
		write(fileno(ho->outFile), ho->fromEther, sizeof(ho->fromEther)-1);
	else
		write(fileno(ho->outFile), ho->toEther, sizeof(ho->toEther)-1);
	
	craftTcp(request, len, ho->direction == FROM_SERVER ? FROM_SERVER : TO_SERVER, TH_ACK|TH_PUSH, ho);


	//and now send the tcp ack
	ph.usec+=INTERVAL;
	ph.length1=packetLen;
	ph.length2=packetLen;
	write(fileno(ho->outFile), &ph, sizeof(struct pcap_packet_header));

	if(ho->direction == FROM_SERVER)
		write(fileno(ho->outFile), ho->toEther, sizeof(ho->toEther)-1);
	else
		write(fileno(ho->outFile), ho->fromEther, sizeof(ho->fromEther)-1);


	craftTcp(NULL,0, ho->direction == FROM_SERVER ? TO_SERVER : FROM_SERVER, TH_ACK, ho);    


return 0;
}

/*********************************************************************************************************************************************/

int http2MagicGetRequest(struct handover *ho) {
	char request[500];
	char *encoded=NULL;
	char http2Magic[] = {           "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"};
	char http2Settings[] = {        0x00, 0x00, 0x0c, 			//Length: 12
					0x04, 					//Type: Headers
					0x00, 					//Flags: 0x00
					0x00, 0x00, 0x00, 0x00, 		//Stream identifier: 0x00
					0x00, 0x03, 0x00, 0x00, 0x00, 0x64, 	//Max concurrent streams: 100
					0x00, 0x04, 0x00, 0x00, 0xff, 0xff 	//Initial window size: 0x00, 0x00, 0xff, 0xff
					};	

	char http2HeaderStart[] = {     0x01,   //stream id 1
                                	0x05,   //flags end headers && end stream
                                	0x00, 0x00, 0x00, 0x01, //reserved
                                	0x01, 0x06, 'w','r','l',':','8','0', //authority wrl:80
					0x82,   //method: GET, hufman
                                	0x04
				  }; 
	char http2HeaderCenter[] = {	 '/','f','i','l','e','2','p','c','a','p','/' //path
                          	   };
	char http2HeaderEnd[] =  {      0x86,   //scheme:http
                                	0x53, 0x03, 0x2a, 0x2f, 0x2a,
                                	0x58, 0x08, 'n', 'o', '-', 'c', 'a', 'c', 'h', 'e'   //cache-control: no cache
				  };
	struct pcap_packet_header ph;
	int len, packetLen;



	
	memset(request,0,sizeof(request));

        encoded=URLencoder(ho->srcFile);
        if(encoded==NULL)
                exit(-1);


	snprintf(request, sizeof(request)-1,"%s", http2Magic);
	memcpy(request+strlen(http2Magic), &http2Settings, sizeof(http2Settings));
	request[strlen(http2Magic) + sizeof(http2Settings) + 0]=0x00; 
	request[strlen(http2Magic) + sizeof(http2Settings) + 1]=0x00; 
	request[strlen(http2Magic) + sizeof(http2Settings) + 2]=(char)(sizeof(http2HeaderStart) - 6 + 1 + strlen(encoded) + strlen("/file2pcap/") + sizeof(http2HeaderEnd)); 


        memcpy(request + strlen(http2Magic) + sizeof(http2Settings) + 3, &http2HeaderStart, sizeof(http2HeaderStart));


        request[strlen(http2Magic) + sizeof(http2Settings) + 3 + sizeof(http2HeaderStart) ]=(char)(strlen(encoded) + strlen("/file2pcap/"));
        memcpy(request + strlen(http2Magic) + sizeof(http2Settings) + 3 + sizeof(http2HeaderStart) + 1, &http2HeaderCenter, sizeof(http2HeaderCenter));
        memcpy(request + strlen(http2Magic) + sizeof(http2Settings) + 3 + sizeof(http2HeaderStart) + 1 + strlen("/file2pcap/"), encoded, strlen(encoded));
	memcpy(request + strlen(http2Magic) + sizeof(http2Settings) + 3 + sizeof(http2HeaderStart) + 1 + strlen("/file2pcap/") + strlen(encoded), http2HeaderEnd, sizeof(http2HeaderEnd));


	len = strlen(http2Magic) + sizeof(http2Settings) + 3 + sizeof(http2HeaderStart) + 1 + strlen("/file2pcap/") + strlen(encoded) + strlen(http2HeaderEnd);





	ph.time = ho->time;
	ph.usec = ho->usec;

        if(ho->ipV == 4)
                packetLen = packetLen4;
        else
                packetLen = packetLen6;


	ph.length1 = packetLen + len;
	ph.length2 = packetLen + len;


	write(fileno(ho->outFile), &ph, sizeof(struct pcap_packet_header));

	if(ho->direction == FROM_SERVER)
		write(fileno(ho->outFile), ho->fromEther, sizeof(ho->fromEther)-1);
	else
		write(fileno(ho->outFile), ho->toEther, sizeof(ho->toEther)-1);
	

	craftTcp(request, len, ho->direction == FROM_SERVER ? FROM_SERVER : TO_SERVER, TH_ACK|TH_PUSH, ho);


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





return 0;
}


/************************************************************************************/

//This sends the clients settings ACK to the server

int http2SettingsAck(struct handover *ho) {
	char settingsAck[] = 	{
					0x00, 0x00 ,0x00, 	//Length: 0 
					0x04, 			//Type: Settings
					0x01,  			//Flags: Ack
					0x00, 0x00, 0x00, 0x00	//Stream identifier: 0
				};
	struct pcap_packet_header ph;
	int len, packetLen;


	
	len = sizeof(settingsAck);


	ph.time = ho->time;
	ph.usec = ho->usec;

        if(ho->ipV == 4)
                packetLen = packetLen4;
        else
                packetLen = packetLen6;


	ph.length1 = packetLen + len;
	ph.length2 = packetLen + len;


	write(fileno(ho->outFile), &ph, sizeof(struct pcap_packet_header));

	if(ho->direction == FROM_SERVER)
		write(fileno(ho->outFile), ho->fromEther, sizeof(ho->fromEther)-1);
	else
		write(fileno(ho->outFile), ho->toEther, sizeof(ho->toEther)-1);
	
	craftTcp(settingsAck, len, ho->direction == FROM_SERVER ? FROM_SERVER : TO_SERVER, TH_ACK|TH_PUSH, ho);


	//and now send the tcp ack
	ph.usec+=INTERVAL;
	ph.length1=packetLen;
	ph.length2=packetLen;
	write(fileno(ho->outFile), &ph, sizeof(struct pcap_packet_header));

	if(ho->direction == FROM_SERVER)
		write(fileno(ho->outFile), ho->toEther, sizeof(ho->toEther)-1);
	else
		write(fileno(ho->outFile), ho->fromEther, sizeof(ho->fromEther)-1);


	craftTcp(NULL,0, ho->direction == FROM_SERVER ? TO_SERVER : FROM_SERVER, TH_ACK, ho);    


return 0;
}


/************************************************************************************/

//This sends the clients settings to the server, which the server acks, and also the client acks the server's settings, sent previously
int http2Settings(struct handover *ho) {
	char settings[] = {
					0x00, 0x00, 0x0c,					//Length: 12
					0x04,							//Type: Settings
					0x00,							//Flags: 0x00
					0x00, 0x00, 0x00, 0x00,					//Stream identifier: 0x00
					0x00, 0x03, 0x00, 0x00, 0x00, 0x64,			//Settings: Max concurrent stream: 100
					0x00, 0x04, 0x00, 0x00, 0xff, 0xff			//Settings: Initial window size: 0x40000000
				};
	struct pcap_packet_header ph;
	int len, packetLen;


	//Send settings from client to server
		
	len = sizeof(settings);


	ph.time = ho->time;
	ph.usec = ho->usec;

        if(ho->ipV == 4)
                packetLen = packetLen4;
        else
                packetLen = packetLen6;


	ph.length1 = packetLen + len;
	ph.length2 = packetLen + len;


	write(fileno(ho->outFile), &ph, sizeof(struct pcap_packet_header));

	if(ho->direction == FROM_SERVER)
		write(fileno(ho->outFile), ho->fromEther, sizeof(ho->fromEther)-1);
	else
		write(fileno(ho->outFile), ho->toEther, sizeof(ho->toEther)-1);
	

	craftTcp(settings, len, ho->direction == FROM_SERVER ? FROM_SERVER : TO_SERVER, TH_ACK|TH_PUSH, ho);


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


return 0;
}



/***************************************************************************************/

int http2Headers(struct handover *ho) {
	char serverHeader[] = 	{	0x00, 0x00, 0x17, 	//3 bytes Length
					0x01,			//Type: Headers
					0x04,			//Flags
					0x00, 0x00, 0x00, 0x01,	//Reserved
					0x88,			//Status: 200
					0x10, 0x0e, 'c','o','n','t','e','n','t','-','l','e','n','g','t','h'};	//content-length
	int len, packetLen, fullLen;
	struct pcap_packet_header ph;
	char temp[20], request[sizeof(serverHeader) + sizeof(temp)];
	size_t filelenLen;
	

	memset(temp, 0, sizeof(temp));
	snprintf(temp, sizeof(temp)-1, "%d",(unsigned int)ho->inFileSize);
	filelenLen = (char)strlen(temp);
	char *bufferPointer;


	memcpy(&request, &serverHeader, sizeof(serverHeader));
	request[26]=filelenLen;
	bufferPointer = request+27;
	sprintf(bufferPointer, "%d",(unsigned int)ho->inFileSize);



	len = sizeof(serverHeader) + 1 + filelenLen;

	//fix the first 3 bytes - the length field
	fullLen = 18 + filelenLen;
	char testpointer = ((char)fullLen);
	memcpy(request+2, &testpointer, 1);


	ph.time = ho->time;
	ph.usec = ho->usec;

        if(ho->ipV == 4)
                packetLen = packetLen4;
        else
                packetLen = packetLen6;


	ph.length1 = packetLen + len;
	ph.length2 = packetLen + len;





        write(fileno(ho->outFile), &ph, sizeof(struct pcap_packet_header));

        if(ho->direction == FROM_SERVER)
                write(fileno(ho->outFile), ho->fromEther, sizeof(ho->fromEther)-1);
        else
                write(fileno(ho->outFile), ho->toEther, sizeof(ho->toEther)-1);

	craftTcp(request, len, ho->direction == FROM_SERVER ? FROM_SERVER : TO_SERVER, TH_ACK|TH_PUSH, ho);


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




return 0;
}




/**************************************************************************************************************/


int http2TransferFile(struct handover *ho) {
        int packetLen;
        unsigned int count, len;
        char buffer[1500], data[1520];
	struct pcap_packet_header ph;


        if(ho->inFile != NULL)
                rewind(ho->inFile);

        //initialize ph with the current values
	ph.time = ho->time;
	ph.usec = ho->usec;


	memset(data, 0, sizeof(data));
	data[8]=0x01;	//stream id 1;


	if(ho->ipV == 4)
		packetLen = packetLen4;
	else
		packetLen = packetLen6;



        while(!(feof(ho->inFile)))
        {
                count=read(fileno(ho->inFile), buffer, ho->blockSize);

		len = count;
		data[0] = len / 65536;
		len     = len % 65536;
		data[1] = len / 256;
		len     = len % 256;
		data[2] = len;


		memcpy(data+9, &buffer, count);

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


                ph.length1 = packetLen + count + 9;
                ph.length2 = packetLen + count + 9;


                write(fileno(ho->outFile), &ph, sizeof(struct pcap_packet_header));

		if(ho->direction == FROM_SERVER)
	                write(fileno(ho->outFile), ho->fromEther, sizeof(ho->fromEther)-1);
		else
			write(fileno(ho->outFile), ho->toEther, sizeof(ho->toEther)-1);
		


                craftTcp(data, count+9, ho->direction == FROM_SERVER ? FROM_SERVER : TO_SERVER, TH_ACK|TH_PUSH, ho);  

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


/***************************************************/


int http2DataStreamClose(struct handover *ho) {
	char dataClose[] = 	{	0x00, 0x00, 0x00, 		//3 bytes Length
					0x00,				//Type: Data
					0x01,				//Flags: End of data
					0x00, 0x00, 0x00, 0x01};	//Reserved; Stream id 1;
	int len, packetLen;
	struct pcap_packet_header ph;
	

	len = sizeof(dataClose);


	ph.time = ho->time;
	ph.usec = ho->usec;

        if(ho->ipV == 4)
                packetLen = packetLen4;
        else
                packetLen = packetLen6;


	ph.length1 = packetLen + len;
	ph.length2 = packetLen + len;





        write(fileno(ho->outFile), &ph, sizeof(struct pcap_packet_header));

        if(ho->direction == FROM_SERVER)
                write(fileno(ho->outFile), ho->fromEther, sizeof(ho->fromEther)-1);
        else
                write(fileno(ho->outFile), ho->toEther, sizeof(ho->toEther)-1);

	craftTcp(dataClose, len, ho->direction == FROM_SERVER ? FROM_SERVER : TO_SERVER, TH_ACK|TH_PUSH, ho);


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




return 0;
}


/***************************************************/


int http2GoAway(struct handover *ho) {
	char goAway[] = 	{	0x00, 0x00, 0x08, 		//3 bytes Length
					0x07,				//Type: GoAway
					0x00,				//Flags
					0x00, 0x00, 0x00, 0x00,		//Reserved; Stream id 0
					0x00, 0x00, 0x00, 0x00,		//Reserved
					0x00, 0x00, 0x00, 0x00};	//No Error
	int len, packetLen;
	struct pcap_packet_header ph;
	

	len = sizeof(goAway);


	ph.time = ho->time;
	ph.usec = ho->usec;

        if(ho->ipV == 4)
                packetLen = packetLen4;
        else
                packetLen = packetLen6;


	ph.length1 = packetLen + len;
	ph.length2 = packetLen + len;





        write(fileno(ho->outFile), &ph, sizeof(struct pcap_packet_header));

        if(ho->direction == FROM_SERVER)
                write(fileno(ho->outFile), ho->fromEther, sizeof(ho->fromEther)-1);
        else
                write(fileno(ho->outFile), ho->toEther, sizeof(ho->toEther)-1);

	craftTcp(goAway, len, ho->direction == FROM_SERVER ? FROM_SERVER : TO_SERVER, TH_ACK|TH_PUSH, ho);


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




return 0;
}



