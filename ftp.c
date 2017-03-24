#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define  __FAVOR_BSD
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>


#include "file2pcap.h"


extern int packetLen4, packetLen6;


/**************************************************************************/

int ftpCommandsStartActive(struct handover *ho) {
	char buffer[200];
	char ftpBanner[] 	= 	"220 Welcome to file2pcap ftp server\r\n";
	char username[] 	=	"USER wrl\r\n";
	char usernameReply[]	=	"331 Please specify the password\r\n";
	char password[]		=	"PASS wrl\r\n";
	char loginSuccessful[]	=	"230 Login successful.\r\n";
	char syst[]		= 	"SYST\r\n";
	char systReply[]	=	"UNIX Type: L8\r\n";
	char typeI[]		=	"TYPE I\r\n";
	char typeIReply[]	=	"200 Switching to Binary mode\r\n";
	char portCommand[]	=	"PORT 192,168,0,1,197,17\r\n";		//FIXME - port 50449 - hard-coded IP:Port is bad
	char portCommandReply[]	=	"200 Port command successful\r\n";
	char eprtCommand[] 	=	"EPRT |2|2a00:1450:4007:80d::200e|50449|\r\n";
	char eprtCommandReply[]	=	"200 EPRT: Command successful\r\n";
	char retr[]		=	"RETR ";
	char dataConnection[]	=	"150 Opening BINARY mode data connection\r\n";



	tcpSendString(ho, ftpBanner, FROM_SERVER);
	tcpSendString(ho, username, TO_SERVER);
	tcpSendString(ho, usernameReply, FROM_SERVER);
	tcpSendString(ho, password, TO_SERVER);
	tcpSendString(ho, loginSuccessful, FROM_SERVER);
	tcpSendString(ho, syst, TO_SERVER);
        tcpSendString(ho, systReply, FROM_SERVER);
        tcpSendString(ho, typeI, TO_SERVER);
        tcpSendString(ho, typeIReply, FROM_SERVER);
        
	if(ho->ipV == 4)
	{
		tcpSendString(ho, portCommand, TO_SERVER);
        	tcpSendString(ho, portCommandReply, FROM_SERVER);
	}
	else if(ho->ipV == 6)
	{
		tcpSendString(ho, eprtCommand, TO_SERVER);
        	tcpSendString(ho, eprtCommandReply, FROM_SERVER);
	}

	memset(buffer, 0, sizeof(buffer));
	snprintf(buffer, sizeof(buffer)-1, "%s%s\r\n", retr, ho->srcFile);
        tcpSendString(ho, buffer, TO_SERVER);

        tcpSendString(ho, dataConnection, FROM_SERVER);

	//FIXME - randomize port and return the value
return 50449;
}

/**************************************************************************/

int ftpCommandsStartPassive(struct handover *ho) {
	char buffer[200];
	char ftpBanner[] 	= 	"220 Welcome to file2pcap ftp server\r\n";
	char username[] 	=	"USER wrl\r\n";
	char usernameReply[]	=	"331 Please specify the password\r\n";
	char password[]		=	"PASS wrl\r\n";
	char loginSuccessful[]	=	"230 Login successful.\r\n";
	char syst[]		= 	"SYST\r\n";
	char systReply[]	=	"UNIX Type: L8\r\n";
	char typeI[]		=	"TYPE I\r\n";
	char typeIReply[]	=	"200 Switching to Binary mode\r\n";
	char pasvCommand[]	=	"PASV\r\n";
	char pasvCommandReply[]	=	"227 Entering Passive Mode (173,37,145,84,197,17)\r\n";	//port 50449
	char epsvCommand[]	=	"EPSV\r\n";
	char epsvCommandReply[]	=	"229 Entering Extended Passive Mode (|||50449|)\r\n";
	char retr[]		=	"RETR ";
	char dataConnection[]	=	"150 Opening BINARY mode data connection\r\n";



	tcpSendString(ho, ftpBanner, FROM_SERVER);
	tcpSendString(ho, username, TO_SERVER);
	tcpSendString(ho, usernameReply, FROM_SERVER);
	tcpSendString(ho, password, TO_SERVER);
	tcpSendString(ho, loginSuccessful, FROM_SERVER);
	tcpSendString(ho, syst, TO_SERVER);
        tcpSendString(ho, systReply, FROM_SERVER);
        tcpSendString(ho, typeI, TO_SERVER);
        tcpSendString(ho, typeIReply, FROM_SERVER);
        
	if(ho->ipV == 4)
	{
		tcpSendString(ho, pasvCommand, TO_SERVER);
        	tcpSendString(ho, pasvCommandReply, FROM_SERVER);
	}
	else if(ho->ipV == 6)
	{
		tcpSendString(ho, epsvCommand, TO_SERVER);
        	tcpSendString(ho, epsvCommandReply, FROM_SERVER);
	
	}

	memset(buffer, 0, sizeof(buffer));
	snprintf(buffer, sizeof(buffer)-1, "%s%s\r\n", retr, ho->srcFile);
        tcpSendString(ho, buffer, TO_SERVER);

        tcpSendString(ho, dataConnection, FROM_SERVER);

	//FIXME - randomize port and return the value
return 50449;
}



/***************************************************************************************************************/

int ftpCommandsEnd(struct handover *ho) {
	char transferComplete[]	=	"226 Transfer complete\r\n";
	char quit[]		=	"QUIT\r\n";
	char goodbye[]		=	"221 Goodbye.\r\n";

	tcpSendString(ho, transferComplete, FROM_SERVER);
	tcpSendString(ho, quit, TO_SERVER);
        tcpSendString(ho, goodbye, FROM_SERVER);



return 0;
}

/**************************************************************************************************************/


int ftpTransferFile(struct handover *ho) {
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
                
		if(ho->direction == TO_SERVER)
			write(fileno(ho->outFile), ho->toEther, sizeof(ho->toEther)-1);
		else
			write(fileno(ho->outFile), ho->fromEther, sizeof(ho->fromEther)-1);
			


                craftTcp(buffer, count, ho->direction, TH_ACK|TH_PUSH, ho);  

                //and now send the ack
                ph.usec+=INTERVAL;
                ph.length1=packetLen;
                ph.length2=packetLen;
                write(fileno(ho->outFile), &ph, sizeof(struct pcap_packet_header));

		if(ho->direction == TO_SERVER)
	        {
		        write(fileno(ho->outFile), ho->fromEther, sizeof(ho->fromEther)-1);
			craftTcp(NULL,0, FROM_SERVER, TH_ACK, ho);   
	
		}
		else
		{
			write(fileno(ho->outFile), ho->toEther, sizeof(ho->toEther)-1);
			craftTcp(NULL,0, TO_SERVER, TH_ACK, ho);   
		}
		
/*
		if(ho->direction == TO_SERVER)
	                craftTcp(NULL,0, FROM_SERVER, TH_ACK, ho);   
		else
	                craftTcp(NULL,0, TO_SERVER, TH_ACK, ho);   
*/
	
        }

	ho->time = ph.time;
	ho->usec = ph.usec;	



return(0);
}

