#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#define  __FAVOR_BSD
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>


#include "file2pcap.h"
#include "pop3.h"
#include "helpers.h"
#include "quoted-printable.h"




/************************************************************************************************************************/

int pop3Request(struct handover *ho) {
	char buffer[5000];
	char *badjoke=NULL;
	char serverMailHeader[5000];
    char serverPop3Header[] =  "+OK Microsoft Exchange Server 2003 POP3 server version 6.5.7638.1 (server.testing) ready.\r\n";
	char clientUser[] = "USER user\r\n";
	char serverOk[] = "+OK\r\n";
	char clientPass[] = "PASS secret\r\n";
	char clientList[] = "LIST\r\n";
	char serverOkList[] = "+OK 1\r\n.\r\n";
	char clientRetr[] = "RETR 1\r\n";
	char clientQuit[] = "QUIT\r\n";
	
	char clientAttachmentSeparator[] = "--------------070104010108080805080502--\r\n.\r\n";
	char serverClose[] = "+OK Microsoft Exchange Server 2003 POP3 server version 6.5.7638.1 signing off.\r\n";

/*
	char serverMailHeader[] = "Received: from " SRC_EMAIL " by (1.2.3.4:25) via " MAILHOST "\r\n"\
		" (199.91.174.187:56258) with [" MAILHOST " SMTP Server] id 1405730148303.WH100\r\n"\
		"  for " DST_EMAIL "; Fri, 23 May 2014 01:48:56 -0200\r\n"\
		"Message-ID: <537F197F.1020309@" MAILHOST ">\r\n"\
		"Date: Fri, 23 May 2014 11:48:47 +0500\r\n"\
		"From: <" SRC_EMAIL ">\r\n"\
		"User-Agent: Mozilla/5.0 (X11; Linux i686; rv:24.0) Gecko/20100101 Thunderbird/24.5.0\r\n"\
		"MIME-Version: 1.0\r\n"\
		"To: " DST_EMAIL "\r\n"\
		"Subject: file2pcap\r\n"\
		"Content-Type: multipart/mixed;\r\n"\
		" boundary=\"------------070104010108080805080502\"\r\n\r\n";
*/
	snprintf(serverMailHeader, sizeof(serverMailHeader)-1, POPSERVERMAILHEADER, ho->srcEmail, ho->dstEmail, MAILHOST);

	char serverMailBody[] = 		"This is a multi-part message in MIME format.\r\n"\
						"--------------070104010108080805080502\r\n"\
						"Content-Type: text/plain; charset=ISO-8859-2\r\n"\
						"Content-Transfer-Encoding: 7bit\r\n\r\n";
	char serverMailAttachmentHeader[] = 	"\r\n--------------070104010108080805080502\r\n"\
						"Content-Type: application/octet-stream;\r\n"\
						" name=\"";
	char serverMailEncodingB64[] = 		"\"\r\n"\
						"Content-Transfer-Encoding: base64\r\n"\
						"Content-Disposition: attachment;"\
						" filename=\"";
	char serverMailEncodingQP[] = 		"\"\r\n"\
						"Content-Transfer-Encoding: quoted-printable\r\n"\
						"Content-Disposition: attachment;"\
						" filename=\"";
	char serverMailEncodingUU[] = 		"\"\r\n"\
						"Encoding: 446 uuencode\r\n\r\n"\
						"begin "; //Missing - FIXME Qj76bwlR5bGN.dOC 8DK9.QWQ
						//FIXME - Is this correct???


	tcpSendString(ho, serverPop3Header, FROM_SERVER);
	tcpSendString(ho, clientUser, TO_SERVER);
	tcpSendString(ho, serverOk, FROM_SERVER);
	tcpSendString(ho, clientPass, TO_SERVER);
	tcpSendString(ho, serverOk, FROM_SERVER);
	tcpSendString(ho, clientList, TO_SERVER);
	tcpSendString(ho, serverOkList, FROM_SERVER);
	tcpSendString(ho, clientRetr, TO_SERVER);

	//FIXME - build 'OK' buffer with message size to send
	snprintf(buffer, sizeof(buffer)-1, "+OK %d octets\r\n", 10000);	//FIXME
	tcpSendString(ho, buffer, FROM_SERVER);
	tcpSendString(ho, serverMailHeader, FROM_SERVER);
	tcpSendString(ho, serverMailBody, FROM_SERVER);

        badjoke = badJoke();
        if(badjoke != NULL)
        {
                tcpSendString(ho, badjoke, FROM_SERVER);
                free(badjoke);
        }

	tcpSendString(ho, serverMailAttachmentHeader, FROM_SERVER);
	tcpSendString(ho, ho->srcFile, FROM_SERVER);

	if(ho->encoder == ENC_BASE64)
		tcpSendString(ho, serverMailEncodingB64, FROM_SERVER);
	else if(ho->encoder == ENC_QUOTED_PRINTABLE)
                tcpSendString(ho, serverMailEncodingQP, FROM_SERVER);
	else if(ho->encoder == ENC_UU)
                tcpSendString(ho, serverMailEncodingUU, FROM_SERVER);
	else
                tcpSendString(ho, serverMailEncodingB64, FROM_SERVER);

	tcpSendString(ho, ho->srcFile, FROM_SERVER);
	
	if(ho->encoder != ENC_UU)
		tcpSendString(ho, "\"\r\n\r\n", FROM_SERVER);
	else
		tcpSendString(ho, "\r\n", FROM_SERVER);
	
//	snprintf(serverFilename, sizeof(serverFilename)-1,"%s", ho->srcFile);

	ho->direction = FROM_SERVER;

	if(ho->encoder == ENC_BASE64)
		transferFileBase64(ho);
	else if(ho->encoder == ENC_QUOTED_PRINTABLE)
		transferFileQuotedPrintable(ho);
	else if(ho->encoder == ENC_UU)
		transferFileUU(ho);
	else
		transferFileBase64(ho);

	tcpSendString(ho, "\r\n", FROM_SERVER);
	tcpSendString(ho, clientAttachmentSeparator, FROM_SERVER);

	tcpSendString(ho, clientQuit, TO_SERVER);
	tcpSendString(ho, serverClose, FROM_SERVER);

return(0);
}

/**************************************************************************************************************/

/****************************************************************************************************************************************/

