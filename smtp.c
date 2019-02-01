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
#include "smtp.h"
#include "helpers.h"
#include "quoted-printable.h"




/************************************************************************************************************************/


int smtpRequest(struct handover *ho) {
	char buffer[5000];
	char *badjoke = NULL;
char clientMailFrom[500], serverSenderOk[500], clientReceiptTo[500], serverRecipientOk[500], clientMailBody[1100]; 
	char serverSmtpHeader[] =  "220 " MAILHOST " ESMTP Sendmail 8.14.5/8.14.5; Thu, 22 May 2014 12:12:12 GMT\r\n";
	char clientEhlo[] = "EHLO user\r\n";
	char serverOptions1[] = "250-" MAILHOST " Hello user." MAILHOST " [10.1.2.3], pleased to meet you\r\n";
	char serverOptions2[] = "250-ENHANCEDSTATUSCODES\r\n250-PIPELINING\r\n250-EXPN\r\n250-VERB\r\n250-8BITMIME\r\n250-SIZE 32000000\r\n250-DSN\r\n250-ETRN\r\n250-STARTTLS\r\n250-DELIVERBY\r\n250 HELP\r\n";
	//char clientMailFrom[] = "MAIL FROM:<" ho.srcEmail "> SIZE="; //FIXME - size is dynamic
	snprintf(clientMailFrom, sizeof(clientMailFrom)-1, CLIENTMAILFROM, ho->srcEmail);
	//char serverSenderOk[] = "250 2.1.0 <" ho.srcEmail ">... Sender ok\r\n";
	snprintf(serverSenderOk, sizeof(serverSenderOk)-1, SERVERSENDEROK, ho->srcEmail);
	//char clientReceiptTo[] = "RCPT TO:<" ho.dstEmail ">\r\n";
	snprintf(clientReceiptTo, sizeof(clientReceiptTo)-1, CLIENTRECEIPTTO, ho->dstEmail);
	//char serverRecipientOk[] = "250 2.1.5 <" ho.dstEmail ">... Recipient ok\r\n";
	snprintf(serverRecipientOk, sizeof(serverRecipientOk)-1, SERVERRECIPIENTOK, ho->dstEmail);
	char clientData[] = "DATA\r\n";
	char serverEnterMail[] = "354 Enter mail, end with \".\" on a line by itself\r\n";
/*
	char clientMailBody[] = "Message-ID: <537DC502.5080409@" MAILHOST ">\r\n"\
		"Date: Thu, 22 May 2014 11:36:02 +0200\r\n"\
		"From: <" SRC_EMAIL ">\r\n"\
		"User-Agent: Mozilla/5.0 (X11; Linux i686; rv:24.0) Gecko/20100101 Thunderbird/24.5.0\r\n"\
		"MIME-Version: 1.0\r\n"\
		"To: <" DST_EMAIL ">\r\n"\
		"Subject: file2pcap from Martin Zeiser\r\n"\
		"X-Enigmail-Version: 1.6\r\n"\
		"Content-Type: multipart/mixed;\r\n"\
		" boundary=\"------------020106020307040709020108\"\r\n\r\n"\
		"This is a multi-part message in MIME format.\r\n"\
		"--------------020106020307040709020108\r\n"\
		"Content-Type: text/plain; charset=ISO-8859-1\r\n"\
		"Content-Transfer-Encoding: 7bit\r\n\r\n";
*/	
	//see smtp.h for CLIENTMAILBODY
	snprintf(clientMailBody, sizeof(clientMailBody)-1, CLIENTMAILBODY, ho->srcEmail, ho->dstEmail); 

	char clientAttachmentSeparator1[] = "--------------020106020307040709020108\r\n";
	char clientAttachment2b64[] = "\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"";
	char clientAttachment2qp[] = "\r\nContent-Transfer-Encoding: quoted-printable\r\nContent-Disposition: attachment; filename=\"";
	char clientAttachment2uu[] = "Content-Type: application/octet-stream\r\nEncoding: 446 uuencode\r\n\r\nbegin "; //Missing - FIXME Qj76bwlR5bGN.dOC 8DK9.QWQ
	char clientAttachmentSeparator2[] = "--------------020106020307040709020108--\r\n.\r\n";
	char serverMessageAccepted[] = "250 2.0.0 s4M9a2xl017623 Message accepted for delivery\r\n";
	char clientQuit[] = "QUIT\r\n";
	char serverClose[] = "221 2.0.0 " MAILHOST " closing connection\r\n";





	tcpSendString(ho, serverSmtpHeader, FROM_SERVER);
	tcpSendString(ho, clientEhlo, TO_SERVER);
	tcpSendString(ho, serverOptions1, FROM_SERVER);
	tcpSendString(ho, serverOptions2, FROM_SERVER);

	snprintf(buffer, sizeof(buffer)-1, "%s%d\r\n", clientMailFrom, 10000);	//FIXME - fix size
	tcpSendString(ho, buffer, TO_SERVER);

	tcpSendString(ho, serverSenderOk, FROM_SERVER);
	tcpSendString(ho, clientReceiptTo, TO_SERVER);
	tcpSendString(ho, serverRecipientOk, FROM_SERVER);
	tcpSendString(ho, clientData, TO_SERVER);
	tcpSendString(ho, serverEnterMail, FROM_SERVER);

	tcpSendString(ho, clientMailBody, TO_SERVER);

        badjoke = badJoke();
        if(badjoke != NULL)
        {
                tcpSendString(ho, badjoke, TO_SERVER);
                free(badjoke);
        }



	tcpSendString(ho, clientAttachmentSeparator1, TO_SERVER);

	if((ho->encoder == ENC_BASE64) || (ho->encoder == ENC_QUOTED_PRINTABLE))
	{
		snprintf(buffer, sizeof(buffer)-1,"Content-Type: application/x-as400attachment;\r\n name=\"%s\"", ho->srcFile);
		tcpSendString(ho, buffer, TO_SERVER);
	}

	
	if(ho->encoder == ENC_BASE64)
		snprintf(buffer,sizeof(buffer)-1,"%s%s\"\r\n\r\n",clientAttachment2b64, ho->srcFile);
	else if(ho->encoder == ENC_QUOTED_PRINTABLE)
		snprintf(buffer,sizeof(buffer)-1,"%s%s\"\r\n\r\n",clientAttachment2qp, ho->srcFile);
	else if(ho->encoder == ENC_UU)
		snprintf(buffer,sizeof(buffer)-1,"%s%s\r\n",clientAttachment2uu, ho->srcFile);
	else
		snprintf(buffer,sizeof(buffer)-1,"%s%s\"\r\n\r\n",clientAttachment2b64, ho->srcFile);
	tcpSendString(ho, buffer, TO_SERVER);
	


	ho->direction = TO_SERVER;

	if(ho->encoder == ENC_BASE64)
		transferFileBase64(ho);
	else if(ho->encoder == ENC_QUOTED_PRINTABLE)
		transferFileQuotedPrintable(ho);
	else if(ho->encoder == ENC_UU)
		transferFileUU(ho);
	else
		transferFileBase64(ho);
	
	

	tcpSendString(ho, clientAttachmentSeparator2, TO_SERVER);
	tcpSendString(ho, serverMessageAccepted, FROM_SERVER);
	tcpSendString(ho, clientQuit, TO_SERVER);
	tcpSendString(ho, serverClose, FROM_SERVER);

return(0);
}

/**************************************************************************************************************/

/****************************************************************************************************************************************/

