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
#include "imap.h"
#include "helpers.h"
#include "quoted-printable.h"


/************************************************************************************************************************/

int imapRequest(struct handover *ho) {
	char *badjoke;
        char serverImapHeader[] =  "* OK [CAPABILITY IMAP4REV1 I18NLEVEL=1 LITERAL+ SASL-IR LOGIN-REFERRALS] [10.10.5.140] \r\nIMAP4rev1 2007e.404 at Tue, 9 Nov 2010 15:13:41 +0000 (WET)\r\n";
	char clientUserPass[] = "A01 LOGIN user secret\r\n";
	char serverOk[] = 	"A01 OK [CAPABILITY IMAP4REV1 I18NLEVEL=1 LITERAL+ IDLE UIDPLUS NAMESPACE CHILDREN MAILBOX-REFERRALS "\
				"BINARY UNSELECT ESEARCH WITHIN SCAN SORT THREAD=REFERENCES THREAD=ORDEREDSUBJECT MULTIAPPEND] User user authenticated\r\n";
	char clientStatus[] = "A02 STATUS INBOX (UIDNEXT MESSAGES)\r\n";
	char serverStatus[] = "* STATUS INBOX (MESSAGES 1 UIDNEXT 3)\r\nA02 OK Assigning new unique identifiers to all messages\r\n";
	char clientSelect[] = "A03 SELECT INBOX\r\n";
	char serverSelect[] = 	"* 1 EXISTS\r\n* 1 RECENT\r\n* OK [UIDVALIDITY 1289315624] UID validity status\r\n* OK [UIDNEXT 3] Predicted next UID\r\n* FLAGS "\
				"(\\Answered \\Flagged \\Deleted \\Draft \\Seen)\r\n* OK [PERMANENTFLAGS (\\* \\Answered \\Flagged \\Deleted \\Draft \\Seen)] Permanent "\
				"flags\r\n* OK [UNSEEN 1] first unseen message in /var/spool/mail/user\r\nA03 OK [READ-WRITE] SELECT completed\r\n";
	char clientFetch[] = "A04 UID FETCH 1 (UID RFC822.SIZE BODY.PEEK[]<0.65536>)\r\n";
	char serverFetch[] = "* 1 FETCH (UID 1 RFC822.SIZE 117982 BODY[]<0> {65536}\r\n";

	char serverMailHeader[] = "Return-Path: <" SRC_EMAIL ">\r\n"\
		"Delivered-To: " MAILHOST "-"DST_EMAIL "\r\n"\
		"Received: (qmail 12912 invoked by uid 89); 26 May 2014 10:14:00 -0000\r\n"\
		"Received: by simscan 1.4.0 ppid: 12861, pid: 12896, t: 0.8526s\r\n"\
		"         scanners: clamav: 0.95.2/m:51/d:9604\r\n"\
		"Received: from unknown (HELO " MAILHOST ") (bmE=@1.2.3.4) by " MAILHOST " with (DHE-RSA-AES256-SHA encrypted) SMTP; 26 May 2014 10:14:00 -0000\r\n"\
		"Received: from [12.21.12.21] by " MAILHOST " with HTTP; Mon, 26 May 2014 12:13:56 +0200\r\n"\
		"MIME-Version: 1.0\r\n"\
		"Message-ID: <trinity-5335e8d2-aa96-4eb1-80cc-e9657b28fc65-1401099236666@" MAILHOST ">\r\n"\
		"From: <" SRC_EMAIL ">\r\n"\
		"To: " DST_EMAIL "\r\n"\
		"Subject: file2pcap\r\n"\
		"Content-Type: multipart/mixed;\r\n"\
		" boundary=refeics-138facf0-915a-4457-8ff5-a6982ea42135\r\n"\
		"Date: Mon, 26 May 2014 12:13:56 +0000\r\n"\
		"Importance: normal\r\n"\
		"Sensitivity: Normal\r\n"\
		"X-Priority: 3\r\n\r\n";

	char serverMailText[] = "--refeics-138facf0-915a-4457-8ff5-a6982ea42135\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n";
	char serverAttachmentHeader[] = "--refeics-138facf0-915a-4457-8ff5-a6982ea42135\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=";

	char serverAttachmentEndB64[]= 	"\r\nContent-Transfer-Encoding: base64\r\n\r\n";
	char serverAttachmentEndQP[]= 	"\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n";
	char serverAttachmentEndUU[] = 	"\r\nContent-Transfer-Encoding: uuencode\r\n\r\nbegin ";	//FIXME - Is this correct????


	char serverFetchEnd[] = "\r\n--refeics-138facf0-915a-4457-8ff5-a6982ea42135--\r\n\r\n)\r\n";
	char serverFetchCompleted[] = "A05 OK Fetch completed.\r\n";
	char clientClose[] = "A06 CLOSE\r\n";
	char clientLogout[] = "A07 LOGOUT\r\n";
	char serverCloseComplete[] = "A08 OK Close completed.\r\n* BYE Logging out\r\n";
	char serverLogoutComplete[] = "A09 OK Logout completed.\r\n";

	tcpSendString(ho, serverImapHeader, FROM_SERVER);
	tcpSendString(ho, clientUserPass, TO_SERVER);
	tcpSendString(ho, serverOk, FROM_SERVER);
	tcpSendString(ho, clientStatus, TO_SERVER);
	tcpSendString(ho, serverStatus, FROM_SERVER);
	tcpSendString(ho, clientSelect, TO_SERVER);
	tcpSendString(ho, serverSelect, FROM_SERVER);
	tcpSendString(ho, clientFetch, TO_SERVER);
	tcpSendString(ho, serverFetch, FROM_SERVER);
	tcpSendString(ho, serverMailHeader, FROM_SERVER);
	tcpSendString(ho, serverMailText, FROM_SERVER);

	badjoke = badJoke();
	if(badjoke != NULL)
	{
		tcpSendString(ho, badjoke, FROM_SERVER);
		free(badjoke);		
	}


	tcpSendString(ho, serverAttachmentHeader, FROM_SERVER);
	tcpSendString(ho, ho->srcFile, FROM_SERVER);

	if(ho->encoder == ENC_BASE64)
		tcpSendString(ho, serverAttachmentEndB64, FROM_SERVER);
	else if(ho->encoder == ENC_QUOTED_PRINTABLE)
		tcpSendString(ho, serverAttachmentEndQP, FROM_SERVER);
	else if(ho->encoder == ENC_UU)
	{
		tcpSendString(ho, serverAttachmentEndUU, FROM_SERVER);
		tcpSendString(ho, ho->srcFile, FROM_SERVER);
		tcpSendString(ho, "\r\n", FROM_SERVER);
	}
	else
		tcpSendString(ho, serverAttachmentEndB64, FROM_SERVER);
	
	ho->direction = FROM_SERVER;

	if(ho->encoder == ENC_BASE64)
		transferFileBase64(ho);
	else if(ho->encoder == ENC_QUOTED_PRINTABLE)
		transferFileQuotedPrintable(ho);
	else if(ho->encoder == ENC_UU)
		transferFileUU(ho);
	else
		transferFileBase64(ho);
	

	tcpSendString(ho, serverFetchEnd, FROM_SERVER);
	tcpSendString(ho, serverFetchCompleted, FROM_SERVER);
	tcpSendString(ho, clientClose, TO_SERVER);
	tcpSendString(ho, clientLogout, TO_SERVER);
	tcpSendString(ho, serverCloseComplete, FROM_SERVER);
	tcpSendString(ho, serverLogoutComplete, FROM_SERVER);

return(0);
}

/**************************************************************************************************************/

/****************************************************************************************************************************************/

