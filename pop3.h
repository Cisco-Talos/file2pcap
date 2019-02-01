
int pop3Request(struct handover *ho);
int pop3TransferFile(struct handover *ho);

#define POPSERVERMAILHEADER	"Received: from %1$s by (1.2.3.4:25) via %3$s\r\n"\
                		" (199.91.174.187:56258) with [%3$s SMTP Server] id 1405730148303.WH100\r\n"\
                		"  for %2$s; Fri, 23 May 2014 01:48:56 -0200\r\n"\
                		"Message-ID: <537F197F.1020309@%3$s>\r\n"\
                		"Date: Fri, 23 May 2014 11:48:47 +0500\r\n"\
                		"From: <%1$s>\r\n"\
                		"User-Agent: Mozilla/5.0 (X11; Linux i686; rv:24.0) Gecko/20100101 Thunderbird/24.5.0\r\n"\
                		"MIME-Version: 1.0\r\n"\
                		"To: %2$s\r\n"\
                		"Subject: file2pcap\r\n"\
                		"Content-Type: multipart/mixed;\r\n"\
                		" boundary=\"------------070104010108080805080502\"\r\n\r\n"

