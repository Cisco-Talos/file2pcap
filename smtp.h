#define CLIENTMAILFROM "MAIL FROM:<%s> SIZE=" //FIXME - size is dynamic
#define SERVERSENDEROK "250 2.1.0 <%s>... Sender ok\r\n"
#define CLIENTRECEIPTTO "RCPT TO:<%s>\r\n"
#define SERVERRECIPIENTOK "250 2.1.5 <%s>... Recipient ok\r\n"
#define CLIENTMAILBODY "Message-ID: <537DC502.5080409@" MAILHOST ">\r\n"\
		"Date: Thu, 22 May 2014 11:36:02 +0200\r\n"\
		"From: <%s>\r\n"\
		"User-Agent: Mozilla/5.0 (X11; Linux i686; rv:24.0) Gecko/20100101 Thunderbird/24.5.0\r\n"\
		"MIME-Version: 1.0\r\n"\
		"To: <%s>\r\n"\
		"Subject: file2pcap from Martin Zeiser\r\n"\
		"X-Enigmail-Version: 1.6\r\n"\
		"Content-Type: multipart/mixed;\r\n"\
		" boundary=\"------------020106020307040709020108\"\r\n\r\n"\
		"This is a multi-part message in MIME format.\r\n"\
		"--------------020106020307040709020108\r\n"\
		"Content-Type: text/plain; charset=ISO-8859-1\r\n"\
		"Content-Transfer-Encoding: 7bit\r\n\r\n"

int smtpRequest(struct handover *ho);
//char *base64_encode(char *data, size_t input_length, size_t *output_length);
int smtpTransferFile(struct handover *ho);
int transferFileUU(struct handover *ho);

