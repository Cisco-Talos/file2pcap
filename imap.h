
int imapRequest(struct handover *ho);
//char *base64_encode(char *data, size_t input_length, size_t *output_length);
int imapTransferFile(struct handover *ho);

#define IMAPSERVERMAILHEADER "Return-Path: <%1$s>\r\n"\
		"Delivered-To: %3$s-%2$s\r\n"\
		"Received: (qmail 12912 invoked by uid 89); 26 May 2014 10:14:00 -0000\r\n"\
		"Received: by simscan 1.4.0 ppid: 12861, pid: 12896, t: 0.8526s\r\n"\
		"         scanners: clamav: 0.95.2/m:51/d:9604\r\n"\
		"Received: from unknown (HELO %3$s) (bmE=@1.2.3.4) by %3$s with (DHE-RSA-AES256-SHA encrypted) SMTP; 26 May 2014 10:14:00 -0000\r\n"\
		"Received: from [12.21.12.21] by %3$s with HTTP; Mon, 26 May 2014 12:13:56 +0200\r\n"\
		"MIME-Version: 1.0\r\n"\
		"Message-ID: <trinity-5335e8d2-aa96-4eb1-80cc-e9657b28fc65-1401099236666@%3$s>\r\n"\
		"From: <%1$s>\r\n"\
		"To: %2$s\r\n"\
		"Subject: file2pcap\r\n"\
		"Content-Type: multipart/mixed;\r\n"\
		" boundary=refeics-138facf0-915a-4457-8ff5-a6982ea42135\r\n"\
		"Date: Mon, 26 May 2014 12:13:56 +0000\r\n"\
		"Importance: normal\r\n"\
		"Sensitivity: Normal\r\n"\
		"X-Priority: 3\r\n\r\n"