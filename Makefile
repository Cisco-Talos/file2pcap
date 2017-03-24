CC = gcc



file2pcap: file2pcap.o ftp.o http.o http2.o smtp.o pop3.o helpers.o imap.o quoted-printable.o
	$(CC) -Wall -o file2pcap file2pcap.c ftp.c http.c http2.c smtp.c pop3.c helpers.c imap.c quoted-printable.c

clean:
	@rm *.o
	@rm *.pcap
	@rm file2pcap

install:
	@echo Copying file2pcap to /usr/bin/file2pcap
	@cp file2pcap /usr/bin/
