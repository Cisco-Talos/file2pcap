CC = gcc



file2pcap: crc32.o file2pcap.o ftp.o http.o http2.o http-gzip.o smtp.o pop3.o helpers.o imap.o quoted-printable.o
	$(CC) -o file2pcap crc32.c file2pcap.c ftp.c http.c http2.c http-gzip.c smtp.c pop3.c helpers.c imap.c quoted-printable.c -lz

clean:
	@rm *.o
	@rm file2pcap

install:
	@echo Copying file2pcap to /usr/bin/file2pcap
	@cp file2pcap /usr/bin/
