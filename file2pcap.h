#include <sys/stat.h>
#include <netinet/ip6.h>      // struct ip6_hdr


#define VERSION         "1.24"

#define INTERVAL        13000   //About 70 packets per second

#define TO_SERVER       0
#define FROM_SERVER     1

#define SRC_ETHER 	"\x00\x11\x22\x33\x44\x55"
#define DST_ETHER 	"\x00\x55\x44\x33\x22\x11"
#define PROTO_ETHER 	"\x08\x00"
#define PROTO_ETHER6	"\x86\xDD"

#define SRC_IP4		"192.168.0.1"
#define DST_IP4		"173.37.145.84"

#define SRC_IP6		"2001:db8::214:51ff:fe2f:1556"
#define DST_IP6		"2a00:1450:4007:80d::200e"

#define SRC_EMAIL	"abc@cisco.com"
#define DST_EMAIL	"def@cisco.com"
#define MAILHOST	"cisco.com"

#define ENC_BASE64 		0
#define ENC_QUOTED_PRINTABLE 	1
#define ENC_UU			2

#define ACTIVE_FTP		0
#define PASSIVE_FTP		1


struct handover {
	unsigned int srcIP;
	unsigned int dstIP;
	struct in6_addr srcIP6[16];
	struct in6_addr dstIP6[16];
	unsigned short srcPort;
	unsigned short dstPort;
	int seq, ack_seq;
	char srcEther[6];
	char dstEther[6];
	char protoEther[2];
	char srcFile[200];
	char dstFile[200];
	char toEther[15];
	char fromEther[15];
	FILE *inFile;
	FILE *outFile;
	char encoder;
	char direction;
	int time;
	int usec;
	char ipV;	//IP version - 4 or 6
};

struct pcap_packet_header
        {
                int time;
                int usec;
                int length1;
                int length2;
        } ph;

struct v6_pseudo_header 
	{
		char src[16];
		char dst[16];
		int length;
		char zeroes[3];
		char next_header;
	} v6ph;


//int 		seq, ack_seq;
unsigned short 	srcport, dstport;
struct 		stat fileStat;


int craftTcp(char *payload, int payloadSize, char direction, unsigned char flags, struct handover *ho);

int craftIpv4(char *payload, int payloadSize, char direction, struct handover *ho);
int craftIpv6(char *payload, int payloadSize, char direction, struct handover *ho);



int tcpSendString(struct handover *ho, char *string, char direction);

int ftp(struct handover *ho, char mode);

