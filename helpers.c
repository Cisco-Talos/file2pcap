#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define  __FAVOR_BSD
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "terrible.h"
#include "file2pcap.h"
#include "quoted-printable.h"


#define ENC(c) ((c) ? ((c) & 077) + ' ': '`')


/***********************************************************************************/

char *base64_encode(char *data, size_t input_length, size_t *output_length) {

        static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                        'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                        'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                        'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                        '4', '5', '6', '7', '8', '9', '+', '/'};
        static int mod_table[] = {0, 2, 1};
        int i=0, j=0;
        char *encoded_data;
        uint32_t octet_a, octet_b, octet_c, triple;



	*output_length = (4 * ((input_length + 2) / 3)) + 2;	//+1 because I'll add a null byte
	*output_length -=1;



	if((encoded_data = malloc(*output_length)) == NULL)
        	return NULL;

	memset(encoded_data, 0, *output_length);




        for (i=0, j=0; i < input_length;) 
        {

                octet_a = i < input_length ? (unsigned char)data[i++] : 0;
                octet_b = i < input_length ? (unsigned char)data[i++] : 0;
                octet_c = i < input_length ? (unsigned char)data[i++] : 0;

                triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

                encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
                encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
                encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
                encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
        }


        for (i = 0; i < mod_table[input_length % 3]; i++)
	{
                encoded_data[*output_length - 2 - i] = '=';
	}


return encoded_data;
}

/*****************************************************************************************/

char *uu_encode(char *data, size_t input_length, size_t *output_length) {
	char *encoded_data=NULL;
	int c1, c2, c3, c4, i, counter=1, boundary=input_length/3;


	*output_length = ((input_length / 3) * 4) + 1;

	if(input_length % 3 != 0) 
		boundary+=1;


	
	if((encoded_data = malloc(*output_length+10)) == NULL)
        	return NULL;

	memset(encoded_data, 0, *output_length+10);



	//Line length
	if(input_length) 
		encoded_data[0] =  (input_length) + 32;
	else
		return NULL;


	for(i=0; i < boundary; i++)
	{
		c1 = data[3*i] >> 2;
		c2 = ((data[3*i] << 4) & 060) | ((data[3*i + 1] >> 4) & 017);
		c3 = ((data[3*i + 1] << 2) & 074) | ((data[3*i + 2] >> 6) & 03);
		c4 = data[3*i + 2] & 077;

		if(c1)
			encoded_data[counter++] = (c1 & 077) + 32;
		else
			encoded_data[counter++] = '`';
		if(c2)
			encoded_data[counter++] = (c2 & 077) + 32;
		else
			encoded_data[counter++] = '`';
		if(c3)
			encoded_data[counter++] = (c3 & 077) + 32;
		else
			encoded_data[counter++] = '`';
		if(c4)
			encoded_data[counter++] = (c4 & 077) + 32;
		else
			encoded_data[counter++] = '`';
	}


return encoded_data;
}

/********************************************************************************/


char *badJoke() {
        char *joke = NULL;
        int i, bufferSize=1000, jokeArraySize=1;

	jokeArraySize =  sizeof(jokeArray) / sizeof(jokeArray[0]);

        if((joke = (char*)malloc(bufferSize))==NULL)
                return NULL;

        i = rand() % jokeArraySize;

        snprintf(joke, bufferSize-1,"%s\r\n\r\n",jokeArray[i]);

return joke;
}

/***********************************************************************************/

int transferFileBase64(struct handover *ho) {
        unsigned int count;
        char buffer[1500], buffer2[60]; 
        int bufferspace=ho->blockSize;
        size_t i = -1;
        char *encodedbuffer=NULL;

        memset(buffer, 0, sizeof(buffer));
        memset(buffer2, 0, sizeof(buffer2));


	if(ho->blockSize < 72)
	{
		printf("Block size too small. Must be bigger than 71\n");
		return -1;
	}	

        if(ho->inFile != NULL)
                rewind(ho->inFile);

        while(!(feof(ho->inFile)))
        {
		memset(buffer2, 0, sizeof(buffer2));
                count=read(fileno(ho->inFile), buffer2, 54);


                if(count<=0)
                {
                        if(bufferspace != ho->blockSize)
			{
                                tcpSendString(ho, buffer, ho->direction);
				memset(buffer, 0, sizeof(buffer));
			}
                        break;
                }


                encodedbuffer = base64_encode(buffer2, count, &i);
                if(encodedbuffer == NULL)
                        return -1;


                strncat(buffer, encodedbuffer, bufferspace);
                free(encodedbuffer);

                strncat(buffer, "\r\n", 2);
                bufferspace -= (i+2);

                if(bufferspace <=0)
                {
                        tcpSendString(ho, buffer, ho->direction);
                        memset(buffer, 0, sizeof(buffer));
                        bufferspace = ho->blockSize;
                }

        }

return(0);
}

/***********************************************************************************/

int transferFileUU(struct handover *ho) {
        unsigned int count;
        char buffer[620], buffer2[61];
        int bufferspace=620;
        size_t i = -1;
        char *encodedbuffer=NULL;

        memset(buffer, 0, sizeof(buffer));
        memset(buffer2, 0, sizeof(buffer2));


        if(ho->inFile != NULL)
                rewind(ho->inFile);

        while(!(feof(ho->inFile)))
        {
		memset(buffer2, 0, sizeof(buffer2));
                count=read(fileno(ho->inFile), buffer2, 45);

                if(count<=0)
                {
                        if(bufferspace != 620)
			{
                                tcpSendString(ho, buffer, ho->direction);
				memset(buffer, 0, sizeof(buffer));
			}
	                break;
                }


                encodedbuffer = uu_encode(buffer2, count, &i);
                if(encodedbuffer == NULL)
                        return -1;


                strncat(buffer, encodedbuffer, bufferspace);
                free(encodedbuffer);

                strncat(buffer, "\n", strlen("\n"));
                bufferspace -= (i+1);

                if(bufferspace <=0)
                {
                        tcpSendString(ho, buffer, ho->direction);
                        memset(buffer, 0, sizeof(buffer));
                        bufferspace = 620;
                }

        }

	tcpSendString(ho, "`\r\nend\r\n", ho->direction);


return(0);
}


/***********************************************************************************/

char *URLencoder(char *url) {
        int i;
        int len=250;
        static char encoded[250];


        memset(encoded, 0, sizeof(encoded));

        for(i=0; i < strlen(url); i++)
        {
                if(len<=5)
                {
                        printf("URL encoder: Filename too long\n");
                        return NULL;
                }

                if(url[i]==' ')
                {
                        strncat(encoded, "%20", 4);
                        len -=4;
                }
		else if(url[i]=='"')
                {
                        strncat(encoded, "%22", 4);
                        len -=4;
                }
		else if(url[i]=='%')
                {
                        strncat(encoded, "%25", 4);
                        len -=4;
                }
		else if(url[i]=='(')
                {
                        strncat(encoded, "%28", 4);
                        len -=4;
                }
		else if(url[i]==')')
                {
                        strncat(encoded, "%29", 4);
                        len -=4;
                }
		else if(url[i]=='+')
                {
                        strncat(encoded, "%2b", 4);
                        len -=4;
                }
		else if(url[i]=='.')
                {
                        strncat(encoded, "%2e", 4);
                        len -=4;
                }
		else if(url[i]=='[')
                {
                        strncat(encoded, "%5b", 4);
                        len -=4;
                }
		else if(url[i]==']')
                {
                        strncat(encoded, "%5d", 4);
                        len -=4;
                }
		else if(url[i]=='/')
                {
			//make sure we don't have a double // between path and filename
			if(strlen(encoded)==0)
				continue;

                        strncat(encoded,"%2f", 4);
                        len-=4;

                }
                else
                {
                        strncat(encoded, &url[i], 1);
                        len-=1;
                }

        }


return encoded;
}

/*************************************************************************************************/
/*
int transferFileQuotedprintable(struct handover *ho) {
        unsigned int count;
        char buffer[1500], buffer2[60];
        int bufferspace=1200;
        size_t i = -1;
        char *encodedbuffer=NULL;

        memset(buffer, 0, sizeof(buffer));
        memset(buffer2, 0, sizeof(buffer2));


        if(ho->inFile != NULL)
                rewind(ho->inFile);

        while(!(feof(ho->inFile)))
        {
		memset(buffer2, 0, sizeof(buffer2));
                count=read(fileno(ho->inFile), buffer2, 54);

                if(count<=0)
                {
                        if(bufferspace != 1200)
                                tcpSendString(ho, buffer, ho->direction);
				memset(buffer, 0, sizeof(buffer));
                        break;
                }


                encodedbuffer = quoted_printable_encode(buffer2, count, &i);
                if(encodedbuffer == NULL)
                        return -1;


                strncat(buffer, encodedbuffer, bufferspace);
                free(encodedbuffer);

                strncat(buffer, "\r\n", 2);
                bufferspace -= (i+2);

                if(bufferspace <=0)
                {
                        tcpSendString(ho, buffer, ho->direction);
                        memset(buffer, 0, sizeof(buffer));
                        bufferspace = 1200;
                }

        }

return(0);
}
*/
