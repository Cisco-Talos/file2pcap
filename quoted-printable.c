#include <stdio.h> 
#include <stdlib.h> 
#include <ctype.h> 
#include <string.h> 
#include <strings.h> 
#include <unistd.h> 

#include "file2pcap.h"
#include "quoted-printable.h"

#define TRUE 1
#define FALSE 0
#define LINELEN 77
#define MAXINLINE 256 

#define ASCII_HORIZONTAL_TAB 9
#define ASCII_LINE_FEED 10
#define ASCII_CARRIAGE_RETURN 13
#define ASCII_SPACE 32
#define ASCII_0 48
#define ASCII_A 65
#define ASCII_LOWER_CASE_A 97 
 

typedef unsigned char byte;

typedef enum {Rule_1,Rule_2,Rule_3,Rule_4,Rule_EBCDIC} character_encoding_rule;
static character_encoding_rule character_class[256];


static int current_line_length= 0;
static int pending_white_space= 0;


#if (SIZEOF_UNSIGNED_LONG == 8) || (SIZEOF_UNSIGNED_LONG_LONG == 0)
typedef unsigned long file_address_type;
#define FILE_ADDRESS_FORMAT_LENGTH "l"
#else
typedef unsigned long long file_address_type;
#define FILE_ADDRESS_FORMAT_LENGTH "ll"
#endif


static int EBCDIC_out= FALSE;

char hexbuffer[10];
char encodedData[20];

/******************************************************************************************************************************************/

/* This is the entry point for this file. 
   This function is called from the protocol stubs, 
   to 'transfer' the file from 'inFile'
*/

int transferFileQuotedPrintable(struct handover *ho) {
        char buffer[1500], buffer2[60];
        int bufferspace=1200, ch;

        memset(buffer, 0, sizeof(buffer));
        memset(buffer2, 0, sizeof(buffer2));

	memset(encodedData, 0, sizeof(encodedData));

        if(ho->inFile != NULL)
                rewind(ho->inFile);

        while((ch=fgetc(ho->inFile))!=EOF)
        {
		encode(ch, encodedData);

                strncat(buffer, encodedData, bufferspace);
		bufferspace -= strlen(encodedData);

		memset(encodedData, 0, sizeof(encodedData));

                if(bufferspace <=0)
                {
                        tcpSendString(ho, buffer, ho->direction);
                        memset(buffer, 0, sizeof(buffer));
                        bufferspace = 1200;
                }

        }


	if(pending_white_space!=0)
	{
		emit_literally(pending_white_space, encodedData);
		pending_white_space= 0;
	}



	if(current_line_length> 0)
	{
		strcat(buffer, "=\r\n");
		bufferspace -= strlen("=\r\n");
	        current_line_length= 0;
	}


	if(bufferspace != 1200)
		tcpSendString(ho, buffer, ho->direction);


return(0);
}



/*********************************************************************************************************/


void check_line_length(int chars_required, char *encoded_data)
{
	if((current_line_length+chars_required)>=(LINELEN-1))
	{
		strcat(encoded_data, "=\r\n");
	        current_line_length= 0;

	}
	current_line_length+= chars_required;
}

/***************************************************************************************************/

void emit_literally(int ch, char *encoded_data)
{
	char buffer[4];

	memset(buffer, 0, sizeof(buffer));

	check_line_length(1, encoded_data);

	snprintf(buffer, sizeof(buffer)-1,"%c", ch);
	strcat(encoded_data, buffer);
}

/**************************************************************************************************************/

static char *emit_hex_encoded(int ch, char *encoded_data)
{
	static char hex[16]= {	ASCII_0,ASCII_0+1,ASCII_0+2,ASCII_0+3,
				ASCII_0+4,ASCII_0+5,ASCII_0+6,
				ASCII_0+7,ASCII_0+8,ASCII_0+9,
				ASCII_A,ASCII_A+1,ASCII_A+2,ASCII_A+3,
				ASCII_A+4,ASCII_A+5};

	check_line_length(3, encoded_data);

	memset(hexbuffer, 0, sizeof(hexbuffer));
	snprintf(hexbuffer, sizeof(hexbuffer)-1,"=%c%c", hex[(ch>>4)&0xF], hex[ch&0xF]);

	strcat(encoded_data, hexbuffer);
	
return hexbuffer;
}


/*************************************************************************************************************/

int encode(int ch, char *encoded_data )
{
	int i;


	for(i= 0;i<=255;i++)
	{
		character_class[i]= Rule_1;
	}


	for(i= 33;i<=60;i++)
	{
		character_class[i]= Rule_2;
	}

	for(i= 62;i<=126;i++)
	{
		character_class[i]= Rule_2;
	}


	character_class[ASCII_HORIZONTAL_TAB]= Rule_3;
	character_class[ASCII_SPACE]= Rule_3;


	character_class[ASCII_LINE_FEED]= Rule_4;
	character_class[ASCII_CARRIAGE_RETURN]= Rule_4;


	character_class[33]= 
	character_class[34]= 
	character_class[35]= 
	character_class[36]= 
	character_class[64]= 
	character_class[91]= 
	character_class[92]= 
	character_class[93]= 
	character_class[94]= 
	character_class[96]= 
	character_class[123]= 
	character_class[124]= 
	character_class[125]= 
	character_class[126]= Rule_EBCDIC;



	switch(character_class[(int)ch])
	{
		case Rule_1:
			if(pending_white_space!=0)
			{
				emit_literally(pending_white_space, encoded_data);
				pending_white_space= 0;
			}
			encoded_data = emit_hex_encoded(ch, encoded_data);
			break;


		case Rule_2:
			if(pending_white_space!=0)
			{
				emit_literally(pending_white_space, encoded_data);
				pending_white_space= 0;
			}
			emit_literally(ch, encoded_data);
			break;


		case Rule_3:
			if(pending_white_space!=0)
			{
				emit_literally(pending_white_space, encoded_data);
				pending_white_space= 0;
			}
			pending_white_space= ch;
			break;


		case Rule_4:
			if(pending_white_space!=0)
			{
				emit_literally(pending_white_space, encoded_data);
				pending_white_space= 0;
			}
			encoded_data = emit_hex_encoded(ch, encoded_data);
                        break;


		case Rule_EBCDIC:
			if(pending_white_space!=0)
			{
				emit_literally(pending_white_space, encoded_data);
				pending_white_space= 0;
			}

			if(EBCDIC_out)
			{
				emit_hex_encoded(ch, encoded_data);
			}
			else
			{
				emit_literally(ch, encoded_data);
			}
			break;
	}

return 0;
}

/**************************************************************************************************************************/
