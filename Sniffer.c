#include <netinet/in.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
/*Etherenet Header*/
struct ethheader {
    u_char  ether_dhost[6];    /* destination host address */
    u_char  ether_shost[6];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};
/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
};

//recieve ip header and print icmp information (no need for switch case because we filter only icmp)
void got_packet(u_char *args, const struct pcap_pkthdr *header, 
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 
      printf("From: %s\n", inet_ntoa(ip->iph_sourceip));//Convert ip to ASCII for print
      printf("To: %s\n", inet_ntoa(ip->iph_destip));//Convert ip to ASCII for print
      printf("Protocol: ICMP\n");
      printf("\n");
      return;
    
  }
}


int main()
{
  
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
   
  struct bpf_program fp;
  char filter_exp[] = "ip proto ICMP"; //Set filter, lower case gave me a syntax error (ip proto icmp)
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name wlo1 (change it to you're NIC name if you want it to work)
  
  handle = pcap_open_live("wlo1", BUFSIZ, 1, 1000, errbuf); 
  //Error Detection
  if (handle == NULL) {
    printf("Can't open wlo1: %s\n", errbuf);
    exit(1);
}
  // Step 2: Compile filter_exp into BPF psuedo-code
  int pcaperr;
  pcaperr=pcap_compile(handle, &fp, filter_exp, 0, net);
  //Error Detection
  if(pcaperr==-1){  
    printf("%s\n",pcap_geterr(handle));
  }
  pcap_setfilter(handle, &fp);
                            
  // Step 3: Capture packets
  printf("Initialization Successful!\n");
  printf("Capturing ICMP packets...\n");
  printf("\n");
  pcap_loop(handle, -1, got_packet, NULL);                

  pcap_close(handle);   //Close the handle 
  return 0;
}





