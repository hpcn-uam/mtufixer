#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>

pcap_dumper_t *dumper;

#define MTU 1514

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
static inline unsigned short from32to16(unsigned int x)
{
	/* add up 16-bit and 16-bit for 16+c bit */
	x = (x & 0xffff) + (x >> 16);
	/* add up carry.. */
	x = (x & 0xffff) + (x >> 16);
	return x;
}

static unsigned int do_csum(const unsigned char *buff, int len)
{
	int odd;
	unsigned int result = 0;

	if (len <= 0)
		goto out;
	odd = 1 & (unsigned long) buff;
	if (odd) {
#ifdef __LITTLE_ENDIAN
		result += (*buff << 8);
#else
		result = *buff;
#endif
		len--;
		buff++;
	}
	if (len >= 2) {
		if (2 & (unsigned long) buff) {
			result += *(unsigned short *) buff;
			len -= 2;
			buff += 2;
		}
		if (len >= 4) {
			const unsigned char *end = buff + ((unsigned)len & ~3);
			unsigned int carry = 0;
			do {
				unsigned int w = *(unsigned int *) buff;
				buff += 4;
				result += carry;
				result += w;
				carry = (w > result);
			} while (buff < end);
			result += carry;
			result = (result & 0xffff) + (result >> 16);
		}
		if (len & 2) {
			result += *(unsigned short *) buff;
			buff += 2;
		}
	}
	if (len & 1)
#ifdef __LITTLE_ENDIAN
		result += *buff;
#else
		result += (*buff << 8);
#endif
	result = from32to16(result);
	if (odd)
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
	return result;
}

/*
 *	This is a version of ip_compute_csum() optimized for IP headers,
 *	which always checksum on 4 octet boundaries.
 */
__sum16 ip_fast_csum(const void *iph, unsigned int len)
{
	return (__sum16)~do_csum(iph, len);
}

static inline unsigned short from64to16(unsigned long x)
{
	/* Using extract instructions is a bit more efficient
	   than the original shift/bitmask version.  */

	union {
		unsigned long	ul;
		unsigned int	ui[2];
		unsigned short	us[4];
	} in_v, tmp_v, out_v;

	in_v.ul = x;
	tmp_v.ul = (unsigned long) in_v.ui[0] + (unsigned long) in_v.ui[1];

	/* Since the bits of tmp_v.sh[3] are going to always be zero,
	   we don't have to bother to add that in.  */
	out_v.ul = (unsigned long) tmp_v.us[0] + (unsigned long) tmp_v.us[1]
			+ (unsigned long) tmp_v.us[2];

	/* Similarly, out_v.us[2] is always zero for the final add.  */
	return out_v.us[0] + out_v.us[1];
}

__sum16 csum_tcpudp_magic(__be32 saddr, __be32 daddr,
			  __u32 len, __u8 proto, __wsum sum)
{
	return (__sum16)~from64to16(
		(uint64_t)saddr + (uint64_t)daddr +
		(uint64_t)sum + ((len + proto) << 8));
}

static inline __sum16 tcp_v4_check(int len, __be32 saddr,
				   __be32 daddr, __wsum base)
{
	return csum_tcpudp_magic(saddr,daddr,len,IPPROTO_TCP,base);
}

__wsum csum_partial(const void *buff, int len, __wsum sum)
{
	unsigned long result = do_csum(buff, len);

	/* add in old sum, and carry.. */
	result += (uint32_t)sum;
	/* 32+c bits -> 32 bits */
	result = (result & 0xffffffff) + (result >> 32);
	return (__wsum)result;
}

static void tcf_csum_ipv4_tcp(struct tcphdr* tcph, struct iphdr *iph, unsigned int len)
{
	tcph->check = 0;
	__wsum pcsum = csum_partial(tcph, len, 0);
	tcph->check = tcp_v4_check(len, iph->saddr, iph->daddr, pcsum);
}

u_char *newpkt=NULL;
void pkthandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    if (header->caplen <= MTU){
        pcap_dump((u_char *)dumper, header, packet);
    } else {
        struct ethhdr* eth = (struct ethhdr*) packet;
        u_char *cdata;
        struct pcap_pkthdr nheader = *header;
        unsigned ns_ip,ns_eth,ns_dat, doff=0, ip_doff=0, tcp_doff=0;

        if (ntohs(eth->h_proto) == ETH_P_IP){
            struct iphdr* ip = (struct iphdr*) (packet+sizeof(struct ethhdr));
            if(ip->protocol == 6){
                struct tcphdr* tcp = (struct tcphdr*) (((uint8_t*) ip)+(ip->ihl*4ul));
                // First packet

                // ETH
                memcpy(newpkt + doff, eth, sizeof(struct ethhdr));
                doff   = sizeof(struct ethhdr);

                // IP
                ns_eth = MTU;
                ns_ip  = ns_eth- sizeof(struct ethhdr);
                ns_dat = ns_ip -(tcp->doff*4 + ip->ihl*4ul);
                nheader.caplen = ns_eth;
                nheader.len    = ns_eth;
                //ip->frag_off=0;
                ip->tot_len = htons(ns_ip);

                ip->check = 0;
                ip->check = ip_fast_csum(ip, ip->ihl*4ul);
                memcpy(newpkt + doff, ip , ip->ihl*4ul);
                ip_doff = doff;
                doff  += ip->ihl*4ul;

                // TCP
                tcf_csum_ipv4_tcp(tcp,ip,tcp->doff*4+ns_dat);
                cdata = ((u_char*)tcp) + tcp->doff*4;
                memcpy(newpkt + doff, tcp, tcp->doff*4);
                tcp_doff = doff;
                doff  += tcp->doff*4;

                // Data
                memcpy(newpkt + doff, cdata, ns_dat);

                // Write packet
                //printf("PKT SIZE = %d -> %d\n",header->caplen, nheader.caplen);
                pcap_dump((u_char *)dumper, &nheader, newpkt);

                // Gen new packets
                int remaindata = header->caplen-ns_dat;
                do{
                     // IP
                    cdata += ns_dat;
                    //ip->frag_off= htons((ntohs(ip->frag_off*8)+ns_dat)/8);
                    tcp->seq = htonl(ntohl(tcp->seq) + ns_dat);

                    ns_eth = remaindata >= MTU ? MTU : remaindata;
                    ns_ip  = ns_eth- sizeof(struct ethhdr);
                    ns_dat = ns_ip -(tcp->doff*4 + ip->ihl*4ul);
                    nheader.caplen = ns_eth;
                    nheader.len    = ns_eth;
                    ip->tot_len = htons(ns_ip);
                    ip->id      = htons((ntohs(ip->id)+1));
                    ip->check   = 0;
                    ip->check   = ip_fast_csum(ip, ip->ihl*4ul);
                    memcpy(newpkt + ip_doff, ip , ip->ihl*4ul);

                    // TCP
                    memcpy(newpkt + tcp_doff, tcp, tcp->doff*4);

                    // Data
                    memcpy(newpkt + doff, cdata, ns_dat);
                    tcf_csum_ipv4_tcp((struct tcphdr*)(newpkt + tcp_doff),ip,tcp->doff*4+ns_dat);

                    // Write packet
                    //printf("PKT SIZE = %d (%d) -> %d\n",remaindata, header->caplen, nheader.caplen);
                    pcap_dump((u_char *)dumper, &nheader, newpkt);
                    remaindata -= ns_dat;
                }while(remaindata > sizeof(struct ethhdr)+ip->ihl*4ul+tcp->doff*4);
            }else{
                printf("PKT SIZE = %d\n",header->caplen);
                printf("NO TCP\n");
            }
        }else{
            printf("PKT SIZE = %d\n",header->caplen);
            printf("NO IP\n");
        }
    }

}

char error_buffer[PCAP_ERRBUF_SIZE];

int main(int argc, char**argv){

    if (argc !=3 ){
        printf("%s <in.pcap> <out.pcap>\n",argv[0]);
        return -1;
    }

    char * fnin = argv[1];
    char * fnout = argv[2];

    // OUT
    pcap_t *fhout = pcap_open_dead(DLT_EN10MB, 1 << 16);
    dumper        = pcap_dump_open(fhout, fnout);

    // IN
    pcap_t *fhin  = pcap_open_offline(fnin, error_buffer);
    newpkt = malloc(MTU);
    if(newpkt==NULL){
        perror("Error allocating Memory...\n");
        return errno;
    }
    pcap_loop       (fhin, -1, pkthandler, NULL);

    pcap_dump_close(dumper);
    pcap_close(fhin);
    pcap_close(fhout);
    free(newpkt);

    return 0;
}