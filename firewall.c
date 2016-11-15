#ifndef __KERNEL__
#define __KERNEL__
#endif

#ifndef MODULE
#define MODULE
#endif

#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>


#define SSH_PORT_BLOCK 22
#define HTTP_PORT_BLOCK 80

#define IN_NETWORK 3232263169 //Inside Network '192.168.108.1'
#define WEB_IP 3232263181 //WebServer IP '192.168.108.13'

static struct nf_hook_ops netfilter_ops;

char* get_ip(unsigned ip)
{
    char* buf;
    buf = kmalloc(16*sizeof(char), GFP_KERNEL);
    
    unsigned char bytes[4];
    bytes[0] = ip & 0x000000FF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    
    snprintf(buf, 16, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
    
    return buf;
}


static unsigned int main_hook(const struct nf_hook_ops *ops,
                              struct sk_buff *sock_buff,
                              const struct net_device *in,
                              const struct net_device *out,
                              int (*okfn)(struct sk_buff*)) {
    
    struct iphdr *iph;          /* IPv4 header */
    struct tcphdr *tcph;        /* TCP header */
    struct icmphdr *icmph;      /* ICMP header */
    u16 sport, dport;           /* Source and destination ports */
    u32 saddr, daddr;           /* Source and destination addresses */
    
    /* Network packet is empty, seems like some problem occurred. Skip it */
    if(!sock_buff) {
        return NF_ACCEPT;
    }

    /* Get IP Header */
    iph = ip_hdr(sock_buff);
    /* Get TCP Header */
    tcph = tcp_hdr(sock_buff);
    /*ICMP Header */
    icmph = icmp_hdr(sock_buff);
    
    /* Convert network endianness to host endiannes */
    sport = ntohs(tcph->source);
    dport = ntohs(tcph->dest);
    saddr = ntohl(iph->saddr);
    daddr = ntohl(iph->daddr);
    
    
    /* Check if its ICMP packet and Drop it if required */
    if(iph->protocol == IPPROTO_ICMP) {
        if(icmph->type != ICMP_ECHOREPLY  && !(saddr > IN_NETWORK && saddr < IN_NETWORK+254) &&
           daddr != WEB_IP) {
            pr_info("Dropped, CAUSE:ICMP, Interface:eth2, DESTINATION:%s\n", get_ip(daddr));
            return NF_DROP;
        }
    }
    
    
    /* Block all SSH access from outside the network */
    if (dport == SSH_PORT_BLOCK && !(saddr > IN_NETWORK && saddr < IN_NETWORK+254) &&
        (daddr >= IN_NETWORK && daddr < IN_NETWORK+254)) {
        pr_info("Dropped, CAUSE:SSH, Interface:eth2, DESTINATION:%s\n", get_ip(daddr));
        return NF_DROP;
    }
    
    /* Block all HTTP access from outside the network except for WebServer */
    if (dport == HTTP_PORT_BLOCK && daddr != WEB_IP &&
        !(saddr > IN_NETWORK && saddr < IN_NETWORK+254) &&
        (daddr >= IN_NETWORK && daddr < IN_NETWORK+254)) {
        pr_info("Dropped, CAUSE:HTTP, Interface:eth2, DESTINATION:%s\n", get_ip(daddr));
        return NF_DROP;
    }
    
    return NF_ACCEPT;
}

/* Register Handler */
static int __init f_init_module(void)
{
    int err_chk;
    netfilter_ops.hook             =       (nf_hookfn *)main_hook;
    netfilter_ops.pf               =       PF_INET;
    netfilter_ops.hooknum          =       NF_INET_PRE_ROUTING;
    netfilter_ops.priority         =       NF_IP_PRI_FIRST;
    err_chk = nf_register_hook(&netfilter_ops);
    if(err_chk < 0)
        pr_err("Error in netfilter hook\n");
    return 0;
}
/* Cleanup */
static void __exit f_cleanup_module(void) {
    nf_unregister_hook(&netfilter_ops);
    pr_info("Unloaded firewall module\n");
}

module_init(f_init_module);
module_exit(f_cleanup_module);
