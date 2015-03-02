//
//  Simple portscanner
//  Copyright (C) 2014  Aliaksandr Krukau
//
//   This program is free software: you can redistribute it and/or modify
//   it under the terms of the GNU General Public License as published by
//   the Free Software Foundation, either version 3 of the License, or
//   (at your option) any later version.
//
//   This program is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//   GNU General Public License for more details.

//   You should have received a copy of the GNU General Public License
//   along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#define __FAVOR_BSD
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/udp.h>
#include <net/if_arp.h>
#include <pcap/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <fcntl.h>

#include <sys/time.h>
#include <time.h>
#include <limits.h>
#include <string.h>
#include <sys/socket.h>
#include <getopt.h>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <iterator>
#include <string>
#include <vector>
#include <map>

#define MAX_SIZE_STRING 100
#define WINDOW_SIZE 1024 
#define DEFAULT_IP_OFFSET 5 
#define PACKET_SIZE 65535
#define TIMEOUT_SECONDS 5

typedef enum {SYN_SCAN, NULL_SCAN, FIN_SCAN, XMAS_SCAN, 
    ACK_SCAN} scan_options; 

struct pseudo_header {
	unsigned long s_addr;
	unsigned long d_addr;
	char zeros;
	unsigned char type_protocol;
	unsigned short length;
};

// Initial version of scanner, parses the arguments,
// and fills out scan_args structure.

typedef struct {
	std::vector < unsigned short > ports;
	std::vector < uint32_t > ips;
	char prefix[MAX_SIZE_STRING];
	int n_threads;
	int ack_flag;
	int null_flag;
	int fin_flag;
	int syn_flag;
	int udp_flag;
	int xmas_flag;
	int debug;
	int timeout;
} scan_args_t;

void hex_dump(unsigned char *message, unsigned int len) {
	unsigned int i = 0, j = 0;

	printf("Hexadecimal dump:\n");

	for (i = 0; i < len; i++) {
		j = (unsigned) (message[i]);
		printf("%-2X ", j);
		if (!((i + 1) % 16))
			printf("\n");
		else if (!((i + 1) % 4))
			printf("  ");
	}
	printf("\n");
}


void print_ip(uint32_t ip) {
    // Prints IP address given in big-endian (network) order.
    unsigned char octet[4];
	octet[3] = ip & 255;

	ip = ip >> 8;
	octet[2] = ip & 255;

	ip = ip >> 8;
	octet[1] = ip & 255;

	ip = ip >> 8;
	octet[0] = ip & 255;
	printf("%u.%u.%u.%u\n",octet[3],octet[2],octet[1],octet[0]);
}

uint32_t string_to_ip(char *ip_string) {
	uint32_t prefix_ip;
	int ret = inet_pton(AF_INET, ip_string, &prefix_ip);
	if (ret == 0) {
		printf
		    ("Error: incorrect form of IP specification: %s \n",
		     ip_string);
		exit(1);
	}
    return prefix_ip;
}

void update_port(int *port, char d) {
	if (isdigit(d)) {
		*port = *port * 10 + d - '0';
	} else {
		printf("Error: wrong character %c as a port value\n", d);
		exit(1);
	}
}

void parse_port_string(char *token, scan_args_t *scan_args) {
	int start_port = 0;
	int end_port = 0;
	int i;
	for (i = 0; (token[i] != '-') && (token[i] != '\0'); i++) {
		update_port(&start_port, token[i]);
	}

	if (token[i] == '\0') {
		if (start_port > 0 && start_port <= USHRT_MAX) {
			scan_args->ports.push_back(start_port);
			return;
		} else {
			printf("Error: wrong port value: %d \n", start_port);
			exit(1);
		}
	} else {
		i++;
		for (; token[i] != '\0'; i++)
			update_port(&end_port, token[i]);
		//printf("Start port %d end port %d \n", start_port, end_port);

		if (end_port > 0 && end_port <= USHRT_MAX) {
			for (i = start_port; i <= end_port; i++) {
				scan_args->ports.push_back(i);
			}
		} else {
			printf("Error: wrong end port value: %d \n", end_port);
			exit(1);
		}
	}
}
void usage() {
	printf(".Usage: ./portScanner [Option1, ..., OptionN] \n"
	       "  --help                  \t Print this help message\n"
	       "  --ports <port list> \t Scan ports specified in `port list'\n"
	       "                       \t `port list' is the sequence of ports or port ranges,\n"
	       "                       \t separated by commas, for example `1,3-4,7,9-12'.    \n"
	       "                       \t If option `--ports' is not specified, scan ports 1-1024\n"
	       "  --ip <IP address>    \t Scan IP address specified by `IP address' \n"
	       "  --prefix <IP prefix> \t Scan all hosts with IPs specified by `IP prefix'\n"
	       "  --file <file name>   \t Scan all hosts with IPs in file `file name'\n"
	       "  --speedup <number_threads> \t Run portScanner with the number of threads specified by <number_threads> \n"
	       "  --timeout <timeout length> \t Length of timeout in milliseconds \n"
	       "  --d                  \t Print debug information \n"
	       "  --scan <scan_types>  \t Types of port scan to perform.\n"
	       "                       \t Scan type can be: SYN, NULL, FIN, XMAS, ACK. \n"
	       "                       \t By default, portScanner performs all scans. \n");
}

void parse_options(int argc, char *argv[], scan_args_t * scan_args) {
	int ip_set = 0;
	scan_args->ack_flag = 0;
	scan_args->null_flag = 0;
	scan_args->fin_flag = 0;
	scan_args->syn_flag = 0;
	scan_args->udp_flag = 0;
	scan_args->xmas_flag = 0;

	scan_args->debug = 0;
	scan_args->n_threads = 0;
	scan_args->timeout = 0;

	while (1) {
		static struct option long_options[] = {
			{"help", no_argument, 0, 'h'},
			{"d", no_argument, 0, 'd'},
			{"timeout", required_argument, 0, 't'},
			{"ports", required_argument, 0, 'p'},
			{"ip", required_argument, 0, 'i'},
			{"prefix", required_argument, 0, 'r'},
			{"file", required_argument, 0, 'f'},
			{"speedup", required_argument, 0, 's'},
			{"scan", required_argument, 0, 'a'},
			{0, 0, 0, 0}
		};
		int index_to_option = 0;

		int c = getopt_long(argc, argv, "hdp:i:r:f:s:a:",
				    long_options, &index_to_option);

		if (c == -1)
			break;

		switch (c) {
		case 'h':
			usage();
			exit(0);
			break;

		case 'd':
            scan_args->debug = 1;
			break;

		case 't':{
				int timeout = atoi(optarg);
				if (timeout > 0)
					scan_args->timeout = timeout;
				break;
			}

		case 'p':{
				char *token = (char *)malloc(MAX_SIZE_STRING);
				token = strtok(optarg, ",");

				while (token != NULL) {
					parse_port_string(token, scan_args);
					token = strtok(NULL, ",");
				}

				break;
			}

		case 'i': {
			    ip_set = 1;
			    scan_args->ips.push_back(string_to_ip(optarg));
			    break;
            }

		case 'r':{
				ip_set = 1;
				char *token = (char *)malloc(MAX_SIZE_STRING);
				token = strtok(optarg, "/");
				if (token == NULL) {
					printf
					    ("Error: incorrect form of IP prefix: %s \n",
					     token);
					exit(1);
				}
                // Need to use low-endian form to simplify prefix processing
				uint32_t low_endian_ip = ntohl(string_to_ip(token));

				token = strtok(NULL, "/");
				if (token == NULL) {
					printf
					    ("Error: incorrect IP prefix %s \n",
					     token);
					exit(1);
				}
				int size_mask = atoi(token);
				if (size_mask < 0 || size_mask > 32) {
					printf
					    ("Error: incorrect number of bits in mask (%d) \n",
					     size_mask);
					exit(1);
				}

				int n_first_bits = 32 - size_mask;
				uint32_t mask = (~0 << (n_first_bits));

				uint32_t i;
				for (i = 0; i < (1u << n_first_bits); i++) {
					uint32_t current_ip =
					    (low_endian_ip & mask) | i;
					scan_args->ips.push_back(htonl(current_ip));
				}
				break;
			}

		case 'f':{
				std::ifstream ip_file(optarg, std::ios::in);
				if (!ip_file.is_open()) {
					printf("Error: can't open file: %s !\n",
					       optarg);
					exit(1);
				}

                std::string ip_address;
                char ip_c_string[MAX_SIZE_STRING];
				while (ip_file >> ip_address) {
			        ip_set = 1;
                    strncpy(ip_c_string, ip_address.c_str(), MAX_SIZE_STRING);
					scan_args->ips.push_back(string_to_ip(ip_c_string));
				}
				ip_file.close();
				break;
			}

		case 's':{
				int speed = atoi(optarg);
				if (speed > 0)
					scan_args->n_threads = speed;
				break;
			}

		case 'a':{
				int index = optind - 1;
				while (index < argc) {
					if (strcmp(argv[index], "ACK") == 0) {
						scan_args->ack_flag = 1;
						index++;
					} else if (strcmp(argv[index], "FIN") ==
						   0) {
						scan_args->fin_flag = 1;
						index++;
					} else if (strcmp(argv[index], "NULL")
						   == 0) {
						scan_args->null_flag = 1;
						index++;
					} else if (strcmp(argv[index], "SYN") ==
						   0) {
						scan_args->syn_flag = 1;
						index++;
					} else if (strcmp(argv[index], "UDP") ==
						   0) {
						scan_args->udp_flag = 1;
						index++;
					} else if (strcmp(argv[index], "XMAS")
						   == 0) {
						scan_args->xmas_flag = 1;
						index++;
					} else if (argv[index][0] == '-') {
						break;
					} else {
						printf
						    ("Error: wrong scan flag %20s \n",
						     argv[index]);
						exit(1);
					}
				}
				break;
			}

		default:
			// unrecognized option    
			exit(1);
		}
	}

	if (ip_set == 0) {
		printf("Error: no IP address was specified!\n"
		       "Usage: ./portScanner [Option1, ..., OptionN] \n");
		exit(1);
	}    
    // If the type of scan not specified, do all types.
    if (!(scan_args->syn_flag || scan_args->ack_flag ||
         scan_args->null_flag || scan_args->fin_flag || 
         scan_args->xmas_flag || scan_args->udp_flag )) {
	    scan_args->ack_flag = 1;
	    scan_args->null_flag = 1;
	    scan_args->fin_flag = 1;
	    scan_args->syn_flag = 1;
	    scan_args->udp_flag = 1;
	    scan_args->xmas_flag = 1;
    }
    
    // If the ports are not specified, scan ports 1 to 1024
    if (scan_args->ports.size() == 0) { 
        uint16_t i;
        for (i = 1; i <= 1024 ; i++)
	        scan_args->ports.push_back(i);
    }
    if (scan_args->debug) {
        printf("SYN=%d ACK=%d NULL=%d FIN=%d XMAS=%d \n", 
            scan_args->syn_flag, scan_args->ack_flag,
            scan_args->null_flag, scan_args->fin_flag, scan_args->xmas_flag);
	    int number_ips = scan_args->ips.size();
        printf("The following %d IPs will be scanned:\n",number_ips);
	    int i;
	    for (i = 0; i < number_ips; i++) {
            print_ip(scan_args->ips[i]);   
	    }
        printf("\n\n");
    }
}

uint16_t ip_checksum(uint16_t *header, int nbytes) {

	register uint32_t sum = 0;
	uint16_t last_byte = 0;
    uint16_t *hdr = header;

	while (nbytes > 1) {
		sum += *hdr++;
		nbytes -= 2;
	}

	if (nbytes == 1) {
        last_byte = *hdr & 0x00ff;
		sum += last_byte;
	}

    
	sum = (sum & 0xffff) + (sum >> 16); // Move carry bits	
	sum += (sum >> 16);	
	register uint16_t answer = ~sum; // invert and truncate 
	return answer;
}

void print_result(struct tcphdr * tcp,scan_options scan_type, int debug, int *no_reply) {
	if (tcp->th_flags & TH_SYN && scan_type == SYN_SCAN) {
        printf("Syn scan : port %d is open \n", ntohs(tcp->th_sport));
        no_reply = 0;
    } else if (tcp->th_flags & TH_RST && scan_type == SYN_SCAN) {
        printf("Syn scan : port %d is closed \n", ntohs(tcp->th_sport));
        no_reply = 0;
    } else if (tcp->th_flags & TH_RST && scan_type == NULL_SCAN) {
        printf("Null scan : port %d is closed \n", ntohs(tcp->th_sport));
        no_reply = 0;
    } else if (tcp->th_flags & TH_RST && scan_type == FIN_SCAN) {
        printf("Fin scan : port %d is closed \n", ntohs(tcp->th_sport));
        no_reply = 0;
    } else if (tcp->th_flags & TH_RST && scan_type == XMAS_SCAN) {
        printf("Xmas scan : port %d is closed \n", ntohs(tcp->th_sport));
        no_reply = 0;
    } else if (tcp->th_flags & TH_RST && scan_type == ACK_SCAN) {
        printf("ACK scan : port %d is unfiltered \n", ntohs(tcp->th_sport));
        no_reply = 0;
    }
}

void show_time() {
    time_t current_time; 
    current_time = time(NULL); 
    printf("%s\n",asctime(localtime(&current_time)));
}

void get_local_ip(struct in_addr *source, int debug) {
    struct ifaddrs *if_addr_list = NULL;
    struct ifaddrs *ifa = NULL;
    void *address_local = NULL;

    getifaddrs(&if_addr_list);

    for (ifa = if_addr_list; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) {
            continue;
        }
        int interface_not_lo = strcmp(ifa->ifa_name,"lo");
        if (ifa->ifa_addr->sa_family == AF_INET && interface_not_lo) { 
            address_local = &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr;
	        memcpy(source, address_local,
			       sizeof(struct in_addr));
            char local_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, address_local, local_ip, INET_ADDRSTRLEN);
            if (debug)
                printf("Interface %s    source IP Address %s\n", ifa->ifa_name, local_ip); 
            freeifaddrs(if_addr_list);
            return;
        } 
    }
    if (if_addr_list != NULL) 
        freeifaddrs(if_addr_list);
}

int send_test_packet(uint32_t dest_ip, int destination_port, scan_options scan_type, int debug) {
	int sd;
	if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		printf("Error: can't open socket! \n");
    if (debug) {
        printf("Entering send_tcp_raw... \n");
        printf("Opening socket: %d \n",sd);
        printf("Size of iphdr: %zu \n",sizeof(struct tcphdr));
    }
	//char *packet = (char *) malloc(sizeof(struct iphdr) + sizeof(struct tcphdr) + 1000);
	unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + 1000];
	struct iphdr *ip = (struct iphdr *)packet;
	struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
	struct pseudo_header *pseudo =
	    (struct pseudo_header *)(packet + sizeof(struct iphdr) -
				     sizeof(struct pseudo_header));

	struct sockaddr_in sock;
	int sport = 49724;
    int dport = destination_port;

    // Setting the source address
	struct in_addr *source = (struct in_addr *)malloc(sizeof(struct in_addr));
    get_local_ip(source, debug);

    // Setting the destination address 
    struct sockaddr_in *destaddr = (struct sockaddr_in *) 
        malloc(sizeof(struct sockaddr_in)); //destination address
    memset(destaddr, 0, sizeof(destaddr)); 
    destaddr->sin_family = AF_INET;         // IPv4 address family
    memcpy(&(destaddr->sin_addr.s_addr),(struct in_addr *) &dest_ip, sizeof(struct in_addr));    
    destaddr->sin_port = htons(dport);    // Server port
    char destination_name[MAX_SIZE_STRING];
    if (inet_ntop(AF_INET, &destaddr->sin_addr, destination_name, 
        sizeof(destination_name)) != NULL) {
        if (debug)
            printf("Destination %s on port %d \n", destination_name, dport);
    } else
        puts("Unable to get server address");

	sock.sin_family = AF_INET;
	sock.sin_port = htons(dport);
	sock.sin_addr.s_addr = destaddr->sin_addr.s_addr;

	memset(packet, 0, sizeof(struct iphdr) + sizeof(struct tcphdr));

	pseudo->s_addr = source->s_addr;
	pseudo->d_addr = destaddr->sin_addr.s_addr;
	pseudo->type_protocol = IPPROTO_TCP;
	pseudo->length = htons(sizeof(struct tcphdr));

	tcp->th_sport = htons(sport);
	tcp->th_dport = htons(dport);
    if (debug)
        printf("2: Sent packet to TCP port %d dport:%d \n",ntohs(tcp->th_dport),dport);
	tcp->th_seq = rand() + rand();

	tcp->th_off = DEFAULT_IP_OFFSET;
    if (scan_type == SYN_SCAN)
	    tcp->th_flags = TH_SYN;
    else if (scan_type == NULL_SCAN)
	    tcp->th_flags = 0;
    else if (scan_type == FIN_SCAN)
	    tcp->th_flags = TH_FIN;
    else if (scan_type == XMAS_SCAN)
	    tcp->th_flags = TH_FIN & TH_PUSH & TH_URG;
    else if (scan_type == ACK_SCAN)
	    tcp->th_flags = TH_ACK;
    else {
        printf("Undefined type of scan %d in send_test_packet!\n", scan_type);
        exit(1);
    }

	tcp->th_win = htons(WINDOW_SIZE);

	tcp->th_sum = ip_checksum((unsigned short *)pseudo,
			       sizeof(struct tcphdr) +
			       sizeof(struct pseudo_header));

    // IP header for first fragment.
	memset(packet, 0, sizeof(struct iphdr));
	ip->version = 4;
	ip->ihl = 5;
	ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) );
	ip->id = rand();
	ip->frag_off = htons(0);
	ip->ttl = 255;
	ip->protocol = IPPROTO_TCP;
	ip->saddr = source->s_addr;
	ip->daddr = destaddr->sin_addr.s_addr;
	ip->check = ip_checksum((unsigned short *)ip, sizeof(struct iphdr));
    
	if (debug) {
	 	printf("First packet fragment \n");
		hex_dump(packet, htons(ip->tot_len));
	}
	if (debug)
		printf("\nTrying to send_packet(%d , packet, %d, 0 , %s , %lu)\n",
		       sd, ntohs(ip->tot_len), inet_ntoa(destaddr->sin_addr),
		       sizeof(struct sockaddr_in));
	int res;
	if ((res = sendto(sd, packet, ntohs(ip->tot_len), 0,
			  (struct sockaddr *)&sock,
			  sizeof(struct sockaddr_in))) == -1) {
        free(source);
        free(destaddr);
	    if (sd >= 0)
		    close(sd);
		return -1;
	}
	if (debug) {
        show_time();
        printf("Sent packet from TCP port %d to TCP port %d\n",
            ntohs(tcp->th_sport), ntohs(tcp->th_dport));
        printf("Successfully sent %d bytes of tcp scan!\n\n", res);
    }
    
    //  Cleaning up
    free(source);
    free(destaddr);
	if (sd >= 0)
		close(sd);
	return 0;

}

void scan_ip(uint32_t dest_ip, scan_args_t *scan_args, scan_options scan_type) {
    printf("\nScanning the IP ");
    print_ip(dest_ip);

    //const useconds_t time_interval = 50;     
    //usleep(time_interval);
    int debug = scan_args->debug;
    struct timeval timeout; 
    if (scan_args->timeout == 0) {
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
    } else {
        timeout.tv_sec = scan_args->timeout / 1000;
        timeout.tv_usec = scan_args->timeout % 1000;
    }
    if (debug)
        printf("Timeout seconds %ld and milliseconds %ld \n",
            timeout.tv_sec, timeout.tv_usec);
	int number_ports = scan_args->ports.size();
	int i;
    struct in_addr *destination = (struct in_addr *) malloc(sizeof(struct in_addr));
    memcpy(destination, &dest_ip, sizeof(struct in_addr));

    // Information about reply
	unsigned char reply[PACKET_SIZE];
	//struct iphdr *ip = (struct iphdr *)(reply);
	struct tcphdr *tcp = (struct tcphdr *)(reply + sizeof(struct iphdr));
    // Information about replier
	struct sockaddr_in replier;
	socklen_t replier_len = sizeof(replier);
	fd_set read_set;
    int reply_socket;
	if ((reply_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) {
		printf("Error: couldn't open raw socket!\n");
		exit(1);
	}

	for (i = 0; i < number_ports; i++) {
	    if (send_test_packet(dest_ip, scan_args->ports[i], scan_type, debug) < 0) {
            printf("Error sending packet with destination port %d and IP \n",
                scan_args->ports[0]);
            print_ip(dest_ip);
        }

        int j;
        int max_tries = 5; 
        int no_reply = 1;
        for (j = 0; j < max_tries && no_reply; j++) {
            if (debug)
                printf("Current attempt to read # %d no_reply %d \n", j, no_reply);
		    FD_ZERO(&read_set);
		    FD_SET(reply_socket, &read_set);
			select(FD_SETSIZE, &read_set, NULL, NULL, &timeout);
            if (debug)
                printf("After select with j %d \n", j);
		    if (FD_ISSET(reply_socket, &read_set)) {
			    recvfrom(reply_socket, &reply, 5000, 0,
				    (struct sockaddr *)&replier, &replier_len);
                int address_agree = (replier.sin_addr.s_addr == destination->s_addr); 
                int port_agree = (ntohs(tcp->th_sport) == scan_args->ports[i]); 
				if (address_agree && port_agree) {
                    if (debug) {            
	                    printf("Got reply from port: %d \n",ntohs(tcp->th_sport));
                        hex_dump(reply, sizeof(struct iphdr) + sizeof(struct tcphdr));
                    }
                    print_result(tcp, scan_type, debug, &no_reply);
                }
		    }
        }
        // If no reply, let's show the answer
        if (no_reply && debug == 0) {
            if (scan_type == SYN_SCAN) 
                printf("Syn scan : port %d is filtered \n", scan_args->ports[i]);
            else if (scan_type == NULL_SCAN) 
                printf("Null scan: port %d is open|filtered \n", scan_args->ports[i]);
            else if (scan_type == FIN_SCAN)
                printf("Fin scan : port %d is open|filtered \n", scan_args->ports[i]);
            else if (scan_type == XMAS_SCAN) 
                printf("Xmas scan: port %d is open|filtered \n", scan_args->ports[i]);
            else if (scan_type == ACK_SCAN) 
                printf("ACK scan: port %d is filtered \n", scan_args->ports[i]);
        }
    }
    free(destination);
}

int main(int argc, char *argv[]) {
	scan_args_t scan_args;
	parse_options(argc, argv, &scan_args);

	int number_ips = scan_args.ips.size();
	int i;
    if (scan_args.debug)
        printf("Number of threads: %d \n",scan_args.n_threads);
	for (i = 0; i < number_ips; i++) {
        if (scan_args.syn_flag)
            scan_ip(scan_args.ips[i], &scan_args, SYN_SCAN);   
        if (scan_args.null_flag)
            scan_ip(scan_args.ips[i], &scan_args, NULL_SCAN);   
        if (scan_args.fin_flag)
            scan_ip(scan_args.ips[i], &scan_args, FIN_SCAN);   
        if (scan_args.xmas_flag)
            scan_ip(scan_args.ips[i], &scan_args, XMAS_SCAN);   
        if (scan_args.ack_flag)
            scan_ip(scan_args.ips[i], &scan_args, ACK_SCAN);   
	}

    if (scan_args.debug)
        printf("Exiting...\n");
	return 0;
}
