/*
github.com/n0nexist/arpScanner
ARP protocol network scanner written in C
*/

// START NECESSARY LIBRARIES
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <pthread.h>
#include <pcap.h>
#include <ctype.h>
#include <netdb.h>
#include <errno.h>
// END NECESSARY LIBRARIES

// START GLOBAL VARIABLES
char* currentIP = "scan has not started yet";
char* subnet = "";
char* netmask = "";
char* fake_ip = "";
char* interface = "";
// END GLOBAL VARIABLES

void* statusThread(void* arg) {
    /*
    PRINTS THE STATUS OF THE SCAN
    EVERYTIME THE USER PRESSES ENTER
    */

    while (1) {
        getchar();
        printf("\033[3;90mCurrent IP: \033[1;90m%s\033[0m\n", currentIP);
    }
    return NULL;
}

int sendArpRequest(char *target_ip){
    /*
    SENDS AN ARP REQUEST WITH A FAKE IP
    */

    currentIP = target_ip; // update the current ip

    // Create a raw socket for ARP
    int raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_socket == -1) {
        perror("socket");
        return 1;
    }

    // Prepare an ARP request
    struct ether_header eth_header;
    struct ether_arp arp_header;

    // Set the source MAC address
    char source_mac[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55}; // Fake MAC address
    memcpy(eth_header.ether_shost, source_mac, 6);

    // Set the destination MAC address to broadcast (FF:FF:FF:FF:FF:FF)
    char broadcast_mac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memcpy(eth_header.ether_dhost, broadcast_mac, 6);

    eth_header.ether_type = htons(ETHERTYPE_ARP); // ARP frame type

    // ARP header setup
    arp_header.arp_hrd = htons(ARPHRD_ETHER); // Ethernet hardware type
    arp_header.arp_pro = htons(ETHERTYPE_IP); // Protocol type (IP)
    arp_header.arp_hln = 6; // Ethernet address length
    arp_header.arp_pln = 4; // IP address length
    arp_header.arp_op = htons(ARPOP_REQUEST); // ARP request

    // Set the source MAC and IP addresses
    memcpy(arp_header.arp_sha, source_mac, 6);
    struct in_addr source_ip;
    inet_pton(AF_INET, fake_ip, &source_ip);
    memcpy(arp_header.arp_spa, &source_ip, 4);

    // Set the target IP address to resolve
    struct in_addr target_ip_struct;
    inet_pton(AF_INET, target_ip, &target_ip_struct);
    memcpy(arp_header.arp_tpa, &target_ip_struct, 4);

    // Prepare the complete ARP frame
    char frame[sizeof(eth_header) + sizeof(arp_header)];
    memcpy(frame, &eth_header, sizeof(eth_header));
    memcpy(frame + sizeof(eth_header), &arp_header, sizeof(arp_header));

    // Send the ARP request
    struct sockaddr_ll socket_address;
    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_ifindex = if_nametoindex(interface);
    socket_address.sll_protocol = htons(ETH_P_ARP);

    if (sendto(raw_socket, frame, sizeof(frame), 0, (struct sockaddr *)&socket_address, sizeof(socket_address)) == -1) {
        perror("sendto");
        return 1;
    }

    //printf("ARP request sent for IP: %s\r", target_ip);

    close(raw_socket);

    return 0;
}

void* iterateAndScan(){
    /*
    ITERATES TROUGH THE SUBNET
    AND SENDS ARP REQUESTS
    */

    // Wait some time before starting the scan ( the sniffing thread must open the handle first or we could lose some responses )
    sleep(2);

    // Start iterating trough the subnet
    struct in_addr addr;
    if (inet_pton(AF_INET, subnet, &(addr.s_addr)) != 1) {
        printf("\033[1;31mError: invalid subnet\033[0m\n");
        exit(1);
    }

    struct in_addr network;
    network.s_addr = addr.s_addr;

    struct in_addr broadcast;
    broadcast.s_addr = addr.s_addr | ~inet_addr(netmask);

    for (uint32_t i = ntohl(network.s_addr); i <= ntohl(broadcast.s_addr); i++) {
        struct in_addr ip;
        ip.s_addr = htonl(i);
        // Send an arp request for each ip in the subnet
        sendArpRequest(inet_ntoa(ip));
    }
}

char* getMacVendor(const char* mac) {
    /*
    GETS THE VENDOR OF A MAC ADDRESS
    */

    FILE *file = fopen("vendorMacs.xml", "r"); // Open the XML file containing vendor data
    if (file == NULL) {
        return NULL; // If we fail to open the file, return NULL
    }

    char line[1024];
    while (fgets(line, sizeof(line), file) != NULL) {
        if (strstr(line, "mac_prefix") != NULL) { // Look for the line containing "mac_prefix"
            char *prefix_start = strstr(line, "mac_prefix=\"");
            if (prefix_start != NULL) {
                prefix_start += strlen("mac_prefix=\""); // Find the start of the MAC address
                char *prefix_end = strchr(prefix_start, '"'); // Find the end of the MAC address
                if (prefix_end != NULL) {
                    char prefix[13];
                    strncpy(prefix, prefix_start, prefix_end - prefix_start);
                    prefix[prefix_end - prefix_start] = '\0'; // Extract the MAC address

                    if (strncmp(mac, prefix, strlen(prefix)) == 0) { // Check if the MAC address starts with the prefix
                        char *vendor_start = strstr(line, "vendor_name=\"");
                        if (vendor_start != NULL) {
                            vendor_start += strlen("vendor_name=\""); // Find the start of the vendor name
                            char *vendor_end = strchr(vendor_start, '"'); // Find the end of the vendor name
                            if (vendor_end != NULL) {
                                char *vendor = (char*)malloc(vendor_end - vendor_start + 1);
                                strncpy(vendor, vendor_start, vendor_end - vendor_start);
                                vendor[vendor_end - vendor_start] = '\0'; // Extract the vendor name
                                fclose(file);
                                return vendor; // Return the vendor name
                            }
                        }
                    }
                }
            }
        }
    }

    fclose(file);
    return NULL; // Return NULL if the MAC address is not found in the XML file
}

char* getHostName(const char* my_addr) {
    /*
    GETS THE HOSTNAME OF AN IP
    */
    
    struct sockaddr_in sa;
    socklen_t len;
    char* hbuf = (char*)malloc(NI_MAXHOST);  // Allocate memory for the hostname

    memset(&sa, 0, sizeof(struct sockaddr_in));

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(my_addr);
    len = sizeof(struct sockaddr_in);

    // Use getnameinfo to retrieve the hostname, and if it fails, set hbuf to "<not_found>"
    if (getnameinfo((struct sockaddr*)&sa, len, hbuf, NI_MAXHOST, NULL, 0, NI_NAMEREQD)) {
        strcpy(hbuf, "<not_found>");
    }

    return hbuf;  // Return the dynamically allocated hostname
}

void handlePacket(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    /*
    CAPTURES ARP RESPONSES
    */

    struct ether_arp *arp_header = (struct ether_arp *)(packet + 14);

    if (ntohs(arp_header->arp_op) == ARPOP_REPLY) {
        struct in_addr sender_ip;
        char sender_mac[18];

        memcpy(&sender_ip, arp_header->arp_spa, 4);

        snprintf(sender_mac, sizeof(sender_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 arp_header->arp_sha[0], arp_header->arp_sha[1], arp_header->arp_sha[2],
                 arp_header->arp_sha[3], arp_header->arp_sha[4], arp_header->arp_sha[5]);

        char mac_upper[18]; // Create an uppercase copy of the MAC address
        strcpy(mac_upper, sender_mac);
        for (int i = 0; i < 17; i++) {
            mac_upper[i] = toupper(mac_upper[i]); // Convert the MAC to uppercase
        }

        char *vendor = getMacVendor(mac_upper);
        if (vendor == NULL) {
            vendor = "<not_found>";
        }

        char* sender_ip_str = inet_ntoa(sender_ip); // Convert the sender IP to a string
        char* myhostname = getHostName(sender_ip_str); // Get the hostname

        printf("\033[1;34m%s\t\033[32m%s\t\033[37m%s\t\033[31m%s\033[0m\n", sender_mac, sender_ip_str, vendor, myhostname);

        // Free the memory
        free(myhostname);
        free(vendor);
    }
}

void* startSniffingResponses(){
    /*
    STARTS CAPTURING RESPONSES
    */

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "\033[1;31mCould not open device %s: %s\033[0m\n", interface, errbuf);
        exit(3);
    }

    pcap_loop(handle, 0, handlePacket, NULL);

    pcap_close(handle);
}

int main(int argc, char *argv[]) {
    /*
    MAIN CODE
    */

    // Print usage if not enough sys args
    if (argc != 5) {
        printf("\033[4mUsage: %s <interface_ip> <interface_netmask> <fake_ip> <interface_name>\033[0m\n", argv[0]);
        return 1;
    }

    // Parse parameters from sys args
    subnet = argv[1];
    netmask = argv[2];
    fake_ip = argv[3];
    interface = argv[4];

    // Print the received parameters
    printf("Scanning \"\033[31m%s\033[0m\" (\033[32m%s\033[0m) with fake ip \"\033[33m%s\033[0m\" on \033[34m%s\033[0m\n", subnet, netmask, fake_ip, interface);

    // Starts the threads
    pthread_t thread1, thread2, thread3;
    pthread_create(&thread1, NULL, startSniffingResponses, NULL); // thread for sniffing arp responses
    pthread_create(&thread2, NULL, iterateAndScan, NULL); // thread for scanning
    pthread_create(&thread3, NULL, statusThread, NULL); // thread for showing scan status
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    pthread_join(thread3, NULL);
    return 0;

}