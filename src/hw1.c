#include "hw1.h"
#include <stdio.h>
#include <stdint.h>

int32_t bytes(unsigned char one, unsigned char two, unsigned char three, unsigned char four){
    return (int32_t)(one << 24 | two << 16 | three << 8 | four);
}

void print_packet_sf(unsigned char packet[])
{
    unsigned int srcAddress = (packet[0] << 20) | (packet[1] << 12) | (packet[2] << 4) | (packet[3] >> 4);
    printf("Source Address: %u\n", srcAddress);

    unsigned int destAddress = ((packet[3] & 0x0F) << 24) | (packet[4] << 16) | (packet[5] << 8) | packet[6];
    printf("Destination Address: %u\n", destAddress);

    unsigned int srcPort = packet[7] >> 4;
    printf("Source Port: %u\n", srcPort);

    unsigned int destPort = packet[7] & 0x0F;
    printf("Destination Port: %u\n", destPort);

    unsigned int fragOffset = (packet[8] << 6) | (packet[9] >> 2);
    printf("Fragment Offset: %u\n", fragOffset);

    unsigned int packLength = ((packet[9] & 0x03) << 12) | (packet[10] << 4) | (packet[11] >> 4);
    printf("Packet Length: %u\n", packLength);

    unsigned int maxhopCount = ((packet[11] & 0x0F) << 1) | (packet[12] >> 7);
    printf("Maximum Hop Count: %u\n", maxhopCount);

    unsigned int checksum = ((packet[12] & 0x7F) << 16) | (packet[13] << 8) | packet[14];
    printf("Checksum: %u\n", checksum);

    unsigned int compScheme = packet[15] >> 6;
    printf("Compression Scheme: %u\n", compScheme);

    unsigned int trafClass = packet[15] & 0x3F;
    printf("Traffic Class: %u\n", trafClass);

    printf("Payload: ");
    for (unsigned int i = 16; i < packLength; i = i + 4){
        int32_t payload = bytes(packet[i], packet[i + 1], packet[i + 2], packet[i + 3]);
        printf("%d ", payload);
    }
    print(" ");
    printf("\n");
    (void)packet;

    
}

unsigned int compute_checksum_sf(unsigned char packet[])
{
    (void)packet;
    return -1;
}

unsigned int reconstruct_array_sf(unsigned char *packets[], unsigned int packets_len, int *array, unsigned int array_len) {
    (void)packets;
    (void)packets_len;
    (void)array;
    (void)array_len;
    return -1;
}

unsigned int packetize_array_sf(int *array, unsigned int array_len, unsigned char *packets[], unsigned int packets_len,
                          unsigned int max_payload, unsigned int src_addr, unsigned int dest_addr,
                          unsigned int src_port, unsigned int dest_port, unsigned int maximum_hop_count,
                          unsigned int compression_scheme, unsigned int traffic_class)
{
    (void)array;
    (void)array_len;
    (void)packets;
    (void)packets_len;
    (void)max_payload;
    (void)src_addr;
    (void)dest_addr;
    (void)src_port;
    (void)dest_port;
    (void)maximum_hop_count;
    (void)compression_scheme;
    (void)traffic_class;
    return -1;
}
