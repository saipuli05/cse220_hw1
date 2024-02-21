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
        if(i + 4 < packLength){
            printf("%d ", payload);
            }
        else{
            printf("%d", payload);
        }
        
    }
    printf("\n");
    (void)packet;

    
}

unsigned int compute_checksum_sf(unsigned char packet[])
{
    unsigned long long sum = 0;

    sum += (packet[0] << 20) | (packet[1] << 12) | (packet[2] << 4) | (packet[3] >> 4);
    sum += ((packet[3] & 0x0F) << 24) | (packet[4] << 16) | (packet[5] << 8) | packet[6];
    sum += packet[7] >> 4;
    sum += packet[7] & 0x0F;
    sum += (packet[8] << 6) | (packet[9] >> 2);
    sum += ((packet[9] & 0x03) << 12) | (packet[10] << 4) | (packet[11] >> 4);
    sum += ((packet[11] & 0x0F) << 1) | (packet[12] >> 7);
    sum += packet[15] >> 6;
    sum += packet[15] & 0x3F;

    unsigned int packLength = ((packet[9] & 0x03) << 12) | (packet[10] << 4) | (packet[11] >> 4);
    for(unsigned int i = 16; i < packLength; i = i + 4){
        int32_t payload = bytes(packet[i], packet[i + 1], packet[i + 2], packet[i + 3]);
        sum = sum + abs(payload);
    }
    unsigned int checksum = sum % ((1 << 23) - 1);
    
    (void)packet;
    return checksum;
}

unsigned int reconstruct_array_sf(unsigned char *packets[], unsigned int packets_len, int *array, unsigned int array_len) {
    

    unsigned int numWrit = 0;
    for(unsigned int i = 0; i < packets_len; i++){
        unsigned char* packet = packets[i];
        
        unsigned int packCheck = ((packet[12] & 0x7F) << 16) | (packet[13] << 8) | packet[14];

        if(compute_checksum_sf(packet) != packCheck){
            continue;
        }
    
    unsigned int fragOffset = (packet[8] << 6) | (packet[9] >> 2);
    unsigned int start = fragOffset / 4;
    if(start >= array_len){
        continue;
    }
    unsigned int packetLength = ((packet[9] & 0x03) << 12) | (packet[10] << 4) | (packet[11] >> 4);
    unsigned int payloadLength = (packetLength - 16) / 4;

    for(unsigned int j = 0; j < payloadLength && (start + j) < array_len; j++){
        array[start + j] = bytes(packet[16 + j * 4], packet[17 + j * 4], packet[18 + j * 4], packet[19 + j * 4]);
        numWrit++;
    }

    }


    (void)packets;
    (void)packets_len;
    (void)array;
    (void)array_len;
    return numWrit;
}

unsigned int packetize_array_sf(int *array, unsigned int array_len, unsigned char *packets[], unsigned int packets_len,
                          unsigned int max_payload, unsigned int src_addr, unsigned int dest_addr,
                          unsigned int src_port, unsigned int dest_port, unsigned int maximum_hop_count,
                          unsigned int compression_scheme, unsigned int traffic_class)
{
    unsigned int ints_in_payload = max_payload / sizeof(int);
    unsigned int total_packets = (array_len + ints_in_payload - 1) / ints_in_payload;

    unsigned int num_packets_created = 0;
    unsigned int array_index = 0;
    for (unsigned int i = 0; i < total_packets && i < packets_len; i++) {
        unsigned int ints_in_this_packet = ints_in_payload;
        if (array_index + ints_in_payload > array_len) {
            ints_in_this_packet = array_len - array_index;
        }
        unsigned int payload_size = ints_in_this_packet * sizeof(int);
        unsigned int packet_size = 16 + payload_size;
        packets[i] = (unsigned char*)malloc(packet_size);

        if (packets[i] == NULL) {
            // Handle memory allocation failure
            for (unsigned int j = 0; j < i; j++) {
                free(packets[j]); // Free any previously allocated memory
            }
            return num_packets_created; // Return the number of packets successfully created so far
        }

        // Zero out the packet memory to avoid uninitialized data
        memset(packets[i], 0, packet_size);

        // Header construction
        packets[i][0] = (src_addr >> 24) & 0xFF;
        packets[i][1] = (src_addr >> 16) & 0xFF;
        packets[i][2] = (src_addr >> 8) & 0xFF;
        packets[i][3] = src_addr & 0xFF;
        packets[i][4] = (dest_addr >> 24) & 0xFF;
        packets[i][5] = (dest_addr >> 16) & 0xFF;
        packets[i][6] = (dest_addr >> 8) & 0xFF;
        packets[i][7] = dest_addr & 0xFF;
        packets[i][8] = (src_port >> 8) & 0xFF;
        packets[i][9] = src_port & 0xFF;
        packets[i][10] = (dest_port >> 8) & 0xFF;
        packets[i][11] = dest_port & 0xFF;
        packets[i][12] = maximum_hop_count;
        packets[i][13] = (compression_scheme << 4) | (traffic_class & 0x0F);
        packets[i][14] = (packet_size >> 8) & 0xFF;
        packets[i][15] = packet_size & 0xFF;

        // Payload construction
        for (unsigned int j = 0; j < ints_in_this_packet; j++) {
            int val = array[array_index + j];
            unsigned int payload_index = 16 + j * 4;
            packets[i][payload_index] = (val >> 24) & 0xFF;
            packets[i][payload_index + 1] = (val >> 16) & 0xFF;
            packets[i][payload_index + 2] = (val >> 8) & 0xFF;
            packets[i][payload_index + 3] = val & 0xFF;
        }

        array_index += ints_in_this_packet;
        num_packets_created++;
    }
    
    
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
    return num_packets_created;
}
