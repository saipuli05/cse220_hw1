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
    unsigned int intinPayload = max_payload / sizeof(int);
    unsigned totalPack = array_len/ intinPayload;

    if(array_len % intinPayload != 0){
        totalPack += 1;
    }

    unsigned int numPack = 0;
    unsigned int index = 0;
    for(unsigned int i = 0; i< totalPack && i < packets_len; i++){
        unsigned int intinPack = intinPayload;
        if(index + intinPayload > array_len){
            intinPack = array_len - index;
        }
        unsigned int payloadSize = intinPack * sizeof(int);
        unsigned int packSize = 16 + payloadSize;
        packets[i] = malloc(packSize);
        if(packets[i] == NULL){
            break;
        }
        packets[i][0] = (src_addr >> 24) & 0xFF;
        packets[i][1] = (src_addr >> 16) & 0xFF;
        packets[i][2] = (src_addr >> 8) & 0xFF;
        packets[i][3] = src_addr & 0xFF;
        packets[i][4] = (dest_addr >> 24) & 0xFF;
        packets[i][5] = (dest_addr >> 16) & 0xFF;
        packets[i][6] = (dest_addr >> 8) & 0xFF;
        packets[i][7] = src_addr & 0xFF;
        packets[i][8] = (src_port >> 8) & 0xFF;
        packets[i][9] = src_port & 0xFF;
        packets[i][10] = (dest_port >> 8) & 0xFF;
        packets[i][11] = dest_port & 0xFF;
        packets[i][12] = maximum_hop_count;
        packets[i][13] = (compression_scheme << 4) | (traffic_class & 0x0F);
        packets[i][14] = (packSize >> 8) & 0xFF;
        packets[i][15] = packSize & 0xFF;

        for(unsigned int j = 0; j < intinPack; j++){
            int val = array[index + j];
            int payIndex = 16 + j * 4;
            packets[i][payIndex] = (val >> 24) & 0xFF;
            packets[i][payIndex + 1] = (val >> 16) & 0xFF;
            packets[i][payIndex + 2] = (val >> 8) & 0xFF;
            packets[i][payIndex + 3] = val & 0xFF;
            
        }
        index += intinPack;
        numPack++;
        

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
    return numPack;
}
