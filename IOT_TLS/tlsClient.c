#include <stdio.h>
#include <stdbool.h>
#include "eth0.h"
#include "tlsClient.h"
#include "timer.h"
#include "uart0.h"

bool tlsHelloMessageSentFlag = false;

bool tlsHelloMessageSent() {
    return tlsHelloMessageSentFlag;
}
void changeTlsHelloMessageSentFlagState(bool state) {
    tlsHelloMessageSentFlag = state;
}
uint16_t tlsBuildHelloMessage(etherHeader *ether) {
    ipHeader *ip = (ipHeader*)ether->data;
    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ((ip->revSize & 0xF) * 4));
//    tcp->destPort = htons(443);
    clientHelloHeader *helloMessage = (clientHelloHeader*)tcp->data;
    uint16_t i;
    uint16_t index = 0;
//    helloMessage->contentType = 22;
//    helloMessage->recordLayerVersion = htons(0x0303);
//    helloMessage->protocolLength = htons(47);
    helloMessage->packetStart[index++] = 22;
    helloMessage->packetStart[index++] = 0x03;
    helloMessage->packetStart[index++] = 0x03;
    helloMessage->packetStart[index++] = 0x01;
    helloMessage->packetStart[index++] = 0xF1; //length = sizeof(clientHelloHeader) - 5
    helloMessage->packetStart[index++] = 0x01;
    helloMessage->packetStart[index++] = 0x00; //protocol length = length - 4
    helloMessage->packetStart[index++] = 0x01;
    helloMessage->packetStart[index++] = 0xED;
    helloMessage->packetStart[index++] = 0x03; //version
    helloMessage->packetStart[index++] = 0x03;
    for(i = 0; i < 32; i++) {
        helloMessage->packetStart[index + i] = (uint8_t)(random32() % 255);
    }
    //length = 11 + 32
    index += i;
    helloMessage->packetStart[index++] = 0x00;

    helloMessage->packetStart[index++] = 0x00;
    helloMessage->packetStart[index++] = 0x36;
    helloMessage->packetStart[index++] = 0x13; //server suite
    helloMessage->packetStart[index++] = 0x01;
    helloMessage->packetStart[index++] = 0x13; //server suite 2
    helloMessage->packetStart[index++] = 0x02;
    helloMessage->packetStart[index++] = 0x13;
    helloMessage->packetStart[index++] = 0x03;
    helloMessage->packetStart[index++] = 0xC0;
    helloMessage->packetStart[index++] = 0x2C;
    helloMessage->packetStart[index++] = 0xC0;
    helloMessage->packetStart[index++] = 0x2B;
    helloMessage->packetStart[index++] = 0xC0;
    helloMessage->packetStart[index++] = 0x30;
    helloMessage->packetStart[index++] = 0xC0;
    helloMessage->packetStart[index++] = 0x2F;
    helloMessage->packetStart[index++] = 0x00;
    helloMessage->packetStart[index++] = 0x9F;
    helloMessage->packetStart[index++] = 0x00;
    helloMessage->packetStart[index++] = 0x9E;
    helloMessage->packetStart[index++] = 0xCC;
    helloMessage->packetStart[index++] = 0xA9;
    helloMessage->packetStart[index++] = 0xCC;
    helloMessage->packetStart[index++] = 0xA8;
    helloMessage->packetStart[index++] = 0xCC;
    helloMessage->packetStart[index++] = 0xAA;
    helloMessage->packetStart[index++] = 0xC0;
    helloMessage->packetStart[index++] = 0x27;
    helloMessage->packetStart[index++] = 0xC0;
    helloMessage->packetStart[index++] = 0x23;
    helloMessage->packetStart[index++] = 0xC0;
    helloMessage->packetStart[index++] = 0x28;
    helloMessage->packetStart[index++] = 0xC0;
    helloMessage->packetStart[index++] = 0x24;
    helloMessage->packetStart[index++] = 0xC0;
    helloMessage->packetStart[index++] = 0x0A;
    helloMessage->packetStart[index++] = 0xC0;
    helloMessage->packetStart[index++] = 0x09;
    helloMessage->packetStart[index++] = 0xC0;
    helloMessage->packetStart[index++] = 0x14;
    helloMessage->packetStart[index++] = 0xC0;
    helloMessage->packetStart[index++] = 0x13;
    helloMessage->packetStart[index++] = 0x00;
    helloMessage->packetStart[index++] = 0x6B;
    helloMessage->packetStart[index++] = 0x00;
    helloMessage->packetStart[index++] = 0x67;
    helloMessage->packetStart[index++] = 0x00;
    helloMessage->packetStart[index++] = 0x39;
    helloMessage->packetStart[index++] = 0x00;
    helloMessage->packetStart[index++] = 0x33;
    helloMessage->packetStart[index++] = 0xCC;
    helloMessage->packetStart[index++] = 0x14;
    helloMessage->packetStart[index++] = 0xCC;
    helloMessage->packetStart[index++] = 0x13;
    helloMessage->packetStart[index++] = 0xCC;
    helloMessage->packetStart[index++] = 0x15;


    helloMessage->packetStart[index++] = 0x01; //compression method length
    helloMessage->packetStart[index++] = 0x00;
    //length = 11 + 32 + 59

    //add extensions maybe?
    helloMessage->packetStart[index++] = 0x01; //extension length
    helloMessage->packetStart[index++] = 0x8E; //= 358 + 28 + 4

    helloMessage->packetStart[index++] = 0x00; //supported versions
    helloMessage->packetStart[index++] = 0x2B;
    helloMessage->packetStart[index++] = 0x00;
    helloMessage->packetStart[index++] = 0x03;
    helloMessage->packetStart[index++] = 0x02;
    helloMessage->packetStart[index++] = 0x03;
    helloMessage->packetStart[index++] = 0x04;
    //length = 11 + 32 + 59 + 9

//    //supported_groups
//    //extension length length (4) + 4 bytes = 8
//    //length 14 bytes
//    //supported group = 0x0100
//    helloMessage->packetStart[index++] = 0x00;
//    helloMessage->packetStart[index++] = 0x0A;
//    helloMessage->packetStart[index++] = 0x00;
//    helloMessage->packetStart[index++] = 0x0C;
//    helloMessage->packetStart[index++] = 0x00;
//    helloMessage->packetStart[index++] = 0x0A;
//    helloMessage->packetStart[index++] = 0x00;
//    helloMessage->packetStart[index++] = 0x19;
//    helloMessage->packetStart[index++] = 0x00;
//    helloMessage->packetStart[index++] = 0x18;
//    helloMessage->packetStart[index++] = 0x00;
//    helloMessage->packetStart[index++] = 0x17;
//    helloMessage->packetStart[index++] = 0x00;
//    helloMessage->packetStart[index++] = 0x15;
//    helloMessage->packetStart[index++] = 0x01;
//    helloMessage->packetStart[index++] = 0x00;
    //length = 11 + 32 + 59 + 9 + 16

    //signature algorithms
    //signature hash algorithms length = 30
    //length = 32
    //extension length += 36 bytes
    //signature algorithm = 0x0403
    helloMessage->packetStart[index++] = 0x00;
    helloMessage->packetStart[index++] = 0x0D;
    helloMessage->packetStart[index++] = 0x00;
    helloMessage->packetStart[index++] = 0x20;
    helloMessage->packetStart[index++] = 0x00;
    helloMessage->packetStart[index++] = 0x1E;
    helloMessage->packetStart[index++] = 0x06;
    helloMessage->packetStart[index++] = 0x03;
    helloMessage->packetStart[index++] = 0x05;
    helloMessage->packetStart[index++] = 0x03;
    helloMessage->packetStart[index++] = 0x04;
    helloMessage->packetStart[index++] = 0x03;
    helloMessage->packetStart[index++] = 0x02;
    helloMessage->packetStart[index++] = 0x03;
    helloMessage->packetStart[index++] = 0x08;
    helloMessage->packetStart[index++] = 0x06;
    helloMessage->packetStart[index++] = 0x08;
    helloMessage->packetStart[index++] = 0x0B;
    helloMessage->packetStart[index++] = 0x08;
    helloMessage->packetStart[index++] = 0x05;
    helloMessage->packetStart[index++] = 0x08;
    helloMessage->packetStart[index++] = 0x0A;
    helloMessage->packetStart[index++] = 0x08;
    helloMessage->packetStart[index++] = 0x04;
    helloMessage->packetStart[index++] = 0x08;
    helloMessage->packetStart[index++] = 0x09;
    helloMessage->packetStart[index++] = 0x06;
    helloMessage->packetStart[index++] = 0x01;
    helloMessage->packetStart[index++] = 0x05;
    helloMessage->packetStart[index++] = 0x01;
    helloMessage->packetStart[index++] = 0x04;
    helloMessage->packetStart[index++] = 0x01;
    helloMessage->packetStart[index++] = 0x03;
    helloMessage->packetStart[index++] = 0x01;
    helloMessage->packetStart[index++] = 0x02;
    helloMessage->packetStart[index++] = 0x01;
    //length = 11 + 32 + 59 + 9 + 16 + 36

    //supported_groups
    //extension length length (4) + 4 bytes = 8
    //length 14 bytes
    //supported group = 0x0100
    helloMessage->packetStart[index++] = 0x00;
    helloMessage->packetStart[index++] = 0x0A;
    helloMessage->packetStart[index++] = 0x00;
    helloMessage->packetStart[index++] = 0x0C;
    helloMessage->packetStart[index++] = 0x00;
    helloMessage->packetStart[index++] = 0x0A;
    helloMessage->packetStart[index++] = 0x00;
    helloMessage->packetStart[index++] = 0x19;
    helloMessage->packetStart[index++] = 0x00;
    helloMessage->packetStart[index++] = 0x18;
    helloMessage->packetStart[index++] = 0x00;
    helloMessage->packetStart[index++] = 0x17;
    helloMessage->packetStart[index++] = 0x00;
    helloMessage->packetStart[index++] = 0x15;
    helloMessage->packetStart[index++] = 0x01;
    helloMessage->packetStart[index++] = 0x00;

    helloMessage->packetStart[index++] = 0x00;
    helloMessage->packetStart[index++] = 0x16;
    helloMessage->packetStart[index++] = 0x00;
    helloMessage->packetStart[index++] = 0x00;

    //extension length = 75
    //extension: key_share length = 71
    //client key share length = 69 bytes
    //key exchange length 65
    helloMessage->packetStart[index++] = 0x00; //type key share
    helloMessage->packetStart[index++] = 0x33;

    helloMessage->packetStart[index++] = 0x01; //length
    helloMessage->packetStart[index++] = 0x4B;

    helloMessage->packetStart[index++] = 0x01; //client share length
    helloMessage->packetStart[index++] = 0x49;

    helloMessage->packetStart[index++] = 0x00; //group secp256r1
    helloMessage->packetStart[index++] = 0x17;

    helloMessage->packetStart[index++] = 0x00; //key exchange length
    helloMessage->packetStart[index++] = 0x41;
    uint8_t key[300] = {0x04,0x36,0x44,0xc0,0x0c,0x4f,0x71,0x78,0xd5,0x3f,0x89,0x60,0xaf,0x22,0x09,0xf7,0x2d,0xdc,0x78,0x10,0xcf,0x00,0x21,0xfc,0x1a,0x1e,0xf6,0x24,0x87,0x64,0x51,0x4a,0xc2,0x66,0xfa,0x1b,0x0c,0x17,0xf0,0x18,0xb6,0x1a,0x76,0xdc,0xee,0x32,0x3a,0xcd,0xab,0x24,0x72,0x12,0x52,0x97,0xd9,0xa4,0x0f,0x32,0x16,0x50,0x1b,0x5a,0x54,0x48,0x48};
    for(i = 0; i < 65; i++) {
        helloMessage->packetStart[index++] = (uint8_t)key[i];
    }
    //length = 11 + 32 + 59 + 9 + 16 + 36 + 10 + 65

    helloMessage->packetStart[index++] = 0x01; //group secp256r1
    helloMessage->packetStart[index++] = 0x00;

    helloMessage->packetStart[index++] = 0x01; //key exchange length
    helloMessage->packetStart[index++] = 0x00;
    for(i = 0; i < 256; i++) {
        helloMessage->packetStart[index++] = (uint8_t)(random32() % 255);
    }
    //length = 11 + 32 + 59 + 9 + 16 + 36 + 10 + 4 + 65 + 4 + 256

    char buffer[10];
    sprintf(buffer, "%d", sizeof(clientHelloHeader));
    putsUart0(buffer);
    return sizeof(clientHelloHeader);
}
