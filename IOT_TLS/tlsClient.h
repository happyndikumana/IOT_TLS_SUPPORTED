#ifndef TLSCLIENT_H_
#define TLSCLIENT_H_

#include <stdint.h>
#include <stdbool.h>

typedef struct _tlsClientHelloHeader //61 bytes + 75 + 260 + 8 + 8 + 8 + 28 + 50 + 4 = 502
{
//    uint8_t contentType;
//    uint16_t recordLayerVersion;
//    uint16_t protocolLength;
    uint8_t packetStart[502];
//    uint32_t typeAndLength;
//    uint16_t version;
//    uint8_t random[32];
//    uint8_t sessionIdLength;
//    uint16_t cipherSuiteLength;
//    uint16_t cipherSuite[1];
//    uint8_t compressionMethodLength;
//    uint8_t compressionMethod;
//    uint16_t extensionsLength;

} clientHelloHeader;

extern bool tlsHelloMessageSentFlag;

bool tlsHelloMessageSent();
void changeTlsHelloMessageSentFlagState(bool state);
uint16_t tlsBuildHelloMessage(etherHeader *ether);

#endif
