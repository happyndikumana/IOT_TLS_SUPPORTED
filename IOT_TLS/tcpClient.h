#ifndef TCPCLIENT_H_
#define TCPCLIENT_H_

#include <stdint.h>
#include <stdbool.h>
#include "eth0.h"

#define TCP_SYN     0x002
#define TCP_SYN_ACK 0x012
#define TCP_ACK     0x010
#define TCP_FIN_ACK 0x011
#define TCP_FIN     0x001
#define TCP_PSH_ACK 0x018

#define TCP_CLOSED 1
#define TCP_SYN_SENT 2
#define TCP_ESTABLISHED 3
#define TCP_CLOSE_WAIT 4
#define TCP_LAST_ACK 5
#define TCP_FIN_WAIT_ONE 6
#define TCP_FIN_WAIT_TWO 7
#define TCP_TIME_WAIT 8

#define SOURCEPORT 53144
#define HTTPPORT 80
#define SERVERPORT 443
//#define SERVERPORT 1883

typedef struct _clientsSocket
{
    uint8_t clientIpAddress[4];
    uint8_t clientHwAddress[6];
    uint16_t clientPort;
    uint32_t clientSequenceNumber;
    uint32_t clientAckNumber;
}clientsSocket;

extern clientsSocket socket;

extern uint8_t serverIpAddress[4];
extern uint8_t routerMacAddress[6];
extern uint8_t tcpState;
extern bool tcpDisconnectFlag;
extern bool tcpConnectFlag;
extern bool tcpSynAckReceivedFlag;
extern bool tcpFinAckReceivedFlag;
extern bool tcpAckReceivedFlag;
extern bool tcpClientTimerFlag;

bool tcpConnect();
void changeTcpConnectFlagState(bool boolState);
bool tcpDisconnect();
void changeTcpDisconnectFlagState(bool state);
bool tcpAckReceived();
void changeTcpAckReceivedFlagState(bool state);
bool tcpClientTimerSet();
void changeTcpClientTimerFlagState(bool state);
void timeClientWaitHandler();
uint8_t getTcpClientState();
bool tcpSynAckReceived();
void changeTcpSynAckReceivedFlagState(bool state);
bool tcpFinAckReceived();
void changeTcpFinAckReceivedFlagState(bool state);
void changeTcpClientState(uint8_t state);
bool tcpIsSynAck(etherHeader *ether);
bool tcpIsFinAck(etherHeader *ether);
void tcpProcessTcpResponse(etherHeader *ether);
void tcpExtractData(etherHeader *ether);
void calculateChecksum(etherHeader *ether, uint16_t length);
void sendEtherMessage(etherHeader *ether, uint16_t length);
void tcpClientSendPendingMessages(etherHeader *ether);
void tcpProcessArpResponse(etherHeader *ether);

#endif
