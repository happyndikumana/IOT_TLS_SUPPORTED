#include <stdio.h>
#include <stdbool.h>
#include "tcpClient.h"
#include "eth0.h"
#include "timer.h"
#include "uart0.h"
#include "tlsClient.h"

clientsSocket socket;
uint8_t serverIpAddress[4] = {52, 54, 110, 50}; //currently Ada fruit
//uint8_t serverIpAddress[4] = {93, 184, 216, 34}; //currently example.com
//uint8_t serverIpAddress[4] = {8, 8, 8, 8}; //currently example.com
uint8_t routerMacAddress[6];// = {0x3C, 0x37, 0x86, 0x2D, 0xB2, 0x3D};
uint8_t tcpState = TCP_CLOSED;

bool tcpDisconnectFlag = false;
bool tcpConnectFlag = true;
bool tcpSynAckReceivedFlag = false;
bool tcpFinAckReceivedFlag = false;
bool tcpAckReceivedFlag = false;
bool tcpClientTimerFlag = false;

bool tcpConnect() {
    return tcpConnectFlag;
}
void changeTcpConnectFlagState(bool boolState) {
    tcpConnectFlag = boolState;
}
bool tcpDisconnect() {
    return tcpDisconnectFlag;
}
void changeTcpDisconnectFlagState(bool state) {
    tcpDisconnectFlag = state;
}
bool tcpAckReceived() {
    return tcpAckReceivedFlag;
}
void changeTcpAckReceivedFlagState(bool state) {
    tcpAckReceivedFlag = state;
}
uint8_t getTcpClientState() {
    return tcpState;
}
void changeTcpClientState(uint8_t state) {
    tcpState = state;
}
bool tcpSynAckReceived() {
    return tcpSynAckReceivedFlag;
}
void changeTcpSynAckReceivedFlagState(bool state) {
    tcpSynAckReceivedFlag = state;
}
bool tcpFinAckReceived() {
    return tcpFinAckReceivedFlag;
}
void changeTcpFinAckReceivedFlagState(bool state) {
    tcpFinAckReceivedFlag = state;
}
bool tcpClientTimerSet() {
    return tcpClientTimerFlag;
}
void changeTcpClientTimerFlagState(bool state) {
    tcpClientTimerFlag = state;
}
void timeClientWaitHandler(){
    changeTcpClientTimerFlagState(false);
    changeTcpClientState(TCP_CLOSED);
}
bool tcpIsSynAck(etherHeader *ether) {
    ipHeader *ip = (ipHeader*)ether->data;
    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ((ip->revSize & 0xF) * 4));
    return (htons(tcp->offsetFields) & 0x01FF) == TCP_SYN_ACK;
}
bool tcpIsFinAck(etherHeader *ether) {
    ipHeader *ip = (ipHeader*)ether->data;
    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ((ip->revSize & 0xF) * 4));
    return (ntohs(tcp->offsetFields) & 0x01FF) == TCP_FIN_ACK;
}
bool tcpIsAck(etherHeader *ether)
{
    ipHeader *ip = (ipHeader*)ether->data;
    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ((ip->revSize & 0xF) * 4));
    return (ntohs(tcp->offsetFields) & 0x01FF) == TCP_ACK;
}
void tcpProcessTcpResponse(etherHeader *ether)
{
    if(tcpIsSynAck(ether))
    {
        changeTcpSynAckReceivedFlagState(true);
    }

    if(tcpIsFinAck(ether))
    {
        changeTcpFinAckReceivedFlagState(true);
    }

    if(tcpIsAck(ether))
    {
        changeTcpAckReceivedFlagState(true);
    }
}
void tcpExtractData(etherHeader *ether) {
    ipHeader *ip = (ipHeader*)ether->data;
    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ((ip->revSize & 0xF) * 4));
    uint8_t i;
    for(i = 0; i < IP_ADD_LENGTH; i++)
    {
        socket.clientIpAddress[i] = ip->sourceIp[i];
    }
    for(i = 0; i < HW_ADD_LENGTH; i++)
    {
        socket.clientHwAddress[i] = ether->sourceAddress[i];
    }
    socket.clientPort = htons(tcp->sourcePort);
    socket.clientAckNumber = htonl(tcp->acknowledgementNumber);
    socket.clientSequenceNumber = htonl(tcp->sequenceNumber);
}
uint16_t buildTcpPacket(etherHeader *ether, uint8_t messageType) {
    uint8_t mac[6];
    uint8_t i = 0;
    uint32_t sum = 0;
    uint16_t tmp16 = 0;
    etherGetMacAddress(mac);
    for (i = 0; i < HW_ADD_LENGTH; i++)
    {
        ether->sourceAddress[i] = mac[i];
        ether->destAddress[i] = routerMacAddress[i];
    }
    ether->frameType = htons(0x800);

    ipHeader *ip = (ipHeader*)ether->data;
    ip->revSize = 0x45;
    uint32_t ipLength = (ip->revSize & 0xf) * 4; //getting length of the ip header
    ip->typeOfService = 0;
    ip->id = 0;
    ip->flagsAndOffset = 0;
    ip->ttl = 128;
    ip->protocol = 6;
    ip->headerChecksum = 0;
    uint8_t sourceIpAddress[4];
    etherGetIpAddress(sourceIpAddress);

    for(i = 0; i < IP_ADD_LENGTH; i++)
    {
        ip->destIp[i] = serverIpAddress[i];
        ip->sourceIp[i] = sourceIpAddress[i];
    }

    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ((ip->revSize & 0xF) * 4));
    tcp->sourcePort = htons(SOURCEPORT);
    tcp->destPort = htons(SERVERPORT);

    if(messageType == TCP_SYN) {
        uint32_t number = random32();
        tcp->sequenceNumber = htonl(number);
        tcp->acknowledgementNumber = 0;
        socket.clientSequenceNumber = number;
        socket.clientAckNumber = 0 + 1;
    }
    else if(messageType == TCP_ACK) {
        tcp->sequenceNumber = htonl(socket.clientAckNumber); //sequence number == the server ack number
        tcp->acknowledgementNumber = htonl(socket.clientSequenceNumber + 1); //ack number = server sequence number+1
    }
    else if(messageType == TCP_FIN_ACK) {
        tcp->sequenceNumber = htonl(socket.clientAckNumber);
        tcp->acknowledgementNumber = htonl(socket.clientSequenceNumber + 1);
    }

    tcp->offsetFields = 0;
    tcp->offsetFields |= htons(((sizeof(tcpHeader)/4) << 12) | messageType);
    tcp->windowSize = htons(2069);
    tcp->urgentPointer = 0;

    //store the length of ip
    ip->length = htons(ipLength + sizeof(tcpHeader));

    //Checksum
    etherCalcIpChecksum(ip);
//  calculating tcp checksum
    etherSumWords(ip->sourceIp, 8, &sum);
    sum += (ip->protocol & 0xff) << 8;
    sum += htons(sizeof(tcpHeader));
    tcp->checksum = 0;
    etherSumWords(tcp, sizeof(tcpHeader), &sum);
    tcp->checksum = getEtherChecksum(sum);

    return sizeof(etherHeader) + ipLength + sizeof(tcpHeader);
}
void calculateChecksum(etherHeader *ether, uint16_t length) {
    ipHeader *ip = (ipHeader*)ether->data;
    tcpHeader *tcp = (tcpHeader*)((uint8_t*)ip + ((ip->revSize & 0xF) * 4));

    uint32_t sum = 0;
    uint32_t ipLength = (ip->revSize & 0xf) * 4;
    tcp->checksum = 0;
    ip->length = htons(ipLength + sizeof(tcpHeader) + length);

    //Checksum
    etherCalcIpChecksum(ip);
//  calculating tcp checksum
    etherSumWords(ip->sourceIp, 8, &sum);
    sum += (ip->protocol & 0xff) << 8;
    uint16_t tcpAndTlsLength = sizeof(tcpHeader) + length;
    sum += htons(tcpAndTlsLength);
    tcp->checksum = 0;
    etherSumWords(tcp, tcpAndTlsLength, &sum);
    tcp->checksum = getEtherChecksum(sum);
}
void sendEtherMessage(etherHeader *ether, uint16_t length) {
    etherPutPacket(ether, length);
}
void tcpClientSendPendingMessages(etherHeader *ether) {
    uint8_t state = getTcpClientState();
    uint16_t packetLength = 0;
    if(state == TCP_CLOSED && tcpConnect()) { //in TCP_CLOSED state and Connect flag is set
        //send syn message
        changeTcpConnectFlagState(false);
        packetLength = buildTcpPacket(ether, TCP_SYN);
        sendEtherMessage(ether, packetLength);
        changeTcpClientState(TCP_SYN_SENT);
    }
    else if(state == TCP_SYN_SENT && tcpSynAckReceived()) { //and syn/ ack was received
        //wait for Syn, Ack
        //send ACK
        //once received change state to TCP_ESTABLISHED
        changeTcpSynAckReceivedFlagState(false);
        packetLength = buildTcpPacket(ether, TCP_ACK);
        sendEtherMessage(ether, packetLength);
        changeTcpClientState(TCP_ESTABLISHED);
    }
    else if(state == TCP_ESTABLISHED) {
        //if active, send FIN/ACK and change state to TCP_FIN_WAIT_ONE (NOT NECESSARY. MQTT DISCONNECT takes care of it)
        //else if passive and a FIN/ACK was received, send ack and change state to TCP_CLOSE_WAIT
        if(tcpDisconnect()) {
            changeTcpDisconnectFlagState(false);
            packetLength = buildTcpPacket(ether, TCP_FIN_ACK);
            sendEtherMessage(ether, packetLength);
            changeTcpClientState(TCP_FIN_WAIT_ONE);
        }
        else if(tcpFinAckReceived()) {
            changeTcpFinAckReceivedFlagState(false);
            packetLength = buildTcpPacket(ether, TCP_ACK);
            sendEtherMessage(ether, packetLength);
            changeTcpClientState(TCP_CLOSE_WAIT);
        }
        else if(!tlsHelloMessageSent()){
        //send TLS client hello
            //build TCP packet
            //build TLS packet
            //calculate tcp checksum and update ip length
            packetLength = buildTcpPacket(ether, TCP_PSH_ACK);
            uint16_t tlsPacketLength = tlsBuildHelloMessage(ether);
            calculateChecksum(ether, tlsPacketLength);
            sendEtherMessage(ether, packetLength + tlsPacketLength);
            changeTlsHelloMessageSentFlagState(true);
        }
    }
    else if(state == TCP_CLOSE_WAIT) {
        //send a FIN/ACK
        //change state to TCP_LAST_ACK
        packetLength = buildTcpPacket(ether, TCP_FIN_ACK);
        sendEtherMessage(ether, packetLength);
        changeTcpClientState(TCP_LAST_ACK);
    }
    else if(state == TCP_LAST_ACK && tcpAckReceived()) {
        //change state to TCP_CLOSED
        changeTcpAckReceivedFlagState(false);
        changeTcpClientState(TCP_CLOSED);
    }
    else if(state == TCP_FIN_WAIT_ONE && tcpAckReceived()) { // and ACK was received
        //change state to TCP_FIN_WAIT_TWO
        changeTcpAckReceivedFlagState(false);
        changeTcpClientState(TCP_FIN_WAIT_TWO);
    }
    else if(state == TCP_FIN_WAIT_TWO && tcpFinAckReceived()) { // and FIN/ACK is received
        //Wait for FIN/ACK
        //send ACK
        //change state to TCP_TIME_WAIT
        changeTcpFinAckReceivedFlagState(false);
        packetLength = buildTcpPacket(ether, TCP_ACK);
        sendEtherMessage(ether, packetLength);
        changeTcpClientState(TCP_TIME_WAIT);
    }
    else if(state == TCP_TIME_WAIT && !tcpClientTimerSet()) { // and timer is not set yet
        //start a 4 min timer with a call back that will change the state to Closed
        startOneshotTimer(timeClientWaitHandler,3);
        changeTcpClientTimerFlagState(true);
    }
}
void tcpProcessArpResponse(etherHeader *ether) {
    arpPacket *arp = (arpPacket*)ether->data;
    uint8_t mac[6];
    uint8_t i;
    for(i = 0; i < HW_ADD_LENGTH; i++) {
        mac[i] = arp->sourceAddress[i];
    }
    setRouterMacAddress(mac);
}
