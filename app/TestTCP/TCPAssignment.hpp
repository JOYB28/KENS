/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <map>


#include <E/E_TimerModule.hpp>

#define WINDOWSIZE 51200
#define BUFFERSIZE 51200
#define MSS 512

namespace E
{
// enum for STATE
enum STATE 
{
    CLOSED, LISTEN, SYN_RCVD, SYN_SENT, ESTABLISHED, CLOSE_WAIT, FIN_WAIT_1, FIN_WAIT_2, TIME_WAIT, LAST_ACK, CLOSING
};
// flags
const unsigned char FIN = 0x1;
const unsigned char SYN = 0x2;
const unsigned char RST = 0x4;
const unsigned char PSH = 0x8;
const unsigned char ACK = 0x10;
const unsigned char URG = 0x20;
const unsigned char ECE = 0x40;
const unsigned char CWR = 0x80;

// structure for TCP header 20B
struct tcp_header
{
	uint16_t srcPort = 0xFFFF;
    uint16_t destPort;
	uint32_t seqNum;
	uint32_t ackNum;
	unsigned char headerLength;
	unsigned char flags = 0;
	uint16_t windowSize;
	uint16_t checksum = 0;
	uint16_t urgentPoint = 0;
};

// connection information
struct connection_info
{
	// always think as my side
	uint16_t srcPort;
	uint16_t destPort;
	uint32_t srcIP;
	uint32_t destIP;

	uint32_t seqNum;
	uint32_t ackNum;
	uint16_t rwnd;
};

// socket information
struct socket_info
{
	uint32_t pid;
	uint32_t fd;
	uint32_t destIP;
	uint16_t destPort = 0xFFFF;
	uint32_t srcIP;
	uint16_t srcPort = 0xFFFF;
	bool isBound = false;
	STATE state = CLOSED;
    // pending map and established map for each server socket
    std::list<connection_info *> pending_lst;
    std::list<connection_info *> established_lst;
    std::list<connection_info *> beforeAccept_lst;
	uint32_t backlog;
	uint32_t family;
	uint32_t type;
	uint32_t protocol;

	uint32_t seqNum;
    uint32_t ackNum;
	UUID connectUUID;
	// UUID closeUUID;
	UUID writeUUID;
	UUID readUUID;
	UUID timerUUID;
	struct accept_info* blocked_accept = NULL;

	struct read_info* blocked_read = NULL;
	struct write_info* blocked_write = NULL;

    uint16_t rwnd;
    // send buffer
    uint8_t send_buffer[BUFFERSIZE];
    uint16_t LastByteSent = 0;
    uint16_t LastByteAcked = 0;
    uint32_t sendBase;
    uint8_t duplicate;
    // block write
    uint8_t* write_pointer;
    int write_length;
    
    //receive buffer
    uint8_t receive_buffer[BUFFERSIZE];
    uint16_t LastByteRead = 0;
    uint16_t LastByteRcvd = 0;
    std::map<uint16_t, uint16_t> missPoint;
    uint16_t endPoint;
    // block read
    uint8_t* read_pointer;
    int read_length;

};

// when server welcome socket block the accept call
struct accept_info
{
	UUID acceptUUID;
	int pid;
	int fd;
	struct sockaddr* addr;
	socklen_t* len;
};
// when read call is blocked
struct read_info
{
	uint8_t* buffer;
	int length;
};
// when write call is blocked
struct write_info
{
	uint8_t* buffer;
	int lenght;
};

// when write call is blocked

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:

private:
	virtual void timerCallback(void* payload) final;
	// KENS1
	virtual void syscall_socket(UUID syscallUUID, int pid, int param1, int param2) final;
	virtual void syscall_close(UUID syscallUUID, int pid, int param1) final;
	virtual void syscall_bind(UUID syscallUUID, int pid, int fd, struct sockaddr* addr_ptr, socklen_t len) final;
	virtual void syscall_getsockname(UUID syscallUUID, int pid, int param1, struct sockaddr* addr, socklen_t* len) final;
	virtual int checkOverlap(struct sockaddr_in* addr) final;
	virtual uint64_t makePidFdKey(uint32_t pid, uint32_t fd) final;
	// KENS2
	virtual void syscall_listen(UUID syscallUUID, int pid, int param1, int param2) final;
    virtual void syscall_connect(UUID syscallUUID, int pid, int param1, struct sockaddr* addr, socklen_t len) final;
    virtual void syscall_accept(UUID syscallUUID, int pid, int param1, struct sockaddr* addr, socklen_t* len) final;
    virtual void syscall_getpeername(UUID syscallUUID, int pid, int param1, struct sockaddr* addr, socklen_t* len) final;
    virtual void makeTCPHeader(struct tcp_header *TCPHeader, uint16_t srcPort, uint16_t destPort, uint32_t seqNum, uint32_t ackNum, unsigned char flags, uint16_t winSize) final;
    virtual uint16_t calculateChecksum(uint32_t srcIP, uint32_t destIP, uint8_t *tcp_packet, uint16_t tcp_packet_length) final;
    //virtual uint32_t pidFromKey(uint64_t key) final;
    //virtual uint32_t fdFromKey(uint64_t key) final;

    // KENS3
    virtual void syscall_read(UUID syscallUUID, int pid, int param1, uint8_t* param2, int param3) final;
    virtual void syscall_write(UUID syscallUUID, int pid, int param1, void* param2, int param3) final;
    virtual void data_send(int length, uint16_t offset, uint64_t key) final;
    virtual uint16_t usingBuffer(uint16_t LastByteAckedOrRead, uint16_t LastByteSentOrRcvd) final;
    virtual void read_memcpy(uint8_t *dest, uint8_t *source, int length, uint16_t source_length, int offset) final;
    virtual void write_memcpy(uint8_t *dest, uint8_t *source, int length, uint16_t source_length, int offset) final;
    virtual int write(UUID syscallUUID, uint64_t key, uint8_t* buffer, int length) final;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;

};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
