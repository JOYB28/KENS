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

namespace E
{

// structure for TCP header 20B
struct TCP_Header
{
	uint16_t sourcePort;
	uint16_t destinationPort;
	uint32_t sequenceNumber;
	uint32_t acknowledgeNumber;
	unsigned int headerLength : 4;
	unsigned int reserved : 4;
	unsigned char flags = 0;
	uint16_t windowSize;
	uint16_t checksum;
	uint16_t urgentPoint;
};

// socket information
struct socket_info
{
	uint32_t pid;
	uint32_t fd;
	uint32_t destIP;
	uint16_t destPort;
	uint32_t srcIP;
	uint16_t srcPort;
	bool isBound = false;
	// State
	// Waiting
	uint32_t backlog;
	uint32_t family;
	uint32_t type;
	uint32_t protocol;
};

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:

private:
	virtual void timerCallback(void* payload) final;
	//KENS1
	virtual void syscall_socket(UUID syscallUUID, int pid, int param1, int param2) final;
	virtual void syscall_close(UUID syscallUUID, int pid, int param1) final;
	virtual void syscall_bind(UUID syscallUUID, int pid, int fd, struct sockaddr* addr_ptr, socklen_t len) final;
	virtual void syscall_getsockname(UUID syscallUUID, int pid, int param1, struct sockaddr* addr, socklen_t* len) final;
	virtual int checkOverlap(struct sockaddr_in* addr) final;
	virtual uint64_t makePidFdKey(uint32_t pid, uint32_t fd) final;
	//KENS2
	virtual void syscall_listen(UUID syscallUUID, int pid, int param1, int param2) final;

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
