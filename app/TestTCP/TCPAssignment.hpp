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
// structure for socket arguments
struct sock_arg
{
	int family;
	int type;
	int protocol;
};

// structure for TCP header
struct TCP_Header
{
	unsigned __int16 sourcePort;
	unsigned __int16 destinationPort;
	unsigned __int32 sequnceNumber;
	unsigned __int32 acknowledgeNumber;
	unsigned int headerLength : 4;
	unsigned int reserved : 4;
	unsigned int CWR : 1;
	unsigned int ECE : 1;
	unsigned int URG : 1;
	unsigned int ACK : 1;
	unsigned int PSH : 1;
	unsigned int RST : 1;
	unsigned int SYN : 1;
	unsigned int FIN : 1;
	unsigned __int16 windowSize;
	unsigned __int16 checksum;
	unsigned __int16 urgentPoint;
}

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
	//KENS2

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
