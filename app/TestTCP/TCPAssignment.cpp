/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"
#include <map>

// 20150547 Lee Sangmin
// 20160140 Kim Yoonseo,

using namespace std;

namespace E
{

map<uint64_t, struct socket_info *> socket_info_map;
// waiting states

const unsigned char FIN = 0x1;
const unsigned char SYN = 0x2;
const unsigned char RST = 0x4;
const unsigned char PSH = 0x8;
const unsigned char ACK = 0x10;
const unsigned char URG = 0x20;
const unsigned char ECE = 0x40;
const unsigned char CWR = 0x80;


TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		this->syscall_connect(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		this->syscall_accept(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}
// KENS1
// socket()
void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int param1, int param2)
{
	// file descriptor
	int fd = this->createFileDescriptor(pid);
	// initialize arguments in struct socket_info
	uint64_t key = makePidFdKey(pid, fd);
	struct socket_info *info = new struct socket_info;
	info->family = param1;
	info->type = param2;
	socket_info_map.insert(pair<uint64_t, struct socket_info *>(key, info));

	this->returnSystemCall(syscallUUID, fd);
}
// close()
void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int param1)
{
	// file descriptor
	int fd = param1;
	// remove file descriptor 
	this->removeFileDescriptor(pid, fd);
	uint64_t key = makePidFdKey(pid, fd);
	// remove value with key fd in arg_map and addr_map
	if (socket_info_map.find(key) == socket_info_map.end()) {
		// fail 
		this->returnSystemCall(syscallUUID, -1);
	} else {

		delete socket_info_map.find(fd)->second;
		socket_info_map.erase(socket_info_map.find(fd));
		this->returnSystemCall(syscallUUID, 0);
	}

}
// bind()
void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int param1,
	struct sockaddr* addr, socklen_t len)
{	
	// lets print all keys and values in addr_map and arg_map
	/*
	print all things in arg_map and addr_map
	map<int, struct sock_arg *>::iterator iter_arg;
	map<int, struct sockaddr_in *>::iterator iter_addr;
	for(iter_arg = arg_map.begin(); iter_arg != arg_map.end(); iter_arg++) {
		cout << "fd: " << iter_arg->first << " family: " << iter_arg->second->family << " type: " << iter_arg->second->type << "\n";	
	}
	for(iter_addr = addr_map.begin(); iter_addr != addr_map.end(); iter_addr++) {
		cout << "fd: " << iter_addr->first << " port: " << ntohs(iter_addr->second->sin_port) << " ip: " << iter_addr->second->sin_addr.s_addr << "\n";
	}
	*/
	// param1 is file descriptor
	int fd = param1;
	uint64_t key = makePidFdKey(pid, fd);
	// change sockaddr to sockaddr_in
	struct sockaddr_in* addr_in = (struct sockaddr_in *) addr;
	map<uint64_t, struct socket_info *>::iterator iter;
	iter = socket_info_map.find(key); 

	if (iter == socket_info_map.end() || len < sizeof(struct sockaddr*)) {
		// fail if socket fd is not exist in arg_map
		this->returnSystemCall(syscallUUID, -1);
	} else if (!(iter->second->isBound)) {
		// check overlap 
		if (this->checkOverlap(addr_in) < 0) {
			// if address overlaps
			this->returnSystemCall(syscallUUID, -1);
		} else {
			iter->second->srcIP = addr_in->sin_addr.s_addr;
			iter->second->srcPort = addr_in->sin_port;
			iter->second->isBound = true;
			this->returnSystemCall(syscallUUID, 0);
		}
	} else {
		this->returnSystemCall(syscallUUID, -1);
	}

}

int TCPAssignment::checkOverlap(struct sockaddr_in* addr)
{
	struct sockaddr_in * addr_in = (struct sockaddr_in *) addr;
	map<uint64_t, struct socket_info *>::iterator iter;
	// check for all addresses in addr_map
	for (iter = socket_info_map.begin(); iter != socket_info_map.end(); iter++) {
		
		if (addr_in->sin_port == iter->second->srcPort) {
			if (addr_in->sin_addr.s_addr == 0) {
				return -1;
			} else if (iter->second->srcIP == 0) {
				return -1;
			} else if (addr_in->sin_addr.s_addr == iter->second->srcIP) {
				return -1;
			}
			
		}

	}
	return 0;
}
// getsockname()
void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int param1,
	struct sockaddr* addr, socklen_t* len)
{
	// param1 is file descriptor
	int fd = param1;
	uint64_t key = makePidFdKey(pid, fd);
	// change sockaddr to sockaddr_in
	struct sockaddr_in* addr_in = (struct sockaddr_in *) addr;
	map<uint64_t, struct socket_info *>::iterator iter;
	iter = socket_info_map.find(key);
	// get socket 
	if (iter == socket_info_map.end() || *len < sizeof(struct sockaddr)) {
		this->returnSystemCall(syscallUUID, -1);
	} else {
		// get from addr_map
		struct sockaddr_in get_addr_in;
		get_addr_in.sin_family = iter->second->family;
		get_addr_in.sin_addr.s_addr = iter->second->srcIP;
		get_addr_in.sin_port = iter->second->srcPort;
		
		memcpy(addr_in, &get_addr_in, *len);
		this->returnSystemCall(syscallUUID, 0);
	}
}
// KENS2
// listen()
void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd, int bl)
{
	/*
	// set listen flag to 1
	LST = 1;
	// set backlog
	backlog = bl;

	this->returnSystemCall(syscallUUID, 0);
	*/
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int param1, struct sockaddr* addr, socklen_t len)
{
 	struct sockaddr_in* addr_in = (struct sockaddr_in *) addr;

    struct in_addr source_ip;
    uint16_t source_port;

    struct in_addr dest_ip = addr_in->sin_addr.s_addr;
    uint16_t dest_port = addr_in->sin_port;

    uint64_t key = makePidFdKey(pid, param1);
    map<uint64_t, struct socket_info *>::iterator iter;

    iter = socket_info_map.find(key);

    if(iter == socket_info_map.end()) {
        this->returnSystemCall(syscallUUID, -1);
    }

    if(addr_map.find(param1) == addr_map.end()) {
        //if not bound
        int interface = getHost()->getRoutingTable((const uint8_t *)&dest_ip);
        getHost()->getIPAddr((uint8_t *)&source_ip, interface);

        source_port = ((rand() % (0x10000 - 0x400)) + 0x400);
    } else {
        //already bound
        source_ip = addr_map.find(param1)->sin_addr.s_addr;
        source_port = addr_map.find(param1)->sin_port;
    }

    iter->second->destIP = dest_ip;
    iter->second->destPort = dest_port;
    iter->second->srcIP = source_ip;
    iter->second->srcPort = source_port;
    iter->second->isBound = true;

    Packet *myPacket = allocatePacket(54);
    struct TCP_Header TCPHeader;

    TCPHeader->sourcePort = source_port;
    TCPHeader->destinationPort = dest_port;
    TCPHeader->sequenceNumber = htonl(rand() % 0xFFFFFFFF);
    TCPHeader->acknowledgeNumber = htonl(0);
    TCPHeader->flags = SYN;
    TCPHeader->windowSize = htons(51200);
    //TCPHeader->checksum = checksum;

    myPacket->writeData(14+12, &source_ip, 4);
    myPacket->writeData(14+12, &dest_ip, 4);
    mypacket->writeData(14+20, &TCPHeader, 20);

    iter->second->state = SYN_SENT;

    sendPacket("IPv4", myPacket);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int param1, struct sockaddr* addr, socklen_t len) {
    
    map<uint64_t, struct socket_info *>::iterator iter;
    key = makePidFdKey(pid, param1);

    iter = socket_info_map.find(key);

    if(iter == socket_info_map.end()) {
        this->returnSystemCall(syscallUUID, -1);
    }

    if(iter->


}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

}

void TCPAssignment::timerCallback(void* payload)
{

}

uint64_t TCPAssignment::makePidFdKey(uint32_t pid, uint32_t fd)
{
	uint64_t key;
	key = ((uint64_t)pid << 32) + (uint64_t)fd;
	return key;
}

}
