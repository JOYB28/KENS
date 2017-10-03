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
// 20160140 Kim Yoonseo

using namespace std;

namespace E
{

map<int, struct sockaddr_in *> addr_map;
map<int, struct sock_arg *> arg_map;

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
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
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
	// initialize arguments in struct sock_arg
	struct sock_arg *args = new struct sock_arg;
	args->family = param1;
	args->type = param2;
	arg_map.insert(pair<int, struct sock_arg *>(fd, args));

	this->returnSystemCall(syscallUUID, fd);
}
// close()
void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int param1)
{
	// file descriptor
	int fd = param1;
	// remove file descriptor 
	this->removeFileDescriptor(pid, fd);
	// remove value with key fd in arg_map and addr_map
	if (arg_map.find(fd) == arg_map.end()) {
		// fail 
		this->returnSystemCall(syscallUUID, -1);
	} else if (addr_map.find(fd) == addr_map.end()) {
		delete arg_map.find(fd)->second;
		arg_map.erase(arg_map.find(fd));
		this->returnSystemCall(syscallUUID, 0);
	} else {
		delete arg_map.find(fd)->second;
		delete addr_map.find(fd)->second;
		arg_map.erase(arg_map.find(fd));
		addr_map.erase(addr_map.find(fd));
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
	// change sockaddr to sockaddr_in
	struct sockaddr_in* addr_in = (struct sockaddr_in *) addr;

	if (arg_map.find(fd) == arg_map.end() || len < sizeof(struct sockaddr*)) {
		// fail if socket fd is not exist in arg_map
		this->returnSystemCall(syscallUUID, -1);
	} else if (addr_map.find(fd) == addr_map.end()) {
		// check overlap 
		if (this->checkOverlap(addr_in) < 0) {
			// if address overlaps
			this->returnSystemCall(syscallUUID, -1);
		} else {
			// there's no fd in addr_map
			struct sockaddr_in *address = new struct sockaddr_in;
			*address = *addr_in;
			// for checking
			// cout << "port: " << ntohs(address->sin_port) << " ip: " << address->sin_addr.s_addr << "\n";
			addr_map.insert(pair<int, struct sockaddr_in *>(fd, address));
			this->returnSystemCall(syscallUUID, 0);
		}
	} else {
		this->returnSystemCall(syscallUUID, -1);
	}

}

int TCPAssignment::checkOverlap(struct sockaddr_in* addr)
{
	struct sockaddr_in * addr_in = (struct sockaddr_in *) addr;
	map<int, struct sockaddr_in *>::iterator iter;
	// check for all addresses in addr_map
	for (iter = addr_map.begin(); iter != addr_map.end(); iter++) {
		struct sockaddr_in* temp = iter->second;
		if (addr_in->sin_port == temp->sin_port) {
			if (addr_in->sin_addr.s_addr == 0) {
				return -1;
			} else if (temp->sin_addr.s_addr == 0) {
				return -1;
			} else if (addr_in->sin_addr.s_addr == temp->sin_addr.s_addr) {
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
	// change sockaddr to sockaddr_in
	struct sockaddr_in* addr_in = (struct sockaddr_in *) addr;
	// get socket 
	if (addr_map.find(fd) == addr_map.end() || *len < sizeof(struct sockaddr)) {
		this->returnSystemCall(syscallUUID, -1);
	} else {
		// get from addr_map
		struct sockaddr_in* get_addr_in = addr_map.find(fd)->second;
		memcpy(addr_in, get_addr_in, *len);
		this->returnSystemCall(syscallUUID, 0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

}

void TCPAssignment::timerCallback(void* payload)
{

}

}
