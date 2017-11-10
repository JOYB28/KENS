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
#include <E/E_TimeUtil.hpp>

#define WINDOWSIZE 51200
#define BUFFERSIZE 51200
#define MSS 512

// 20150547 Lee Sangmin
// 20160140 Kim Yoonseo,

using namespace std;

namespace E
{

map<uint64_t, struct socket_info *> socket_info_map;

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
    socket_info_map.clear();
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
		this->syscall_read(syscallUUID, pid, param.param1_int, (uint8_t*)param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		this->syscall_write(syscallUUID, pid, param.param1_int, (uint8_t*)param.param2_ptr, param.param3_int);
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
		this->syscall_getpeername(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}
// KENS1
// socket()
void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int param1, int param2)
{
    //cout << "socket!!!!\n";
	// file descriptor
	int fd = this->createFileDescriptor(pid);
	// initialize arguments in struct socket_info
	uint64_t key = makePidFdKey(pid, fd);

	struct socket_info *info = new struct socket_info;
    info->pid = pid;
    info->fd = fd;
	info->family = param1;
	info->type = param2;
    // state to listen
    info->state = STATE::LISTEN;
	socket_info_map.insert(pair<uint64_t, struct socket_info *>(key, info));

	this->returnSystemCall(syscallUUID, fd);
}
// close()
void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int param1)
{
    //cout << "close!!!!\n";
	// file descriptor
	int fd = param1;
	uint64_t key = makePidFdKey(pid, fd);
    // find socket with key
    map<uint64_t, struct socket_info *>::iterator iter;
    iter = socket_info_map.find(key);
    struct socket_info * current_socket = iter->second;
    // not exist socket
    if (iter == socket_info_map.end()) {
        this->returnSystemCall(syscallUUID, -1);
    } else if (current_socket->state == static_cast<int>(STATE::LISTEN) ||
                current_socket->state == static_cast<int>(STATE::SYN_RCVD) ||
                current_socket->state == static_cast<int>(STATE::CLOSED) ||
                current_socket->state == static_cast<int>(STATE::SYN_SENT)) {
        // remove file descriptor 
        this->removeFileDescriptor(pid, fd);
        delete socket_info_map.find(key)->second;
		socket_info_map.erase(socket_info_map.find(key));
		this->returnSystemCall(syscallUUID, 0);
        return;
    } else {
        /*
            Send FIN packet
        */
        Packet *my_packet = allocatePacket(54);
        struct tcp_header TCPHeader;
       
        // packet header
        makeTCPHeader(&TCPHeader, current_socket->srcPort, current_socket->destPort, current_socket->seqNum, 0, FIN, WINDOWSIZE);
        current_socket->seqNum += 1;
        // checksum
        uint16_t checksum = calculateChecksum(current_socket->srcIP, current_socket->destIP,
            (uint8_t*)&TCPHeader, 20);
        // need to change to network order
        TCPHeader.checksum = htons(checksum);
        // write packet
        my_packet->writeData(14 + 12, &current_socket->srcIP, 4);
        my_packet->writeData(14 + 16, &current_socket->destIP, 4);
        my_packet->writeData(14 + 20, &TCPHeader, 20);

        // change state
        if (current_socket->state == static_cast<int> (STATE::ESTABLISHED)){
            current_socket->state = FIN_WAIT_1;
        } else if (current_socket->state == static_cast<int> (STATE::CLOSE_WAIT)) {
            current_socket->state = LAST_ACK;
        }
        
        // send packet
        this->sendPacket("IPv4", my_packet);
        this->returnSystemCall(syscallUUID, 0);
        return;
    }
}
// bind()
void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int param1,
	struct sockaddr* addr, socklen_t len)
{	
    //cout << "bind!!!!\n";
	int fd = param1;
	uint64_t key = makePidFdKey(pid, fd);
	// change sockaddr to sockaddr_in
	struct sockaddr_in* addr_in = (struct sockaddr_in *) addr;

    // find corresponding socket
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
	int fd = param1;
	uint64_t key = makePidFdKey(pid, fd);
    // find corresponding socket
	map<uint64_t, struct socket_info *>::iterator iter;
	iter = socket_info_map.find(key);

	if (iter == socket_info_map.end() || *len < sizeof(struct sockaddr)) {
		this->returnSystemCall(syscallUUID, -1);
	} else {
		// make sockaddr_in* to save information of socket address
    	struct sockaddr_in* get_addr_in = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
        socklen_t tlen = sizeof(struct sockaddr_in);
        // initialize memory
        memset(get_addr_in, 0, tlen);
        // save information of socket address to get_addr_in
		get_addr_in->sin_family = iter->second->family;
		get_addr_in->sin_addr.s_addr = iter->second->srcIP;
		get_addr_in->sin_port = iter->second->srcPort;
        // type_case of get_addr_in sockaddr_in* to sockaddr*
        struct sockaddr* tt = (struct sockaddr *) get_addr_in;
        // copy data from tt to addr
        memcpy(addr, tt, *len);
        //method 2
        /*
        ((struct sockaddr_in *) addr)->sin_family = iter->second->family;
        ((struct sockaddr_in *) addr)->sin_addr.s_addr = iter->second->srcIP;
        ((struct sockaddr_in *) addr)->sin_port = iter->second->srcPort;
        */
		this->returnSystemCall(syscallUUID, 0);
	}
    return;
}
// KENS2
// listen()
void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd, int bl)
{
    //cout << "listen!!!!\n";
    // server socket
    uint64_t key = makePidFdKey(pid, fd);
    map<uint64_t, struct socket_info *>::iterator iter;
    iter = socket_info_map.find(key); 
	iter->second->state = E::LISTEN;
    iter->second->backlog = bl;

	this->returnSystemCall(syscallUUID, 0);
    return;
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int param1, struct sockaddr* addr, socklen_t len)
{
    //cout << "connect!!!\n";
    // client socket
 	struct sockaddr_in* addr_in = (struct sockaddr_in *) addr;

    uint32_t source_ip;
    uint16_t source_port;

    uint32_t dest_ip = addr_in->sin_addr.s_addr;
    uint16_t dest_port = addr_in->sin_port;

    uint64_t key = makePidFdKey(pid, param1);
    // find corresponding socket
    map<uint64_t, struct socket_info *>::iterator iter;
    iter = socket_info_map.find(key);

    if (iter == socket_info_map.end()) {
        this->returnSystemCall(syscallUUID, -1);
        return;
    }
    struct socket_info * current_socket = iter->second;
    if (current_socket->srcPort == 0xFFFF) {
        //if not bound
        int interface = getHost()->getRoutingTable((const uint8_t *)&dest_ip);
        if (!getHost()->getIPAddr((uint8_t *)&source_ip, interface)) {
            this->returnSystemCall(syscallUUID, -1);
            return;
        }
        source_port = ((rand() % (0x10000 - 0x401)) + 0x400);
    } else {
        //already bound
        source_ip = current_socket->srcIP;
        source_port = current_socket->srcPort;
    }
    // save the UUID for futre unblocking
    current_socket->connectUUID = syscallUUID;

    current_socket->destIP = dest_ip;
    current_socket->destPort = dest_port;
    current_socket->srcIP = source_ip;
    current_socket->srcPort = source_port;
    current_socket->isBound = true;

    Packet *myPacket = allocatePacket(54);
    struct tcp_header TCPHeader;
    // randonm sequence number
    uint32_t seqNum = rand() % 0xFFFFFFFF;
    // make TCP header
    uint16_t windowsize = BUFFERSIZE - usingBuffer(current_socket->LastByteRcvd, current_socket->LastByteRcvd);
    makeTCPHeader(&TCPHeader, source_port, dest_port, seqNum,  0, SYN, windowsize);
    current_socket->seqNum = seqNum + 1;

    // checksum
    uint16_t checksum = calculateChecksum(source_ip, dest_ip, (uint8_t*)&TCPHeader, 20);
    // need to change to network order
    TCPHeader.checksum = htons(checksum);
    // write packet
    myPacket->writeData(14+12, &source_ip, 4);
    myPacket->writeData(14+16, &dest_ip, 4);
    myPacket->writeData(14+20, &TCPHeader, 20);
    // change state
    current_socket->state = SYN_SENT;
    // send packet
    sendPacket("IPv4", myPacket);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int param1, struct sockaddr* addr, socklen_t* len) {
    //cout << "accept!!!!\n";
    map<uint64_t, struct socket_info *>::iterator iter;
    uint64_t key = makePidFdKey(pid, param1);

    // find corresponding socket
    iter = socket_info_map.find(key);
    struct socket_info * current_socket = iter->second;

    if(iter == socket_info_map.end()) {
        this->returnSystemCall(syscallUUID, -1);
    }
    // check if there is beforeAccept_lst
    if(!current_socket->beforeAccept_lst.empty()) {
        map<uint64_t, struct socket_info *>::iterator iter2;

        struct connection_info * temp = iter->second->beforeAccept_lst.front();

        ((struct sockaddr_in *) addr)->sin_family = AF_INET;
        ((struct sockaddr_in *) addr)->sin_port = temp->srcPort;
        ((struct sockaddr_in *) addr)->sin_addr.s_addr = temp->srcIP;

        iter->second->beforeAccept_lst.pop_front();

        for(iter2 = socket_info_map.begin(); iter2 != socket_info_map.end(); iter2++) {
            if ((iter2->second->destIP == temp->destIP) &&
                    (iter2->second->srcIP == temp->srcIP) &&
                    (iter2->second->destPort == temp->destPort) &&
                    (iter2->second->srcPort == temp->srcPort)) {
                break;
            }
        }
        // return corresponding fd
        this->returnSystemCall(syscallUUID, iter2->second->fd);
        return;
    } else if(current_socket->established_lst.empty()) {
        // block the accept syscall
        struct accept_info* blocked_accept = new struct accept_info;
        blocked_accept->acceptUUID = syscallUUID;
        blocked_accept->pid = pid;
        blocked_accept->fd = param1;
        blocked_accept->addr = addr;
        blocked_accept->len = len;
        current_socket->blocked_accept = blocked_accept;
        return;
    } else {
        // create new socket by using first one in established_lst
        struct socket_info* new_socket = new struct socket_info;
        struct connection_info *cnt_info;
        cnt_info = iter->second->established_lst.front();
        // create fd
        int socketfd = this->createFileDescriptor(pid);

        new_socket->pid = pid;
        new_socket->fd = socketfd;
        new_socket->destIP = cnt_info->destIP;
        new_socket->destPort = cnt_info->destPort;
        new_socket->srcIP = cnt_info->srcIP;
        new_socket->srcPort = cnt_info->srcPort;
        new_socket->isBound = true;
        new_socket->state = ESTABLISHED;
        new_socket->family = AF_INET;
        new_socket->type = SOCK_STREAM;
        new_socket->rwnd = cnt_info->rwnd;
        ///////////
        new_socket->seqNum = cnt_info->seqNum;
        new_socket->ackNum = cnt_info->ackNum;
        
        ((struct sockaddr_in *) addr)->sin_family = new_socket->family;
        ((struct sockaddr_in *) addr)->sin_port = new_socket->srcPort;
        ((struct sockaddr_in *) addr)->sin_addr.s_addr = new_socket->srcIP;

        iter->second->established_lst.pop_front();

    	uint64_t key = makePidFdKey(pid, socketfd);
	   	socket_info_map.insert(pair<uint64_t, struct socket_info *>(key, new_socket));

        this->returnSystemCall(syscallUUID, socketfd);
        return;
    }

}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
    //cout << "packetArrived!!!!!\n";
	// packet arrived
    // packet length information (IP 14B + 12B + 4B + 4B, tcp header 20B)
    uint16_t packet_length = packet->getSize();
    uint16_t tcp_packet_length = packet_length - 34;
    uint16_t tcp_data_length = tcp_packet_length - 20;
    // received tcp header and packet
    // tcp header
    struct tcp_header tcp_header;
    // whole packet
    uint8_t tcp_packet[tcp_packet_length];
    packet->readData(34, tcp_packet, tcp_packet_length);
    packet->readData(34, &tcp_header, 20);
    
    // IP addresses 
    // IPv4 32bit, 4B each, received one
    uint32_t src_ip, dest_ip;
    packet->readData(14 + 12, &src_ip, 4);
    packet->readData(14 + 16, &dest_ip, 4);

    // checksum check on received packet
    uint16_t checksum = calculateChecksum(src_ip, dest_ip, tcp_packet, tcp_packet_length);
    // bit error
    if (checksum != 0) {
        this->freePacket(packet);
        return;
    }
    // define my packet (sending packet)
    Packet* my_packet = this->clonePacket(packet);
    // tcp packet header for my packet (sending packet)
    struct tcp_header my_packet_header;
    // swap src and dest IP
    my_packet->writeData(14 + 12, &dest_ip, 4);
    my_packet->writeData(14 + 16, &src_ip, 4);

    // find for matching socket
    uint64_t key = -1;
    map<uint64_t, struct socket_info*>::iterator iter;
    for (iter = socket_info_map.begin(); iter != socket_info_map.end(); iter++) {
        struct socket_info * temp_socket = iter->second;
        if (temp_socket->srcPort == tcp_header.destPort &&
            temp_socket->destPort == tcp_header.srcPort &&
            temp_socket->srcIP == dest_ip &&
            temp_socket->destIP == src_ip) {
            key = iter->first;
            break;
        }
    }
    // can't find perfectly right socket (4 arguments same)
    // there can be other situation in server when that is welcoming socket
    if ((int64_t)key == -1) {
        for (iter = socket_info_map.begin(); iter != socket_info_map.end(); iter++) {
            struct socket_info * temp_socket = iter->second;
            if (temp_socket->srcPort == tcp_header.destPort && 
                (temp_socket->srcIP == dest_ip || temp_socket->srcIP == 0)) {
                key = iter->first;
                // if srcIP is 0, fill it with arrived packet 
                if (temp_socket->srcIP == 0) {
                    temp_socket->srcIP = dest_ip;
                }
                break;
            }
        }
    }
    // can't find right socket
    // need to deal with when key is 111111...1 = -1
    if ((int64_t)key == -1) {
    	this->freePacket(packet);
    	this->freePacket(my_packet);
    	return;
    }
    // finally found
    iter = socket_info_map.find(key);
    struct socket_info * current_socket = iter->second;

    uint32_t recv_seq_number = ntohl(tcp_header.seqNum);
    uint32_t recv_ack_number = ntohl(tcp_header.ackNum);
    current_socket->rwnd = ntohs(tcp_header.windowSize);
    //cout << "rwnd1: " << current_socket->rwnd << endl;

    // flag of arrived packet
    unsigned char flags = tcp_header.flags;
    unsigned char type = flags & 0x13; //to see ACK SYN FIN
    
    switch(type) {
    	// SYN packet
    	case(0x2):
        {
            /*
                SERVER SIDE
            */
    		// if number of pending is backlog, reject the packet
    		if (current_socket->pending_lst.size() == current_socket->backlog) {
    			this->freePacket(packet);
    			this->freePacket(my_packet);
    			return;
  			}
            // choose init sequence number randomly
            uint32_t send_seq_number = (rand() % 0xffffffff);
            uint32_t send_ack_number = recv_seq_number + 1;

  			// make new connection
  			struct connection_info *new_connection = new struct connection_info;
            // new connection's src is dest in received tcp header and vice versa
  			new_connection->srcPort = tcp_header.destPort;
  			new_connection->destPort = tcp_header.srcPort;
  			new_connection->srcIP = dest_ip;
  			new_connection->destIP = src_ip;
              new_connection->rwnd = ntohs(tcp_header.windowSize);

            // push it to pending list for current_socket
  			current_socket->pending_lst.push_back(new_connection);

  			// make packet header for sending packet
            uint16_t windowsize = BUFFERSIZE - usingBuffer(current_socket->LastByteRcvd, current_socket->LastByteRcvd);
            makeTCPHeader(&my_packet_header, new_connection->srcPort, new_connection->destPort,
                send_seq_number, send_ack_number, SYN + ACK, windowsize);

            new_connection->seqNum = send_seq_number + 1;
            new_connection->ackNum = send_ack_number;

            // checksum  
            uint16_t checksum = calculateChecksum(new_connection->srcIP, new_connection->destIP, 
                (uint8_t*)&my_packet_header, 20);
            my_packet_header.checksum = htons(checksum);
  
            // write packet
            my_packet->writeData(14 + 20, &my_packet_header, 20);
            // change state
            current_socket->state = SYN_RCVD;
            // send packet
            this->sendPacket(fromModule, my_packet);
            return;
        }
    	// SYN_ACK packet
    	case(0x12):
        {
    		// client side

    		// reject packet if it's state is not SYN_SENT
    		if (current_socket->state != static_cast<int> (SYN_SENT)) {
    			this->freePacket(packet);
    			this->freePacket(my_packet);
    			return;
    		}
    		/*
    			send ACK packet to server
    			with ack_number
    		*/
            uint32_t send_ack_number = recv_seq_number + 1;
            uint32_t send_seq_number = current_socket->seqNum;
            uint16_t windowsize = BUFFERSIZE - usingBuffer(current_socket->LastByteRcvd, current_socket->LastByteRcvd);
            makeTCPHeader(&my_packet_header, tcp_header.destPort, tcp_header.srcPort,
                send_seq_number, send_ack_number, ACK, windowsize);

            current_socket->ackNum = send_ack_number;

            // checksum
            uint16_t checksum = calculateChecksum(src_ip, dest_ip, (uint8_t*)&my_packet_header, (uint16_t)20);
            my_packet_header.checksum = htons(checksum);

            // write packet
            my_packet->writeData(14 + 20, &my_packet_header, 20);
            // change state
    		current_socket->state = ESTABLISHED;
            // send packet
            this->sendPacket("IPv4", my_packet);

            // unblock the connect syscall
            this->returnSystemCall(current_socket->connectUUID, 0);
    		return;
        }
    	// ACK
    	case(0x10):
        {
            // for debugging
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
            /*
            cout << "ACK for SYN_ACK\n";
            cout << "pending_lst\n";
            for(auto v: current_socket->pending_lst) {
                cout << "srcPort: "<< v->srcPort << " destPort: " << v->destPort << " srcIP: " << v->srcIP << " destIP: " << v->destIP << " seqNum: " << v->seqNum << endl;

                //cout << v << "\n";
            }
            cout << "established_lst\n";
            for(auto v: current_socket->established_lst) {
                cout << "srcPort: "<< v->srcPort << " destPort: " << v->destPort << " srcIP: " << v->srcIP << " destIP: " << v->destIP << " seqNum: " << v->seqNum << endl; 
                //cout << v << "\n";
            }
            cout << "received packet info\n";
            cout << "srcPort: " << tcp_header.destPort << " destPort: " << tcp_header.srcPort << " srcIP: " << dest_ip << " destIP: " << src_ip << " seqNum: " << ntohl(tcp_header.ackNum) << endl;

            cout << current_socket->state << endl;
            */

            // SYN_RCVD (server)
            if (current_socket->state == static_cast<int> (STATE::SYN_RCVD)) {
                list<connection_info *>::iterator iter;
                for(iter = current_socket->pending_lst.begin(); 
                    iter != current_socket->pending_lst.end(); iter ++) {
                    if (((*iter)->srcPort == tcp_header.destPort) &&
                        ((*iter)->destPort == tcp_header.srcPort) &&
                        ((*iter)->srcIP == dest_ip) &&
                        ((*iter)->destIP == src_ip) &&
                        ((*iter)->seqNum == ntohl(tcp_header.ackNum))) {

                        // push it to established list and erase it in pending list
                        current_socket->established_lst.push_back(*iter);
                        current_socket->pending_lst.erase(iter);
                        break;
                    }
                }

                // if there are blocked accept
                if (current_socket->blocked_accept != NULL) {
                    struct socket_info* new_socket = new struct socket_info;
                    struct connection_info *cnt_info;
                    cnt_info = current_socket->established_lst.front();
                    
                    int socketfd = this->createFileDescriptor(current_socket->blocked_accept->pid);

                    new_socket->pid = current_socket->blocked_accept->pid;
                    new_socket->fd = socketfd;
                    new_socket->destIP = cnt_info->destIP;
                    new_socket->destPort = cnt_info->destPort;
                    new_socket->srcIP = cnt_info->srcIP;
                    new_socket->srcPort = cnt_info->srcPort;
                    new_socket->isBound = true;
                    new_socket->state = ESTABLISHED;
                    new_socket->family = AF_INET;
                    new_socket->type = SOCK_STREAM;
                    new_socket->rwnd = cnt_info->rwnd;
                    ///////////
                    new_socket->seqNum = cnt_info->seqNum;
                    new_socket->ackNum = cnt_info->ackNum;

                    ((struct sockaddr_in *) current_socket->blocked_accept->addr)->sin_family = new_socket->family;
                    ((struct sockaddr_in *) current_socket->blocked_accept->addr)->sin_port = new_socket->srcPort;
                    ((struct sockaddr_in *) current_socket->blocked_accept->addr)->sin_addr.s_addr = new_socket->srcIP;
                    
                    current_socket->established_lst.pop_front();
                    uint64_t key = makePidFdKey(current_socket->blocked_accept->pid, socketfd);
                    socket_info_map.insert(pair<uint64_t, struct socket_info *>(key, new_socket));
                    this->returnSystemCall(current_socket->blocked_accept->acceptUUID, socketfd);
                }
                break;

            } 
            // FIN_WAIT_1
            else if (current_socket->state == static_cast<int> (STATE::FIN_WAIT_1)) {
                current_socket->state = FIN_WAIT_2;
                
            }
            // LAST_ACK 
            else if (current_socket->state == static_cast<int> (STATE::LAST_ACK)) {
                current_socket->state = CLOSED;
                // remove filedecriptor
                this->removeFileDescriptor(current_socket->pid, current_socket->fd);
                delete iter->second;
                socket_info_map.erase(iter);
            }
            // CLOSING
            else if (current_socket->state == static_cast<int> (STATE::CLOSING)) {
                Time current_time = this->getHost()->getSystem()->getCurrentTime();
                // store our key in new pointer and put it in payload for addTimer
                uint64_t* timerKey = new uint64_t;
                *timerKey = key;
                current_socket->timerUUID = TimerModule::addTimer(timerKey, current_time + (Time)1000000000);
            }
            // ESTABLISHED
            else if (current_socket->state == static_cast<int> (STATE::ESTABLISHED)) {
                // data received
                // when write call is blocked
                if (tcp_data_length == 0) {
                    if (current_socket->writeUUID != 0xFFFFFFFFFFFFFFFF) {
                        //cout << "fuck!!\n";
                        uint16_t sent_byte = write(current_socket->writeUUID, key,
                            current_socket->write_pointer, current_socket->write_length);
                         //cout << "tcp_data_length: " << tcp_data_length << endl;
                         //cout << "current_socket->write_length: " << current_socket->write_length << endl;
                        if (current_socket->writeUUID == 0xFFFFFFFFFFFFFFFF) {
                            this->returnSystemCall(current_socket->writeUUID, sent_byte);
                        }
                    }

                    if (recv_ack_number > current_socket->sendBase) {
                        uint32_t gap = recv_ack_number - current_socket->sendBase;
                        current_socket->sendBase = recv_ack_number;
                        current_socket->LastByteAcked = (current_socket->LastByteAcked + gap) % 0xFFFFFFFF;
                        current_socket->duplicate = 0;
                    } else {
                        current_socket->duplicate += 1;
                    }

                    if (current_socket->duplicate == 3) {
                        // fast retransmit
                        int write_byte = usingBuffer(current_socket->LastByteSent, current_socket->LastByteAcked);
                        current_socket->seqNum = current_socket->seqNum - write_byte;
                        struct tcp_header TCPHeader;

                        while (write_byte > 0) {
                            // write_byte is larger than MSS
                            if (write_byte >= MSS) {
                                // encapsulate that data and send it
                                // data_send(MSS, current_socket->LastByteSent ,current_socket, TCPHeader, tcp_packet)
                                data_send(MSS, current_socket->LastByteSent - write_byte,
                                    key);
                                write_byte -= MSS;

                            } else {
                                // last part for sending
                                // encapsulate that data and send it
                                data_send(write_byte, current_socket->LastByteSent - write_byte,
                                    key);
                                write_byte = 0;

                            }
                        }
                    }
                } else {
                    //cout << "data received with ACK!!!!!\n";
                    if (current_socket->readUUID != 0xFFFFFFFFFFFFFFFF) {
                        if (tcp_data_length <= current_socket->read_length) {
                            //cout << "tcp_data_length: " << tcp_data_length << endl;
                            //cout << "current_socket->read_length: " << current_socket->read_length << endl; 
                            memcpy(current_socket->read_pointer, tcp_packet+20, tcp_data_length);
                            this->returnSystemCall(current_socket->readUUID, (int) tcp_data_length);
                        } else {
                            //cout << "hihihih\n";
                            //cout << "tcp_data_length: " << tcp_data_length << endl;
                            //cout << "current_socket->read_length: " << current_socket->read_length << endl;
                            //cout << "before write_memcpy: " << current_socket->LastByteRcvd << endl;
                            memcpy(current_socket->read_pointer, tcp_packet+20, current_socket->read_length);
                            write_memcpy(current_socket->receive_buffer, tcp_packet+20+current_socket->read_length, 
                                tcp_data_length - current_socket->read_length, BUFFERSIZE, current_socket->LastByteRcvd);
                            current_socket->LastByteRcvd = (current_socket->LastByteRcvd + tcp_data_length - current_socket->read_length) % BUFFERSIZE;
                            //cout << "after write_memcpy: " << current_socket->LastByteRcvd << endl;
                            this->returnSystemCall(current_socket->readUUID, current_socket->read_length);
                        }
                        current_socket->readUUID = -1;
                        current_socket->ackNum = (current_socket->ackNum + tcp_data_length) & 0xFFFFFFFF;
                    } else {
                        //cout << "1\n";
                        // incoming packet's seq number is larger than expected seq number
                        // save in missing point 
                        if (current_socket->ackNum < recv_seq_number) {
                            //cout << "2\n";
                            uint16_t LastByteRcvd = current_socket->LastByteRcvd;
                            uint16_t gap = (uint16_t) (recv_seq_number - current_socket->ackNum);
                            
                            write_memcpy(current_socket->receive_buffer, tcp_packet + 20, 
                                tcp_data_length, BUFFERSIZE, current_socket->LastByteRcvd);

                            map<uint16_t, uint16_t>::iterator iter;
                            iter = current_socket->missPoint.find(LastByteRcvd);

                            if (iter == current_socket->missPoint.end()) {
                                current_socket->missPoint.insert(pair<uint16_t, uint16_t>(LastByteRcvd, LastByteRcvd + gap));
                                current_socket->endPoint = LastByteRcvd + gap + tcp_data_length;
                            } else if (current_socket->endPoint <= LastByteRcvd + gap) {
                                current_socket->missPoint.insert(pair<uint16_t, uint16_t>(current_socket->endPoint, LastByteRcvd + gap));
                                current_socket->endPoint = LastByteRcvd + gap + tcp_data_length;
                            } else {
                                map<uint16_t, uint16_t>::iterator iter2;
                                for(iter2 = current_socket->missPoint.begin();
                                        iter2 != current_socket->missPoint.end(); iter2++) {
                                    if(iter2->first < LastByteRcvd + gap &&
                                            iter2->second > LastByteRcvd + gap + tcp_data_length) {
                                        current_socket->missPoint.insert(pair<uint16_t, uint16_t>(LastByteRcvd + gap + tcp_data_length, iter2->second));
                                        iter2->second = LastByteRcvd + gap;
                                        break;
                                    } else if(iter2->first == LastByteRcvd + gap &&
                                            iter2->second > LastByteRcvd + gap + tcp_data_length) {
                                        uint16_t iter2End = iter2->second;
                                        current_socket->missPoint.erase(iter2);
                                        current_socket->missPoint.insert(pair<uint16_t, uint16_t>(LastByteRcvd + gap + tcp_data_length, iter2End));
                                        break;
                                    } else if(iter2->first < LastByteRcvd + gap &&
                                            iter2->second == LastByteRcvd + gap + tcp_data_length) {
                                        iter2->second = LastByteRcvd + gap;
                                        break;
                                    } else if(iter2->first == LastByteRcvd + gap &&
                                            iter2->second == LastByteRcvd + gap + tcp_data_length) {
                                        current_socket->missPoint.erase(iter2);
                                        break;
                                    } else {
                                        continue;
                                    }
                                }
                            }
                        } else if (current_socket->ackNum == recv_seq_number) {
                            // comes here in reliable network
                            //cout << "data comes\n";
                            uint16_t LastByteRcvd = current_socket->LastByteRcvd;

                            write_memcpy(current_socket->receive_buffer, tcp_packet+20, tcp_data_length, BUFFERSIZE, current_socket->LastByteRcvd);

                            map<uint16_t, uint16_t>::iterator iter;
                            iter = current_socket->missPoint.find(LastByteRcvd);

                            if(iter == current_socket->missPoint.end()) {
                                current_socket->ackNum = (current_socket->ackNum + tcp_data_length) & 0xFFFFFFFF;
                                current_socket->endPoint = (current_socket->endPoint + tcp_data_length) % BUFFERSIZE;
                                current_socket->LastByteRcvd = (current_socket->LastByteRcvd + tcp_data_length) % BUFFERSIZE;
                            } else if(iter->second == LastByteRcvd + tcp_data_length) {
                                current_socket->ackNum = (current_socket->ackNum + current_socket->endPoint - LastByteRcvd) & 0xFFFFFFFF;
                                current_socket->LastByteRcvd = (current_socket->LastByteRcvd + current_socket->endPoint) % BUFFERSIZE;
                                current_socket->missPoint.erase(iter);
                            } else if(iter->second > LastByteRcvd + tcp_data_length) {
                                current_socket->ackNum = (current_socket->ackNum + tcp_data_length) & 0XFFFFFFFF;
                                current_socket->LastByteRcvd = (current_socket->LastByteRcvd + tcp_data_length) % BUFFERSIZE;

                                uint16_t iterEnd = iter->second;
                                current_socket->missPoint.erase(iter);
                                current_socket->missPoint.insert(pair<uint16_t, uint16_t>(LastByteRcvd + tcp_data_length, iterEnd));
                            }
                        }
                    }
                    //cout <<"3\n";
                    uint32_t send_seq_number = current_socket->seqNum;
                    uint32_t send_ack_number = current_socket->ackNum;
                    makeTCPHeader(&my_packet_header, tcp_header.destPort, tcp_header.srcPort,
                            send_seq_number, send_ack_number, ACK, WINDOWSIZE - current_socket->LastByteRcvd);

                   // checksum
                    uint16_t checksum = calculateChecksum(src_ip, dest_ip, (uint8_t*)&my_packet_header, (uint16_t)20);
                    
                    Packet* ack_packet = allocatePacket(54);

                    my_packet_header.checksum = htons(checksum);

                    // write packet
                    ack_packet->writeData(26, &dest_ip, 4);
                    ack_packet->writeData(30, &src_ip, 4);
                    ack_packet->writeData(34, &my_packet_header, 20);
                    // send packet
                    this->sendPacket("IPv4", ack_packet);
                }
            }
            break;
    		
        }
        // FIN packet
        case(0x1):
        {
            // reject packet if it's state is not ESTABLISHED and FIN_WAIT_2
            if (current_socket->state != static_cast<int> (STATE::ESTABLISHED)&&
                current_socket->state != static_cast<int> (STATE::FIN_WAIT_2)&&
                current_socket->state != static_cast<int> (STATE::FIN_WAIT_1)) {
                if (current_socket->state == static_cast<int> (STATE::SYN_RCVD)) {
                    list<connection_info *>::iterator iter;
                    for(iter = current_socket->established_lst.begin(); 
                        iter != current_socket->established_lst.end(); iter ++) {
                        if (((*iter)->srcPort == tcp_header.destPort) &&
                            ((*iter)->destPort == tcp_header.srcPort) &&
                            ((*iter)->srcIP == dest_ip) &&
                            ((*iter)->destIP == src_ip)) {

                            int newpid = current_socket->pid;
                            int newfd = this->createFileDescriptor(newpid);
                            uint64_t newkey = makePidFdKey(newpid, newfd);

                            struct socket_info *temp_socket = new struct socket_info;

                            temp_socket->pid = newpid;
                            temp_socket->fd = newfd;
                            temp_socket->destIP = src_ip;
                            temp_socket->srcIP = dest_ip;
                            temp_socket->destPort = tcp_header.srcPort;
                            temp_socket->srcPort = tcp_header.destPort;
                            temp_socket->seqNum = (*iter)->seqNum;
                            temp_socket->ackNum = (*iter)->ackNum;
                            temp_socket->isBound = true;
                            temp_socket->family = AF_INET;
                            temp_socket->type = SOCK_STREAM;
                            temp_socket->state = CLOSE_WAIT;

                            socket_info_map.insert(pair<uint64_t, struct socket_info *>(newkey, temp_socket));
                            current_socket->beforeAccept_lst.push_back(*iter);
                            current_socket->established_lst.erase(iter);

                            uint32_t send_ack_number = recv_seq_number + 1;
                            makeTCPHeader(&my_packet_header, tcp_header.destPort, tcp_header.srcPort,
                            temp_socket->seqNum, send_ack_number, ACK, WINDOWSIZE);
                            
                            temp_socket->ackNum = send_ack_number;
                            // checksum
                            uint16_t checksum = calculateChecksum(src_ip, dest_ip, (uint8_t*)&my_packet_header, 20);
                            my_packet_header.checksum = htons(checksum);

                            // write packet
                            my_packet->writeData(14 + 20, &my_packet_header, 20);
                            // send packet
                            this->sendPacket("IPv4", my_packet);
                            break;
                        }
                    }
                } else {
                    this->freePacket(packet);
                    this->freePacket(my_packet);
                    return;
                }
                break;
            }
            /*
                send ACK packet 
                for FIN 
            */
            uint32_t send_ack_number = recv_seq_number + 1;
            makeTCPHeader(&my_packet_header, tcp_header.destPort, tcp_header.srcPort,
                current_socket->seqNum, send_ack_number, ACK, WINDOWSIZE);

            current_socket->ackNum = send_ack_number;
            // checksum
            uint16_t checksum = calculateChecksum(src_ip, dest_ip, (uint8_t*)&my_packet_header, 20);
            my_packet_header.checksum = htons(checksum);

            // write packet
            my_packet->writeData(14 + 20, &my_packet_header, 20);
            // change state
            if (current_socket->state == static_cast<int> (STATE::ESTABLISHED)) {
                current_socket->state = CLOSE_WAIT;
                this->sendPacket("IPv4", my_packet);
            } else if (current_socket->state == static_cast<int> (STATE::FIN_WAIT_2)) {
                current_socket->state = TIME_WAIT;
                this->sendPacket("IPv4", my_packet);

                Time current_time = this->getHost()->getSystem()->getCurrentTime();

                // store our key in new pointer and put it in payload for addTimer
                uint64_t* timerKey = new uint64_t;
                *timerKey = key;
                current_socket->timerUUID = TimerModule::addTimer(timerKey, current_time + (Time)1000000000);
            } else if (current_socket->state == static_cast<int> (STATE::FIN_WAIT_1)) {
                current_socket->state = CLOSING;
                this->sendPacket("IPv4", my_packet);
            }
            break;
        }
        // FIN_ACK packet
        case(0x11):
        {
    		// reject packet if it's state is not SYN_SENT
    		if (current_socket->state != static_cast<int> (FIN_WAIT_1)) {
    			this->freePacket(packet);
    			this->freePacket(my_packet);
    			return;
    		}
    		/*
    			send ACK packet
    			with ack_number
    		*/
            uint32_t send_ack_number = recv_seq_number + 1;
            uint32_t send_seq_number = current_socket->seqNum;
            makeTCPHeader(&my_packet_header, tcp_header.destPort, tcp_header.srcPort,
                send_seq_number, send_ack_number, ACK, WINDOWSIZE);

            current_socket->ackNum = send_ack_number;
            // checksum
            uint16_t checksum = calculateChecksum(src_ip, dest_ip, (uint8_t*)&my_packet_header, (uint16_t)20);
            my_packet_header.checksum = htons(checksum);

            // write packet
            my_packet->writeData(14 + 20, &my_packet_header, 20);
            // change state
    		current_socket->state = TIME_WAIT;
            // send packet
            this->sendPacket("IPv4", my_packet);

            Time current_time = this->getHost()->getSystem()->getCurrentTime();

            // store our key in new pointer and put it in payload for addTimer
            uint64_t* timerKey = new uint64_t;
            *timerKey = key;
            current_socket->timerUUID = TimerModule::addTimer(timerKey, current_time + (Time)1000000000);
        }
        this->freePacket(my_packet);
    }
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int param1,
        struct sockaddr* addr, socklen_t* len)
{
	// param1 is file descriptor
	int fd = param1;
	uint64_t key = makePidFdKey(pid, fd);
	map<uint64_t, struct socket_info *>::iterator iter;
	iter = socket_info_map.find(key);
	// get socket 
	if (iter == socket_info_map.end() || *len < sizeof(struct sockaddr)) {
		this->returnSystemCall(syscallUUID, -1);
	} else {
		// make sockaddr_in* to save information of socket address
    	struct sockaddr_in* get_addr_in = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
        socklen_t tlen = sizeof(struct sockaddr_in);
        // initialize memory
        memset(get_addr_in, 0, tlen);
        // save information of socket address to get_addr_in
		get_addr_in->sin_family = iter->second->family;
		get_addr_in->sin_addr.s_addr = iter->second->destIP;
		get_addr_in->sin_port = iter->second->destPort;
        // type_case of get_addr_in sockaddr_in* to sockaddr*
        struct sockaddr* tt = (struct sockaddr *) get_addr_in;
        // copy data from tt to addr
        memcpy(addr, tt, *len);

        //method 2
        /*
        ((struct sockaddr_in *) addr)->sin_family = iter->second->family;
        ((struct sockaddr_in *) addr)->sin_addr.s_addr = iter->second->srcIP;
        ((struct sockaddr_in *) addr)->sin_port = iter->second->srcPort;
        */

		this->returnSystemCall(syscallUUID, 0);
	}
}
// KENS3 
void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int param1, void* param2, int param3)
{
    //cout << "write!!!\n";

    uint64_t key = makePidFdKey(pid, param1);
    // find corresponding socket
    map<uint64_t, struct socket_info *>::iterator iter;
    iter = socket_info_map.find(key); 
    uint8_t* buffer = (uint8_t*) param2;
    //memcpy(buffer, param2, param3);

    /*
    int i;
    int count = 0;
    for(i = 0; i < param3; i++) {
        if(buffer[i] == param2[i]) {
            count++;
        }
    }
    cout << "count: " << count << endl;
    */

    if (iter == socket_info_map.end()) {
        this->returnSystemCall(syscallUUID, -1);
        return;
    }
    struct socket_info * current_socket = iter->second;
    //cout << "state: " << current_socket->state << endl;
    if (current_socket->state != static_cast<int>(STATE::ESTABLISHED)) {
        //cout << "not established\n";
        this->returnSystemCall(syscallUUID, -1);
        return;
    }

    //struct socket_info * current_socket = iter->second;
    //cout << "hi\n";
    //cout << "buffer address before write func: " << param2 << endl;
    //cout << "first character: " << param2[0] << endl;
    int sent_byte = write(syscallUUID, key, buffer, param3);
    //cout << "bye\n";
    if (sent_byte == -1) {
        //cout << "damm\n";
        return;
    }
    //cout << "sent_byte!: " << sent_byte << endl;
 
    this->returnSystemCall(syscallUUID, sent_byte);
    return; 
}
int TCPAssignment::write(UUID syscallUUID, uint64_t key, uint8_t* buffer, int length)
{
    map<uint64_t, struct socket_info *>::iterator iter;
    iter = socket_info_map.find(key);
    struct socket_info * current_socket = iter->second;

    //cout << "buffer address after write func: " << buffer << endl;
    //cout << "first character: " << buffer[0] << endl;

    current_socket->writeUUID = -1;
    uint32_t dest_ip = current_socket->destIP;
    uint32_t source_ip = current_socket->srcIP;
    uint16_t using_buffer = usingBuffer(current_socket->LastByteAcked, current_socket->LastByteSent);
    uint16_t remaining_buffer = BUFFERSIZE - using_buffer;

    int interface = getHost()->getRoutingTable((const uint8_t *)&dest_ip);
    if (!getHost()->getIPAddr((uint8_t *)&source_ip, interface)) {
        //cout << "111\n";
        this->returnSystemCall(syscallUUID, -1);
        return -1;
    }

    // byte we need to write
    int write_byte;
    // byte we sent
    int sent_byte = 0;
    // when we need to block write call
    //cout << "rwnd: " << current_socket->rwnd << endl;
    //cout << "using_buffer: " << using_buffer << endl;
    //cout << "remaining_buffer: " << remaining_buffer << endl;
    //cout << "length: " << length << endl;
    if (using_buffer >= current_socket->rwnd || remaining_buffer == 0) {
        //cout << "222\n";
        current_socket->writeUUID = syscallUUID;
        current_socket->write_pointer = buffer;
        current_socket->write_length = length;
        return -1;
    }

    write_byte = std::min((int)(current_socket->rwnd - using_buffer), (int)remaining_buffer);
    write_byte = std::min((int)write_byte, (int)length);

    while (write_byte > 0) {
        //cout << "write_byte: " << write_byte << endl;
        // write_byte is larger than MSS
        if (write_byte >= MSS) {
            // save in buffer
            //cout << "LastByteSent1: " << current_socket->LastByteSent << endl;
            write_memcpy(current_socket->send_buffer, buffer+sent_byte, MSS, BUFFERSIZE, current_socket->LastByteSent);
            // encapsulate that data and send it
            data_send(MSS, current_socket->LastByteSent, key);
            write_byte -= MSS;
            sent_byte += MSS;
            //cout << "sent!\n";

        } else {
            // last part for sending
            //cout << "LastByteSent2: " << current_socket->LastByteSent << endl;
            write_memcpy(current_socket->send_buffer, buffer+sent_byte, write_byte, BUFFERSIZE, current_socket->LastByteSent);
            // encapsulate that data and send it
            data_send(write_byte, current_socket->LastByteSent, key);
            sent_byte += write_byte;
            write_byte = 0;
        }
    }
    //cout << "LastByteAcked: " << current_socket->LastByteAcked << endl;
    //cout << "LastByteSent: " << current_socket->LastByteSent << endl;
    //cout << "sent length: " << sent_byte << endl;

    return sent_byte;

}

// send data with length
void TCPAssignment::data_send(int length, uint16_t offset, uint64_t key) {
    //cout << "data_send!!\n";

    map<uint64_t, struct socket_info *>::iterator iter;
    iter = socket_info_map.find(key);
    struct socket_info * current_socket = iter->second;

    struct tcp_header TCPHeader;
    uint8_t tcp_packet[length+20];
    uint32_t source_ip = current_socket->srcIP; 
    uint32_t dest_ip = current_socket->destIP;

    Packet *myPacket = allocatePacket(54+length);

    makeTCPHeader(&TCPHeader, current_socket->srcPort, current_socket->destPort, current_socket->seqNum,
        current_socket->ackNum, ACK, WINDOWSIZE);
    memcpy(tcp_packet, &TCPHeader, 20);
    memcpy(tcp_packet+20, current_socket->send_buffer+offset, length);
    current_socket->seqNum = (current_socket->seqNum + length) & 0xFFFFFFFF;
    uint16_t checksum = calculateChecksum(source_ip, dest_ip, tcp_packet, 20+length);
    checksum = htons(checksum);
    // allocate checksum
    memcpy(tcp_packet+16, &checksum, 2);
    //cout << "checksum: " << calculateChecksum(source_ip, dest_ip, tcp_packet, 20+length) << endl;

    myPacket->writeData(14+12, &source_ip, 4);
    myPacket->writeData(14+16, &dest_ip, 4);
    myPacket->writeData(14+20, tcp_packet, 20+length);
    // send packet
    sendPacket("IPv4", myPacket);
    //this->freePacket(myPacket);
    current_socket->LastByteSent = (current_socket->LastByteSent + length) % BUFFERSIZE;
    
    return;
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int param1, uint8_t* param2, int param3)
{
    //cout << "read!!!!!\n";
    int fd = param1;
    uint64_t key = makePidFdKey(pid, fd);

    map<uint64_t, struct socket_info *>::iterator iter;

    // find corresponding socket
    iter = socket_info_map.find(key);
    struct socket_info * current_socket = iter->second;

    current_socket->readUUID = -1;

    uint16_t using_buffer = usingBuffer(current_socket->LastByteRead, current_socket->LastByteRcvd);
    //cout << "LastByteRead: " << current_socket->LastByteRead << endl;
    //cout << "LastByteRcvd: " << current_socket->LastByteRcvd << endl;
    //cout << "using_buffer: " << using_buffer << endl;
    //cout << "read param3: " << param3 << endl;

    if(iter == socket_info_map.end()) {
        this->returnSystemCall(syscallUUID, -1);
        return; 
    }
    // nothing to read in buffer
    if(using_buffer == 0) {
        //cout << "read blocked \n";
        // block read()
        current_socket->readUUID = syscallUUID;
        current_socket->read_pointer = param2;
        current_socket->read_length = param3;
        return;
    } else if(using_buffer < param3) {
        read_memcpy(param2, current_socket->receive_buffer, using_buffer, BUFFERSIZE, current_socket->LastByteRead);
        current_socket->LastByteRead = (current_socket->LastByteRead + using_buffer) % BUFFERSIZE;
        this->returnSystemCall(syscallUUID, (int) using_buffer);
        //cout << "sent byte: " << using_buffer << endl;
    } else {
        read_memcpy(param2, current_socket->receive_buffer, param3, BUFFERSIZE, current_socket->LastByteRead);
        current_socket->LastByteRead = (current_socket->LastByteRead + param3) % BUFFERSIZE;
        this->returnSystemCall(syscallUUID, param3);
        //cout << "sent byte: " << param3 << endl;
    }
    return;
}

uint64_t TCPAssignment::makePidFdKey(uint32_t pid, uint32_t fd)
{
	uint64_t key;
	key = ((uint64_t)pid << 32) + (uint64_t)fd;
	return key;
}

uint16_t TCPAssignment::calculateChecksum(uint32_t srcIP, uint32_t destIP, uint8_t *tcp_packet, uint16_t tcp_packet_length)
{
    uint16_t checksum;
    uint16_t tempsum = NetworkUtil::tcp_sum(srcIP, destIP, tcp_packet, tcp_packet_length);
    checksum = ~tempsum;
    // 0xffff is not legal
    if (checksum == 0xffff) {
        checksum = 0;
    }
    return checksum;
}
/*
uint32_t TCPAssignment::pidFromKey(uint64_t key) 
{
	return (uint32_t)(key >> 32);
}
uint32_t TCPAssignment::fdFromKey(uint64_t key)
{
	return (uint32_t)(key & 0xffffffff);
}
*/

void TCPAssignment::makeTCPHeader(struct tcp_header *TCPHeader, uint16_t srcPort, uint16_t destPort, uint32_t seqNum, uint32_t ackNum, unsigned char flags, uint16_t winSize)
{
    TCPHeader->srcPort = srcPort;
    TCPHeader->destPort = destPort;
    TCPHeader->seqNum = htonl(seqNum);
    TCPHeader->ackNum = htonl(ackNum);
    TCPHeader->flags = flags;
    TCPHeader->windowSize = htons(winSize);
    // for headerLength 20B, after consider hton process
    TCPHeader->headerLength = 80;
}

void TCPAssignment::timerCallback(void* payload)
{
    // get key from payload
    uint64_t *key_ptr = (uint64_t*) payload;
    uint64_t key = *key_ptr;
    //key = 0;
    
    map<uint64_t, struct socket_info*>::iterator iter;
    iter = socket_info_map.find(key);
    if(iter == socket_info_map.end()) {
        free((uint64_t *) payload);
        return;
    }
    struct socket_info * current_socket = iter->second;

    if(current_socket->state == static_cast<int>(STATE::TIME_WAIT)) {
        current_socket->state = CLOSED;

        // remove filedecriptor
        this->removeFileDescriptor(current_socket->pid, current_socket->fd);
        //cout << "delete3\n";
        delete iter->second;
        socket_info_map.erase(iter);
        free((uint64_t *) payload);
    }
    return;
}

uint16_t TCPAssignment::usingBuffer(uint16_t LastByteAckedOrRead, uint16_t LastByteSentOrRcvd)
{
    //uint16_t result = LastByteSentOrRcvd - LastByteAckedOrRead;
    // abnormal case
    if (LastByteSentOrRcvd < LastByteAckedOrRead) {
        return BUFFERSIZE - (LastByteAckedOrRead - LastByteSentOrRcvd);
    } 
    return LastByteSentOrRcvd - LastByteAckedOrRead;
}
// memcpy(param2, &current_socket->receive_buffer + current_socket->LastByteRead, readbyte)
void TCPAssignment::read_memcpy(uint8_t *dest, uint8_t *source, int length, uint16_t source_length, int offset)
{
    if (offset + length > source_length) {
        memcpy(dest, source+offset, source_length-offset);
        memcpy(dest+(source_length-offset), source, length - (source_length - offset));
    } else {
        memcpy(dest, source+offset, length);
    }
    return;
}

void TCPAssignment::write_memcpy(uint8_t *dest, uint8_t *source, int length, uint16_t dest_length, int offset)
{   
    //write_memcpy(current_socket->send_buffer, buffer, MSS, BUFFERSIZE, current_socket->LastByteSent)
    if (offset + length > dest_length) {
        memcpy(dest+offset, source, dest_length-offset);
        memcpy(dest, source+(dest_length-offset), length-(dest_length-offset));
    } else {
        memcpy(dest+offset, source, length);
    }
    return;
}

}
