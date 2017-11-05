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

    if(iter == socket_info_map.end()) {
        this->returnSystemCall(syscallUUID, -1);
        return;
    }

    if(iter->second->srcPort == 0xFFFF) {
        //if not bound
        int interface = getHost()->getRoutingTable((const uint8_t *)&dest_ip);
        getHost()->getIPAddr((uint8_t *)&source_ip, interface);
        source_port = ((rand() % (0x10000 - 0x401)) + 0x400);
    } else {
        //already bound
        source_ip = iter->second->srcIP;
        source_port = iter->second->srcPort;
    }
    // save the UUID for futre unblocking
    iter->second->connectUUID = syscallUUID;

    iter->second->destIP = dest_ip;
    iter->second->destPort = dest_port;
    iter->second->srcIP = source_ip;
    iter->second->srcPort = source_port;
    iter->second->isBound = true;

    Packet *myPacket = allocatePacket(54);
    struct tcp_header TCPHeader;
    // randonm sequence number
    uint32_t seqNum = rand() % 0xFFFFFFFF;
    // make TCP header
    makeTCPHeader(&TCPHeader, source_port, dest_port, seqNum,  0, SYN, WINDOWSIZE);
    iter->second->seqNum = seqNum + 1;

    // checksum
    uint16_t checksum = calculateChecksum(source_ip, dest_ip, (uint8_t*)&TCPHeader, 20);
    // need to change to network order
    TCPHeader.checksum = htons(checksum);
    // write packet
    myPacket->writeData(14+12, &source_ip, 4);
    myPacket->writeData(14+16, &dest_ip, 4);
    myPacket->writeData(14+20, &TCPHeader, 20);
    // change state
    iter->second->state = SYN_SENT;
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
    uint32_t recv_seq_number = ntohl(tcp_header.seqNum);
    // finally found
    iter = socket_info_map.find(key);
    struct socket_info * current_socket = iter->second;

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

            // push it to pending list for current_socket
  			current_socket->pending_lst.push_back(new_connection);

  			// make packet header for sending packet
            makeTCPHeader(&my_packet_header, new_connection->srcPort, new_connection->destPort,
                send_seq_number, send_ack_number, SYN + ACK, WINDOWSIZE);

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
            makeTCPHeader(&my_packet_header, tcp_header.destPort, tcp_header.srcPort,
                send_seq_number, send_ack_number, ACK, WINDOWSIZE);

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

            else if (current_socket->state == static_cast<int> (STATE::CLOSING)) {
                Time current_time = this->getHost()->getSystem()->getCurrentTime();
                // store our key in new pointer and put it in payload for addTimer
                uint64_t* timerKey = new uint64_t;
                *timerKey = key;
                current_socket->timerUUID = TimerModule::addTimer(timerKey, current_time + (Time)1000000000);
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
        default:
        {
            if(current_socket->ackNum < recv_seq_number) {
                memcpy(&current_socket->receive_buffer + current_socket->LastByteRcvd + recv_seq_number - current_socket->ackNum,
                        &tcp_packet + 54, tcp_data_length);

                map<uint64_t, uint64_t>::iterator iter;
            	iter = current_socket->missPoint.find(LastByteRcvd);

                if(iter == current_socket->missPoint.end()) {
                    current_socket->missPoint.insert(pair<uint64_t, uint64_t>(LastbyteRcvd, LastByteRcvd + recv_seq_number - current_socket->ackNum));
                    current_socket->endPoint = recv_seq_number + 
                } else if(iter->second < recv_seq_number)


                uint32_t send_seq_number = current_socket->seqNum;
                uint32_t send_ack_number = current_socket->ackNum;
                makeTCPHeader(&my_packet_header, tcp_header.destPort, tcp_header.srcPort,
                        send_seq_number, send_ack_number, ACK, current_socket->rwnd);

               // checksum
                uint16_t checksum = calculateChecksum(src_ip, dest_ip, (uint8_t*)&my_packet_header, (uint16_t)20);
                my_packet_header.checksum = htons(checksum);

                // write packet
                my_packet->writeData(14 + 20, &my_packet_header, 20);
                // send packet
                this->sendPacket("IPv4", my_packet);

            } else if(current_socket->ackNum > recv_seq_number) {
                uint32_t send_seq_number = current_socket->seqNum;
                uint32_t send_ack_number = current_socket->ackNum;
                makeTCPHeader(&my_packet_header, tcp_header.destPort, tcp_header.srcPort,
                        send_seq_number, send_ack_number, ACK, current_socket->rwnd);

               // checksum
                uint16_t checksum = calculateChecksum(src_ip, dest_ip, (uint8_t*)&my_packet_header, (uint16_t)20);
                my_packet_header.checksum = htons(checksum);

                // write packet
                my_packet->writeData(14 + 20, &my_packet_header, 20);
                // send packet
                this->sendPacket("IPv4", my_packet);                

            } else {
                uint32_t send_seq_number = current_socket->seqNum;
                uint32_t send_ack_number = recv_seq_number + (uint32_t) tcp_data_length;
                makeTCPHeader(&my_packet_header, tcp_header.destPort, tcp_header.srcPort,
                        send_seq_number, send_ack_number, ACK, WINDOWSIZE);
            }
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
/// read & write
void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int param1, uint8_t* param2, int param3)
{
    //cout << "write!!!\n";

    uint64_t key = makePidFdKey(pid, param1);
    // find corresponding socket
    map<uint64_t, struct socket_info *>::iterator iter;
    iter = socket_info_map.find(key);

    if (iter == socket_info_map.end()) {
        this->returnSystemCall(syscallUUID, -1);
        return;
    }
    struct socket_info * current_socket = iter->second;
    
    uint16_t using_buffer = current_socket->LastByteSent - current_socket->LastByteAcked;
    uint16_t remaining_buffer = BUFFERSIZE - using_buffer;

    struct tcp_header TCPHeader;
    uint8_t tcp_packet[MSS];

    int write_byte = param3;
    // sending buffer is not enough 
    if (remaining_buffer == 0 || remaining_buffer < param3){
        // block write()
        current_socket->writeUUID = syscallUUID;
        return;
    } else {
        while (current_socket->LastByteSent - current_socket->LastByteAcked < current_socket->rwnd
            && write_byte > 0) {
            // write_byte is larger than
            if (write_byte >= MSS) {
                // save in buffer
                memcpy(param2, &current_socket->send_buffer[current_socket->LastByteSent], MSS);
                // encapsulate that data and send it
                data_send(MSS, current_socket, TCPHeader, tcp_packet);

                write_byte -= MSS;

            } else {
                // last part for sending
                memcpy(param2, current_socket->send_buffer, write_byte);
                // encapsulate that data and send it
                data_send(write_byte, current_socket, TCPHeader, tcp_packet);

                write_byte = 0;

            }
        }
    }
    this->returnSystemCall(syscallUUID, param3);
    return; 
}

void TCPAssignment::data_send(int length, struct socket_info* current_socket,
    struct tcp_header TCPHeader, uint8_t* tcp_packet) {

    uint32_t source_ip = current_socket->srcIP; 
    uint32_t dest_ip = current_socket->destIP;

    Packet *myPacket = allocatePacket(54 + length);

    makeTCPHeader(&TCPHeader, current_socket->srcPort, current_socket->destPort, current_socket->seqNum,
        current_socket->ackNum, 0, WINDOWSIZE);
    memcpy(&TCPHeader, tcp_packet, 20);
    memcpy(&current_socket->send_buffer[current_socket->LastByteSent], &tcp_packet[20], MSS);
    current_socket->seqNum += MSS;
    uint16_t checksum = calculateChecksum(source_ip, dest_ip, tcp_packet, 20 + MSS);
    checksum = htons(checksum);
    // allocate checksum
    memcpy(&checksum, &tcp_packet[16], 2);
    cout << "checksum: " << calculateChecksum(source_ip, dest_ip, tcp_packet, 20 + MSS) << endl;

    myPacket->writeData(14+12, &source_ip, 4);
    myPacket->writeData(14+16, &dest_ip, 4);
    myPacket->writeData(14+20, tcp_packet, MSS);
    // send packet
    sendPacket("IPv4", myPacket);
    current_socket->LastByteSent += MSS;
    return;
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int param1, uint8_t* param2, int param3)
{
    int fd = param1;
    uint64_t key = makePidFdKey(pid, fd);

    map<uint64_t, struct socket_info *>::iterator iter;

    // find corresponding socket
    iter = socket_info_map.find(key);
    struct socket_info * current_socket = iter->second;

    if(iter == socket_info_map.end()) {
        this->returnSystemCall(syscallUUID, -1);
    }

    if(current_socket->LastByteRcvd == 0) {
        return;
    } else if(current_socket->LastByteRcvd - current_socket->LastByteRead < param3) {
        int readbyte = current_socket->LastByteRcvd - current_socket->LastByteRead;
        memcpy(param2, &current_socket->receive_buffer + current_socket->LastByteRead, readbyte);
        current_socket->LastByteRead += readbyte;
        this->returnSystemCall(syscallUUID, readbyte);
    } else {
        memcpy(param2, &current_socket->receive_buffer + current_socket->LastByteRead, param3);
        current_socket->LastByteRead += param3;
        this->returnSystemCall(syscallUUID, param3);
    }
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

void TCPAssignment::makeTCPHeader(struct tcp_header *TCPHeader, uint16_t srcPort, uint16_t destPort, uint32_t seqNum, uint32_t ackNum, unsigned char flags, uint16_t winSize) {
    TCPHeader->srcPort = srcPort;
    TCPHeader->destPort = destPort;
    TCPHeader->seqNum = htonl(seqNum);
    TCPHeader->ackNum = htonl(ackNum);
    TCPHeader->flags = flags;
    TCPHeader->windowSize = htons(winSize);
    // for headerLength 20B, after consider hton process
    TCPHeader->headerLength = 80;
}

void TCPAssignment::timerCallback(void* payload) {
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

}
