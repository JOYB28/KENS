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

// 20150547 Lee Sangmin
// 20160140 Kim Yoonseo,

using namespace std;

namespace E
{

map<uint64_t, struct socket_info *> socket_info_map;

// FIN, SYN, RST, PSH, ACK, URG, ECE, CWR

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
    cout << "close!!!!\n";
	// file descriptor
	int fd = param1;
	uint64_t key = makePidFdKey(pid, fd);
    // if there's no socket for our key
    map<uint64_t, struct socket_info *>::iterator iter;
    iter = socket_info_map.find(key);
    struct socket_info * current_socket = iter->second;

    // save the UUID for future unblocking close 
    current_socket->closeUUID = syscallUUID;

    if (iter == socket_info_map.end()) {
        this->returnSystemCall(syscallUUID, -1);
    } else {
        
        // send FIN packet
        Packet *my_packet = allocatePacket(54);
        struct tcp_header TCPHeader;
        
        // packet header
        makeTCPHeader(&TCPHeader, current_socket->srcPort, current_socket->destPort, current_socket->seqNum+1, 0, FIN, 10000);
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
        // client server
        if (current_socket->state == static_cast<int> (STATE::ESTABLISHED)){
            current_socket->state = FIN_WAIT_1;
        } else if (current_socket->state == static_cast<int> (STATE::CLOSE_WAIT)) {
            current_socket->state = LAST_ACK;
        }
        
        // send packet
        this->sendPacket("IPv4", my_packet);  
        
    }
    /*
    // remove file descriptor 
    this->removeFileDescriptor(pid, fd);
	// remove value with key fd in arg_map and addr_map
	if (socket_info_map.find(key) == socket_info_map.end()) {
		// fail 
		this->returnSystemCall(syscallUUID, -1);
	} else {
		delete socket_info_map.find(fd)->second;
		socket_info_map.erase(socket_info_map.find(fd));
		this->returnSystemCall(syscallUUID, 0);
	}
    */

}
// bind()
void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int param1,
	struct sockaddr* addr, socklen_t len)
{	
	// lets print all keys and values in addr_map and arg_map
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
}
// KENS2
// listen()
void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd, int bl)
{
    //cout << "listen!!!!\n";
    //cout << "pid: " << pid << " fd: " << fd << " bl: " << bl << endl;
    // server socket
    uint64_t key = makePidFdKey(pid, fd);
    map<uint64_t, struct socket_info *>::iterator iter;
    iter = socket_info_map.find(key); 
	iter->second->state = E::LISTEN;
    iter->second->backlog = bl;

	this->returnSystemCall(syscallUUID, 0);

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
    map<uint64_t, struct socket_info *>::iterator iter;

    iter = socket_info_map.find(key);

    if(iter == socket_info_map.end()) {
        this->returnSystemCall(syscallUUID, -1);
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
/*
    TCPHeader->srcPort = source_port;
    TCPHeader->destPort = dest_port;
    TCPHeader->seqNum = htonl(rand() % 0xFFFFFFFF);
    TCPHeader->ackNum = htonl(0);
    TCPHeader->flags = SYN;
    TCPHeader->windowSize = htons(10000);
*/
    uint32_t seqNum = rand() % 0xFFFFFFFF;
    iter->second->seqNum = seqNum;
    makeTCPHeader(&TCPHeader, source_port, dest_port, seqNum,  0, SYN, 10000);

    // checksum
    uint16_t checksum = calculateChecksum(source_ip, dest_ip, (uint8_t*)&TCPHeader, 20);
    // need to change to network order
    TCPHeader.checksum = htons(checksum);

    myPacket->writeData(14+12, &source_ip, 4);
    myPacket->writeData(14+16, &dest_ip, 4);
    myPacket->writeData(14+20, &TCPHeader, 20);

    iter->second->state = SYN_SENT;

    sendPacket("IPv4", myPacket);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int param1, struct sockaddr* addr, socklen_t* len) {
    cout << "accept!!!\n";
    map<uint64_t, struct socket_info *>::iterator iter;
    uint64_t key = makePidFdKey(pid, param1);

    //cout << "accept pid: " << pid << endl;
    //cout << "accept fd: " << param1 << endl;
    //cout << "accept key: " << key << endl;

    iter = socket_info_map.find(key);

    if(iter == socket_info_map.end()) {
        this->returnSystemCall(syscallUUID, -1);
    }

    if(iter->second->established_lst.empty()) {
        cout << "accept: established_lst empty\n";
        return;
    } else {
        struct socket_info* new_socket = new struct socket_info;
        struct connection_info *cnt_info;

        cnt_info = iter->second->established_lst.front();

        int socketfd = this->createFileDescriptor(pid);
        //cout << "accept: socketfd: " << socketfd << endl;

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
        
        ((struct sockaddr_in *) addr)->sin_family = new_socket->family;
        ((struct sockaddr_in *) addr)->sin_port = new_socket->srcPort;
        ((struct sockaddr_in *) addr)->sin_addr.s_addr = new_socket->srcIP;

        iter->second->established_lst.pop_front();

    	uint64_t key = makePidFdKey(pid, socketfd);
	   	socket_info_map.insert(pair<uint64_t, struct socket_info *>(key, new_socket));

        this->returnSystemCall(syscallUUID, socketfd);
    }

}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
    cout << "packetArrived!!!!!\n";
    /*
    Time currentTime = this->getHost()->getSystem()->getCurrentTime();
    cout << "currentTime: " << currentTime << endl;
    */
	// packet arrived
    // packet length information (IP 14B + 12B + 4B + 4B, tcp header 20B)
    uint16_t packet_length = packet->getSize();
    uint16_t tcp_packet_length = packet_length - 34;
    //uint16_t tcp_data_length = tcp_packet_length - 20;
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
        //cout << "packetArrived: arrived pkt checksum error!\n";
        this->freePacket(packet);
        return;
    }
    // define my packet (sending packet)
    Packet* my_packet = this->clonePacket(packet);
    // tcp packet header for my packet
    struct tcp_header my_packet_header;
    // swap src and dest IP (already done here)
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

    iter = socket_info_map.find(key);
    struct socket_info * current_socket = iter->second;

    // flag of arrived packet
    unsigned char flags = tcp_header.flags;
    unsigned char type = flags & 0x13; //to see ACK SYN FIN
    
    // SYN
    switch(type) {
    	// SYN packet
    	case(0x2):
        {
            //cout << "packetArrived: SYN pkt arrived\n";
            /*
                SERVER SIDE
            */

    		// reject packet if it is not listening
            /*
    		if (cc) {
                cout << "not listening socket!!\n";
    			this->freePacket(packet);
    			this->freePacket(my_packet);
    			return;
    		}
            */

    		// if number of pending is backlog, reject the packet
    		if (current_socket->pending_lst.size() == current_socket->backlog) {
                cout << "full pending_lst!!\n";
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
            ////
            new_connection->seqNum = send_seq_number;

            // push it to pending list for current_socket
  			current_socket->pending_lst.push_back(new_connection);

  			// make packet header for sending packet
            makeTCPHeader(&my_packet_header, new_connection->srcPort, new_connection->destPort,
                send_seq_number, send_ack_number, SYN + ACK, 10000);

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
            break;

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
            makeTCPHeader(&my_packet_header, tcp_header.destPort, tcp_header.srcPort,
                0, send_ack_number, ACK, 10000);
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

            // SYN_RCVD (server)
            if (current_socket->state == static_cast<int> (STATE::SYN_RCVD)) {

                list<connection_info *>::iterator iter;
                for(iter = current_socket->pending_lst.begin(); 
                    iter != current_socket->pending_lst.end(); iter ++) {
                    if (((*iter)->srcPort == tcp_header.destPort) &&
                        ((*iter)->destPort == tcp_header.srcPort) &&
                        ((*iter)->srcIP == dest_ip) &&
                        ((*iter)->destIP == src_ip) &&
                        ((*iter)->seqNum + 1 == ntohl(tcp_header.ackNum))) {

                        cout << "same one found!\n";
                        // push it to established list and erase it in pending list
                        current_socket->established_lst.push_back(*iter);
                        current_socket->pending_lst.erase(iter);
                        break;
                    }
                }
                // change state
                current_socket->state = SYN_RCVD;
                break;

            } 
            // FIN_WAIT_1 (client)
            else if (current_socket->state == static_cast<int> (STATE::FIN_WAIT_1)) {
                current_socket->state = FIN_WAIT_2;
                
            }
            // LAST_ACK (server)
            else if (current_socket->state == static_cast<int> (STATE::LAST_ACK)) {
                current_socket->state = CLOSED;

                // remove filedecriptor
                this->removeFileDescriptor(current_socket->pid, current_socket->fd);

                delete iter->second;
                socket_info_map.erase(iter);
                // unblock the close syscall
                this->returnSystemCall(current_socket->closeUUID, 0);
                
            }

            break;
    		
        }
        // FIN packet
        case(0x1):
        {
            cout << "fin packet!!\n";
            // reject packet if it's state is not ESTABLISHED and FIN_WAIT_2
            if (current_socket->state != static_cast<int> (STATE::ESTABLISHED)&&
                current_socket->state != static_cast<int> (STATE::FIN_WAIT_2)) {
                this->freePacket(packet);
                this->freePacket(my_packet);
                return;
            }
            /*
                send ACK packet 
                for FIN 
            */
            cout << "haha\n";
            uint32_t send_ack_number = recv_seq_number + 1;
            makeTCPHeader(&my_packet_header, tcp_header.destPort, tcp_header.srcPort,
                0, send_ack_number, ACK, 10000);
            // checksum
            uint16_t checksum = calculateChecksum(src_ip, dest_ip, (uint8_t*)&my_packet_header, 20);
            my_packet_header.checksum = htons(checksum);

            // write packet
            my_packet->writeData(14 + 20, &my_packet_header, 20);
            // change state
            if (current_socket->state == static_cast<int> (STATE::ESTABLISHED)) {
                current_socket->state = CLOSE_WAIT;
            } else if (current_socket->state == static_cast<int> (STATE::FIN_WAIT_2)) {
                current_socket->state = TIME_WAIT;
                Time current_time = this->getHost()->getSystem()->getCurrentTime();
                current_socket->timerUUID = TimerModule::addTimer(&key, current_time + (Time)1000000000);
            }
            // send packet
            this->sendPacket("IPv4", my_packet);
            return;
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
uint32_t TCPAssignment::pidFromKey(uint64_t key) 
{
	return (uint32_t)(key >> 32);
}
uint32_t TCPAssignment::fdFromKey(uint64_t key)
{
	return (uint32_t)(key & 0xffffffff);
}

void TCPAssignment::makeTCPHeader(struct tcp_header *TCPHeader, uint16_t srcPort, uint16_t destPort, uint32_t seqNum, uint32_t ackNum, unsigned char flags, uint16_t winSize) {
    TCPHeader->srcPort = srcPort;
    TCPHeader->destPort = destPort;
    TCPHeader->seqNum = htonl(seqNum);
    TCPHeader->ackNum = htonl(ackNum);
    TCPHeader->flags = flags;
    TCPHeader->windowSize = htons(winSize);
}

void TCPAssignment::timerCallback(void* payload) {
    uint64_t key = (uint64_t) payload;
    
    map<uint64_t, struct socket_info*>::iterator iter;
    iter = socket_info_map.find(key);
    struct socket_info * current_socket = iter->second;

    if(current_socket->state == static_cast<int>(STATE::TIME_WAIT)) {
        current_socket->state = CLOSED;

        // remove filedecriptor
        this->removeFileDescriptor(current_socket->pid, current_socket->fd);

        delete iter->second;
        socket_info_map.erase(iter);
        // unblock the close syscall
        this->returnSystemCall(current_socket->closeUUID, 0);
    }
}

}
