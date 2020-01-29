#ifndef TCPSERVER_H
#define TCPSERVER_H

#include <list>
#include <memory>
#include <String>
#include "Server.h"
#include "FileDesc.h"
#include "TCPConn.h"

class TCPServer : public Server 
{
public:
   TCPServer();
   ~TCPServer();

   void bindSvr(const char *ip_addr, unsigned short port);
   void listenSvr();
   void shutdown();

private:
   // Class to manage the server socket
   SocketFD _sockfd;
 
   // List of TCPConn objects to manage connections
   std::list<std::unique_ptr<TCPConn>> _connlist;

   //Approved IP Address List
   std::list<std::string> _whiteList;

   
   


};


#endif
