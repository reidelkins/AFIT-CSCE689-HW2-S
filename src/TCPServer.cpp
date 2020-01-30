#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdexcept>
#include <strings.h>
#include <vector>
#include <iostream>
#include <string>
#include <fstream>
#include <memory>
#include <sstream>
#include "FileDesc.h"
#include "TCPServer.h"

const char whitelistfilename[] = "whitelist";
TCPConn *new_conn = new TCPConn();

TCPServer::TCPServer(){ // :_server_log("server.log", 0) {
   
   new_conn->serverLog("Started server\n");
   FileFD _IPFile = FileFD(whitelistfilename);
   //reads in IPs from text file and puts them into string list
   _IPFile.openFile(FileFD::readfd);
   std::string line;
   while(_IPFile.readStr(line) > 0) {
      _whiteList.push_back(line);

   }
   _IPFile.closeFD();
   
   //this can be deleted
   for(auto x = _whiteList.begin(); x != _whiteList.end(); x++) {
      std::cout << *x << "\n";
   }

}


TCPServer::~TCPServer() {

}

/**********************************************************************************************
 * bindSvr - Creates a network socket and sets it nonblocking so we can loop through looking for
 *           data. Then binds it to the ip address and port
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPServer::bindSvr(const char *ip_addr, short unsigned int port) {

   struct sockaddr_in servaddr;

   // _server_log.writeLog("Server started.");

   // Set the socket to nonblocking
   _sockfd.setNonBlocking();

   // Load the socket information to prep for binding
   _sockfd.bindFD(ip_addr, port);
 
}

/**********************************************************************************************
 * listenSvr - Performs a loop to look for connections and create TCPConn objects to handle
 *             them. Also loops through the list of connections and handles data received and
 *             sending of data. 
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPServer::listenSvr() {

   bool online = true;
   timespec sleeptime;
   sleeptime.tv_sec = 0;
   sleeptime.tv_nsec = 100000000;
   int num_read = 0;

   // Start the server socket listening
   _sockfd.listenFD(5);

    
   while (online) {
      struct sockaddr_in cliaddr;
      socklen_t len = sizeof(cliaddr);

      if (_sockfd.hasData()) {
         //TCPConn *new_conn = new TCPConn();

         if (!new_conn->accept(_sockfd)) {
            // _server_log.strerrLog("Data received on socket but failed to accept.");
            continue;
         }
         std::cout << "***Got a connection***\n";

         _connlist.push_back(std::unique_ptr<TCPConn>(new_conn));

         // Get their IP Address string to use in logging
         std::string ipaddr_str;
         new_conn->getIPAddrStr(ipaddr_str);

         std::string msg;
         //check if IP Addr from new connection is in the approved list, need to check formatting of 
         if(std::find(_whiteList.begin(), _whiteList.end(), ipaddr_str) == _whiteList.end()) {
            //disconnect this connection
            std::cout << "New connection not from approved list of IP Addresses, disconnecting now\n";
            //how to get server to manually disconnect client
            _connlist.remove(_connlist.back());
            std::cout << "Connection disconnected.\n";
            msg = "Connection attempted from non-approved IP. IP : ";
            
            new_conn->serverLog(msg);
         }
         msg = "Connection established from IP ";
         msg += ipaddr_str;
         msg += "\n";
         new_conn->serverLog(msg);

         new_conn->sendText("Welcome to the CSCE 689 Server!\n");

         // Change this later
         new_conn->startAuthentication();
      }

      // Loop through our connections, handling them
      std::list<std::unique_ptr<TCPConn>>::iterator tptr = _connlist.begin();
      while (tptr != _connlist.end())
      {
         // If the user lost connection
         if (!(*tptr)->isConnected()) {
            // Log it

            // Remove them from the connect list
            tptr = _connlist.erase(tptr);
            std::cout << "Connection disconnected.\n";
            continue;
         }

         // Process any user inputs
         (*tptr)->handleConnection();

         // Increment our iterator
         tptr++;
      }

      // So we're not chewing up CPU cycles unnecessarily
      nanosleep(&sleeptime, NULL);
   } 
   
}


/**********************************************************************************************
 * shutdown - Cleanly closes the socket FD.
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPServer::shutdown() {

   _sockfd.closeFD();
}



