#include <stdexcept>
#include <strings.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>
#include <iostream>
#include <chrono>
#include <ctime> 
#include "TCPConn.h"
#include "strfuncts.h"
#include "PasswdMgr.h"

// The filename/path of the password file
const char pwdfilename[] = "passwd";
const char logname[] = "server.log";
PasswdMgr *passwdMgr = new PasswdMgr(pwdfilename);;

TCPConn::TCPConn(){ // LogMgr &server_log):_server_log(server_log) {
   

}


TCPConn::~TCPConn() {

}

/**********************************************************************************************
 * accept - simply calls the acceptFD FileDesc method to accept a connection on a server socket.
 *
 *    Params: server - an open/bound server file descriptor with an available connection
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

bool TCPConn::accept(SocketFD &server) {
   return _connfd.acceptFD(server);
}

/**********************************************************************************************
 * sendText - simply calls the sendText FileDesc method to send a string to this FD
 *
 *    Params:  msg - the string to be sent
 *             size - if we know how much data we should expect to send, this should be populated
 *
 *    Throws: runtime_error for unrecoverable errors
 **********************************************************************************************/

int TCPConn::sendText(const char *msg) {
   return sendText(msg, strlen(msg));
}

int TCPConn::sendText(const char *msg, int size) {
   if (_connfd.writeFD(msg, size) < 0) {
      return -1;  
   }
   return 0;
}

/**********************************************************************************************
 * startAuthentication - Sets the status to request username
 *
 *    Throws: runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPConn::startAuthentication() {

   // Skipping this for now
   _status = s_username;

   _connfd.writeFD("Username: "); 
}

/**********************************************************************************************
 * handleConnection - performs a check of the connection, looking for data on the socket and
 *                    handling it based on the _status, or stage, of the connection
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::handleConnection() {

   timespec sleeptime;
   sleeptime.tv_sec = 0;
   sleeptime.tv_nsec = 100000000;

   try {
      switch (_status) {
         case s_username:
            getUsername();
            break;

         case s_passwd:
            getPasswd();
            break;
   
         case s_changepwd:
         case s_confirmpwd:
            changePassword();
            break;

         case s_menu:
            getMenuChoice();
            break;

         default:
            throw std::runtime_error("Invalid connection status!");
            break;
      }
   } catch (socket_error &e) {
      std::cout << "Socket error, disconnecting.";
      disconnect();
      return;
   }

   nanosleep(&sleeptime, NULL);
}

/**********************************************************************************************
 * getUsername - called from handleConnection when status is s_username--if it finds user data,
 *               it expects a username and compares it against the password database
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getUsername() {
   // Insert your mind-blowing code here
   std::string username;
   if(!getUserInput(username)) {
      
      //std::cout << "commmand was not entered\n";
      
      //should throw an error here to exit function

   } else {
      if(!passwdMgr->checkUser(username.c_str())){
         _connfd.writeFD("Invalid username\n");
         disconnect();
         //should throw an error here to exit function
      }
      else{
         _username = username;
         _status = s_passwd;
         _connfd.writeFD("Password: ");
      }
   }
   
}

/**********************************************************************************************
 * getPasswd - called from handleConnection when status is s_passwd--if it finds user data,
 *             it assumes it's a password and hashes it, comparing to the database hash. Users
 *             get two tries before they are disconnected
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getPasswd() {
   // Insert your astounding code here
   std::string password;
   if(!getUserInput(password)) {
      //std::cout << "commmand was not entered\n";
      //should throw an error here to exit function

   } else {
      if( _pwd_attempts < 2) {
         if(!passwdMgr->checkPasswd(_username.c_str(), password.c_str())){
            if (_pwd_attempts == 0 ){
               _connfd.writeFD("Wrong password. Please try again\nPassword: ");
               _pwd_attempts++;
            } else {
               _connfd.writeFD("Wrong password. Max amount of attempts used, disconnecting now\n");
               disconnect();
            }
         } else {
            _connfd.writeFD("Password successfully entered\n");
            sendMenu();
            _status = s_menu;
         }
      }
   }
}


/**********************************************************************************************
 * changePassword - called from handleConnection when status is s_changepwd or s_confirmpwd--
 *                  if it finds user data, with status s_changepwd, it saves the user-entered
 *                  password. If s_confirmpwd, it checks to ensure the saved password from
 *                  the s_changepwd phase is equal, then saves the new pwd to the database
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::changePassword() {
   // Insert your amazing code here
   std::string password;
   if(!getUserInput(password)) {
      std::cout << "Commmand was not entered\n";
      //should throw an error here to exit function
   }
   if(_status == s_changepwd) {
      _newpwd = password;
      _status = s_confirmpwd; //not sure if this is necessary (maybe done somewhere else)
      _connfd.writeFD("Enter New Password Again: ");

   } else {
      if(_newpwd.compare(password) == 0) {
         if(!passwdMgr->changePasswd(_username.c_str(), password.c_str())) {
            _connfd.writeFD("Change password failed\n");
            //exit failure
         }
         _connfd.writeFD("Password successfully changed\n");
         //else change status to something else?, password successfully changed message
      }
   }
}


/**********************************************************************************************
 * getUserInput - Gets user data and includes a buffer to look for a carriage return before it is
 *                considered a complete user input. Performs some post-processing on it, removing
 *                the newlines
 *
 *    Params: cmd - the buffer to store commands - contents left alone if no command found
 *
 *    Returns: true if a carriage return was found and cmd was populated, false otherwise.
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

bool TCPConn::getUserInput(std::string &cmd) {
   std::string readbuf;

   // read the data on the socket
   _connfd.readFD(readbuf);

   // concat the data onto anything we've read before
   _inputbuf += readbuf;

   // If it doesn't have a carriage return, then it's not a command
   int crpos;
   if ((crpos = _inputbuf.find("\n")) == std::string::npos)
      return false;

   cmd = _inputbuf.substr(0, crpos);
   _inputbuf.erase(0, crpos+1);

   // Remove \r if it is there
   clrNewlines(cmd);

   return true;
}

/**********************************************************************************************
 * getMenuChoice - Gets the user's command and interprets it, calling the appropriate function
 *                 if required.
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getMenuChoice() {
   if (!_connfd.hasData())
      return;
   std::string cmd;
   if (!getUserInput(cmd))
      return;
   lower(cmd);      

   // Don't be lazy and use my outputs--make your own!
   std::string msg;
   if (cmd.compare("hello") == 0) {
      _connfd.writeFD("Welcome to the server!\n");
   } else if (cmd.compare("menu") == 0) {
      sendMenu();
   } else if (cmd.compare("exit") == 0) {
      _connfd.writeFD("'Insert AOL goodbye tone here'\n");
      disconnect();
   } else if (cmd.compare("passwd") == 0) {
      _connfd.writeFD("New Password: ");
      _status = s_changepwd;
   } else if (cmd.compare("1") == 0) {
      _connfd.writeFD("Don't cry because it's over. Smile because it happened.\n");
   } else if (cmd.compare("2") == 0) {
      _connfd.writeFD("If the track is tough and the hill is rough, THINKING you can just ain't enough.\n");
   } else if (cmd.compare("3") == 0) {
      _connfd.writeFD("Everything negative - pressure, challenges - is all an opportunity for me to rise.\n");
   } else if (cmd.compare("4") == 0) {
      _connfd.writeFD("You hear about how many fourth quarter comebacks that a guy has and I think it means a guy screwed up in the first three quarters.\n");
   } else if (cmd.compare("5") == 0) {
      _connfd.writeFD("Talent wins games, but teamwork and intelligence wins championships.\n");
   } else {
      msg = "Unrecognized command: ";
      msg += cmd;
      msg += "\n";
      _connfd.writeFD(msg);
   }

}

/**********************************************************************************************
 * sendMenu - sends the menu to the user via their socket
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
void TCPConn::sendMenu() {
   std::string menustr;

   // Make this your own!
   menustr += "Command Options: \n";
   menustr += "  '1' - Dr. Suess\n";
   menustr += "  '2' - Shel Silverstein\n";
   menustr += "  '3' - Kobe Bryant\n";
   menustr += "  '4' - Peyton Manning\n";
   menustr += "  '5' -  MJ\n";
   menustr += "  'Hello' - Welcome Message\n";
   menustr += "  'Passwd' - change your password\n";
   menustr += "  'Menu' - display this menu\n";
   menustr += "  'Exit' - disconnect.\n\n";

   _connfd.writeFD(menustr);
}


/**********************************************************************************************
 * disconnect - cleans up the socket as required and closes the FD
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
void TCPConn::disconnect() {
   _connfd.closeFD();
}


/**********************************************************************************************
 * isConnected - performs a simple check on the socket to see if it is still open 
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
bool TCPConn::isConnected() {
   return _connfd.isOpen();
}

/**********************************************************************************************
 * getIPAddrStr - gets a string format of the IP address and loads it in buf
 *
 **********************************************************************************************/
void TCPConn::getIPAddrStr(std::string &buf) {
   return _connfd.getIPAddrStr(buf);
}

void TCPConn::serverLog(std::string msg) {
    time_t rawtime;
    struct tm * timeinfo;

    time (&rawtime);
    timeinfo = localtime (&rawtime);

   FileFD log = FileFD(logname);
   log.openFile(FileFD::appendfd);
   log.writeFD(asctime(timeinfo));
   std::vector<char> msgV(msg.begin(), msg.end());
   log.writeBytes(msgV);
   log.writeByte('\n');
   log.closeFD();

}

