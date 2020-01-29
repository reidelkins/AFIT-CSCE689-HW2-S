#include <argon2.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <list>
#include <ctime>
#include "PasswdMgr.h"
#include "FileDesc.h"
#include "strfuncts.h"

const int hashlen = 32;
const int saltlen = 16;

PasswdMgr::PasswdMgr(const char *pwd_file):_pwd_file(pwd_file) {

}


PasswdMgr::~PasswdMgr() {

}

/*******************************************************************************************
 * checkUser - Checks the password file to see if the given user is listed
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            reading
 *******************************************************************************************/

bool PasswdMgr::checkUser(const char *name) {
   std::cout << "in checkUser\n";
   std::vector<uint8_t> hash, salt;

   bool result = findUser(name, hash, salt);

   return result;
     
}

/*******************************************************************************************
 * checkPasswd - Checks the password for a given user to see if it matches the password
 *               in the passwd file
 *
 *    Params:  name - username string to check (case insensitive)
 *             passwd - password string to hash and compare (case sensitive)
 *    
 *    Returns: true if correct password was given, false otherwise
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            reading
 *******************************************************************************************/

bool PasswdMgr::checkPasswd(const char *name, const char *passwd) {
   std::vector<uint8_t> userhash; // hash from the password file
   std::vector<uint8_t> passhash; // hash derived from the parameter passwd
   std::vector<uint8_t> salt;

   // Check if the user exists and get the passwd string
   if (!findUser(name, userhash, salt)) {
      return false;
   }

   hashArgon2(passhash, salt, passwd, &salt);

   const char tmpfilename[] = "tmp";
   FileFD tmp = FileFD(tmpfilename);
   tmp.openFile(FileFD::writefd);
   tmp.writeBytes(passhash);
   tmp.closeFD();

   tmp.openFile(FileFD::readfd);
   tmp.readBytes(passhash, hashlen);
   tmp.closeFD();
   //do not need to write back because the next write will write over this line
   

   for (auto x = userhash.begin(); x != userhash.end(); x++) {
      std:: cout << (*x);
   }
   std::cout << "\n" << userhash.size() << "\n";
   for (auto x = passhash.begin(); x != passhash.end(); x++) {
      std:: cout << (*x);
   }
   std::cout << "\n" << passhash.size() << "\n";

   if (userhash == passhash)
      return true;

   return true;
}

/*******************************************************************************************
 * changePasswd - Changes the password for the given user to the password string given
 *
 *    Params:  name - username string to change (case insensitive)
 *             passwd - the new password (case sensitive)
 *
 *    Returns: true if successful, false if the user was not found
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            writing
 *
 *******************************************************************************************/

bool PasswdMgr::changePasswd(const char *name, const char *passwd) {
   //DOES NOT HAVE ANY ERROR CHECKING
   FileFD pwfile(_pwd_file.c_str());
   if(!pwfile.openFile(FileFD::readfd)) {
      std::list<std::string> pswds;
      std::string line, last = "";
      std::vector<uint8_t> hash, salt, outSalt;
      std::string hashStr; //hashStr = hashArgon2(hash, salt, passwd, outSalt);
      while(!pwfile.readStr(line) != -1) {
         if(last.compare(name) == 0) {
            pswds.push_back(hashStr);
         } else {
            pswds.push_back(line);
            last = line;
         }
      }
      pwfile.closeFD();
      if(!pwfile.openFile(FileFD::writefd)) {
         //does doing a writestr in a file that is opened as a writefd overwrite the current line
         for(auto lne = pswds.begin(); lne != pswds.end(); lne++) {
            pwfile.writeFD(*lne);
         }
         pwfile.closeFD();
      }
   }
   return true;
}

/*****************************************************************************************************
 * readUser - Taking in an opened File Descriptor of the password file, reads in a user entry and
 *            loads the passed in variables
 *
 *    Params:  pwfile - FileDesc of password file already opened for reading
 *             name - std string to store the name read in
 *             hash, salt - vectors to store the read-in hash and salt respectively
 *
 *    Returns: true if a new entry was read, false if eof reached 
 * 
 *    Throws: pwfile_error exception if the file appeared corrupted
 *
 *****************************************************************************************************/

bool PasswdMgr::readUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt)
{
   // Insert your perfect code here!

   //reads a line from the file, if the line is not the EOF, it returns true
   if(pwfile.readStr(name) <= 0) {
      //throw error
      return false;
   }
   if(pwfile.readBytes(hash, 32) <= 0) {
      //throw error
      return false;
   }
   if(pwfile.readBytes(salt, 16) <= 0) {
      //throw error
      return false;
   }
   std::string newL;
   if(pwfile.readStr(newL) <= 0) {
      //throw error
      return false;
   }

   return true;
}

/*****************************************************************************************************
 * writeUser - Taking in an opened File Descriptor of the password file, writes a user entry to disk
 *
 *    Params:  pwfile - FileDesc of password file already opened for writing
 *             name - std string of the name 
 *             hash, salt - vectors of the hash and salt to write to disk
 *
 *    Returns: bytes written
 *
 *    Throws: pwfile_error exception if the writes fail
 *
 *****************************************************************************************************/

int PasswdMgr::writeUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt)
{
   // Insert your wild code here!
   int results = 0;
   std::vector<char> nameV(name.begin(), name.end());
   results += pwfile.writeBytes(nameV);
   results += pwfile.writeByte('\n');
   results += pwfile.writeBytes(hash);
   results += pwfile.writeBytes(salt);
   results += pwfile.writeByte('\n');
   return results; 
}

/*****************************************************************************************************
 * findUser - Reads in the password file, finding the user (if they exist) and populating the two
 *            passed in vectors with their hash and salt
 *
 *    Params:  name - the username to search for
 *             hash - vector to store the user's password hash
 *             salt - vector to store the user's salt string
 *
 *    Returns: true if found, false if not
 *
 *    Throws: pwfile_error exception if the pwfile could not be opened for reading
 *
 *****************************************************************************************************/

bool PasswdMgr::findUser(const char *name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt) {

   FileFD pwfile(_pwd_file.c_str());
   // You may need to change this code for your specific implementation

   if (!pwfile.openFile(FileFD::readfd))
      throw pwfile_error("Could not open passwd file for reading");

   // Password file should be in the format username\n{32 byte hash}{16 byte salt}\n
   bool eof = false;
   while (!eof) {
      std::string uname;

      if (!readUser(pwfile, uname, hash, salt)) {
         eof = true;
         continue;
      }

      if (!uname.compare(name)) {
         pwfile.closeFD();
         return true;
      }
   }

   hash.clear();
   salt.clear();
   pwfile.closeFD();
   return false;
}


/*****************************************************************************************************
 * hashArgon2 - Performs a hash on the password using the Argon2 library. Implementation algorithm
 *              taken from the http://github.com/P-H-C/phc-winner-argon2 example. 
 *
 *    Params:  dest - the std string object to store the hash
 *             passwd - the password to be hashed
 *
 *    Throws: runtime_error if the salt passed in is not the right size
 *****************************************************************************************************/
void PasswdMgr::hashArgon2(std::vector<uint8_t> &ret_hash, std::vector<uint8_t> &ret_salt, 
                           const char *in_passwd, std::vector<uint8_t> *in_salt) {
   // Hash those passwords!!!!
   uint8_t hash[hashlen];
   uint8_t salt[saltlen];

   //if user passed in there own salt
   if(in_salt != NULL){
      if (in_salt->size() < saltlen) {
         //throw error
         throw std::runtime_error("salt is not proper size\n");

      } else {
         for(int i = 0; i < saltlen; i++) {
            salt[i] = (*in_salt)[i];
         }
      }
   } 
   
   //variables for the hash method
   const uint32_t t_cost = 2;
   const uint32_t m_cost = (1<<16);   
   const uint32_t parrallelism = 1;

   /*int argon2d_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
                     const uint32_t parallelism, const void *pwd,
                     const size_t pwdlen, const void *salt,
                     const size_t saltlen, void *hash, const size_t hashlen)j
   */
   argon2i_hash_raw(t_cost, m_cost, parrallelism, in_passwd, strlen(in_passwd), salt, saltlen, hash, hashlen);

   ret_hash.clear();
   ret_salt.clear();
   ret_hash.reserve(hashlen);
   ret_hash.reserve(saltlen);
   for(int i = 0; i < hashlen; i++) {
      if(i < saltlen) {
         ret_salt.push_back(salt[i]);
      }
      ret_hash.push_back(hash[i]);

   }


}

/****************************************************************************************************
 * addUser - First, confirms the user doesn't exist. If not found, then adds the new user with a new
 *           password and salt
 *
 *    Throws: pwfile_error if issues editing the password file
 ****************************************************************************************************/

void PasswdMgr::addUser(const char *name, const char *passwd) {
   // Add those users!
   std::vector<uint8_t> hash, salt;
   if(checkUser(name)) {
      std::cout << "User already exists\n";
      return;
   } else {
      makeSalt(salt);
      hashArgon2(hash, salt, passwd, &salt);

      FileFD pwfile(_pwd_file.c_str());
      std::string nameToAdd = name;
      if(!pwfile.openFile(FileFD::appendfd)) {
         std::cout << "Could not open password file\n";
         //throw error
      } else if(writeUser(pwfile, nameToAdd, hash, salt) == 0) {
         std::cout << "Could not write user\n";
         //throw error
      }
      std::cout << "User successfully added\n";
   }

}

void PasswdMgr::makeSalt(std::vector<uint8_t> &salt) {
   srand(time(NULL));
   int tmp;
   for(int i = 0; i < saltlen; i++) {
      //96 ASCII chars between space and DEL
      tmp = (rand() % 96);
      salt.push_back('!' + tmp);
   }

}


