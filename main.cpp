/*
    compile: g++ main.cpp -lcrypt -pthread -o shadowBreaker --std=c++11
*/

#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>
#include <unistd.h>     // for crypt function
#include <sysexits.h>   // for exit codes
#include <string.h>
#include <thread>
#include <mutex>
#include <crypt.h>

//FUNCTIONS SECTION
std::vector<std::string> split(const std::string &s, char delim); // when we will have standart split func?
bool isUserHaveHash(char data[256]);                              //check for len and special symbols in hash (to avoid unvailable hashes)
void parseShadowFile(char* path);                                 //Parsing file with passwords. Separate realization for parsing hash strings.
void parsePassListFile(char* path);                               //Parsing file with passwords

//DATA SECTION
//We can use spwd from shadow.h, but it have extra data fields and didn't have field for salt
//Salt contains special salt format, according to man shadow and man crypt  ($id$salt$)
class UserHash{
public:
    std::string username;
    std::string hash;
    std::string salt;
    UserHash(std::string raw){
        std::vector<std::string> data = split(raw, ':');
        if (data[1].size() > 4){
            this->username = data[0];
            this->hash = data[1];
            this->salt = "$"+split(data[1], '$')[1]+'$'+split(data[1], '$')[2]+'$'; // bad code
        }
        data.clear();
    }
    std::string toString(){
        std::string data = "[>]"+this->username+"\n \u2514\u2500hash="+this->hash+"\n";
        return data;
    }
    bool checkPassword(std::string pass){
        struct crypt_data data[1] = {0};
        if (this->hash.compare( crypt_r(pass.c_str(), this->salt.c_str(), data) ))
            return true;
        return false;
    }
    ~UserHash(){
        this->username.clear();
        this->hash.clear();
        this->salt.clear();
    }
};

std::vector<UserHash> shadow;      //for parsed strings from shadow file
std::vector<std::string> passList; //for passwords list file
std::vector<std::thread> threads;  //threads container
std::mutex lockList;               //to lock passList in thread
std::mutex lockio;


//WORK SECTION
//our main function for threading. Gets hash data and brute it with passwords from passList.
void bruteUserHash(UserHash hashData){
    for (int i=0; i<passList.size(); i++){
        lockList.lock();
            std::string pass = passList[i];
        lockList.unlock();
        if (!hashData.checkPassword(pass)){
            lockio.lock();
            std::cout<< "\n[!] Found Password \n \u2514\u2500> {"<< hashData.username << " <\u2500\u2500> " << pass << "}\n" << std::endl;
            lockio.unlock();
            return void();
        }
    }
    lockio.lock();
      std::cout << "[X] Password not found for {" << hashData.username << "} in your list :("<< std::endl<< std::endl;
    lockio.unlock();
}

int main(int argc, char* argv[]){
    if (argc != 3){
        std::cout<<"Use: "<<argv[0]<<" <dict with passwords> </etc/shadow file>" << std::endl;
        return EX_USAGE;
    }
    std::cout << "[>]\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500[<]\n"
              <<" |ShadowBreaker by greg0r0|\n" 
              << "[>]\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500[<]\n"<< std::endl<< std::endl;
    parsePassListFile(argv[1]);
    parseShadowFile(argv[2]);

    for (int i=0; i<shadow.size(); i++){
        threads.emplace_back(std::thread(bruteUserHash, shadow[i]));              //starting threads, one per UserHash
    }
    std::cout << "[!] Breaking started, please wait..." << std::endl<< std::endl;  
    for (int i=0; i<shadow.size(); i++){                                          //Syncronizing threads
        threads[i].join();
    }
    
    return 0;
}

std::vector<std::string> split(const std::string &str, char del){
    std::vector<std::string> elements;

    std::stringstream stringStream(str);
    std::string item;
    while (std::getline(stringStream, item, del)){
        elements.push_back(item);
    }

    return elements;
}
bool isUserHaveHash(char data[256]){
    std::vector<std::string> info = split(data, ':');
    
    if ( info.size() >= 2 && info[1].size() > 4){ // dont match not available hashes
        return true;
    }
    return false;
}
void parseShadowFile(char* path){
    std::ifstream infile;
    infile.open(path);
    if (!infile.is_open()){
        std::cout << "[!] File " << path << " can't be open. " << std::endl;
        exit(EX_NOINPUT);
    }
    char buff[256];
    while (!infile.eof()){
        infile >> buff;
        if (isUserHaveHash(buff))
        {   
            shadow.push_back(UserHash(buff));
        }
        memset(buff, 0, 256);
    }
    std::cout << "[!] Found Users with hashes in {" << path << "}"<< std::endl;
    for (int i = 0; i<shadow.size(); i++)
        std::cout << shadow[i].toString() << std::endl;
    infile.close();
}
void parsePassListFile(char* path){
    std::ifstream infile;
    infile.open(path);
    if (!infile.is_open()){
        std::cout << "[!] File " << path << " can't be open. " << std::endl;
        exit(EX_NOINPUT);
    }
    char buff[256];
    while (!infile.eof()){
        infile >> buff;
        passList.push_back(buff);
        memset(buff, 0, 256);
    }
    std::cout << "[!] {"<< path <<"} password list size = "<< passList.size() << " words"<<std::endl<< std::endl;
    infile.close();
}
