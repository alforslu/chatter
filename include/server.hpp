#pragma once

#include <netdb.h>
#include <poll.h>
#include <queue>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <vector>

namespace chat {
class Server {

  public:
    // Functions
    Server();
    Server(std::string port);
    ~Server();
    void setup();
    void run();
    // void stop();

    struct Client {
        int fd;
        std::string name;
        std::string inbuf;
        std::queue<std::string> outbuf;
        size_t offset;
    };

  private:
    // Structs

    // Variables
    std::vector<Client> m_clients;
    std::string m_port;
    std::string outbuf;
    int m_sockfd;

    // Functions
    void broadcast_messages();
    void accept_all();
    void remove_client(int fd);
    int handle_recv(pollfd &pfd);
    Client &get_client(int fd);
};

} // namespace chat
