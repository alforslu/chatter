#pragma once

#include <poll.h>
#include <queue>

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
    int handle_command(std::string &cmd, int fd);
    void broadcast_messages();
    void accept_all();
    void remove_client(int fd);
    int handle_recv(pollfd &pfd);
    Client &get_client(int fd);
    // To all users
    void queue_message(std::string &msg);
    // To specific user
    void queue_message(std::string &msg, int fd);
};

} // namespace chat
