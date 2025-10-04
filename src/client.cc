#include "client.hpp"
#include "misc.hpp"
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

namespace chat {
Client::Client() {
    int m_serverfd{-1};
    std::string m_outbuf{};
    std::string m_targetip{};
    std::string m_targetport{};
}

Client::~Client() { close(m_fd); }

int Client::setup() {
    std::string target = get_user_string(
        "Enter server IP:PORT.\nFor example: \"192.168.0.1:5000\":\n");

    m_targetip = target.substr(0, target.find(":"));
    m_targetport = target.substr(target.find(":") + 1);

    int status;
    addrinfo hints{};
    hints.ai_family = AF_INET;       // Ipv4
    hints.ai_socktype = SOCK_STREAM; // stream = tcp
    addrinfo *res = nullptr;
    if ((status = getaddrinfo(m_targetip.data(), m_targetport.data(), &hints,
                              &res) != 0)) {
        chat::clear_terminal();
        std::cerr << "[ERROR > getaddrinfo] " << gai_strerror(status) << "."
                  << std::endl;
        return -1;
    }

    m_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (m_fd < 0) {
        std::cerr << "[ERROR > socket] " << strerror(errno) << "." << std::endl;
        return -1;
    }

    if (connect(m_fd, res->ai_addr, res->ai_addrlen) == -1) {
        std::cerr << "[ERROR > connect] " << strerror(errno) << "."
                  << std::endl;
        close(m_fd);
        freeaddrinfo(res);
        return -1;
    }

    chat::clear_terminal();
    std::cout << "Connected to " << m_targetip << ":" << m_targetport << "."
              << std::endl;

    freeaddrinfo(res);
    return 0;
}

std::string get_user_string(const std::string &input_msg) {
    // Don't need error handling because string can't rly fail lol
    std::string input;
    std::cout << input_msg;
    std::cin >> input;

    return input;
}

} // namespace chat
