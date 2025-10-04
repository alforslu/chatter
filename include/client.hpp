#pragma once

#include <string>
namespace chat {

std::string get_user_string(const std::string &input_msg);

class Client {
    int m_fd;
    std::string m_outbuf;
    std::string m_targetip;
    std::string m_targetport;

  public:
    Client();
    ~Client();

    int setup();
    void run();
};

} // namespace chat
