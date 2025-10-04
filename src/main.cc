#include "server.hpp"
#include <algorithm>
#include <cctype>
#include <iostream>
#include <string>

int main(int argc, char *argv[]) {
    if (argc == 1) {
        // Start client
        std::cout << "Client" << std::endl;
        return 0;
    }
    if (argc == 2) {
        std::string arg = argv[1]; // Safer than strcmp
        std::transform(arg.begin(), arg.end(), arg.begin(),
                       [](unsigned char c) { return std::tolower(c); });

        if (arg == "--server") {
            chat::Server server = chat::Server();
            server.setup();
            server.run();
            return 0; // End after server quits
        }
    }

    std::cout << "Usage: chatter [--server]\n";
    return -1;
}
