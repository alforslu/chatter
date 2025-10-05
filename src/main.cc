#include "client.hpp"
#include "misc.hpp"
#include "server.hpp"
#include <algorithm>
#include <cctype>
#include <iostream>
#include <string>

int main(int argc, char *argv[]) {
    if (argc == 1) {
        // Start client
        chat::Client client = chat::Client();
        for (;;) {
            // If setup broke, try again
            int res = client.setup();
            if (res == -1) {
                std::cout << "Failed to connect... Please try again."
                          << std::endl;
            } else {
                break;
            }
        }
        // client.run();
        return 0;
    }
    if (argc == 2) {
        std::string arg = argv[1]; // Safer than strcmp
        chat::to_lower(arg);

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
