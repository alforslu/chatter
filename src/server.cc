#include "server.hpp"
#include "misc.hpp"
#include <arpa/inet.h>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <iostream>
#include <memory>
#include <netdb.h>
#include <netinet/in.h>
#include <stdexcept>
#include <sys/socket.h>

constexpr bool DEBUG = false;

namespace chat {

// Constants
constexpr int MAX_RETRY = 3;
constexpr int BACKLOG = 10;

struct AddrInfoDeleter {
    void operator()(addrinfo *p) const noexcept {
        if (p) {
            freeaddrinfo(p);
        }
    }
};

Server::Server() {
    m_port = "5000";
    int m_sockfd{-1};
}
Server::Server(std::string port) {
    m_port = port;
    int m_sockfd{-1};
}

Server::~Server() {
    if (m_sockfd >= 1) {
        close(m_sockfd);
    }

    // Make sure all the fd's are closed when server dies
    // Probably doesn't matter tho, OS would handle
    for (Client &c : m_clients) {
        if (c.fd >= 1) {
            close(c.fd);
        }
    }
}

void Server::setup() {
    // Incase connection failed then this is freed, not that it matters because
    // process will exit anyways, but it was cool and I want to try best
    // practice
    std::unique_ptr<addrinfo, AddrInfoDeleter> servinfo;

    // Get addr info
    for (int i = 0; i < MAX_RETRY; i++) {
        int status;
        addrinfo hints{};
        hints.ai_family = AF_INET;       // Ipv4
        hints.ai_socktype = SOCK_STREAM; // stream = tcp
        hints.ai_flags = AI_PASSIVE;     // "This host"

        addrinfo *raw = nullptr;
        if ((status = getaddrinfo(NULL, m_port.data(), &hints, &raw)) != 0) {
            std::cerr << "[ERROR > getaddrinfo] " << gai_strerror(status) << "."
                      << std::endl;
            if (i != MAX_RETRY - 1) {
                std::cout << "Retrying..." << std::endl;
            } else {
                exit(-1); // Give up
            }
            continue;
        }

        // Got a valid addrinfo, set the servinfo unique_ptr to it.
        servinfo.reset(raw);
        break;
    }

    // Get the listening socket
    m_sockfd = socket(servinfo->ai_family, servinfo->ai_socktype,
                      servinfo->ai_protocol);
    if (m_sockfd < 0) {
        std::cerr << "[ERROR > socket] " << strerror(errno) << "." << std::endl;
        exit(-1);
    }
    // Set to nonblocking for, e.i., accept()
    int flags = fcntl(m_sockfd, F_GETFL, 0);
    fcntl(m_sockfd, F_SETFL, flags | O_NONBLOCK);

    // Disable address in use (lol)
    int yes = 1;
    setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    // Bind to the port to lock it from other processes
    if (bind(m_sockfd, servinfo->ai_addr, servinfo->ai_addrlen) != 0) {
        std::cerr << "[ERROR > bind] " << strerror(errno) << "." << std::endl;
        exit(-1);
    }

    char ipstr[INET_ADDRSTRLEN];
    sockaddr_in *sin = (sockaddr_in *)servinfo->ai_addr;
    void *addr = &(sin->sin_addr);
    inet_ntop(servinfo->ai_family, addr, ipstr, sizeof ipstr);
    std::cout << "Server started on port " << ntohs(sin->sin_port) << "."
              << std::endl;
}

void Server::run() {

    if (listen(m_sockfd, BACKLOG)) {
        std::cerr << "[ERROR > listen] " << strerror(errno) << "." << std::endl;
        exit(-1);
    }

    for (;;) {
        // Always listener first
        std::vector<pollfd> pfds{{m_sockfd, POLLIN, 0}};
        pfds.reserve(m_clients.size() + 1);
        for (Client &c : m_clients) {
            short ev = POLLIN;
            if (!c.outbuf.empty()) {
                // If there is something to write to this
                // but it got stopped for some reason
                // then try again when pollout is ready.
                ev |= POLLOUT;
            }
            pfds.push_back({c.fd, ev, 0});
        }

        // Will poll all pfds for events, listener has only POLLIN
        // rest have POLLIN and MAYBE POLLOUT, if there is remaining in buffer.
        // n is the amount of fds with events
        int n = poll(pfds.data(), pfds.size(), -1);
        if (n <= 0) {
            continue; // Shouldn't get here, no events occured??
        }

        // First is listener, so this is if there are connections waiting to be
        // accepted
        if (pfds[0].revents & POLLIN) {
            accept_all();
        }

        // Handle all the clients
        for (pollfd &pfd : pfds) {
            if (pfd.fd == m_sockfd) {
                continue; // Don't want to handle this here
            }

            // Handle bad fd's
            if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) {
                // Something went wrong with this pfd, remove it.
                remove_client(pfd.fd);
                continue; // Don't do anything to this client, it is gone
            }

            // Handle incoming messages
            if (pfd.revents & POLLIN) {
                // Loop because stream might not be
                if (handle_recv(pfd) == -1) {
                    // This client has been removed
                    continue;
                } else {
                    // Broadcast to all as much as possible
                    // The ones that could not get everything
                    // will be handeled bellow in the POLLOUT.
                    broadcast_messages();
                }
            }

            // Handle outgoing messages (this should be rare)
            if (pfd.revents & POLLOUT) {
                // WARN: Look into if this is fine?
                // I don't see why it shouldn't be
                // I'm rebroadcasting to everyone that
                // don't have all the messages.
                // This includes the ones that aren't ready, but they'll just
                // error again? Which is fine. It is a little bit of double work
                // but that doesn't matter at this scale
                broadcast_messages();
            }
        }
    }
}

void Server::broadcast_messages() {
    for (Client &c : m_clients) {
        for (;;) {
            if (c.outbuf.empty()) {
                break;
            }

            int sent;
            std::string &msg = c.outbuf.front();
            const char *offset_msg = msg.data() + c.offset;
            size_t remainder = msg.size() - c.offset;

            sent = send(c.fd, offset_msg, remainder, MSG_NOSIGNAL);
            // Valid sent
            if (sent > 0) {
                // Increase the offset with what was sent
                // If this is equal to the msg length
                // Then we know we sent the entire thing.
                c.offset += sent;

                if (c.offset == msg.length()) {
                    c.outbuf.pop(); // Remove from the queue
                    c.offset = 0;
                }
            } else if (sent < 0) {
                if (errno == EAGAIN) {
                    break; // Can't send more RN
                } else {
                    remove_client(c.fd);
                    break;
                }
            } else {
                std::cerr << "[ERROR > broadcast_messages] This shouldn't "
                             "happen, sent = 0"
                          << std::endl;
                break; // This shouldn't happen
            }
        }
    }
}

int Server::handle_recv(pollfd &pfd) {
    Client *c = nullptr;
    try {
        c = &get_client(pfd.fd);
    } catch (std::runtime_error re) {
        std::cerr << "[ERROR > handle_recv] " << re.what() << std::endl;
        return -1;
    }
    assert(c); // Double check we have the user

    for (;;) {
        // Read incoming
        char buf[4096]{}; // Empty

        // r < 0 = error (or just full buffer etc), r == 0 = bye, r > 0 = msg
        ssize_t r = recv(pfd.fd, buf, sizeof buf, 0);
        if (r > 0) {
            if (r == 1 && buf[0] == '\n') {
                continue; // Ignore this
            }
            // Received valid data
            if (DEBUG) {
                std::cout << "Received: " << buf;
            }

            // Write to fd's inbuf
            // Will be added to all others outbuf whenever
            // The inbuf has a newline. This is a valid msg
            c->inbuf.append(buf, r);

            // Check if there is a newline in the inbuf
            size_t pos;
            // (while pos is not last character of a string)
            while ((pos = c->inbuf.find("\n")) != std::string::npos) {
                std::string msg = c->inbuf.substr(0, pos + 1); // Including \n
                c->inbuf.erase(0, pos + 1);

                std::string prepend_string =
                    chat::get_timestamp() + c->name + ": ";
                msg.insert(0, prepend_string);

                // Add to all people's outqueue
                for (Client &c : m_clients) {
                    // NOTE: Disables the repeat message back to client, this
                    // will depend on how client implementation is
                    // Currently testing using nc which keeps the input
                    if (c.fd == pfd.fd && DEBUG) {
                        continue;
                    }
                    c.outbuf.push(msg);
                }
            }

        } else if (r < 0 && (errno == EAGAIN)) {
            break; // Can't read anymore for some reason
            // But is not broken, will come back here later
            // when the pollin revent fires
        } else {
            remove_client(pfd.fd);
            return -1;
        }
    }

    return 0;
}

void Server::accept_all() {
    for (;;) {
        sockaddr_storage inc_addr;
        socklen_t inc_addr_size = sizeof inc_addr;
        int fd = accept4(m_sockfd, reinterpret_cast<sockaddr *>(&inc_addr),
                         &inc_addr_size, SOCK_NONBLOCK);
        if (fd < 0) {
            // No more connections
            return;
        } else {
            if (DEBUG) {
                std::cout << "Created a client: " << fd << std::endl;
            }
            // Create a client and push it to the vector
            Client c = {fd, "Anonymous", {}, {}, 0};
            m_clients.push_back(c);
        }
    }
}

void Server::remove_client(int fd) {
    for (size_t i = 0; i < m_clients.size(); i++) {
        if (m_clients[i].fd == fd) {
            if (DEBUG) {
                std::cout << "Disconnected: " << fd << std::endl;
            }
            close(fd);
            std::swap(m_clients[i], m_clients.back()); // Move to back
            m_clients.pop_back();                      // Remove last
            // This is fast, one swap and one pop. Better than
            // erase that shifts everything after the removed element
            return;
        }
    }
}

Server::Client &Server::get_client(int fd) {
    for (Client &c : m_clients) {
        if (c.fd == fd) {
            return c;
        }
    }
    throw std::runtime_error("No such client.");
}

} // namespace chat
