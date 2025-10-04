#include <chrono>
#include <iostream>

namespace chat {

std::string get_timestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);

    std::tm tm{};
    localtime_r(&t, &tm);
    std::ostringstream oss;
    oss << "[" << std::setw(2) << std::setfill('0') << tm.tm_hour << ":"
        << std::setw(2) << std::setfill('0') << tm.tm_min << "]";
    return oss.str();
}

void clear_terminal() { std::cout << "\033[2J\033[H"; }

} // namespace chat
