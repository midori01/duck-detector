#pragma once

#include <string>

namespace duckdetector::zygisk {

    constexpr int kFdTrapClean = 0;
    constexpr int kFdTrapEbadf = 1;
    constexpr int kFdTrapCorruption = 2;
    constexpr int kFdTrapProcfsAnomaly = 3;
    constexpr int kFdTrapBindFailed = -2;
    constexpr int kFdTrapTimeout = -3;
    constexpr int kFdTrapNativeUnavailable = -4;

    int setup_trap_fd(const std::string &cache_dir);

    int verify_trap_fd(int fd);

    std::string get_trap_details();

    void cleanup_trap_fd(int fd);

}  // namespace duckdetector::zygisk
