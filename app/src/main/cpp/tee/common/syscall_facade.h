#ifndef DUCKDETECTOR_TEE_COMMON_SYSCALL_FACADE_H
#define DUCKDETECTOR_TEE_COMMON_SYSCALL_FACADE_H

#include <cstddef>
#include <cstdint>

namespace ducktee::common {

    long raw_syscall3(long number, long arg0, long arg1, long arg2);

    int raw_open_readonly(const char *path);

    long raw_ioctl(int fd, unsigned long request, void *arg);

    bool bytes_equal(const void *lhs, const void *rhs, std::size_t length);

}  // namespace ducktee::common

#endif  // DUCKDETECTOR_TEE_COMMON_SYSCALL_FACADE_H
