#include "tee/common/syscall_facade.h"

#include <cstring>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace ducktee::common {

#if defined(__aarch64__)
    extern "C" long tee_arm64_syscall3(long number, long arg0, long arg1, long arg2);
#endif

    long raw_syscall3(long number, long arg0, long arg1, long arg2) {
#if defined(__aarch64__)
        return tee_arm64_syscall3(number, arg0, arg1, arg2);
#else
        return syscall(number, arg0, arg1, arg2);
#endif
    }

    int raw_open_readonly(const char *path) {
#if defined(__NR_openat)
        return static_cast<int>(raw_syscall3(__NR_openat, AT_FDCWD, reinterpret_cast<long>(path),
                                             O_RDONLY | O_CLOEXEC));
#else
        return open(path, O_RDONLY | O_CLOEXEC);
#endif
    }

    long raw_ioctl(int fd, unsigned long request, void *arg) {
#if defined(__NR_ioctl)
        return raw_syscall3(__NR_ioctl, fd, static_cast<long>(request),
                            reinterpret_cast<long>(arg));
#else
        return -1;
#endif
    }

    bool bytes_equal(const void *lhs, const void *rhs, std::size_t length) {
        return std::memcmp(lhs, rhs, length) == 0;
    }

}  // namespace ducktee::common
