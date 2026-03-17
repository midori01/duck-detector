#include "zygisk/probes/atexit_probe.h"

#include <dlfcn.h>

namespace duckdetector::zygisk {

    ProbeResult collect_atexit_probe() {
        ProbeResult result;
        const auto maps = read_proc_maps();
        if (maps.empty()) {
            result.available = false;
            return result;
        }

        void *cxa_atexit = dlsym(RTLD_DEFAULT, "__cxa_atexit");
        void *cxa_finalize = dlsym(RTLD_DEFAULT, "__cxa_finalize");
        const auto *atexit_owner = find_map_for_address(maps,
                                                        reinterpret_cast<uintptr_t>(cxa_atexit));
        const auto *finalize_owner = find_map_for_address(maps,
                                                          reinterpret_cast<uintptr_t>(cxa_finalize));

        const bool atexit_drift =
                atexit_owner != nullptr && atexit_owner->path.find("libc.so") == std::string::npos;
        const bool finalize_drift = finalize_owner != nullptr &&
                                    finalize_owner->path.find("libc.so") == std::string::npos;
        if (atexit_drift || finalize_drift) {
            std::string detail = "__cxa_atexit owner=" +
                                 std::string(atexit_owner != nullptr ? atexit_owner->path
                                                                     : "<unknown>") +
                                 ", __cxa_finalize owner=" +
                                 std::string(finalize_owner != nullptr ? finalize_owner->path
                                                                       : "<unknown>") + '.';
            result.traces.push_back({
                                            SignalGroup::kLinker,
                                            SignalSeverity::kWarning,
                                            "Atexit runtime drift",
                                            detail,
                                    });
            result.hit_count = 1;
            result.heuristic_hits = 1;
        }

        return result;
    }

}  // namespace duckdetector::zygisk
