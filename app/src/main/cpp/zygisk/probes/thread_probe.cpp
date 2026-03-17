#include "zygisk/probes/thread_probe.h"

#include <dirent.h>
#include <sstream>

namespace duckdetector::zygisk {

    namespace {

        int parse_tracer_pid() {
            for (const auto &line: split_lines(read_text_file("/proc/self/status"))) {
                if (!starts_with(line, "TracerPid:")) {
                    continue;
                }
                return std::atoi(trim_copy(line.substr(std::string("TracerPid:").size())).c_str());
            }
            return 0;
        }

    }  // namespace

    ProbeResult collect_thread_probe() {
        ProbeResult result;
        result.numeric_value = parse_tracer_pid();
        if (result.numeric_value > 0) {
            result.traces.push_back({
                                            SignalGroup::kRuntime,
                                            SignalSeverity::kDanger,
                                            "TracerPid",
                                            "TracerPid is non-zero (" +
                                            std::to_string(result.numeric_value) +
                                            "), which means another process is tracing this app process.",
                                    });
            result.strong_hits = 1;
        }

        DIR *directory = opendir("/proc/self/task");
        if (directory == nullptr) {
            result.available = false;
            return result;
        }

        std::vector<std::string> suspicious_names;
        while (const auto *entry = readdir(directory)) {
            if (entry->d_name[0] == '.') {
                continue;
            }
            const std::string path = std::string("/proc/self/task/") + entry->d_name + "/comm";
            const auto name = trim_copy(read_text_file(path));
            if (name.empty()) {
                continue;
            }
            const auto lower = lowercase_copy(name);
            if (lower.find("zygisk") != std::string::npos ||
                lower.find("magisk") != std::string::npos ||
                lower.find("riru") != std::string::npos ||
                lower.find("xposed") != std::string::npos) {
                suspicious_names.push_back(name);
            }
        }
        closedir(directory);

        if (!suspicious_names.empty()) {
            std::ostringstream detail;
            detail << "Suspicious thread names include ";
            for (size_t index = 0; index < suspicious_names.size() && index < 3U; ++index) {
                if (index > 0U) {
                    detail << ", ";
                }
                detail << suspicious_names[index];
            }
            if (suspicious_names.size() > 3U) {
                detail << " and " << (suspicious_names.size() - 3U) << " more";
            }
            detail << '.';
            result.traces.push_back({
                                            SignalGroup::kThreads,
                                            SignalSeverity::kWarning,
                                            "Suspicious thread",
                                            detail.str(),
                                    });
            result.hit_count = static_cast<int>(suspicious_names.size());
            result.heuristic_hits = 1;
        }

        return result;
    }

}  // namespace duckdetector::zygisk
