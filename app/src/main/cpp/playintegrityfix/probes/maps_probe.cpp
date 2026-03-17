#include "playintegrityfix/probes/maps_probe.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <set>
#include <string>
#include <utility>

namespace duckdetector::playintegrityfix {
    namespace {

        std::string to_lower_ascii(std::string value) {
            std::transform(
                    value.begin(),
                    value.end(),
                    value.begin(),
                    [](const unsigned char ch) { return static_cast<char>(std::tolower(ch)); }
            );
            return value;
        }

        bool contains_any(
                const std::string &haystack,
                const std::initializer_list<const char *> needles
        ) {
            for (const char *needle: needles) {
                if (haystack.find(needle) != std::string::npos) {
                    return true;
                }
            }
            return false;
        }

    }  // namespace

    std::vector<RuntimeTrace> scan_runtime_maps() {
        std::vector<RuntimeTrace> traces;
        std::set<std::string> dedupe;

        FILE *fp = std::fopen("/proc/self/maps", "r");
        if (fp == nullptr) {
            return traces;
        }

        char line[768];
        while (std::fgets(line, sizeof(line), fp) != nullptr) {
            const std::string raw_line(line);
            const std::string lowered = to_lower_ascii(raw_line);

            const bool pif_named = contains_any(
                    lowered,
                    {"playintegrity", "integrityfix", "pihooks", "pixelprops"}
            );
            const bool keystore_associated = lowered.find("keystore") != std::string::npos;
            const bool deleted_loader = lowered.find("(deleted)") != std::string::npos;

            if (!(pif_named || (keystore_associated && lowered.find("pif") != std::string::npos))) {
                continue;
            }

            std::string trimmed = raw_line;
            while (!trimmed.empty() && (trimmed.back() == '\n' || trimmed.back() == '\r')) {
                trimmed.pop_back();
            }
            if (!dedupe.insert(trimmed).second) {
                continue;
            }

            RuntimeTrace trace;
            if (keystore_associated) {
                trace.label = "Keystore-associated PIF trace";
            } else if (contains_any(lowered, {"pixelprops"})) {
                trace.label = "Pixel props runtime trace";
            } else {
                trace.label = "PIF runtime trace";
            }
            trace.detail = trimmed;
            trace.severity = (keystore_associated || deleted_loader)
                             ? TraceSeverity::kDanger
                             : TraceSeverity::kWarning;
            traces.push_back(std::move(trace));
        }

        std::fclose(fp);
        return traces;
    }

}  // namespace duckdetector::playintegrityfix
