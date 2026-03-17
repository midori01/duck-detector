#include "playintegrityfix/common/codec.h"

#include <sstream>
#include <string>

namespace duckdetector::playintegrityfix {
    namespace {

        std::string escape_value(const std::string &value) {
            std::string escaped;
            escaped.reserve(value.size());
            for (const char ch: value) {
                switch (ch) {
                    case '\\':
                        escaped += "\\\\";
                        break;
                    case '\n':
                        escaped += "\\n";
                        break;
                    case '\r':
                        escaped += "\\r";
                        break;
                    case '\t':
                        escaped += "\\t";
                        break;
                    default:
                        escaped += ch;
                        break;
                }
            }
            return escaped;
        }

    }  // namespace

    const char *to_string(const TraceSeverity severity) {
        switch (severity) {
            case TraceSeverity::kDanger:
                return "DANGER";
            case TraceSeverity::kWarning:
                return "WARNING";
        }
        return "WARNING";
    }

    std::string encode_snapshot(const Snapshot &snapshot) {
        std::ostringstream output;
        output << "AVAILABLE=" << (snapshot.available ? '1' : '0') << '\n';
        for (const auto &[key, value]: snapshot.native_properties) {
            output << "PROP=" << key << "|" << escape_value(value) << '\n';
        }
        for (const RuntimeTrace &trace: snapshot.runtime_traces) {
            output << "TRACE="
                   << to_string(trace.severity) << '\t'
                   << trace.label << '\t'
                   << escape_value(trace.detail)
                   << '\n';
        }
        return output.str();
    }

}  // namespace duckdetector::playintegrityfix
