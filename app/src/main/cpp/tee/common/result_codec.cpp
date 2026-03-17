#include "tee/common/result_codec.h"

namespace ducktee::common {

    void ResultCodec::put(std::string_view key, std::string_view value) {
        buffer_.append(key);
        buffer_.push_back('=');
        buffer_.append(value);
        buffer_.push_back('\n');
    }

    void ResultCodec::put_bool(std::string_view key, bool value) {
        put(key, value ? "1" : "0");
    }

    void ResultCodec::put_int(std::string_view key, long value) {
        put(key, std::to_string(value));
    }

    void ResultCodec::put_many(std::string_view key, const std::vector<std::string> &values) {
        for (const auto &value: values) {
            put(key, value);
        }
    }

    std::string ResultCodec::str() const {
        return buffer_;
    }

}  // namespace ducktee::common
