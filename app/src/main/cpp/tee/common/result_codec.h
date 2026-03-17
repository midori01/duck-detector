#ifndef DUCKDETECTOR_TEE_COMMON_RESULT_CODEC_H
#define DUCKDETECTOR_TEE_COMMON_RESULT_CODEC_H

#include <string>
#include <string_view>
#include <vector>

namespace ducktee::common {

    class ResultCodec {
    public:
        void put(std::string_view key, std::string_view value);

        void put_bool(std::string_view key, bool value);

        void put_int(std::string_view key, long value);

        void put_many(std::string_view key, const std::vector<std::string> &values);

        [[nodiscard]] std::string str() const;

    private:
        std::string buffer_;
    };

}  // namespace ducktee::common

#endif  // DUCKDETECTOR_TEE_COMMON_RESULT_CODEC_H
