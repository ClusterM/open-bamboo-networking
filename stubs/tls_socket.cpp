#include "tls_socket.hpp"

#include "source_log.hpp"

namespace {
struct SourceErrorSink {
    SourceErrorSink()
    {
        obn::tls::set_last_error_sink(
            [](const char* msg) { obn::source::set_last_error(msg); });
    }
};
SourceErrorSink g_source_error_sink;
} // namespace
