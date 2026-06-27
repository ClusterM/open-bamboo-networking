#ifndef SLIC3R_BAMBU_BRIDGE_HEADLESS_SIGNAL_HANDLER_HPP
#define SLIC3R_BAMBU_BRIDGE_HEADLESS_SIGNAL_HANDLER_HPP

#ifdef _WIN32
#  error "phase 10 SignalHandler is Linux-only for now"
#endif

#include <functional>

namespace Slic3r {
namespace bambu {
namespace headless {

class SignalHandler {
public:

    explicit SignalHandler(std::function<void()> on_signal);

    ~SignalHandler();

    SignalHandler(const SignalHandler&)            = delete;
    SignalHandler& operator=(const SignalHandler&) = delete;
};

}
}
}

#endif
