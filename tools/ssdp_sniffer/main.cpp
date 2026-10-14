// Standalone SSDP sniffer: binds to UDP :2021 and prints every Bambu-looking
// JSON it builds from the incoming packets. Meant as a quick-feedback tool
// while developing the parser; also doubles as a sanity check in CI when an
// env-provided dummy broadcaster is available.

#include "obn/ssdp.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <thread>

int main(int argc, char** argv)
{
    int port          = 2021;
    int seconds       = 15;
    if (argc > 1) seconds = std::atoi(argv[1]);
    if (argc > 2) port    = std::atoi(argv[2]);

    obn::ssdp::Discovery d;
    std::atomic<int>     count{0};
    std::mutex           stdout_mu;

    if (!d.start(port, [&](std::string json) {
            std::lock_guard<std::mutex> lk(stdout_mu);
            std::printf("[ssdp] %s\n", json.c_str());
            ++count;
        }))
    {
        std::fprintf(stderr, "ssdp start on :%d failed\n", port);
        return 1;
    }

    std::this_thread::sleep_for(std::chrono::seconds(seconds));
    d.stop();
    std::printf("received %d printer advertisements in %ds on :%d\n",
                count.load(), seconds, port);
    return count.load() > 0 ? 0 : 2;
}
