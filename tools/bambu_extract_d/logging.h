#pragma once
#include <time.h>
#include <cstdio>

extern bool g_verbose;
extern double g_t0;

inline double now_s() {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

#define LOGF(prefix, fmt, ...) do { \
    std::fprintf(stderr, "[%6.2fs] %s " fmt "\n", now_s() - g_t0, prefix, ##__VA_ARGS__); \
} while (0)
#define LOG_I(fmt, ...) LOGF("[ info]", fmt, ##__VA_ARGS__)
#define LOG_W(fmt, ...) LOGF("[ warn]", fmt, ##__VA_ARGS__)
#define LOG_E(fmt, ...) LOGF("[ err ]", fmt, ##__VA_ARGS__)
#define LOG_V(fmt, ...) do { if (g_verbose) LOGF("[trap ]", fmt, ##__VA_ARGS__); } while (0)
