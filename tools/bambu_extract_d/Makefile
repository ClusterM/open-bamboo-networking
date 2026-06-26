# Build the bambu_extract_d self-contained binary.
#
# Prerequisites:
#   apt install build-essential cmake ninja-build libssl-dev libcurl4-openssl-dev \
#               libboost-log-dev zlib1g-dev
#
# All embed headers are built from source automatically.  Build everything with:
#   make

CXX      ?= g++
CC       ?= gcc
CXXFLAGS ?= -std=c++17 -O2 -DUSE_SECCOMP_UNOTIFY -Wall -Wextra
LDFLAGS  ?= -lpthread -ldl -lssl -lcrypto -lz

SRCS = main.cpp \
       version.cpp \
       bigint.cpp \
       envelope.cpp \
       capture.cpp \
       fake_broker.cpp \
       reconstruct.cpp \
       output.cpp \
       daemon.cpp \
       vendored/BigIntModExp.cpp \
       vendored/mqtt_mini_broker.cpp

EMBED_HEADERS = daemon_embed.h connect_redirect_embed.h watchdog_defeat_embed.h

HEADERS = logging.h \
          version.h \
          bigint.h \
          envelope.h \
          capture.h \
          reconstruct.h \
          output.h \
          fake_broker.h \
          daemon.h

.PHONY: all clean

all: bambu_extract_d

bambu_extract_d: $(SRCS) $(EMBED_HEADERS) $(HEADERS)
	$(CXX) $(CXXFLAGS) -o $@ $(SRCS) $(LDFLAGS)

# connect_redirect.so is built from source in this repo.
build/connect_redirect.so: connect_redirect.c | build
	$(CC) -shared -fPIC -O2 -nostartfiles -o $@ $< -ldl -lssl

connect_redirect_embed.h: build/connect_redirect.so
	xxd -i $< \
	  | sed 's/^unsigned char build_connect_redirect_so/static unsigned char connect_redirect_embed_so/' \
	  | sed 's/^unsigned int  *build_connect_redirect_so_len/static unsigned int  connect_redirect_embed_so_len/' \
	  > $@

build/daemon/bambu-daemon: daemon/CMakeLists.txt | build
	cmake -S daemon -B build/daemon -DCMAKE_BUILD_TYPE=Release \
	      -DCMAKE_EXE_LINKER_FLAGS="-Wl,--strip-all" -Wno-dev -G Ninja -DCMAKE_MAKE_PROGRAM=ninja
	cmake --build build/daemon --parallel

daemon_embed.h: build/daemon/bambu-daemon
	xxd -i $< \
	  | sed 's/^unsigned char build_daemon_bambu_daemon/static const unsigned char daemon_embed_bin/' \
	  | sed 's/^unsigned int  *build_daemon_bambu_daemon_len/static const size_t daemon_embed_bin_len/' \
	  > $@

build/watchdog_defeat_v2.so: shims/watchdog_defeat_v2.c | build
	$(CC) -shared -fPIC -O2 -o $@ $< -ldl -pthread

watchdog_defeat_embed.h: build/watchdog_defeat_v2.so
	xxd -i $< \
	  | sed 's/^unsigned char build_watchdog_defeat_v2_so/static unsigned char watchdog_defeat_embed_so/' \
	  | sed 's/^unsigned int  *build_watchdog_defeat_v2_so_len/static unsigned int  watchdog_defeat_embed_so_len/' \
	  > $@

build:
	mkdir -p build

clean:
	rm -f bambu_extract_d
	rm -rf build
	rm -f connect_redirect_embed.h daemon_embed.h watchdog_defeat_embed.h
