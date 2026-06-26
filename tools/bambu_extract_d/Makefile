CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -DUSE_SECCOMP_UNOTIFY
LDFLAGS  ?= -lpthread -ldl -lssl -lcrypto -lz

SRCS = bambu_extract_d.cpp \
       vendored/BigIntModExp.cpp \
       vendored/mqtt_mini_broker.cpp

.PHONY: all clean

all: bambu_extract_d

bambu_extract_d: $(SRCS)
	$(CXX) $(CXXFLAGS) -o $@ $(SRCS) $(LDFLAGS)

clean:
	rm -f bambu_extract_d
