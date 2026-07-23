//
// IotcClient.hpp — public API for the clean-room TUTK LAN-direct transport.
//
// Single source of truth for the handshake + AV entry points implemented in
// IotcClient.cpp. Consumed by OssTutkCameraSource (the full plugin's camera
// source) and tools/tutk_lan_probe.
//
// Flow: iotc_connect() (UDP + LAN_SEARCH3 + DTLS-PSK) → oss_av_start()
// (avClientStartEx + AV LOGIN + IPCAM_START) → avRecvFrameData2() to pull one
// reassembled H.264 Annex-B frame at a time.

#pragma once

#include "IotcProtocol.hpp"   // TutkRegion

#include <cstdint>
#include <string>

namespace bambu_net {
namespace oss_tutk {

struct OssSession;  // opaque; owned by iotc_connect / iotc_close

// UDP socket + LAN_SEARCH3 broadcast + DTLS-PSK handshake.
// authkey: first up-to-8 bytes of the URL authkey string, little-endian.
// Returns a new session on success, nullptr on failure (caller never frees).
OssSession* iotc_connect(const std::string& uid, uint64_t authkey,
                         const std::string& password, TutkRegion region);

// Close the session, stop keepalives, free it.
void iotc_close(OssSession* sess);

// avClientStartEx + 570-byte AV LOGIN + IPCAM_START.
// Returns the av_index (>= 0) or a negative error code.
int  oss_av_start(OssSession* sess, int channel,
                  const char* account, const char* password);

} // namespace oss_tutk
} // namespace bambu_net

// Pull ONE reassembled H.264 frame (Annex-B) and drive the RUDP ack/retransmit.
// Returns >=0 (bytes/status), or a negative AV error (AV_ER_TIMEOUT -20012 and
// AV_ER_INCOMPLETE_FRAME -20014 are non-fatal; other negatives end the stream).
extern "C" int avRecvFrameData2(int av_index, char* video_buf, int buf_size,
                                int* actual, int* frame_count, char* ioctrl_buf,
                                int ioctrl_size, unsigned int* timestamp,
                                int* ioctrl_count);

// Stop the AV channel opened by oss_av_start.
extern "C" void avClientStop(int av_index);
