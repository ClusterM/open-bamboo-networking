//
// tutk_lan_probe — exercise the OSS TUTK LAN-direct pipeline against a real
// printer and report how far the handshake gets.
//
// It reuses the (otherwise-unwired) LAN-direct path in IotcClient.cpp:
//   iotc_connect()  — UDP socket + LAN_SEARCH3 broadcast + DTLS-PSK handshake
//   oss_av_start()  — avClientStartEx + AV LOGIN + IPCAM_START
//   avRecvFrameData2() — pull one H.264 frame at a time
//
// Usage:
//   tutk_lan_probe '<bambu:///tutk?...>'   [seconds]
//   tutk_lan_probe --uid UID --passwd PW [--authkey K] [--region us] [seconds]
//
// Read-only: performs only camera operations, emits no print commands.

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <chrono>
#include <thread>
#include <vector>

namespace bambu_net {
namespace oss_tutk {

enum class TutkRegion : int { Global = 0, CN = 1, EU = 2, US = 3, Asia = 4 };

struct OssSession;  // opaque

OssSession* iotc_connect(const std::string& uid, uint64_t authkey,
                         const std::string& password, TutkRegion region);
void iotc_close(OssSession* sess);
int  oss_av_start(OssSession* sess, int channel,
                  const char* account, const char* password);

} // namespace oss_tutk
} // namespace bambu_net

extern "C" int avRecvFrameData2(int av_index, char* video_buf, int buf_size,
                                int* actual, int* frame_count, char* ioctrl_buf,
                                int ioctrl_size, unsigned int* timestamp,
                                int* ioctrl_count);
extern "C" void avClientStop(int av_index);

using namespace bambu_net::oss_tutk;

static std::string url_param(const std::string& q, const std::string& key)
{
    size_t pos = 0;
    while (pos <= q.size()) {
        size_t amp = q.find('&', pos);
        size_t end = (amp == std::string::npos) ? q.size() : amp;
        size_t eq = q.find('=', pos);
        if (eq != std::string::npos && eq < end &&
            eq - pos == key.size() && q.compare(pos, key.size(), key) == 0)
            return q.substr(eq + 1, end - eq - 1);
        if (amp == std::string::npos) break;
        pos = amp + 1;
    }
    return {};
}

static uint64_t authkey_to_u64(const std::string& s)
{
    // First up-to-8 bytes of the authkey string, little-endian null-padded
    // (matches IotcConnectCfg { authkey_lo, authkey_hi }).
    uint64_t v = 0;
    for (size_t i = 0; i < s.size() && i < 8; ++i)
        v |= (uint64_t)(uint8_t)s[i] << (8 * i);
    return v;
}

int main(int argc, char** argv)
{
    std::string uid, passwd, authkey, region = "us";
    int seconds = 20;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a.rfind("bambu://", 0) == 0) {
            auto q = a.find('?');
            std::string query = (q == std::string::npos) ? "" : a.substr(q + 1);
            uid     = url_param(query, "uid");
            authkey = url_param(query, "authkey");
            passwd  = url_param(query, "passwd");
            if (passwd.empty()) passwd = url_param(query, "key");
            std::string r = url_param(query, "region");
            if (!r.empty()) region = r;
        } else if (a == "--uid"     && i + 1 < argc) uid = argv[++i];
        else if (a == "--passwd"    && i + 1 < argc) passwd = argv[++i];
        else if (a == "--authkey"   && i + 1 < argc) authkey = argv[++i];
        else if (a == "--region"    && i + 1 < argc) region = argv[++i];
        else { char* end = nullptr; long v = strtol(a.c_str(), &end, 10);
               if (end && *end == '\0') seconds = (int)v; }
    }

    for (char& c : uid) if (c >= 'a' && c <= 'z') c -= 0x20;

    if (uid.size() != 20 || passwd.empty()) {
        fprintf(stderr, "usage: tutk_lan_probe '<bambu:///tutk?...>' [seconds]\n"
                        "       tutk_lan_probe --uid UID --passwd PW "
                        "[--authkey K] [--region us] [seconds]\n"
                        "(need 20-char uid and a passwd)\n");
        return 2;
    }

    TutkRegion reg = TutkRegion::US;
    if (region == "cn") reg = TutkRegion::CN;
    else if (region == "eu") reg = TutkRegion::EU;
    else if (region == "asia") reg = TutkRegion::Asia;

    printf("[probe] uid=%s region=%s authkey=%s passwd=%zuB\n",
           uid.c_str(), region.c_str(),
           authkey.empty() ? "(none)" : "set", passwd.size());
    printf("[probe] --- iotc_connect (LAN search + DTLS-PSK) ---\n");

    OssSession* sess = iotc_connect(uid, authkey_to_u64(authkey), passwd, reg);
    if (!sess) {
        printf("[probe] RESULT: iotc_connect FAILED (no LAN session / DTLS)\n");
        return 1;
    }
    printf("[probe] iotc_connect OK — LAN-direct session + DTLS established\n");

    printf("[probe] --- oss_av_start (avClientStartEx + LOGIN + IPCAM_START) ---\n");
    int av = oss_av_start(sess, 0, "admin", passwd.c_str());
    if (av < 0) {
        printf("[probe] RESULT: oss_av_start FAILED rc=%d "
               "(DTLS ok, AV login/start not)\n", av);
        iotc_close(sess);
        return 1;
    }
    printf("[probe] oss_av_start OK av_index=%d — pulling frames for %ds\n",
           av, seconds);

    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::seconds(seconds);
    long frames = 0, keyframes = 0, bytes = 0, timeouts = 0;
    bool saw_sps = false, saw_pps = false;
    unsigned first_w = 0, first_h = 0;

    FILE* dump = nullptr;
    if (const char* dp = getenv("OBN_TUTK_DUMP")) {
        dump = fopen(dp, "wb");
        if (dump) printf("[probe] dumping H.264 frames to %s\n", dp);
    }

    std::vector<char> buf(1u << 20);
    while (std::chrono::steady_clock::now() < deadline) {
        int actual = 0, fcount = 0, ioc = 0; unsigned ts = 0;
        int rc = avRecvFrameData2(av, buf.data(), (int)buf.size(),
                                  &actual, &fcount, nullptr, 0, &ts, &ioc);
        if (rc == -20012 /*AV_ER_TIMEOUT*/) { timeouts++; continue; }
        if (rc < 0 && rc != -20014 /*INCOMPLETE*/) {
            printf("[probe] avRecvFrameData2 rc=%d — stream ended\n", rc);
            break;
        }
        if (actual <= 0) continue;
        frames++;
        bytes += actual;
        if (dump) fwrite(buf.data(), 1, (size_t)actual, dump);
        // Scan Annex-B NAL types in this frame.
        const uint8_t* p = (const uint8_t*)buf.data();
        for (int i = 0; i + 4 < actual; ++i) {
            if (p[i] == 0 && p[i+1] == 0 && p[i+2] == 0 && p[i+3] == 1) {
                uint8_t nt = p[i+4] & 0x1f;
                if (nt == 7) { saw_sps = true; keyframes++; }
                else if (nt == 8) saw_pps = true;
                else if (nt == 5) keyframes++;
                i += 4;
            }
        }
        if (frames <= 3 || frames % 100 == 0)
            printf("[probe] frame %ld: %d bytes ts=%u\n", frames, actual, ts);
    }

    printf("\n[probe] ===== RESULT =====\n");
    printf("[probe] frames=%ld keyframes=%ld bytes=%ld timeouts=%ld\n",
           frames, keyframes, bytes, timeouts);
    printf("[probe] SPS=%s PPS=%s\n", saw_sps ? "yes" : "no",
           saw_pps ? "yes" : "no");
    printf("[probe] %s\n", frames > 0 ? "PULLED H.264 FRAMES" :
           "AV started but NO frames received");

    if (dump) fclose(dump);

    avClientStop(av);
    iotc_close(sess);
    return frames > 0 ? 0 : 1;
}
