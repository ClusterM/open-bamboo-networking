// Wire-compliance test: runs the OSS library against the golden fixtures in
// tests/wire-fixtures/ and asserts that the HTTP it emits matches the genuine
// plugin's contract (method / path / query / header set+order / body shape).
//
// Self-contained: embeds a minimal HTTP mock of api.bambulab.com on a thread,
// points the OSS config at it, drives a flow's OSS entry points, then compares
// the recorded requests against the fixture's steps[].
//
//   ctest --test-dir build -R wire_ --output-on-failure
//   (each fixture is registered as its own test: wire_<flow>)
//
// Argv: <flow.json fixture path>

#include "obn/agent.hpp"
#include "obn/cloud_auth.hpp"
#include "obn/cloud_presets.hpp"
#include "obn/cloud_filament.hpp"
#include "obn/cert_store.hpp"
#include "obn/config.hpp"
#include "obn/ftps.hpp"
#include "obn/json_lite.hpp"
#include "obn/ssdp.hpp"
#include "obn/bambu_networking.hpp"

#include "lan_mocks.hpp"   // FtpsMock + MqttBrokerMock (printer LAN legs)

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cctype>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>
#include <libgen.h>
#include <cstring>
#include <fstream>
#include <map>
#include <mutex>
#include <regex>
#include <string>
#include <thread>
#include <vector>

// Exposed under OBN_TESTING (src/cloud_print.cpp) so we can assert the exact
// create_task body the OSS would build for the lan_file channel without needing
// a live printer for the LAN upload leg.
namespace obn { namespace cloud_print {
std::string test_build_task_body(const BBL::PrintParams& p,
                                 const std::string& project_id,
                                 const std::string& model_id,
                                 const std::string& profile_id,
                                 bool use_lan_channel);
} }

// Self-signed cert/key the LAN mocks present, generated fresh at startup by
// lanmock::make_self_signed() (see main). The OSS FTPS/MQTT clients accept it
// because the fixture sets lan_tls_skip_verify. The same cert seeds the
// printer's RSA pubkey (for url_enc) and its private half is the test slicer
// signing key, so cert and key are always a matched pair.
static std::string kMockCertPem;
static std::string kMockKeyPem;

// A stand-in slicer cert_id for the device-command signing test. The real
// plugin uses the account's cloud-registered id; the harness only needs the
// signature to VERIFY against the matching (test) public key, so any id works.
static const char* kTestCertId = "wirecompliance00000000000000000CN=test.bambulab.com";

// base64-decode (single line, no newlines) for the envelope's sign_string.
static std::string b64decode(const std::string& in) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* mem = BIO_push(b64, BIO_new_mem_buf(in.data(), (int)in.size()));
    std::string out(in.size(), '\0');
    int n = BIO_read(mem, &out[0], (int)out.size());
    BIO_free_all(mem);
    out.resize(n > 0 ? n : 0);
    return out;
}

// Verify an RSA-SHA256 (PKCS#1 v1.5) signature over `msg` using the public key
// inside the certificate PEM `cert_pem`.
static bool verify_rsa_sha256(const char* cert_pem, const std::string& msg,
                              const std::string& sig) {
    BIO* b = BIO_new_mem_buf(cert_pem, -1);
    X509* x = PEM_read_bio_X509(b, nullptr, nullptr, nullptr);
    BIO_free(b);
    if (!x) return false;
    EVP_PKEY* pk = X509_get_pubkey(x);
    X509_free(x);
    if (!pk) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool ok = ctx
        && EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pk) == 1
        && EVP_DigestVerify(ctx, (const unsigned char*)sig.data(), sig.size(),
                            (const unsigned char*)msg.data(), msg.size()) == 1;
    if (ctx) EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pk);
    return ok;
}

// ---------------------------------------------------------------------------
// Recorded request
// ---------------------------------------------------------------------------
struct Rec {
    std::string method, path, body;
    std::vector<std::pair<std::string,std::string>> headers;
    bool has(const char* n) const {
        for (auto& h : headers) if (::strcasecmp(h.first.c_str(), n) == 0) return true;
        return false;
    }
};

// ---------------------------------------------------------------------------
// Minimal embedded HTTP mock server (blocking, one request per connection).
// Records every request; returns just enough JSON for each OSS call to proceed.
// ---------------------------------------------------------------------------
class MockServer {
public:
    MockServer() {
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        int one = 1; ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
        ::bind(fd_, (sockaddr*)&a, sizeof a);
        socklen_t len = sizeof a; ::getsockname(fd_, (sockaddr*)&a, &len);
        port_ = ntohs(a.sin_port);
        ::listen(fd_, 16);
        // 200ms accept timeout so the loop can observe stop_.
        timeval tv{0, 200000}; ::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        th_ = std::thread([this]{ loop(); });
    }
    ~MockServer() { stop_ = true; if (th_.joinable()) th_.join(); if (fd_ >= 0) ::close(fd_); }
    int port() const { return port_; }
    std::vector<Rec> records() { std::lock_guard<std::mutex> lk(mu_); return recs_; }

private:
    void loop() {
        while (!stop_) {
            int c = ::accept(fd_, nullptr, nullptr);
            if (c < 0) continue;
            handle(c);
            ::close(c);
        }
    }
    static std::string read_line_hdr(int c, std::string& buf) {
        while (buf.find("\r\n\r\n") == std::string::npos) {
            char tmp[4096]; ssize_t n = ::recv(c, tmp, sizeof tmp, 0);
            if (n <= 0) break;
            buf.append(tmp, n);
        }
        return buf;
    }
    void handle(int c) {
        std::string buf; read_line_hdr(c, buf);
        auto hdr_end = buf.find("\r\n\r\n");
        if (hdr_end == std::string::npos) return;
        std::string head = buf.substr(0, hdr_end);
        std::string body = buf.substr(hdr_end + 4);

        Rec r;
        // request line
        auto nl = head.find("\r\n");
        std::string reqline = head.substr(0, nl);
        {
            auto sp1 = reqline.find(' '); auto sp2 = reqline.find(' ', sp1 + 1);
            r.method = reqline.substr(0, sp1);
            r.path   = reqline.substr(sp1 + 1, sp2 - sp1 - 1);
        }
        size_t content_length = 0;
        size_t pos = nl + 2;
        while (pos < head.size()) {
            auto e = head.find("\r\n", pos);
            if (e == std::string::npos) e = head.size();
            std::string line = head.substr(pos, e - pos);
            auto colon = line.find(':');
            if (colon != std::string::npos) {
                std::string k = line.substr(0, colon);
                std::string v = line.substr(colon + 1);
                while (!v.empty() && (v.front()==' '||v.front()=='\t')) v.erase(v.begin());
                r.headers.push_back({k, v});
                if (::strcasecmp(k.c_str(), "content-length") == 0) content_length = std::stoul(v);
            }
            pos = e + 2;
        }
        // read the rest of the body if needed
        while (body.size() < content_length) {
            char tmp[4096]; ssize_t n = ::recv(c, tmp, sizeof tmp, 0);
            if (n <= 0) break;
            body.append(tmp, n);
        }
        r.body = body.substr(0, content_length);
        { std::lock_guard<std::mutex> lk(mu_); recs_.push_back(r); }

        std::string resp = canned(r.method, r.path);
        std::string out =
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "
            + std::to_string(resp.size()) + "\r\n\r\n" + resp;
        ::send(c, out.data(), out.size(), 0);
    }
    // Enough JSON for each OSS parser to accept and proceed. Presigned upload
    // URLs point back at this mock so the S3 PUTs are recorded here too.
    std::string canned(const std::string& m, const std::string& path) {
        auto has = [&](const char* s){ return path.find(s) != std::string::npos; };
        std::string self = "http://127.0.0.1:" + std::to_string(port_);
        if (has("/user/ticket/"))
            return R"({"accessToken":"testtoken","refreshToken":"testrt","expiresIn":31536000,"refreshExpiresIn":31536000,"tfaKey":"","loginType":""})";
        if (has("/my/profile"))
            return R"({"uidStr":"1234567890","name":"Test User","nickname":"Tester","avatar":"","account":"t@example.com"})";
        if (has("/slicer/setting") && m == "POST")
            return R"({"message":"success","setting_id":"PPUStestcreate01","updated_time":"2026-07-14 12:00:00"})";
        if (has("/slicer/setting") && (m == "PATCH" || m == "DELETE"))
            return R"({"message":"success","updated_time":"2026-07-14 12:00:01"})";
        if (has("/slicer/setting") && m == "GET")
            return R"({"message":"success","print":{"private":[],"public":[]},"printer":{"private":[],"public":[]},"filament":{"private":[],"public":[]}})";
        if (has("/my/filament/v2") && m == "PUT")   return R"({"filamentV2":{}})";
        if (has("/my/filament/v2"))                 return R"({"hits":[],"total":0})";
        if (has("/filament/config"))                return R"({"categories":[],"filaments":[]})";
        if (has("/user/project") && m == "POST")
            return std::string(R"({"project_id":"900000001","profile_id":"800000001","model_id":"UStest01",)")
                 + R"("upload_url":")" + self + R"(/up_config","upload_ticket":"uploader_test"})";
        if (has("/user/upload"))
            return std::string(R"({"urls":[{"url":")") + self + R"(/up_main"}]})";
        if (has("/my/task") && m == "POST")         return R"({"id":"1000000001","message":"success"})";
        return R"({"message":"success"})";
    }

    int fd_{-1}, port_{0};
    std::thread th_;
    std::atomic<bool> stop_{false};
    std::mutex mu_;
    std::vector<Rec> recs_;
};

// ---------------------------------------------------------------------------
// Fixture (obn::json)
// ---------------------------------------------------------------------------
struct Step {
    std::string method, path, id;
    bool client_id{false}, content_type{false}, authorization{false};
    bool is_http{true};
    bool repeatable{false};
    bool body_builder{false};    // assert create_task body via test_build_task_body
    std::string channel_only;    // "", "cloud", "cloud_lan", ...
    obn::json::Value body;       // body_json (may be null)
    bool has_body{false};
    std::vector<std::string> id_order;  // identity_block order
};
struct Fixture {
    std::string flow, channel;
    std::vector<std::string> id_order;
    std::vector<Step> steps;
    obn::json::Value driver;     // "driver" block: PrintParams inputs for start_print
};

static bool load_fixture(const std::string& path, Fixture& fx, std::string& err) {
    std::ifstream in(path);
    if (!in) { err = "cannot open " + path; return false; }
    std::string txt((std::istreambuf_iterator<char>(in)), {});
    auto root = obn::json::parse(txt, &err);
    if (!root) return false;
    fx.flow    = root->find("meta").find("flow").as_string();
    fx.channel = root->find("meta").find("channel").as_string();
    fx.driver  = root->find("driver");   // copy (null for non-start_print flows)
    for (auto& h : root->find("identity_block").find("order").as_array())
        fx.id_order.push_back(h.as_string());
    for (auto& s : root->find("steps").as_array()) {
        Step st;
        std::string proto = s.find("protocol").as_string();
        st.is_http = (proto.empty() || proto == "http");
        st.repeatable = s.find("repeatable").as_bool();
        st.body_builder = s.find("body_builder").as_bool();
        st.channel_only = s.find("channel_only").as_string();
        st.id = s.find("id").as_string();
        auto req = s.find("request");
        st.method = req.find("method").as_string();
        st.path   = req.find("path").as_string();
        auto hd = req.find("headers");
        st.client_id     = hd.find("client_id").as_bool();
        st.content_type  = hd.find("content_type").as_bool();
        st.authorization = hd.find("authorization").as_bool();
        auto bj = req.find("body_json");
        if (!bj.is_null()) { st.body = bj; st.has_body = true; }
        st.id_order = fx.id_order;
        fx.steps.push_back(st);
    }
    return true;
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------
static std::regex path_regex(const std::string& tmpl) {
    std::string rx = "^";
    for (size_t i = 0; i < tmpl.size();) {
        if (tmpl.compare(i, 2, "{{") == 0) {
            auto e = tmpl.find("}}", i);
            rx += "[^/?]+"; i = e + 2;
        } else {
            char ch = tmpl[i++];
            if (std::strchr(".^$|()[]{}*+?\\", ch)) rx += '\\';
            rx += ch;
        }
    }
    rx += "$";
    return std::regex(rx);
}

static int g_fail = 0;
#define FAILF(...) do { std::fprintf(stderr, "  FAIL: " __VA_ARGS__); std::fprintf(stderr,"\n"); ++g_fail; } while(0)

// Check the identity-block X-BBL headers appear in the recorded request in the
// fixture's relative order (JA4H), and the CID/CT/Auth presence flags match.
static void check_headers(const Step& st, const Rec& r) {
    // relative order of identity headers that are present in the record
    int last = -1;
    for (size_t i = 0; i < st.id_order.size(); ++i) {
        const std::string& name = st.id_order[i];
        int idx = -1;
        for (size_t j = 0; j < r.headers.size(); ++j)
            if (::strcasecmp(r.headers[j].first.c_str(), name.c_str()) == 0) { idx = (int)j; break; }
        if (idx < 0) continue;
        if (idx < last)
            FAILF("[%s] header %s out of JA4H order", st.id.c_str(), name.c_str());
        last = idx;
    }
    if (st.client_id     != r.has("X-BBL-Client-ID"))
        FAILF("[%s] X-BBL-Client-ID presence: expected %d got %d", st.id.c_str(), st.client_id, r.has("X-BBL-Client-ID"));
    if (st.content_type  != r.has("Content-Type"))
        FAILF("[%s] Content-Type presence: expected %d got %d", st.id.c_str(), st.content_type, r.has("Content-Type"));
    if (st.authorization != r.has("Authorization"))
        FAILF("[%s] Authorization presence: expected %d got %d", st.id.c_str(), st.authorization, r.has("Authorization"));
}

// Structural body check: every literal leaf in the fixture must be present &
// equal in the recorded body. Objects and arrays recurse; numbers/bools compare
// by value; strings that are {{var}} or <...> placeholders require presence only.
static void check_value(const std::string& id, const obn::json::Value& exp,
                        const obn::json::Value& got, const std::string& where) {
    if (exp.is_object()) {
        if (!got.is_object()) { FAILF("[%s] body %s: expected object", id.c_str(), where.c_str()); return; }
        for (auto& kv : exp.as_object()) {
            const std::string& k = kv.first;
            const obn::json::Value& ev = kv.second;
            obn::json::Value gv = got.find(k);
            if (gv.is_null() && !ev.is_null()) { FAILF("[%s] body missing key %s%s", id.c_str(), where.c_str(), k.c_str()); continue; }
            check_value(id, ev, gv, where + k + ".");
        }
        return;
    }
    if (exp.is_array()) {
        if (!got.is_array()) { FAILF("[%s] body %s: expected array", id.c_str(), where.c_str()); return; }
        const auto& ea = exp.as_array();
        const auto& ga = got.as_array();
        if (ga.size() < ea.size())
            FAILF("[%s] body %s: array len expected >=%zu got %zu", id.c_str(), where.c_str(), ea.size(), ga.size());
        for (size_t i = 0; i < ea.size() && i < ga.size(); ++i)
            check_value(id, ea[i], ga[i], where + "[" + std::to_string(i) + "].");
        return;
    }
    if (exp.is_string()) {
        std::string es = exp.as_string();
        bool ph = es.find("{{") != std::string::npos ||
                  (es.size() >= 2 && es.front() == '<' && es.back() == '>');
        if (ph) return;                                             // placeholder: presence only
        // accept a fixture string matching either a recorded string or number
        if (es != got.as_string() && es != std::to_string((long long)got.as_number()))
            FAILF("[%s] body %s: expected '%s' got '%s'", id.c_str(), where.c_str(), es.c_str(), got.as_string().c_str());
        return;
    }
    if (exp.is_bool()) {
        if (exp.as_bool() != got.as_bool())
            FAILF("[%s] body %s: expected bool %d got %d", id.c_str(), where.c_str(), exp.as_bool(), got.as_bool());
        return;
    }
    if (exp.is_number()) {
        if (exp.as_number() != got.as_number())
            FAILF("[%s] body %s: expected %g got %g", id.c_str(), where.c_str(), exp.as_number(), got.as_number());
        return;
    }
    // exp.is_null(): nothing to assert
}
static void check_body_obj(const std::string& id, const obn::json::Value& exp,
                           const obn::json::Value& got, const std::string& where) {
    check_value(id, exp, got, where);
}

static void compare(const Fixture& fx, const std::vector<Rec>& recs) {
    // Expected http steps for this run: skip non-http, skip S3 <presigned>
    // uploads (host not api), skip channel_only that don't match, and treat
    // repeatable/absent per-id or poll GETs leniently (match if present).
    size_t ri = 0;
    for (const Step& st : fx.steps) {
        if (!st.is_http) continue;
        if (st.path.find("://") != std::string::npos || st.path.rfind("{{",0)==0) continue; // presigned PUT (path is a {{var}} url)
        if (!st.channel_only.empty() && st.channel_only != fx.channel) continue;
        std::regex rx = path_regex(st.path);
        // find the next recorded request matching method+path
        size_t found = std::string::npos;
        for (size_t j = ri; j < recs.size(); ++j) {
            std::string p = recs[j].path.substr(0, recs[j].path.find('?'));
            if (recs[j].method == st.method && std::regex_match(p, rx)) { found = j; break; }
        }
        if (found == std::string::npos) {
            // repeatable steps (per-id GET on an empty list, polls) may legitimately
            // occur zero times; a required step that is missing is a failure.
            if (!st.repeatable)
                FAILF("[%s] expected %s %s not emitted", st.id.c_str(), st.method.c_str(), st.path.c_str());
            continue;
        }
        const Rec& r = recs[found];
        check_headers(st, r);
        // body_builder steps (create_task) are asserted via test_build_task_body
        // in the driver so mode=lan_file is checked even though the HTTP run is
        // driven in cloud mode; skip the recorded-body check here.
        if (st.has_body && !st.body_builder && !r.body.empty()) {
            std::string perr; auto gb = obn::json::parse(r.body, &perr);
            if (!gb) FAILF("[%s] recorded body not JSON: %s", st.id.c_str(), perr.c_str());
            else check_body_obj(st.id, st.body, *gb, "");
        }
        ri = found + 1;
    }
}

// ---------------------------------------------------------------------------
// Drivers (per flow) — point OSS at the mock, run the entry points
// ---------------------------------------------------------------------------
static void seed_session(obn::Agent& a, const std::string& dir) {
    a.set_config_dir(dir);   // creates the on-disk auth store + reloads obn.conf (mock host)
    a.apply_login_info(
        R"({"data":{"token":"testtoken","refresh_token":"testrt","expires_in":"31536000","refresh_expires_in":"31536000","user":{"uid":"1234567890","name":"Test User"}}})");
}

static void drive_login() {
    auto res = obn::cloud::login_with_ticket("", "TESTTICKET");
    (void)obn::cloud::get_profile("", res.access_token.empty() ? "testtoken" : res.access_token);
}

static void drive_preset_write(obn::Agent& a) {
    std::map<std::string,std::string> vals = {
        {"base_id","GP124"}, {"type","print"}, {"version","2.7.0.2"},
        {"inherits","0.20mm Standard @BBL H2D"}, {"initial_layer_print_height","0.24"},
        {"print_extruder_id","1,1,2,2,2"},
        {"print_extruder_variant","\"Direct Drive Standard\";\"Direct Drive High Flow\""},
        {"print_settings_id","obn_write_test"}, {"updated_time","0"},
    };
    unsigned int http = 0;
    std::string id = obn::cloud_presets::create(&a, "obn_write_test", vals, &http);
    if (id.empty()) id = "PPUStestcreate01";
    vals["initial_layer_print_height"] = "0.28";
    obn::cloud_presets::update(&a, id, "obn_write_test", vals, &http);
    obn::cloud_presets::del(&a, id);
}

static void drive_preset_sync(obn::Agent& a) {
    std::vector<obn::cloud_presets::Meta> out;
    obn::cloud_presets::list(&a, "2.7.0.2", &out);
}

static void drive_filament(obn::Agent& a) {
    std::string body;
    obn::cloud_filament::config(&a, &body);                 // GET /filament/config
    BBL::FilamentQueryParams q{}; std::string lb;
    obn::cloud_filament::list(&a, q, &lb);                  // GET /my/filament/v2
    std::string put_body =
        R"({"color":"#001489","colors":["#001489"],"filamentName":"PETG Basic","id":1000001,"note":"obncap"})";
    std::string ub;
    obn::cloud_filament::update(&a, "1000001", put_body, &ub);  // PUT /my/filament/v2
}

// Populate a PrintParams from the fixture's "driver" block. Asset paths are
// resolved relative to the fixture directory.
static BBL::PrintParams params_from_driver(const obn::json::Value& d, const std::string& fxdir) {
    BBL::PrintParams p{};
    p.dev_id          = d.find("dev_id").as_string();
    p.project_name    = d.find("project_name").as_string();
    p.task_name       = p.project_name;
    p.filename        = fxdir + "/" + d.find("asset").as_string();
    p.config_filename = fxdir + "/" + d.find("config_asset").as_string();
    p.plate_index     = (int)d.find("plate_index").as_int();
    p.task_bed_type   = d.find("task_bed_type").as_string();
    p.ftp_file_md5    = d.find("ftp_file_md5").as_string();
    p.ams_mapping     = d.find("ams_mapping").as_string();
    p.ams_mapping2    = d.find("ams_mapping2").as_string();
    p.ams_mapping_info= d.find("ams_mapping_info").as_string();
    p.nozzles_info    = d.find("nozzles_info").as_string();
    p.task_use_ams        = d.find("task_use_ams").as_bool();
    p.task_record_timelapse = d.find("task_record_timelapse").as_bool();
    p.task_layer_inspect  = d.find("task_layer_inspect").as_bool();
    p.task_bed_leveling   = d.find("task_bed_leveling").as_bool();
    p.task_flow_cali      = d.find("task_flow_cali").as_bool();
    p.task_vibration_cali = d.find("task_vibration_cali").as_bool();
    p.auto_bed_leveling   = (int)d.find("auto_bed_leveling").as_int();
    p.auto_flow_cali      = (int)d.find("auto_flow_cali").as_int();
    p.auto_offset_cali    = (int)d.find("auto_offset_cali").as_int();
    p.extruder_cali_manual_mode = (int)d.find("extruder_cali_manual_mode").as_int();
    return p;
}

// Assert the exact create_task body the OSS builds for this flow's channel
// (lan_file for cloud_lan) against the create_task step's body_json, so the ams
// mapping / dual-nozzle / mode fields are checked precisely.
static void assert_task_body(const Fixture& fx, const BBL::PrintParams& p) {
    const Step* cs = nullptr;
    for (const auto& s : fx.steps) if (s.body_builder) { cs = &s; break; }
    if (!cs) return;
    bool lan = (fx.channel == "cloud_lan");
    std::string body = obn::cloud_print::test_build_task_body(p, "PID", "MID", "874668027", lan);
    std::string perr; auto bv = obn::json::parse(body, &perr);
    if (!bv) { FAILF("[%s] built task body not JSON: %s", cs->id.c_str(), perr.c_str()); return; }
    check_body_obj(cs->id, cs->body, *bv, "");
}

static void drive_start_print(obn::Agent& a, const Fixture& fx, const std::string& fxdir) {
    BBL::PrintParams p = params_from_driver(fx.driver, fxdir);
    // Drive the full HTTP pipeline in CLOUD mode (use_lan_channel=false): this
    // avoids the LAN-upload leg (which needs a live printer) while still emitting
    // the whole api.bambulab.com sequence, including the ftp-placeholder PATCH and
    // GET /my/setting (the OSS emits those unconditionally). The MQTT publish at
    // the end has no printer key and returns non-zero -- expected, we assert on
    // the recorded requests, not the return code.
    (void)a.run_cloud_print_job(p, nullptr, nullptr, /*use_lan_channel=*/false);
    // Assert the exact lan_file create_task body separately.
    assert_task_body(fx, p);
}

static std::string lower_hex(std::string s) {
    for (char& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

// Full lan_file end-to-end: drives run_cloud_print_job(use_lan_channel=true)
// against the HTTP mock PLUS a printer FTPS mock and MQTT broker mock (the two
// LAN legs). Asserts the create_task body, the FTPS STOR of the sliced 3mf, and
// the project_file MQTT publish.
static void drive_lan_start_print(obn::Agent& a, const Fixture& fx,
                                  const std::string& fxdir, const std::string& dir) {
    BBL::PrintParams p = params_from_driver(fx.driver, fxdir);
    p.dev_ip          = "127.0.0.1";
    p.username        = "bblp";
    p.password        = fx.driver.find("access_code").as_string();  // FTP/MQTT auth
    p.use_ssl_for_ftp = true;    // implicit FTPS, as the real printer
    p.try_emmc_print  = false;   // force the FTPS leg (not brtc :6000)

    // Write the mock TLS cert/key to disk for the FTPS mock, and seed the printer
    // RSA pubkey (same cert) so the url_enc step succeeds without an app_cert
    // round-trip (printer_supports_new_auth is false in-test).
    std::string crt = dir + "/mock.crt", key = dir + "/mock.key";
    { std::ofstream(crt) << kMockCertPem; std::ofstream(key) << kMockKeyPem; }
    obn::cert_store::set_printer_pub_key_from_cert_pem(p.dev_id, kMockCertPem);

    lanmock::FtpsMock      ftp(crt, key);
    lanmock::MqttBrokerMock mqtt;
    setenv("OBN_LAN_FTP_PORT",  std::to_string(ftp.port()).c_str(),  1);
    setenv("OBN_LAN_MQTT_PORT", std::to_string(mqtt.port()).c_str(), 1);

    // Bring up the LAN MQTT session (plain; port overridden to the mock broker).
    int rc = a.connect_printer(p.dev_id, "127.0.0.1", "bblp", p.password, /*use_ssl=*/false);
    std::fprintf(stderr, "connect_printer rc=%d (mqtt mock :%d)\n", rc, mqtt.port());
    for (int i = 0; i < 50 && !mqtt.got_connect(); ++i)   // wait for CONNACK
        std::this_thread::sleep_for(std::chrono::milliseconds(20));

    (void)a.run_cloud_print_job(p, nullptr, nullptr, /*use_lan_channel=*/true);
    assert_task_body(fx, p);   // create_task body (lan_file)

    // LAN leg 1: FTPS STOR of the print-ready 3mf.
    auto stors = ftp.stors();
    if (stors.empty()) {
        FAILF("[ftp] printer FTPS mock received no STOR");
    } else {
        const auto& s = stors[0];
        std::fprintf(stderr, "FTPS STOR path=%s bytes=%zu md5=%s\n",
                     s.path.c_str(), s.bytes, s.md5_hex.c_str());
        std::string want = lower_hex(fx.driver.find("ftp_file_md5").as_string());
        if (!want.empty() && s.md5_hex != want)
            FAILF("[ftp] STOR md5 mismatch: expected %s got %s", want.c_str(), s.md5_hex.c_str());
        if (s.bytes == 0) FAILF("[ftp] STOR uploaded 0 bytes");
    }

    // LAN leg 2: project_file MQTT publish to device/<serial>/request. The
    // publish is qos=0 and the mock records it on its reader thread, so poll
    // briefly instead of racing a single immediate check.
    std::string want_topic = "device/" + p.dev_id + "/request";
    bool found = false;
    for (int attempt = 0; attempt < 50 && !found; ++attempt) {
        for (const auto& pub : mqtt.pubs()) {
            if (pub.topic != want_topic) continue;
            std::string perr; auto v = obn::json::parse(pub.payload, &perr);
            if (!v) continue;
            if (v->find("print").find("command").as_string() != "project_file") continue;
            found = true;
            std::fprintf(stderr, "MQTT project_file on %s (%zu bytes)\n",
                         pub.topic.c_str(), pub.payload.size());
            // LAN channel publishes the cleartext local fetch url (ftp://…); it
            // is NOT the encrypted cloud url_enc (that is the cloud-channel path).
            std::string url = v->find("print").find("url").as_string();
            if (url.rfind("ftp://", 0) != 0)
                FAILF("[mqtt] project_file url expected ftp://… got '%s'", url.c_str());
        }
        if (!found) std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (!found)
        FAILF("[mqtt] no project_file publish to %s", want_topic.c_str());

    a.disconnect_printer();
}

// Pure-LAN print (bambu_network_start_local_print -> run_local_print_job): no
// cloud pipeline at all -- just the FTPS STOR upload + the MQTT project_file
// publish over the LAN session. channel=lan. No create_task / api.bambulab.com.
static void drive_lan_only_print(obn::Agent& a, const Fixture& fx,
                                 const std::string& fxdir, const std::string& dir) {
    BBL::PrintParams p = params_from_driver(fx.driver, fxdir);
    p.dev_ip          = "127.0.0.1";
    p.username        = "bblp";
    p.password        = fx.driver.find("access_code").as_string();
    p.use_ssl_for_ftp = true;    // implicit FTPS, as the real printer
    p.try_emmc_print  = false;   // force the FTPS leg (not brtc :6000)

    std::string crt = dir + "/mock.crt", key = dir + "/mock.key";
    { std::ofstream(crt) << kMockCertPem; std::ofstream(key) << kMockKeyPem; }

    lanmock::FtpsMock      ftp(crt, key);
    lanmock::MqttBrokerMock mqtt;
    setenv("OBN_LAN_FTP_PORT",  std::to_string(ftp.port()).c_str(),  1);
    setenv("OBN_LAN_MQTT_PORT", std::to_string(mqtt.port()).c_str(), 1);

    // Bring up the LAN MQTT session (plain; port overridden to the mock broker).
    int rc = a.connect_printer(p.dev_id, "127.0.0.1", "bblp", p.password, /*use_ssl=*/false);
    std::fprintf(stderr, "connect_printer rc=%d (mqtt mock :%d)\n", rc, mqtt.port());
    for (int i = 0; i < 50 && !mqtt.got_connect(); ++i)   // wait for CONNACK
        std::this_thread::sleep_for(std::chrono::milliseconds(20));

    // Pure LAN: upload + publish, no cloud pipeline / create_task.
    (void)a.run_local_print_job(p, nullptr, nullptr);

    // LAN leg 1: FTPS STOR of the print-ready 3mf.
    auto stors = ftp.stors();
    if (stors.empty()) {
        FAILF("[ftp] printer FTPS mock received no STOR");
    } else {
        const auto& s = stors[0];
        std::fprintf(stderr, "FTPS STOR path=%s bytes=%zu md5=%s\n",
                     s.path.c_str(), s.bytes, s.md5_hex.c_str());
        std::string want = lower_hex(fx.driver.find("ftp_file_md5").as_string());
        if (!want.empty() && s.md5_hex != want)
            FAILF("[ftp] STOR md5 mismatch: expected %s got %s", want.c_str(), s.md5_hex.c_str());
        if (s.bytes == 0) FAILF("[ftp] STOR uploaded 0 bytes");
    }

    // LAN leg 2: project_file MQTT publish to device/<serial>/request (ftp:// url).
    std::string want_topic = "device/" + p.dev_id + "/request";
    bool found = false;
    for (int attempt = 0; attempt < 50 && !found; ++attempt) {
        for (const auto& pub : mqtt.pubs()) {
            if (pub.topic != want_topic) continue;
            std::string perr; auto v = obn::json::parse(pub.payload, &perr);
            if (!v) continue;
            if (v->find("print").find("command").as_string() != "project_file") continue;
            found = true;
            std::fprintf(stderr, "MQTT project_file on %s (%zu bytes)\n",
                         pub.topic.c_str(), pub.payload.size());
            std::string url = v->find("print").find("url").as_string();
            if (url.rfind("ftp://", 0) != 0)
                FAILF("[mqtt] project_file url expected ftp://… got '%s'", url.c_str());
        }
        if (!found) std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    if (!found)
        FAILF("[mqtt] no project_file publish to %s", want_topic.c_str());

    a.disconnect_printer();
}

// Drive a single device-control command (light / drying / bed_temp / chamber_temp
// / filament_setting) through the OSS and assert what it publishes to
// device/<dev>/request against a mock broker. For a "print"-envelope command the
// OSS RSA-SHA256 signs the sorted print body with the slicer key; the harness
// verifies that signature against the (test) slicer public key and checks the
// carried print body -- i.e. it validates maybe_sign end-to-end without a printer.
// A non-"print" command (ledctrl) must be published verbatim.
static void drive_device_command(obn::Agent& a, const Fixture& fx, const std::string& dir) {
    // Configure the (test) slicer signing key so maybe_sign engages.
    { std::ofstream(dir + "/slicer_key.pem")     << kMockKeyPem;
      std::ofstream(dir + "/slicer_cert_id.txt") << kTestCertId; }

    std::string dev  = fx.driver.find("dev_id").as_string();
    std::string code = fx.driver.find("access_code").as_string();
    std::string cmd  = fx.driver.find("command_json").as_string();
    bool signed_exp  = fx.driver.find("signed").as_bool();

    lanmock::MqttBrokerMock mqtt;
    setenv("OBN_LAN_MQTT_PORT", std::to_string(mqtt.port()).c_str(), 1);

    int rc = a.connect_printer(dev, "127.0.0.1", "bblp", code, /*use_ssl=*/false);
    std::fprintf(stderr, "connect_printer rc=%d (mqtt mock :%d)\n", rc, mqtt.port());
    for (int i = 0; i < 50 && !mqtt.got_connect(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(20));

    (void)a.send_message_to_printer(dev, cmd, /*qos=*/1);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    a.disconnect_printer();

    std::string topic = "device/" + dev + "/request";
    auto pubs = mqtt.pubs();   // keep the copy alive (pubs() returns by value)
    const lanmock::MqttBrokerMock::Pub* got = nullptr;
    for (const auto& p : pubs)
        if (p.topic == topic) { got = &p; break; }
    if (!got) { FAILF("[device_command] no publish to %s", topic.c_str()); return; }

    std::string perr; auto pub = obn::json::parse(got->payload, &perr);
    if (!pub) { FAILF("[device_command] published payload not JSON: %s", perr.c_str()); return; }

    if (!signed_exp) {
        // Non-print command: must be forwarded byte-for-byte (structural check).
        auto want = obn::json::parse(cmd, &perr);
        if (want) check_body_obj("device_command", *want, *pub, "");
        if (!pub->find("header").is_null())
            FAILF("[device_command] unsigned command was wrapped in a signed envelope");
        return;
    }

    // Signed command: expect {"header":{cert_id,sign_alg,sign_string,...},"print":{...}}.
    auto hdr = pub->find("header");
    if (hdr.is_null()) { FAILF("[device_command] signed command missing header envelope"); return; }
    if (hdr.find("cert_id").as_string() != kTestCertId)
        FAILF("[device_command] cert_id mismatch: got '%s'", hdr.find("cert_id").as_string().c_str());
    if (hdr.find("sign_alg").as_string() != "RSA_SHA256")
        FAILF("[device_command] sign_alg expected RSA_SHA256 got '%s'", hdr.find("sign_alg").as_string().c_str());

    // Reconstruct the signed string exactly as build_to_sign does: {"print":<sorted dump>}.
    std::string to_sign = "{\"print\":" + pub->find("print").dump() + "}";
    std::string sig = b64decode(hdr.find("sign_string").as_string());
    if (sig.empty())
        FAILF("[device_command] empty/undecodable sign_string");
    else if (!verify_rsa_sha256(kMockCertPem.c_str(), to_sign, sig))
        FAILF("[device_command] signature does NOT verify against the slicer public key");
    else
        std::fprintf(stderr, "signature verified over %zu bytes; command '%s'\n",
                     to_sign.size(), pub->find("print").find("command").as_string().c_str());

    // The signed print body must carry the caller's command unchanged.
    auto want = obn::json::parse(cmd, &perr);
    if (want) check_body_obj("device_command", want->find("print"), pub->find("print"), "print.");
}

// List printer storage over FTPS through the OSS's real FTPS client
// (obn::ftps::Client::list_entries — the same code the libBambuSource CTRL
// bridge / Device->Storage tab uses when force_ftps is on). Drives it against
// FtpsMock and asserts the parsed file entries (name + size).
static void drive_storage_list(const Fixture& fx, const std::string& dir) {
    std::string crt = dir + "/mock.crt", key = dir + "/mock.key";
    { std::ofstream(crt) << kMockCertPem; std::ofstream(key) << kMockKeyPem; }

    lanmock::FtpsMock ftp(crt, key);
    std::string listing = fx.driver.find("listing").as_string();
    if (!listing.empty()) ftp.set_listing(listing);

    obn::ftps::ConnectConfig cfg;
    cfg.host     = "127.0.0.1";
    cfg.port     = ftp.port();
    cfg.username = "bblp";
    cfg.password = fx.driver.find("access_code").as_string();
    cfg.use_tls  = true;   // implicit FTPS; lan_tls_skip_verify accepts the mock cert

    obn::ftps::Client cli;
    if (std::string e = cli.connect(cfg); !e.empty()) { FAILF("[storage_list] connect: %s", e.c_str()); return; }

    std::vector<obn::ftps::Entry> entries;
    if (std::string e = cli.list_entries("/", &entries); !e.empty()) {
        FAILF("[storage_list] list_entries: %s", e.c_str()); return;
    }
    std::fprintf(stderr, "storage LIST parsed %zu entries; mock served %d LIST(s)\n",
                 entries.size(), ftp.list_count());
    if (ftp.list_count() < 1) FAILF("[storage_list] mock received no LIST command");

    for (const auto& want : fx.driver.find("expect_files").as_array()) {
        std::string wname = want.find("name").as_string();
        long long   wsize = (long long)want.find("size").as_number();
        const obn::ftps::Entry* got = nullptr;
        for (const auto& e : entries) if (e.name == wname) { got = &e; break; }
        if (!got) { FAILF("[storage_list] expected file '%s' not in listing", wname.c_str()); continue; }
        if ((long long)got->size != wsize)
            FAILF("[storage_list] '%s' size expected %lld got %llu",
                  wname.c_str(), wsize, (unsigned long long)got->size);
    }
}

// ---------------------------------------------------------------------------
// Full libBambuSource CTRL-channel storage listing. This exercises the real
// shipped Bambu_* ABI end to end: Bambu_Open dials the printer's native :6000
// TLS tunnel, Bambu_StartStreamEx(0x3001) runs the BambuTunnelLocal handshake,
// then a LIST_INFO CTRL request is served over FTPS (force_ftps bridge) and the
// {reply:{file_lists}} envelope comes back through Bambu_ReadSample.
//
//   NativeTunnelMock  -> answers the :6000 login/setup handshake
//   FtpsMock          -> serves the LIST once the bridge dispatches it
static void drive_ctrl_storage_list(const Fixture& fx, const std::string& dir) {
#ifndef OBN_BAMBUSOURCE_SO
    std::fprintf(stderr, "  SKIP: OBN_BAMBUSOURCE_SO not defined\n");
    g_fail = 0; std::exit(77);
#else
    struct BSample { int itrack; int size; int flags;
                     const unsigned char* buffer; unsigned long long decode_time; };
    constexpr int kCtrlType = 0x3001;
    constexpr int kWouldBlock = 2;

    void* so = dlopen(OBN_BAMBUSOURCE_SO, RTLD_NOW | RTLD_LOCAL);
    if (!so) { FAILF("[ctrl_storage_list] dlopen: %s", dlerror()); return; }
    auto sym = [&](const char* n) { void* p = dlsym(so, n);
        if (!p) FAILF("[ctrl_storage_list] dlsym %s: %s", n, dlerror()); return p; };
    auto p_init    = (int (*)())sym("Bambu_Init");
    auto p_deinit  = (void (*)())sym("Bambu_Deinit");
    auto p_create  = (int (*)(void**, const char*))sym("Bambu_Create");
    auto p_open    = (int (*)(void*))sym("Bambu_Open");
    auto p_startex = (int (*)(void*, int))sym("Bambu_StartStreamEx");
    auto p_send    = (int (*)(void*, int, const char*, int))sym("Bambu_SendMessage");
    auto p_read    = (int (*)(void*, BSample*))sym("Bambu_ReadSample");
    auto p_close   = (void (*)(void*))sym("Bambu_Close");
    auto p_destroy = (void (*)(void*))sym("Bambu_Destroy");
    if (g_fail) return;

    std::string crt = dir + "/mock.crt", key = dir + "/mock.key";
    { std::ofstream(crt) << kMockCertPem; std::ofstream(key) << kMockKeyPem; }

    lanmock::NativeTunnelMock tun(crt, key);   // :6000 handshake endpoint
    lanmock::FtpsMock         ftp(crt, key);   // FTPS LIST endpoint
    std::string listing = fx.driver.find("listing").as_string();
    if (!listing.empty()) ftp.set_listing(listing);

    // The bridge picks these up from the environment (same process as the .so).
    setenv("OBN_FORCE_FTPS", "1", 1);
    setenv("OBN_SKIP_TLS_VERIFY", "1", 1);
    setenv("OBN_LAN_FTP_PORT", std::to_string(ftp.port()).c_str(), 1);

    std::string code   = fx.driver.find("access_code").as_string();
    std::string serial = fx.driver.find("dev_id").as_string();
    std::string url = "bambu:///local/127.0.0.1?port=" + std::to_string(tun.port()) +
                      "&user=bblp&passwd=" + code + "&device=" + serial;

    p_init();
    void* t = nullptr;
    if (p_create(&t, url.c_str()) != 0 || !t) { FAILF("[ctrl_storage_list] Bambu_Create failed"); return; }
    if (p_open(t) != 0) { FAILF("[ctrl_storage_list] Bambu_Open (:6000 dial) failed"); p_destroy(t); return; }

    // StartStreamEx is polled: would_block between handshake steps.
    int rc = kWouldBlock;
    for (int i = 0; i < 400 && rc == kWouldBlock; ++i) {
        rc = p_startex(t, kCtrlType);
        if (rc == kWouldBlock) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (rc != 0) { FAILF("[ctrl_storage_list] StartStreamEx handshake rc=%d", rc); p_close(t); p_destroy(t); return; }
    if (!tun.handshake_ok()) FAILF("[ctrl_storage_list] :6000 handshake never completed on the mock");

    // LIST_INFO for the External (models) tab. type/storage live under `req`.
    std::string req = "{\"cmdtype\":1,\"sequence\":1,"
                      "\"req\":{\"type\":\"model\",\"storage\":\"\"}}";
    if (p_send(t, kCtrlType, req.data(), (int)req.size()) != 0)
        FAILF("[ctrl_storage_list] Bambu_SendMessage failed");

    std::string reply;
    for (int i = 0; i < 500; ++i) {
        BSample s{};
        if (p_read(t, &s) == 0 && s.buffer && s.size > 0) {
            reply.assign(reinterpret_cast<const char*>(s.buffer), (size_t)s.size);
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    p_close(t);
    p_destroy(t);
    p_deinit();

    if (reply.empty()) { FAILF("[ctrl_storage_list] no CTRL reply from Bambu_ReadSample"); return; }
    std::fprintf(stderr, "ctrl reply: %s\n", reply.c_str());

    std::string perr;
    auto root = obn::json::parse(reply, &perr);
    if (!root) { FAILF("[ctrl_storage_list] reply parse: %s", perr.c_str()); return; }
    if ((int)root->find("result").as_int(-1) != 0)
        FAILF("[ctrl_storage_list] reply result != 0");
    auto files = root->find("reply").find("file_lists").as_array();

    for (const auto& want : fx.driver.find("expect_files").as_array()) {
        std::string wname = want.find("name").as_string();
        long long   wsize = (long long)want.find("size").as_number();
        const obn::json::Value* got = nullptr;
        for (const auto& f : files) if (f.find("name").as_string() == wname) { got = &f; break; }
        if (!got) { FAILF("[ctrl_storage_list] expected file '%s' not in file_lists", wname.c_str()); continue; }
        if ((long long)got->find("size").as_number() != wsize)
            FAILF("[ctrl_storage_list] '%s' size expected %lld got %lld",
                  wname.c_str(), wsize, (long long)got->find("size").as_number());
    }
    // type=model must filter out non-model entries (the .mp4 and the dir).
    for (const auto& f : files) {
        std::string n = f.find("name").as_string();
        if (n.size() >= 4 && n.substr(n.size() - 4) == ".mp4")
            FAILF("[ctrl_storage_list] .mp4 '%s' leaked into a type=model listing", n.c_str());
    }
    std::fprintf(stderr, "CTRL storage list: %zu file(s) via :6000 handshake + FTPS bridge\n",
                 files.size());
    dlclose(so);
#endif
}

// ---------------------------------------------------------------------------
// SSDP LAN discovery. Bambu printers broadcast an HTTP-style NOTIFY on UDP
// :2021 (~every 5s). The OSS parses it (obn::ssdp::parse) and maps the headers
// to the device-info JSON Studio's DeviceManager consumes
// (obn::ssdp::to_device_info_json). This drives both the pure mapping contract
// and the live UDP listener (obn::ssdp::Discovery) over loopback, feeding it
// the genuine captured packet.
static void drive_ssdp(const Fixture& fx) {
    std::string packet = fx.driver.find("packet").as_string();
    if (packet.empty()) { FAILF("[ssdp] fixture has no packet"); return; }

    auto check_expected = [&](const std::string& json, const char* via) {
        std::string perr;
        auto v = obn::json::parse(json, &perr);
        if (!v) { FAILF("[ssdp:%s] device-info parse: %s", via, perr.c_str()); return; }
        for (const auto& kv : fx.driver.find("expect").as_object()) {
            std::string want = kv.second.as_string();
            std::string got  = v->find(kv.first).as_string();
            if (got != want)
                FAILF("[ssdp:%s] %s: expected '%s' got '%s'",
                      via, kv.first.c_str(), want.c_str(), got.c_str());
        }
    };

    // 1) Direct wire->JSON mapping contract.
    obn::ssdp::Headers h;
    if (!obn::ssdp::parse(packet.data(), packet.size(), h)) { FAILF("[ssdp] parse failed"); return; }
    std::string json = obn::ssdp::to_device_info_json(h);
    std::fprintf(stderr, "ssdp device-info: %s\n", json.c_str());
    check_expected(json, "parse");

    // 2) Live listener over loopback: pick a free UDP port, start Discovery,
    //    unicast the genuine packet to it, assert the callback JSON.
    int probe = ::socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in pa{}; pa.sin_family = AF_INET;
    pa.sin_addr.s_addr = htonl(INADDR_LOOPBACK); pa.sin_port = 0;
    ::bind(probe, (sockaddr*)&pa, sizeof pa);
    socklen_t plen = sizeof pa; ::getsockname(probe, (sockaddr*)&pa, &plen);
    int port = ntohs(pa.sin_port);
    ::close(probe);

    obn::ssdp::Discovery disc;
    std::mutex jm; std::string got_json;
    if (!disc.start(port, [&](std::string j) {
            std::lock_guard<std::mutex> lk(jm);
            if (got_json.empty()) got_json = std::move(j);
        })) { FAILF("[ssdp] Discovery.start(:%d) failed", port); return; }

    int tx = ::socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in dst{}; dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK); dst.sin_port = htons(port);
    for (int i = 0; i < 40; ++i) {
        ::sendto(tx, packet.data(), packet.size(), 0, (sockaddr*)&dst, sizeof dst);
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
        std::lock_guard<std::mutex> lk(jm);
        if (!got_json.empty()) break;
    }
    ::close(tx);
    disc.stop();

    std::string live; { std::lock_guard<std::mutex> lk(jm); live = got_json; }
    if (live.empty()) { FAILF("[ssdp] Discovery listener produced no JSON"); return; }
    check_expected(live, "listener");
    std::fprintf(stderr, "SSDP discovery OK (parse + live listener on :%d)\n", port);
}

// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
    std::signal(SIGPIPE, SIG_IGN);   // socket writes to a closed mock peer must not kill us
    // Identity headers now detect the real host OS version + UI language; pin
    // the linux fixtures' captured values so the suite is host-independent.
    setenv("BBL_OS_TYPE", "linux", 1);
    setenv("BBL_OS_VERSION", "5.15.0", 1);
    setenv("BBL_LANGUAGE", "en-US", 1);
    setenv("BBL_DEVICE_ID", "887b3544-9221-4b48-9838-cc01c35e6e8d", 1);
    if (!lanmock::make_self_signed(kMockCertPem, kMockKeyPem)) {
        std::fprintf(stderr, "failed to generate mock cert/key\n"); return 2;
    }
    if (argc < 2) { std::fprintf(stderr, "usage: %s <flow.json>\n", argv[0]); return 2; }
    Fixture fx; std::string err;
    if (!load_fixture(argv[1], fx, err)) { std::fprintf(stderr, "fixture load: %s\n", err.c_str()); return 2; }

    MockServer mock;
    std::string host = "http://127.0.0.1:" + std::to_string(mock.port());

    // point OSS config at the mock
    char tmpl[] = "/tmp/obn_wire_XXXXXX";
    std::string dir = mkdtemp(tmpl);
    { std::ofstream cf(dir + "/obn.conf");
      cf << "cloud_global_api_host=" << host << "\n"
         << "cloud_global_web_host=" << host << "\n"
         << "block_cloud=false\n"          // start_print aborts early if block_cloud is set
         << "lan_tls_skip_verify=1\n"      // accept the LAN mocks' self-signed cert
         << "force_ftps=1\n"; }            // force the FTPS leg (not brtc :6000)
    obn::config::load_or_create(dir);

    // Fixture directory (for resolving start_print upload assets).
    std::string fxpath = argv[1];
    std::vector<char> fxbuf(fxpath.begin(), fxpath.end()); fxbuf.push_back('\0');
    std::string fxdir = ::dirname(fxbuf.data());

    std::fprintf(stderr, "wire-compliance: flow=%s channel=%s host=%s\n",
                 fx.flow.c_str(), fx.channel.c_str(), host.c_str());

    if (fx.flow == "login") {
        drive_login();
    } else if (fx.flow == "preset_write") {
        obn::Agent a(dir); seed_session(a, dir); drive_preset_write(a);
    } else if (fx.flow == "preset_sync") {
        obn::Agent a(dir); seed_session(a, dir); drive_preset_sync(a);
    } else if (fx.flow == "filament_manager") {
        obn::Agent a(dir); seed_session(a, dir); drive_filament(a);
    } else if (fx.flow == "start_print") {
        obn::Agent a(dir); seed_session(a, dir);
        // cloud_lan drives the full lan_file pipeline (FTPS + MQTT mocks);
        // cloud drives the HTTP pipeline in cloud_file mode.
        if (fx.channel == "cloud_lan" && !fx.driver.find("access_code").as_string().empty())
            drive_lan_start_print(a, fx, fxdir, dir);
        else if (fx.channel == "lan")
            drive_lan_only_print(a, fx, fxdir, dir);   // pure LAN, no cloud pipeline
        else
            drive_start_print(a, fx, fxdir);
    } else if (fx.flow == "device_command") {
        obn::Agent a(dir); a.set_config_dir(dir); drive_device_command(a, fx, dir);
    } else if (fx.flow == "storage_list") {
        drive_storage_list(fx, dir);
    } else if (fx.flow == "ctrl_storage_list") {
        drive_ctrl_storage_list(fx, dir);
    } else if (fx.flow == "ssdp_discovery") {
        drive_ssdp(fx);
    } else {
        std::fprintf(stderr, "  SKIP: no driver for flow '%s' yet\n", fx.flow.c_str());
        return 77;   // ctest SKIP_RETURN_CODE
    }

    auto recs = mock.records();
    std::fprintf(stderr, "recorded %zu request(s) to the mock\n", recs.size());
    compare(fx, recs);

    if (g_fail) { std::fprintf(stderr, "WIRE-COMPLIANCE FAILED (%d)\n", g_fail); return 1; }
    std::fprintf(stderr, "WIRE-COMPLIANCE OK\n");
    return 0;
}
