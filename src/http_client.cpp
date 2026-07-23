#include "obn/http_client.hpp"

#include "obn/log.hpp"

#include <curl/curl.h>

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <sstream>

namespace obn::http {

namespace {

std::atomic<bool> g_inited{false};
std::mutex        g_init_mu;

// Identify HTTP traffic as this project. Callers (or Studio via
// bambu_network_set_extra_http_header) may override with Request.headers.
std::string default_user_agent()
{
#ifndef OBN_VERSION_STRING
#    error "OBN_VERSION_STRING is not defined; build through the top-level ./configure or pass -DOBN_VERSION=... to cmake"
#endif
    return std::string("OBN/") + OBN_VERSION_STRING;
}

size_t on_body(void* ptr, size_t size, size_t nmemb, void* userdata)
{
    auto* out = static_cast<std::string*>(userdata);
    out->append(static_cast<char*>(ptr), size * nmemb);
    return size * nmemb;
}

int on_curl_debug(CURL* /*handle*/, curl_infotype type, char* data, size_t size,
                  void* /*userp*/)
{
    // Keep verbose output to our log so we can diagnose "helpful"
    // things libcurl does behind our back (e.g. auto Expect:
    // 100-continue, forced Transfer-Encoding: chunked).
    if (type != CURLINFO_HEADER_OUT && type != CURLINFO_HEADER_IN)
        return 0;
    std::string s(data, size);
    // Strip trailing CRLF run to keep the log one-line-per-header.
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n')) s.pop_back();
    if (s.empty()) return 0;
    const char* dir = type == CURLINFO_HEADER_OUT ? ">>" : "<<";
    OBN_DEBUG("curl %s %s", dir, s.c_str());
    return 0;
}

size_t on_header(char* buffer, size_t size, size_t nitems, void* userdata)
{
    auto* resp = static_cast<Response*>(userdata);
    size_t n = size * nitems;
    std::string line(buffer, n);
    // Strip CRLF.
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
        line.pop_back();
    // case-insensitive prefix check
    auto ieq = [](const std::string& s, const char* p) {
        auto len = std::strlen(p);
        if (s.size() < len) return false;
        for (size_t i = 0; i < len; ++i)
            if (std::tolower(static_cast<unsigned char>(s[i])) !=
                std::tolower(static_cast<unsigned char>(p[i])))
                return false;
        return true;
    };
    if (ieq(line, "content-type:")) {
        auto pos = line.find(':');
        if (pos != std::string::npos) {
            std::string v = line.substr(pos + 1);
            while (!v.empty() && v.front() == ' ') v.erase(v.begin());
            resp->content_type = v;
        }
    } else if (ieq(line, "set-cookie:")) {
        auto pos = line.find(':');
        if (pos != std::string::npos) {
            std::string v = line.substr(pos + 1);
            while (!v.empty() && v.front() == ' ') v.erase(v.begin());
            resp->set_cookies.push_back(v);
        }
    }
    return n;
}

const char* method_verb(Method m)
{
    switch (m) {
        case Method::GET:   return "GET";
        case Method::POST:  return "POST";
        case Method::PUT:   return "PUT";
        case Method::DEL:   return "DELETE";
        case Method::PATCH: return "PATCH";
    }
    return "GET";
}

} // namespace

void global_init()
{
    if (g_inited.load(std::memory_order_acquire)) return;
    std::lock_guard<std::mutex> lk(g_init_mu);
    if (g_inited.load(std::memory_order_relaxed)) return;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    g_inited.store(true, std::memory_order_release);
}

Response perform(const Request& req)
{
    global_init();

    Response resp;
    CURL*    curl = curl_easy_init();
    if (!curl) {
        resp.error = "curl_easy_init failed";
        return resp;
    }

    // Stock bambu_network_agent wire order for the identity headers.
    // Anything else (Studio extras, non-cloud requests) follows in
    // map order. Names match Agent::cloud_api_http_headers().
    static const char* const kBblHeaderOrder[] = {
        "User-Agent",         "X-BBL-Client-ID",    "X-BBL-Client-Name",
        "X-BBL-Client-Type",  "X-BBL-Client-Version", "X-BBL-Device-ID",
        "X-BBL-Language",     "X-BBL-OS-Type",      "X-BBL-OS-Version",
        "X-BBL-Agent-Version","X-BBL-Executable-info", "X-BBL-Agent-OS-Type",
        "X-BBL-Executable-Env", "accept",           "Authorization",
        "Content-Type",
    };
    curl_slist* hdrs = nullptr;
    bool        have_ua = false;
    bool        have_accept = false;
    bool        have_ct = false;
    auto append = [&](const std::string& k, const std::string& v) {
        // libcurl idiom: "Header:" (no value, no space) removes an
        // internally-added header such as Content-Type or Expect.
        // "Header: value" sends the header normally.
        std::string kv = v.empty() ? (k + ":") : (k + ": " + v);
        hdrs = curl_slist_append(hdrs, kv.c_str());
        std::string lk = k;
        for (auto& c : lk) c = std::tolower(static_cast<unsigned char>(c));
        if (lk == "user-agent")   have_ua = true;
        if (lk == "accept")       have_accept = true;
        if (lk == "content-type") have_ct = true;
    };
    auto is_ordered = [&](const std::string& k) {
        for (const char* name : kBblHeaderOrder) if (k == name) return true;
        return false;
    };
    for (const char* name : kBblHeaderOrder) {
        auto it = req.headers.find(name);
        if (it != req.headers.end()) append(it->first, it->second);
    }
    for (const auto& [k, v] : req.headers) {
        if (!is_ordered(k)) append(k, v);
    }
    if (!have_ua) {
        std::string kv = "User-Agent: " + default_user_agent();
        hdrs = curl_slist_append(hdrs, kv.c_str());
    }
    if (!have_accept && !req.no_default_accept) {
        hdrs = curl_slist_append(hdrs, "Accept: application/json");
    }
    if ((req.method == Method::POST || req.method == Method::PUT ||
         req.method == Method::PATCH) && !have_ct &&
        !req.no_default_content_type) {
        hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    }

    curl_easy_setopt(curl, CURLOPT_URL,              req.url.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST,    method_verb(req.method));
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT,   static_cast<long>(req.connect_timeout_s));
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,          static_cast<long>(req.timeout_s));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,       hdrs);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION,   1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS,        10L);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING,  "");       // auto gzip/br if libcurl was built with it
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,    on_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,        &resp.body);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION,   on_header);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA,       &resp);

    if (req.method == Method::POST || req.method == Method::PUT ||
        req.method == Method::PATCH) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(req.body.size()));
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS,    req.body.data());
    }

    // Wire-level tracing of every HTTP request is very useful when
    // debugging signatures (S3, Bambu cloud) but fills the log fast
    // during normal use. Gated behind OBN_HTTP_TRACE=1 so we can turn
    // it on for a single session without a rebuild.
    static const bool s_trace_http = []() {
        const char* v = std::getenv("OBN_HTTP_TRACE");
        return v && *v && *v != '0';
    }();
    if (s_trace_http) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE,       1L);
        curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, on_curl_debug);
    }

    if (req.insecure) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    } else if (!req.ca_file.empty()) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, req.ca_file.c_str());
    }

    OBN_DEBUG("http %s %s (body=%zu)",
              method_verb(req.method), req.url.c_str(), req.body.size());

    CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        resp.error = curl_easy_strerror(rc);
    } else {
        long status = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        resp.status_code = status;
    }

    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    OBN_DEBUG("http %s %s -> %ld (%zu bytes)%s%s",
              method_verb(req.method), req.url.c_str(),
              resp.status_code, resp.body.size(),
              resp.error.empty() ? "" : " err=",
              resp.error.c_str());
    return resp;
}

Response get_json(const std::string& url,
                  const std::map<std::string, std::string>& headers,
                  const std::string& ca_file)
{
    Request r;
    r.method  = Method::GET;
    r.url     = url;
    r.headers = headers;
    r.ca_file = ca_file;
    return perform(r);
}

Response post_json(const std::string& url,
                   const std::string& body,
                   const std::map<std::string, std::string>& headers,
                   const std::string& ca_file)
{
    Request r;
    r.method  = Method::POST;
    r.url     = url;
    r.body    = body;
    r.headers = headers;
    r.ca_file = ca_file;
    return perform(r);
}

std::string url_encode(const std::string& in)
{
    static const char HEX[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(in.size() * 3);
    for (unsigned char c : in) {
        bool unreserved = (c >= 'A' && c <= 'Z') ||
                          (c >= 'a' && c <= 'z') ||
                          (c >= '0' && c <= '9') ||
                          c == '-' || c == '_' || c == '.' || c == '~';
        if (unreserved) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(HEX[(c >> 4) & 0xF]);
            out.push_back(HEX[c & 0xF]);
        }
    }
    return out;
}

} // namespace obn::http
