#include "envelope.h"
#include <array>
#include <cstring>

namespace mini_json {

void skip_ws(const std::string& s, size_t& i) {
    while (i < s.size()) {
        char c = s[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') ++i;
        else break;
    }
}

bool parse_string(const std::string& s, size_t& i, std::string& out) {
    if (i >= s.size() || s[i] != '"') return false;
    ++i;
    out.clear();
    while (i < s.size()) {
        char c = s[i++];
        if (c == '"') return true;
        if (c == '\\') {
            if (i >= s.size()) return false;
            char e = s[i++];
            switch (e) {
                case '"':  out.push_back('"');  break;
                case '\\': out.push_back('\\'); break;
                case '/':  out.push_back('/');  break;
                case 'n':  out.push_back('\n'); break;
                case 'r':  out.push_back('\r'); break;
                case 't':  out.push_back('\t'); break;
                case 'b':  out.push_back('\b'); break;
                case 'f':  out.push_back('\f'); break;
                case 'u': {
                    if (i + 4 > s.size()) return false;
                    int cp = 0;
                    for (int k = 0; k < 4; ++k) {
                        char h = s[i++]; int d = -1;
                        if (h >= '0' && h <= '9') d = h - '0';
                        else if (h >= 'a' && h <= 'f') d = 10 + h - 'a';
                        else if (h >= 'A' && h <= 'F') d = 10 + h - 'A';
                        else return false;
                        cp = (cp << 4) | d;
                    }
                    if (cp < 0x80) out.push_back(char(cp));
                    else if (cp < 0x800) {
                        out.push_back(char(0xc0 | (cp >> 6)));
                        out.push_back(char(0x80 | (cp & 0x3f)));
                    } else {
                        out.push_back(char(0xe0 | (cp >> 12)));
                        out.push_back(char(0x80 | ((cp >> 6) & 0x3f)));
                        out.push_back(char(0x80 | (cp & 0x3f)));
                    }
                    break;
                }
                default: return false;
            }
        } else {
            out.push_back(c);
        }
    }
    return false;
}

bool skip_value(const std::string& s, size_t& i) {
    skip_ws(s, i);
    if (i >= s.size()) return false;
    char c = s[i];
    if (c == '"') { std::string t; return parse_string(s, i, t); }
    if (c == '{' || c == '[') {
        char open = c, close = (c == '{') ? '}' : ']';
        ++i;
        int depth = 1;
        bool in_str = false;
        bool esc = false;
        while (i < s.size() && depth > 0) {
            char ch = s[i++];
            if (in_str) {
                if (esc) { esc = false; continue; }
                if (ch == '\\') { esc = true; continue; }
                if (ch == '"') in_str = false;
                continue;
            }
            if (ch == '"') in_str = true;
            else if (ch == open) ++depth;
            else if (ch == close) --depth;
        }
        return depth == 0;
    }
    while (i < s.size()) {
        char ch = s[i];
        if (ch == ',' || ch == '}' || ch == ']' || ch == ' ' || ch == '\n' ||
            ch == '\r' || ch == '\t') break;
        ++i;
    }
    return true;
}

bool parse_envelope(const std::string& s, size_t& i, Envelope& env) {
    if (i >= s.size() || s[i] != '{') return false;
    ++i;
    while (true) {
        skip_ws(s, i);
        if (i >= s.size()) return false;
        if (s[i] == '}') { ++i; return true; }
        if (s[i] == ',') { ++i; continue; }
        std::string key;
        if (!parse_string(s, i, key)) return false;
        skip_ws(s, i);
        if (i >= s.size() || s[i] != ':') return false;
        ++i;
        skip_ws(s, i);
        if (key == "to_sign") {
            if (!parse_string(s, i, env.to_sign)) return false;
        } else if (key == "sig_b64") {
            if (!parse_string(s, i, env.sig_b64)) return false;
        } else if (key == "cmd") {
            if (s[i] == '"') { parse_string(s, i, env.cmd); }
            else skip_value(s, i);
        } else {
            if (!skip_value(s, i)) return false;
        }
    }
}

bool parse_envelopes(const std::string& s, std::vector<Envelope>& out) {
    size_t i = 0;
    skip_ws(s, i);
    if (i >= s.size() || s[i] != '{') return false;
    ++i;
    bool found = false;
    while (i < s.size()) {
        skip_ws(s, i);
        if (i >= s.size() || s[i] == '}') break;
        if (s[i] == ',') { ++i; continue; }
        std::string key;
        if (!parse_string(s, i, key)) return false;
        skip_ws(s, i);
        if (s[i] != ':') return false;
        ++i;
        skip_ws(s, i);
        if (key == "envelopes") {
            if (s[i] != '[') return false;
            ++i;
            while (true) {
                skip_ws(s, i);
                if (i >= s.size()) return false;
                if (s[i] == ']') { ++i; break; }
                if (s[i] == ',') { ++i; continue; }
                Envelope env;
                if (!parse_envelope(s, i, env)) return false;
                if (!env.to_sign.empty() && !env.sig_b64.empty()) {
                    out.push_back(std::move(env));
                }
            }
            found = true;
        } else {
            if (!skip_value(s, i)) return false;
        }
    }
    return found && !out.empty();
}

}  // namespace mini_json

bool base64_decode(const std::string& in, std::vector<uint8_t>& out) {
    static const auto T = []() {
        std::array<int8_t, 256> t{};
        t.fill(-1);
        const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; b64[i]; ++i) t[(unsigned char)b64[i]] = (int8_t)i;
        t[(unsigned char)'='] = -2;
        return t;
    }();
    uint32_t buf = 0; int bits = 0;
    for (char c : in) {
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
        int v = T[uint8_t(c)];
        if (v == -2) break;
        if (v < 0) return false;
        buf = (buf << 6) | uint32_t(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(uint8_t(buf >> bits));
            buf &= (1u << bits) - 1;
        }
    }
    return true;
}

void pkcs1_v15_pad_sha256(const uint8_t hash[32], uint8_t out[256]) {
    static const uint8_t DI[] = {
        0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,
        0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20
    };
    const size_t k = 256;
    const size_t t_len = sizeof(DI) + 32;
    const size_t ps_len = k - 3 - t_len;
    size_t i = 0;
    out[i++] = 0x00;
    out[i++] = 0x01;
    for (size_t j = 0; j < ps_len; ++j) out[i++] = 0xff;
    out[i++] = 0x00;
    std::memcpy(out + i, DI, sizeof(DI)); i += sizeof(DI);
    std::memcpy(out + i, hash, 32); i += 32;
}
