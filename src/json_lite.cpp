#include "obn/json_lite.hpp"

#include <cctype>
#include <cmath>
#include <cstdint>
#include <sstream>

namespace obn::json {

namespace {

// Nested {}/[] recurse one C++ stack frame per level with no other bound;
// wire data (MQTT push_status, HTTP/cloud responses) can be arbitrarily
// deeply nested, so cap it well short of a real stack overflow.
constexpr int kMaxNestingDepth = 512;

struct Parser {
    const char* p;
    const char* end;
    std::string err;
    int depth = 0;

    bool at_end() const { return p >= end; }

    void skip_ws() {
        while (p < end) {
            char c = *p;
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') ++p;
            else break;
        }
    }

    bool expect(char c) {
        skip_ws();
        if (p >= end || *p != c) {
            err = std::string("expected '") + c + "'";
            return false;
        }
        ++p;
        return true;
    }

    bool literal(const char* lit) {
        std::size_t n = std::char_traits<char>::length(lit);
        if (static_cast<std::size_t>(end - p) < n) return false;
        for (std::size_t i = 0; i < n; ++i)
            if (p[i] != lit[i]) return false;
        p += n;
        return true;
    }

    bool parse_string(std::string& out) {
        if (p >= end || *p != '"') { err = "expected string"; return false; }
        ++p;
        out.clear();
        while (p < end) {
            char c = *p++;
            if (c == '"') return true;
            if (c == '\\') {
                if (p >= end) { err = "bad escape"; return false; }
                char e = *p++;
                switch (e) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u': {
                        if (end - p < 4) { err = "bad \\u escape"; return false; }
                        unsigned cp = 0;
                        for (int i = 0; i < 4; ++i) {
                            char h = p[i];
                            cp <<= 4;
                            if (h >= '0' && h <= '9')      cp |= h - '0';
                            else if (h >= 'a' && h <= 'f') cp |= h - 'a' + 10;
                            else if (h >= 'A' && h <= 'F') cp |= h - 'A' + 10;
                            else { err = "bad hex in \\u"; return false; }
                        }
                        p += 4;
                        // surrogate pair?
                        if (cp >= 0xD800 && cp <= 0xDBFF && end - p >= 6 &&
                            p[0] == '\\' && p[1] == 'u') {
                            unsigned lo = 0;
                            for (int i = 0; i < 4; ++i) {
                                char h = p[2 + i];
                                lo <<= 4;
                                if (h >= '0' && h <= '9')      lo |= h - '0';
                                else if (h >= 'a' && h <= 'f') lo |= h - 'a' + 10;
                                else if (h >= 'A' && h <= 'F') lo |= h - 'A' + 10;
                                else { err = "bad low surrogate"; return false; }
                            }
                            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                p += 6;
                            }
                        }
                        // encode as UTF-8
                        if (cp < 0x80) {
                            out.push_back(static_cast<char>(cp));
                        } else if (cp < 0x800) {
                            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
                            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                        } else if (cp < 0x10000) {
                            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
                            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                        } else {
                            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
                            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
                            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                        }
                        break;
                    }
                    default: err = "bad escape char"; return false;
                }
            } else {
                out.push_back(c);
            }
        }
        err = "unterminated string";
        return false;
    }

    bool parse_number(double& out) {
        const char* start = p;
        if (*p == '-') ++p;
        while (p < end && std::isdigit(static_cast<unsigned char>(*p))) ++p;
        if (p < end && *p == '.') {
            ++p;
            while (p < end && std::isdigit(static_cast<unsigned char>(*p))) ++p;
        }
        if (p < end && (*p == 'e' || *p == 'E')) {
            ++p;
            if (p < end && (*p == '+' || *p == '-')) ++p;
            while (p < end && std::isdigit(static_cast<unsigned char>(*p))) ++p;
        }
        if (p == start) { err = "bad number"; return false; }
        try {
            out = std::stod(std::string(start, p - start));
        } catch (...) {
            err = "number range";
            return false;
        }
        return true;
    }

    bool parse_value(Value& out) {
        skip_ws();
        if (at_end()) { err = "unexpected EOF"; return false; }
        char c = *p;
        if (c == '"') {
            std::string s;
            if (!parse_string(s)) return false;
            out = Value(std::move(s));
            return true;
        }
        if (c == '{' || c == '[') {
            if (depth >= kMaxNestingDepth) {
                err = "max nesting depth exceeded";
                return false;
            }
            ++depth;
            struct DepthGuard {
                int& d;
                ~DepthGuard() { --d; }
            } depth_guard{depth};

            if (c == '{') {
                ++p;
                Object obj;
                skip_ws();
                if (p < end && *p == '}') { ++p; out = Value(std::move(obj)); return true; }
                while (true) {
                    skip_ws();
                    std::string key;
                    if (!parse_string(key)) return false;
                    skip_ws();
                    if (p >= end || *p != ':') { err = "expected ':'"; return false; }
                    ++p;
                    Value v;
                    if (!parse_value(v)) return false;
                    obj.emplace(std::move(key), std::move(v));
                    skip_ws();
                    if (p < end && *p == ',') { ++p; continue; }
                    if (p < end && *p == '}') { ++p; break; }
                    err = "expected ',' or '}'";
                    return false;
                }
                out = Value(std::move(obj));
                return true;
            }
            // c == '['
            ++p;
            Array arr;
            skip_ws();
            if (p < end && *p == ']') { ++p; out = Value(std::move(arr)); return true; }
            while (true) {
                Value v;
                if (!parse_value(v)) return false;
                arr.emplace_back(std::move(v));
                skip_ws();
                if (p < end && *p == ',') { ++p; continue; }
                if (p < end && *p == ']') { ++p; break; }
                err = "expected ',' or ']'";
                return false;
            }
            out = Value(std::move(arr));
            return true;
        }
        if (c == 't') { if (literal("true"))  { out = Value(true);  return true; } err = "bad literal"; return false; }
        if (c == 'f') { if (literal("false")) { out = Value(false); return true; } err = "bad literal"; return false; }
        if (c == 'n') { if (literal("null"))  { out = Value();      return true; } err = "bad literal"; return false; }
        if (c == '-' || (c >= '0' && c <= '9')) {
            double d;
            if (!parse_number(d)) return false;
            out = Value(d);
            return true;
        }
        err = "unexpected character";
        return false;
    }
};

} // namespace

std::optional<Value> parse(const std::string& text, std::string* err)
{
    Parser ps;
    ps.p = text.data();
    ps.end = text.data() + text.size();
    ps.skip_ws();
    Value v;
    if (!ps.parse_value(v)) {
        if (err) *err = ps.err;
        return std::nullopt;
    }
    ps.skip_ws();
    if (!ps.at_end()) {
        if (err) *err = "trailing characters";
        return std::nullopt;
    }
    return v;
}

Value Value::find(const std::string& path) const
{
    const Value* cur = this;
    std::size_t  pos = 0;
    while (pos < path.size()) {
        if (cur->kind_ == Kind::Null) return Value();
        if (path[pos] == '[') {
            auto close = path.find(']', pos);
            if (close == std::string::npos) return Value();
            std::string idx = path.substr(pos + 1, close - pos - 1);
            if (!cur->is_array()) return Value();
            std::size_t i = 0;
            try { i = static_cast<std::size_t>(std::stoul(idx)); } catch (...) { return Value(); }
            const auto& arr = cur->as_array();
            if (i >= arr.size()) return Value();
            cur = &arr[i];
            pos = close + 1;
            if (pos < path.size() && path[pos] == '.') ++pos;
        } else {
            std::size_t next = path.find_first_of(".[", pos);
            std::string key = path.substr(pos, next == std::string::npos ? std::string::npos : next - pos);
            if (!cur->is_object()) return Value();
            const auto& obj = cur->as_object();
            auto it = obj.find(key);
            if (it == obj.end()) return Value();
            cur = &it->second;
            if (next == std::string::npos) { pos = path.size(); }
            else {
                pos = next;
                if (path[pos] == '.') ++pos;
            }
        }
    }
    return *cur;
}

std::string Value::dump() const
{
    std::ostringstream os;
    switch (kind_) {
        case Kind::Null:   os << "null"; break;
        case Kind::Bool:   os << (boolean_ ? "true" : "false"); break;
        case Kind::Number: {
            // Prefer integer-looking output when the value fits losslessly
            // into int64 and has no fractional part. Studio's json parser
            // chokes on "1.62e+09" for fields it expects to be u64 (file
            // sizes, epoch timestamps, sequence numbers), so we emit them
            // as plain decimals.
            if (std::isfinite(number_) &&
                number_ >= -9.2233720368547748e18 &&
                number_ <=  9.2233720368547748e18 &&
                std::trunc(number_) == number_)
            {
                std::ostringstream tmp;
                tmp << static_cast<long long>(number_);
                os << tmp.str();
            } else {
                // Preserve enough precision for doubles; 17 is the IEEE-754
                // round-trip guarantee for binary64.
                std::ostringstream tmp;
                tmp.precision(17);
                tmp << number_;
                os << tmp.str();
            }
            break;
        }
        case Kind::String: os << escape(string_); break;
        case Kind::Array: {
            os << '[';
            bool first = true;
            for (const auto& v : *array_) {
                if (!first) os << ',';
                first = false;
                os << v.dump();
            }
            os << ']';
            break;
        }
        case Kind::Object: {
            os << '{';
            bool first = true;
            for (const auto& [k, v] : *object_) {
                if (!first) os << ',';
                first = false;
                os << escape(k) << ':' << v.dump();
            }
            os << '}';
            break;
        }
    }
    return os.str();
}

std::string escape(const std::string& in)
{
    std::string out;
    out.reserve(in.size() + 2);
    out.push_back('"');
    for (unsigned char c : in) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char b[8];
                    std::snprintf(b, sizeof(b), "\\u%04x", c);
                    out += b;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    out.push_back('"');
    return out;
}

} // namespace obn::json
