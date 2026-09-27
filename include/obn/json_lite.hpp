#pragma once

// Tiny, single-file JSON parser used where we only need to pull a few
// fields out of server responses.
//
// Goals:
//   * Zero dependencies; plain C++17.
//   * Strict enough to catch malformed payloads; not a validator.
//   * Ergonomic lookup via dotted paths ("foo.bar.baz", "hits[0].id").
//
// Non-goals:
//   * Round-tripping / pretty-printing. We only read.
//   * Every last JSON oddity (UTF-16 surrogate pairs in \uXXXX escapes
//     are handled, but we don't renormalise).

#include <cmath>
#include <cstdint>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace obn::json {

class Value;
using Object = std::map<std::string, Value>;
using Array  = std::vector<Value>;

class Value {
public:
    enum class Kind { Null, Bool, Number, String, Array, Object };

    Value() : kind_(Kind::Null) {}
    Value(std::nullptr_t) : kind_(Kind::Null) {}
    Value(bool b) : kind_(Kind::Bool), boolean_(b) {}
    Value(double d) : kind_(Kind::Number), number_(d) {}
    Value(std::string s) : kind_(Kind::String), string_(std::move(s)) {}
    // Without this explicit overload, string literals (const char*) bind
    // to Value(bool) via the standard pointer-to-bool conversion, which
    // wins over the user-defined std::string conversion. Every
    // obn::json::Value("...") call would silently become `true`.
    Value(const char* s) : kind_(Kind::String), string_(s ? s : "") {}
    Value(Array a) : kind_(Kind::Array), array_(std::make_shared<Array>(std::move(a))) {}
    Value(Object o) : kind_(Kind::Object), object_(std::make_shared<Object>(std::move(o))) {}

    Kind kind() const { return kind_; }
    bool is_null()   const { return kind_ == Kind::Null;   }
    bool is_bool()   const { return kind_ == Kind::Bool;   }
    bool is_number() const { return kind_ == Kind::Number; }
    bool is_string() const { return kind_ == Kind::String; }
    bool is_array()  const { return kind_ == Kind::Array;  }
    bool is_object() const { return kind_ == Kind::Object; }

    bool        as_bool(bool def = false)   const { return is_bool() ? boolean_ : def; }
    double      as_number(double def = 0)   const { return is_number() ? number_ : def; }
    // static_cast<int64_t> of a double outside [INT64_MIN, INT64_MAX] (or NaN)
    // is undefined behavior. Wire data (printer/cloud JSON) is untrusted, so
    // clamp instead of trusting the field to be in range.
    std::int64_t as_int(std::int64_t d = 0) const {
        if (!is_number()) return d;
        if (std::isnan(number_)) return d;
        if (number_ >= static_cast<double>(std::numeric_limits<std::int64_t>::max()))
            return std::numeric_limits<std::int64_t>::max();
        if (number_ <= static_cast<double>(std::numeric_limits<std::int64_t>::min()))
            return std::numeric_limits<std::int64_t>::min();
        return static_cast<std::int64_t>(number_);
    }
    const std::string& as_string() const {
        static const std::string empty;
        return is_string() ? string_ : empty;
    }
    const Array&  as_array()  const { static const Array  empty; return is_array()  ? *array_  : empty; }
    const Object& as_object() const { static const Object empty; return is_object() ? *object_ : empty; }

    // Path lookup: "a.b", "a.b[2].c". Returns null value on any miss.
    Value find(const std::string& path) const;

    // Convenience: stringify a value back to JSON text (compact).
    std::string dump() const;

private:
    Kind kind_;
    bool boolean_ = false;
    double number_ = 0;
    std::string string_;
    std::shared_ptr<Array>  array_;
    std::shared_ptr<Object> object_;
};

// Parses `text` into a Value. On failure returns std::nullopt and, if
// `err` is non-null, writes a human-readable reason.
std::optional<Value> parse(const std::string& text, std::string* err = nullptr);

// Helpers for building JSON from primitives, used on the serialising
// side (Agent -> Studio, auth file writes). Escape a raw string into
// a JSON-safe double-quoted literal, e.g. "hello\nworld" -> "\"hello\\nworld\"".
std::string escape(const std::string& in);

} // namespace obn::json
