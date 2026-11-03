#include "obn/model_metadata.hpp"

#include "obn/zip_read.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace obn::model_metadata {

namespace {

// A sliced project's 3dmodel.model holds metadata and component references
// (a few KiB); meshes live in 3D/Objects/. Bounds a damaged or odd archive.
constexpr std::size_t kMaxModelBytes = 4 * 1024 * 1024;

void append_utf8(std::string* out, unsigned long cp)
{
    if (cp < 0x80) {
        out->push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out->push_back(static_cast<char>(0xc0 | (cp >> 6)));
        out->push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else if (cp < 0x10000) {
        out->push_back(static_cast<char>(0xe0 | (cp >> 12)));
        out->push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
        out->push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else {
        out->push_back(static_cast<char>(0xf0 | (cp >> 18)));
        out->push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
        out->push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
        out->push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    }
}

// Only predefined entities and character references; anything else stays verbatim.
std::string decode_xml_text(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    std::size_t i = 0;
    while (i < s.size()) {
        const std::size_t semi = s[i] == '&' ? s.find(';', i + 1) : std::string::npos;
        if (semi == std::string::npos || semi - i > 12) {
            out.push_back(s[i++]);
            continue;
        }
        const std::string ent = s.substr(i + 1, semi - i - 1);
        bool ok = true;
        if (ent == "amp") out.push_back('&');
        else if (ent == "lt") out.push_back('<');
        else if (ent == "gt") out.push_back('>');
        else if (ent == "quot") out.push_back('"');
        else if (ent == "apos") out.push_back('\'');
        else if (ent.size() > 1 && ent[0] == '#') {
            const bool hex = ent[1] == 'x' || ent[1] == 'X';
            const char* digits = ent.c_str() + (hex ? 2 : 1);
            char* end = nullptr;
            const unsigned long cp = std::strtoul(digits, &end, hex ? 16 : 10);
            ok = *digits != '\0' && end && *end == '\0' && cp != 0 &&
                 cp <= 0x10ffff && (cp < 0xd800 || cp > 0xdfff);
            if (ok) append_utf8(&out, cp);
        } else {
            ok = false;
        }
        if (!ok) out.append(s, i, semi - i + 1);
        i = semi + 1;
    }
    return out;
}

bool is_xml_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

// Text inside another attribute's value is never taken for an attribute.
bool xml_attribute(const std::string& attrs, const std::string& name,
                   std::string* value)
{
    const std::size_t n = attrs.size();
    std::size_t i = 0;
    while (i < n) {
        while (i < n && is_xml_space(attrs[i])) ++i;
        const std::size_t key_start = i;
        while (i < n && !is_xml_space(attrs[i]) && attrs[i] != '=') ++i;
        const std::string key = attrs.substr(key_start, i - key_start);
        while (i < n && is_xml_space(attrs[i])) ++i;
        if (i >= n || attrs[i] != '=') {
            if (i == key_start) ++i;  // stray character
            continue;
        }
        ++i;
        while (i < n && is_xml_space(attrs[i])) ++i;
        if (i >= n || (attrs[i] != '"' && attrs[i] != '\'')) return false;
        const std::size_t vend = attrs.find(attrs[i], i + 1);
        if (vend == std::string::npos) return false;
        if (key == name) {
            *value = attrs.substr(i + 1, vend - i - 1);
            return true;
        }
        i = vend + 1;
    }
    return false;
}

// A '>' inside a quoted attribute value does not end the tag.
std::size_t xml_tag_end(const std::string& xml, std::size_t pos)
{
    char quote = 0;
    for (; pos < xml.size(); ++pos) {
        const char c = xml[pos];
        if (quote) {
            if (c == quote) quote = 0;
        } else if (c == '"' || c == '\'') {
            quote = c;
        } else if (c == '>') {
            return pos;
        }
    }
    return std::string::npos;
}

// Empty when the element is unterminated or has child elements.
std::string xml_element_text(const std::string& xml, std::size_t pos,
                             const std::string& close_tag)
{
    std::string out;
    while (pos < xml.size()) {
        const std::size_t lt = xml.find('<', pos);
        if (lt == std::string::npos) return {};
        out += decode_xml_text(xml.substr(pos, lt - pos));
        if (xml.compare(lt, 9, "<![CDATA[") == 0) {
            const std::size_t e = xml.find("]]>", lt + 9);
            if (e == std::string::npos) return {};
            out.append(xml, lt + 9, e - lt - 9);
            pos = e + 3;
        } else if (xml.compare(lt, 4, "<!--") == 0) {
            const std::size_t e = xml.find("-->", lt + 4);
            if (e == std::string::npos) return {};
            pos = e + 3;
        } else if (xml.compare(lt, close_tag.size(), close_tag) == 0) {
            return out;
        } else {
            return {};
        }
    }
    return {};
}

} // namespace

std::string value(const std::string& xml, const std::string& name)
{
    static const std::string kOpen = "<metadata";
    std::size_t pos = 0;
    while ((pos = xml.find('<', pos)) != std::string::npos) {
        const char* skip_to = nullptr;
        std::size_t skip_from = 0;
        if (xml.compare(pos, 4, "<!--") == 0) {
            skip_to = "-->";
            skip_from = pos + 4;
        } else if (xml.compare(pos, 9, "<![CDATA[") == 0) {
            skip_to = "]]>";
            skip_from = pos + 9;
        } else if (xml.compare(pos, 2, "<?") == 0) {
            skip_to = "?>";
            skip_from = pos + 2;
        }
        if (skip_to) {
            const std::size_t e = xml.find(skip_to, skip_from);
            if (e == std::string::npos) break;
            pos = e + std::strlen(skip_to);
            continue;
        }
        const std::size_t after = pos + kOpen.size();
        if (xml.compare(pos, kOpen.size(), kOpen) != 0 ||
            (after < xml.size() && !is_xml_space(xml[after]) &&
             xml[after] != '>' && xml[after] != '/')) {
            ++pos;  // another element, or <metadatagroup> and the like
            continue;
        }
        const std::size_t tag_end = xml_tag_end(xml, after);
        if (tag_end == std::string::npos) break;
        std::string attrs = xml.substr(after, tag_end - after);
        pos = tag_end + 1;
        const bool self_closing = !attrs.empty() && attrs.back() == '/';
        if (self_closing) attrs.pop_back();
        std::string key;
        if (!xml_attribute(attrs, "name", &key) || key != name) continue;
        if (self_closing) return {};
        return xml_element_text(xml, pos, "</metadata");
    }
    return {};
}

std::vector<int> sliced_plates(const std::string& xml)
{
    std::vector<int> out;
    std::size_t pos = 0;
    while ((pos = xml.find("<plate", pos)) != std::string::npos) {
        const std::size_t after = pos + 6;
        if (after >= xml.size() || (xml[after] != '>' && !is_xml_space(xml[after]))) {
            pos = after;  // <plate_...> and the like
            continue;
        }
        std::size_t end = xml.find("</plate>", after);
        if (end == std::string::npos) end = xml.size();
        std::size_t m = after;
        while ((m = xml.find("<metadata", m)) != std::string::npos && m < end) {
            const std::size_t tag_end = xml_tag_end(xml, m + 9);
            if (tag_end == std::string::npos || tag_end > end) break;
            std::string attrs = xml.substr(m + 9, tag_end - m - 9);
            if (!attrs.empty() && attrs.back() == '/') attrs.pop_back();
            m = tag_end + 1;
            std::string key, value;
            if (!xml_attribute(attrs, "key", &key) || key != "index") continue;
            if (!xml_attribute(attrs, "value", &value)) break;
            char* num_end = nullptr;
            const long n = std::strtol(value.c_str(), &num_end, 10);
            if (!value.empty() && num_end && *num_end == '\0' && n > 0 && n < 1000) {
                out.push_back(static_cast<int>(n));
            }
            break;
        }
        pos = end;
    }
    return out;
}

bool makerworld_design_id(const std::string& path_3mf, std::string* id,
                          std::string* err)
{
    std::vector<std::uint8_t> data;
    if (!obn::zip::read_entry(path_3mf, kModelMember, kMaxModelBytes, &data, err)) {
        return false;
    }
    if (id) *id = value(std::string(data.begin(), data.end()), "DesignModelId");
    return true;
}

} // namespace obn::model_metadata
