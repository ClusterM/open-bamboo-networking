#include "obn/zip_read.hpp"

#include <zlib.h>

#include <algorithm>
#include <cstring>
#include <fstream>

namespace obn::zip {

namespace {

constexpr std::uint32_t kEocdSig    = 0x06054b50;
constexpr std::uint32_t kCentralSig = 0x02014b50;
constexpr std::uint32_t kLocalSig   = 0x04034b50;
constexpr std::size_t   kEocdLen    = 22;
constexpr std::size_t   kCentralLen = 46;
constexpr std::size_t   kLocalLen   = 30;
constexpr std::size_t   kMaxComment = 0xffff;

// A .3mf has a few dozen entries (~100 bytes each in the central
// directory); these caps only bound the reads for a damaged archive.
constexpr std::uint32_t kMaxCentralDir = std::uint32_t{16} << 20;
constexpr std::uint32_t kMaxPacked     = std::uint32_t{16} << 20;

std::uint16_t le16(const std::uint8_t* p)
{
    return static_cast<std::uint16_t>(p[0] | (p[1] << 8));
}

std::uint32_t le32(const std::uint8_t* p)
{
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

bool fail(std::string* err, const char* why)
{
    if (err) *err = why;
    return false;
}

bool read_at(std::ifstream& f, std::uint64_t off, std::size_t n,
             std::vector<std::uint8_t>* buf)
{
    buf->assign(n, 0);
    f.clear();
    f.seekg(static_cast<std::streamoff>(off));
    if (!f) return false;
    if (n == 0) return true;
    f.read(reinterpret_cast<char*>(buf->data()),
           static_cast<std::streamsize>(n));
    return static_cast<std::size_t>(f.gcount()) == n;
}

bool inflate_raw(const std::vector<std::uint8_t>& in,
                 std::vector<std::uint8_t>*       out)
{
    z_stream zs{};
    if (inflateInit2(&zs, -MAX_WBITS) != Z_OK) return false;
    std::uint8_t none = 0;
    zs.next_in   = const_cast<Bytef*>(in.data());
    zs.avail_in  = static_cast<uInt>(in.size());
    zs.next_out  = out->empty() ? &none : out->data();
    zs.avail_out = static_cast<uInt>(out->size());
    const int rc = inflate(&zs, Z_FINISH);
    const uLong produced = zs.total_out;
    inflateEnd(&zs);
    return rc == Z_STREAM_END && produced == out->size();
}

} // namespace

bool read_entry(const std::string&         zip_path,
                const std::string&         name,
                std::size_t                max_size,
                std::vector<std::uint8_t>* out,
                std::string*               err)
{
    if (!out) return fail(err, "no output buffer");
    std::ifstream f(zip_path, std::ios::binary | std::ios::ate);
    if (!f) return fail(err, "cannot open archive");
    const std::streamoff end = f.tellg();
    if (end < static_cast<std::streamoff>(kEocdLen)) {
        return fail(err, "not a zip archive");
    }
    const std::uint64_t size = static_cast<std::uint64_t>(end);

    // The end-of-central-directory record is the last 22 bytes plus an
    // optional comment of up to 64 KiB; scan backwards for a signature
    // whose comment length runs exactly to the end of the file.
    const std::size_t tail_len = static_cast<std::size_t>(
        std::min<std::uint64_t>(size, kEocdLen + kMaxComment));
    std::vector<std::uint8_t> tail;
    if (!read_at(f, size - tail_len, tail_len, &tail)) {
        return fail(err, "read failed");
    }
    std::size_t eocd = std::string::npos;
    for (std::size_t i = tail_len - kEocdLen + 1; i-- > 0;) {
        if (le32(&tail[i]) == kEocdSig &&
            i + kEocdLen + le16(&tail[i + 20]) == tail_len) {
            eocd = i;
            break;
        }
    }
    if (eocd == std::string::npos) {
        return fail(err, "no end of central directory record");
    }
    const std::uint8_t* e        = &tail[eocd];
    const std::uint16_t disk     = le16(e + 4);
    const std::uint16_t cd_disk  = le16(e + 6);
    const std::uint16_t on_disk  = le16(e + 8);
    const std::uint16_t entries  = le16(e + 10);
    const std::uint32_t cd_size  = le32(e + 12);
    const std::uint32_t cd_off   = le32(e + 16);
    if (entries == 0xffff || cd_size == 0xffffffffu || cd_off == 0xffffffffu) {
        return fail(err, "zip64 archive");
    }
    if (disk != 0 || cd_disk != 0 || on_disk != entries) {
        return fail(err, "multi-disk archive");
    }
    const std::uint64_t eocd_off = size - tail_len + eocd;
    if (static_cast<std::uint64_t>(cd_off) + cd_size > eocd_off ||
        cd_size > kMaxCentralDir) {
        return fail(err, "central directory out of bounds");
    }
    std::vector<std::uint8_t> cd;
    if (!read_at(f, cd_off, cd_size, &cd)) return fail(err, "read failed");

    std::size_t pos = 0;
    for (std::uint16_t i = 0; i < entries; ++i) {
        if (cd.size() - pos < kCentralLen || le32(&cd[pos]) != kCentralSig) {
            return fail(err, "bad central directory entry");
        }
        const std::uint8_t* c      = &cd[pos];
        const std::uint16_t flags  = le16(c + 8);
        const std::uint16_t method = le16(c + 10);
        const std::uint32_t crc    = le32(c + 16);
        const std::uint32_t csize  = le32(c + 20);
        const std::uint32_t usize  = le32(c + 24);
        const std::uint16_t nlen   = le16(c + 28);
        const std::size_t   rec    = kCentralLen + nlen + le16(c + 30) +
                                     le16(c + 32);
        const std::uint32_t loff   = le32(c + 42);
        if (cd.size() - pos < rec) {
            return fail(err, "bad central directory entry");
        }
        const bool hit = nlen == name.size() &&
            std::memcmp(c + kCentralLen, name.data(), nlen) == 0;
        pos += rec;
        if (!hit) continue;

        if (flags & 0x1) return fail(err, "encrypted entry");
        if (csize == 0xffffffffu || usize == 0xffffffffu ||
            loff == 0xffffffffu) {
            return fail(err, "zip64 entry");
        }
        if (usize > max_size) return fail(err, "entry too large");
        if (method != 0 && method != 8) {
            return fail(err, "unsupported compression method");
        }
        if (method == 0 ? csize != usize : csize > kMaxPacked) {
            return fail(err, "bad entry sizes");
        }

        std::vector<std::uint8_t> lh;
        if (!read_at(f, loff, kLocalLen, &lh) || le32(lh.data()) != kLocalSig) {
            return fail(err, "bad local header");
        }
        const std::uint64_t data_off = static_cast<std::uint64_t>(loff) +
            kLocalLen + le16(&lh[26]) + le16(&lh[28]);
        if (data_off + csize > cd_off) {
            return fail(err, "entry data out of bounds");
        }
        std::vector<std::uint8_t> packed;
        if (!read_at(f, data_off, csize, &packed)) {
            return fail(err, "read failed");
        }

        std::vector<std::uint8_t> data;
        if (method == 0) {
            data = std::move(packed);
        } else {
            data.assign(usize, 0);
            if (!inflate_raw(packed, &data)) return fail(err, "inflate failed");
        }
        uLong sum = crc32(0L, Z_NULL, 0);
        if (!data.empty()) {
            sum = crc32(sum, data.data(), static_cast<uInt>(data.size()));
        }
        if (sum != crc) return fail(err, "crc mismatch");
        *out = std::move(data);
        return true;
    }
    return fail(err, "entry not found");
}

} // namespace obn::zip
