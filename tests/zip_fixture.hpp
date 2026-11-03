#pragma once

// In-memory ZIP archives laid out like Bambu Studio's 3MF export, for tests
// of the .3mf readers.

#include <zlib.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace obn_test {

using Bytes = std::vector<std::uint8_t>;

inline void put16(Bytes& b, std::uint32_t v)
{
    b.push_back(static_cast<std::uint8_t>(v & 0xff));
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xff));
}

inline void put32(Bytes& b, std::uint32_t v)
{
    put16(b, v & 0xffff);
    put16(b, v >> 16);
}

inline void put_str(Bytes& b, const std::string& s)
{
    b.insert(b.end(), s.begin(), s.end());
}

// Raw deflate; with `sync_every` > 0 the input is flushed (Z_SYNC_FLUSH)
// every that many bytes, as streaming writers do, which can make the
// output larger than compressBound().
inline Bytes deflate_raw(const Bytes& in, std::size_t sync_every = 0)
{
    z_stream zs{};
    deflateInit2(&zs, Z_BEST_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8,
                 Z_DEFAULT_STRATEGY);
    Bytes out(compressBound(static_cast<uLong>(in.size())) + 16 +
              (sync_every ? 8 * (in.size() / sync_every + 1) : 0));
    zs.next_out  = out.data();
    zs.avail_out = static_cast<uInt>(out.size());
    std::size_t pos = 0;
    int rc = Z_OK;
    do {
        const std::size_t n =
            sync_every ? std::min(sync_every, in.size() - pos) : in.size() - pos;
        zs.next_in  = const_cast<Bytef*>(in.data() + pos);
        zs.avail_in = static_cast<uInt>(n);
        pos += n;
        rc = deflate(&zs, pos < in.size() ? Z_SYNC_FLUSH : Z_FINISH);
    } while (pos < in.size());
    out.resize(zs.total_out);
    deflateEnd(&zs);
    if (rc != Z_STREAM_END) {
        std::fprintf(stderr, "zip_fixture: deflate failed (%d)\n", rc);
        std::abort();
    }
    return out;
}

struct Entry {
    std::string   name;
    Bytes         data;
    std::uint16_t method      = 0;     // 0 stored, 8 deflate
    bool          descriptor  = true;  // Studio sets flag bit 3 on every entry
    std::uint16_t extra_flags = 0;
    bool          bad_crc     = false;
    int           method_tag  = -1;    // >= 0: method written to the headers
    std::size_t   sync_every  = 0;     // deflate: Z_SYNC_FLUSH interval
};

// Writes entries the way Bambu Studio's 3MF export lays them out: local
// header with zero sizes + 4-byte extra field, data, data descriptor; the
// central directory carries the real sizes.
inline Bytes make_zip(const std::vector<Entry>& entries,
                      const std::string& comment = {},
                      bool zip64_marker = false)
{
    Bytes z, cd;
    for (const Entry& e : entries) {
        const Bytes packed =
            e.method == 8 ? deflate_raw(e.data, e.sync_every) : e.data;
        std::uint32_t crc = static_cast<std::uint32_t>(
            crc32(crc32(0L, Z_NULL, 0), e.data.data(),
                  static_cast<uInt>(e.data.size())));
        if (e.bad_crc) crc ^= 1u;
        const std::uint16_t flags = static_cast<std::uint16_t>(
            (e.descriptor ? 0x8 : 0) | 0x800 | e.extra_flags);
        const std::uint16_t method = e.method_tag >= 0
            ? static_cast<std::uint16_t>(e.method_tag) : e.method;
        const std::uint32_t off = static_cast<std::uint32_t>(z.size());
        const auto csize = static_cast<std::uint32_t>(packed.size());
        const auto usize = static_cast<std::uint32_t>(e.data.size());

        put32(z, 0x04034b50); put16(z, 20); put16(z, flags); put16(z, method);
        put16(z, 0); put16(z, 0);
        put32(z, e.descriptor ? 0 : crc);
        put32(z, e.descriptor ? 0 : csize);
        put32(z, e.descriptor ? 0 : usize);
        put16(z, static_cast<std::uint32_t>(e.name.size())); put16(z, 4);
        put_str(z, e.name);
        put16(z, 0xcafe); put16(z, 0);  // extra field only in the local header
        z.insert(z.end(), packed.begin(), packed.end());
        if (e.descriptor) {
            put32(z, 0x08074b50); put32(z, crc); put32(z, csize); put32(z, usize);
        }

        put32(cd, 0x02014b50); put16(cd, 20); put16(cd, 20); put16(cd, flags);
        put16(cd, method); put16(cd, 0); put16(cd, 0);
        put32(cd, crc); put32(cd, csize); put32(cd, usize);
        put16(cd, static_cast<std::uint32_t>(e.name.size()));
        put16(cd, 0); put16(cd, 0); put16(cd, 0); put16(cd, 0); put32(cd, 0);
        put32(cd, off);
        put_str(cd, e.name);
    }
    const std::uint32_t cd_off = static_cast<std::uint32_t>(z.size());
    z.insert(z.end(), cd.begin(), cd.end());
    put32(z, 0x06054b50); put16(z, 0); put16(z, 0);
    put16(z, static_cast<std::uint32_t>(entries.size()));
    put16(z, static_cast<std::uint32_t>(entries.size()));
    put32(z, static_cast<std::uint32_t>(cd.size()));
    put32(z, zip64_marker ? 0xffffffffu : cd_off);
    put16(z, static_cast<std::uint32_t>(comment.size()));
    put_str(z, comment);
    return z;
}

} // namespace obn_test
