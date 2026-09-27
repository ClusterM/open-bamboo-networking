#pragma once
// Cross-platform endian conversion macros (htobe16/32/64, be*toh, htole*, le*toh).
// Use this header instead of <endian.h> in any translation unit that must
// build on Linux, macOS, and Windows.

#if defined(__linux__)
#  include <endian.h>

#elif defined(__APPLE__)
#  include <machine/endian.h>
#  include <libkern/OSByteOrder.h>
#  define htobe16(x)  OSSwapHostToBigInt16(x)
#  define htobe32(x)  OSSwapHostToBigInt32(x)
#  define htobe64(x)  OSSwapHostToBigInt64(x)
#  define be16toh(x)  OSSwapBigToHostInt16(x)
#  define be32toh(x)  OSSwapBigToHostInt32(x)
#  define be64toh(x)  OSSwapBigToHostInt64(x)
#  define htole16(x)  OSSwapHostToLittleInt16(x)
#  define htole32(x)  OSSwapHostToLittleInt32(x)
#  define htole64(x)  OSSwapHostToLittleInt64(x)
#  define le16toh(x)  OSSwapLittleToHostInt16(x)
#  define le32toh(x)  OSSwapLittleToHostInt32(x)
#  define le64toh(x)  OSSwapLittleToHostInt64(x)

#elif defined(_WIN32)
// Windows targets are always little-endian (x86/x86-64/ARM in LE mode).
#  include <stdlib.h>
#  define htobe16(x)  _byteswap_ushort(static_cast<unsigned short>(x))
#  define htobe32(x)  _byteswap_ulong(static_cast<unsigned long>(x))
#  define htobe64(x)  _byteswap_uint64(static_cast<unsigned __int64>(x))
#  define be16toh(x)  _byteswap_ushort(static_cast<unsigned short>(x))
#  define be32toh(x)  _byteswap_ulong(static_cast<unsigned long>(x))
#  define be64toh(x)  _byteswap_uint64(static_cast<unsigned __int64>(x))
#  define htole16(x)  (x)
#  define htole32(x)  (x)
#  define htole64(x)  (x)
#  define le16toh(x)  (x)
#  define le32toh(x)  (x)
#  define le64toh(x)  (x)

#else
#  error "endian_compat.hpp: unsupported platform — add macros for your platform here"
#endif
