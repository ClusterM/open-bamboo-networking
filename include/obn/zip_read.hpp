#pragma once

// Reads a single entry out of a local ZIP archive (a .3mf project).
//
// Covers what Bambu Studio and Orca Slicer write: stored or deflated
// entries, with or without data descriptors (sizes always come from the
// central directory). Zip64, encrypted and multi-disk archives are
// rejected.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace obn::zip {

// Reads entry `name` (exact match, '/' separators) of the archive at
// `zip_path` into `*out`. Returns false and leaves `*out` untouched when
// the archive cannot be parsed, the entry is missing, encrypted, uses a
// method other than stored / deflate, would inflate to more than
// `max_size` bytes, or fails its CRC-32 check. `*err` (optional) gets a
// short reason.
bool read_entry(const std::string&         zip_path,
                const std::string&         name,
                std::size_t                max_size,
                std::vector<std::uint8_t>* out,
                std::string*               err = nullptr);

} // namespace obn::zip
