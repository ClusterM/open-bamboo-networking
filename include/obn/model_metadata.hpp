#pragma once

// Project metadata of a Bambu Studio / Orca Slicer .3mf: the
// <metadata name="..."> elements of 3D/3dmodel.model and the plate list of
// Metadata/slice_info.config.

#include <string>
#include <vector>

namespace obn::model_metadata {

inline constexpr const char* kModelMember     = "3D/3dmodel.model";
inline constexpr const char* kSliceInfoMember = "Metadata/slice_info.config";

// Text of the first <metadata name="`name`"> element of a 3dmodel.model,
// entities decoded. Empty when absent, empty or self-closing; an element
// inside a comment, CDATA section or processing instruction does not count.
std::string value(const std::string& xml, const std::string& name);

// Plates sliced into the file: the first <metadata key="index" value="N"/> of
// each <plate> in Metadata/slice_info.config. Comments are not skipped; Studio
// writes none there.
std::vector<int> sliced_plates(const std::string& xml);

// MakerWorld model id (DesignModelId) of the local .3mf at `path_3mf`;
// empty `*id` for a project that does not come from MakerWorld. False, with
// `*err` (optional) set, only when 3D/3dmodel.model cannot be read.
bool makerworld_design_id(const std::string& path_3mf, std::string* id,
                          std::string* err = nullptr);

} // namespace obn::model_metadata
