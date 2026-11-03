// Tests for the .3mf project metadata reader (model_metadata.cpp): the
// <metadata name="..."> lookup and the MakerWorld DesignModelId check that
// cloud_print = cloud_for_makerworld_only relies on. Archives are built
// in-process; nothing here needs the Agent.

#include "obn/model_metadata.hpp"

#include "zip_fixture.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <system_error>

namespace fs = std::filesystem;
using obn_test::Bytes;
using obn_test::make_zip;

static int fail_count = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::fprintf(stderr, "FAIL %s:%d: %s\n",                      \
                         __FILE__, __LINE__, #cond);                       \
            ++fail_count;                                                  \
        }                                                                  \
    } while (0)

static fs::path g_dir;

static Bytes bytes_of(const std::string& s) { return Bytes(s.begin(), s.end()); }

static std::string write_file(const std::string& name, const Bytes& data)
{
    const fs::path p = g_dir / name;
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size()));
    return p.string();
}

// Head of 3D/3dmodel.model as Bambu Studio 02.08 writes it into a
// .gcode.3mf; `extra` goes among the other <metadata> elements.
static std::string model_xml(const std::string& extra)
{
    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
           "<model unit=\"millimeter\" xml:lang=\"en-US\" "
           "xmlns=\"http://schemas.microsoft.com/3dmanufacturing/core/2015/02\">\n"
           " <metadata name=\"Application\">BambuStudio-02.08.04.57</metadata>\n"
           " <metadata name=\"BambuStudio:3mfVersion\">1</metadata>\n" +
           extra +
           " <metadata name=\"Title\"></metadata>\n"
           " <resources/>\n <build/>\n</model>\n";
}

static std::string project_3mf(const std::string& file, const std::string& xml)
{
    return write_file(file, make_zip({
        {"Metadata/plate_1.png", bytes_of(std::string(512, 'p'))},
        {"3D/3dmodel.model", bytes_of(xml), 8},
        {"Metadata/slice_info.config", bytes_of("<config/>"), 8},
    }));
}

static void test_value_lookup()
{
    using obn::model_metadata::value;
    const std::string xml = model_xml(
        " <!-- <metadata name=\"DesignModelId\">commented</metadata> -->\n"
        " <metadata name=\"Designer\"></metadata>\n"
        " <metadata name=\"Copyright\"/>\n"
        " <metadata name=\"Description\">a &amp; b &#x263A;</metadata>\n"
        " <metadata name=\"DesignModelId\">USeb7cfca8b03a55</metadata>\n");
    CHECK(value(xml, "DesignModelId") == "USeb7cfca8b03a55");
    CHECK(value(xml, "Application") == "BambuStudio-02.08.04.57");
    CHECK(value(xml, "Description") == "a & b \xE2\x98\xBA");
    CHECK(value(xml, "Designer").empty());
    CHECK(value(xml, "Copyright").empty());
    CHECK(value(xml, "DesignProfileId").empty());
    CHECK(value(model_xml(
        " <!-- <metadata name=\"DesignModelId\">x</metadata> -->\n"),
        "DesignModelId").empty());
    CHECK(value("", "Title").empty());
}

static void test_makerworld_project()
{
    std::string id = "stale", err;
    const std::string path = project_3mf("makerworld.gcode.3mf", model_xml(
        " <metadata name=\"DesignModelId\">USeb7cfca8b03a55</metadata>\n"
        " <metadata name=\"DesignProfileId\">1058875782</metadata>\n"
        " <metadata name=\"DesignRegion\">US</metadata>\n"));
    CHECK(obn::model_metadata::makerworld_design_id(path, &id, &err));
    CHECK(id == "USeb7cfca8b03a55");
}

static void test_local_project()
{
    // A project sliced from the user's own model: no DesignModelId at all,
    // or (hand-edited) an empty one.
    std::string id = "stale";
    const std::string bare = project_3mf("local.gcode.3mf", model_xml(
        " <metadata name=\"DesignerUserId\">3575315859</metadata>\n"));
    CHECK(obn::model_metadata::makerworld_design_id(bare, &id));
    CHECK(id.empty());

    id = "stale";
    const std::string empty = project_3mf("empty-id.gcode.3mf", model_xml(
        " <metadata name=\"DesignModelId\"></metadata>\n"));
    CHECK(obn::model_metadata::makerworld_design_id(empty, &id));
    CHECK(id.empty());
}

static void test_unreadable_project()
{
    std::string id = "stale", err;
    const std::string no_model = write_file("no-model.3mf", make_zip({
        {"Metadata/plate_1.png", bytes_of(std::string(64, 'p'))},
    }));
    CHECK(!obn::model_metadata::makerworld_design_id(no_model, &id, &err));
    CHECK(!err.empty());
    CHECK(id == "stale");

    err.clear();
    const std::string not_zip = write_file("not-a-zip.3mf", bytes_of("G28\nG1 X0\n"));
    CHECK(!obn::model_metadata::makerworld_design_id(not_zip, &id, &err));
    CHECK(!err.empty());

    err.clear();
    CHECK(!obn::model_metadata::makerworld_design_id(
        (g_dir / "missing.3mf").string(), &id, &err));
    CHECK(!err.empty());
}

int main(int argc, char** argv)
{
    // model_metadata_test <file.3mf>...: print each file's DesignModelId.
    if (argc > 1) {
        int rc = 0;
        for (int i = 1; i < argc; ++i) {
            std::string id, err;
            if (obn::model_metadata::makerworld_design_id(argv[i], &id, &err)) {
                std::printf("%s: DesignModelId='%s'\n", argv[i], id.c_str());
            } else {
                std::printf("%s: unreadable (%s)\n", argv[i], err.c_str());
                rc = 1;
            }
        }
        return rc;
    }

    std::random_device rd;
    g_dir = fs::temp_directory_path() /
            ("obn-model-metadata-test-" + std::to_string(rd()));
    fs::create_directories(g_dir);

    test_value_lookup();
    test_makerworld_project();
    test_local_project();
    test_unreadable_project();

    std::error_code ec;
    fs::remove_all(g_dir, ec);
    if (fail_count) {
        std::fprintf(stderr, "%d test(s) failed\n", fail_count);
        return 1;
    }
    std::fprintf(stdout, "model_metadata_test: ok\n");
    return 0;
}
