// Wire-format tests for the Filament Manager request bodies.
//
// Every expected string below is a verbatim copy of a request captured
// under mitmproxy from the stock plugin — 02.08.02.54 for the AMS and
// slot-mapping syncs, 02.08.03.52 for soft match — so a regression here
// means we have drifted from what the cloud expects.

#include "obn/cloud_filament.hpp"

#include <cstdio>
#include <string>

static int fail_count = 0;

#define CHECK_EQ(actual, expected)                                          \
    do {                                                                    \
        const std::string a_ = (actual);                                    \
        const std::string e_ = (expected);                                  \
        if (a_ != e_) {                                                     \
            std::fprintf(stderr, "FAIL %s:%d\n  expected: %s\n  actual:   %s\n", \
                         __FILE__, __LINE__, e_.c_str(), a_.c_str());       \
            ++fail_count;                                                   \
        }                                                                   \
    } while (0)

#define CHECK(cond)                                                         \
    do {                                                                    \
        if (!(cond)) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                         #cond);                                            \
            ++fail_count;                                                   \
        }                                                                   \
    } while (0)

#if ABI_VERSION >= 0x020802

namespace {

BBL::SlotMappingItem make_item()
{
    BBL::SlotMappingItem it;
    it.amsSn   = "19C06A610109584";
    it.slotId  = "1";
    it.spoolId = 6498430;
    it.rfid    = "C0150FF4913D492495F86923A61F8195";
    it.amsId   = 0;
    it.amsType = 3;
    return it;
}

} // namespace

// Capture C1: binding a spool carries both spoolId and rfid, and the item
// keys go out in ASCII order rather than struct-declaration order.
static void test_bind_body()
{
    BBL::SlotMappingsSyncParams p;
    p.devId = "22E8BJ610801473";
    p.mappings.push_back(make_item());

    CHECK_EQ(obn::cloud_filament::detail::build_slot_mappings_body(p),
             R"({"devId":"22E8BJ610801473","mappings":[{"amsId":0,)"
             R"("amsSn":"19C06A610109584","amsType":3,)"
             R"("rfid":"C0150FF4913D492495F86923A61F8195",)"
             R"("slotId":"1","spoolId":6498430}]})");
}

// Capture C2: an unbind zeroes spoolId and clears rfid, and stock renders
// both as JSON null while leaving amsId/amsType as literal numbers.
static void test_unbind_nulls()
{
    BBL::SlotMappingsSyncParams p;
    p.devId = "22E8BJ610801473";
    auto it = make_item();
    it.spoolId = 0;
    it.rfid.clear();
    it.amsId   = 0;
    it.amsType = 0;
    p.mappings.push_back(it);

    CHECK_EQ(obn::cloud_filament::detail::build_slot_mappings_body(p),
             R"({"devId":"22E8BJ610801473","mappings":[{"amsId":0,)"
             R"("amsSn":"19C06A610109584","amsType":0,)"
             R"("rfid":null,"slotId":"1","spoolId":null}]})");
}

// Capture C3c: several trays ride in one request.
static void test_batch_body()
{
    BBL::SlotMappingsSyncParams p;
    p.devId = "22E8BJ610801473";
    auto bind = make_item();
    bind.slotId  = "0";
    bind.spoolId = 10004295;
    bind.rfid.clear();
    p.mappings.push_back(bind);
    auto unbind = make_item();
    unbind.slotId  = "2";
    unbind.spoolId = 0;
    unbind.rfid.clear();
    p.mappings.push_back(unbind);

    CHECK_EQ(obn::cloud_filament::detail::build_slot_mappings_body(p),
             R"({"devId":"22E8BJ610801473","mappings":[)"
             R"({"amsId":0,"amsSn":"19C06A610109584","amsType":3,)"
             R"("rfid":null,"slotId":"0","spoolId":10004295},)"
             R"({"amsId":0,"amsSn":"19C06A610109584","amsType":3,)"
             R"("rfid":null,"slotId":"2","spoolId":null}]})");
}

// Capture C3a/C3b: stock posts an empty devId (and gets a 400) and an
// empty mappings array (and gets {"results":[]}), so neither is a local
// error for us either.
static void test_empty_dev_and_mappings_still_serialize()
{
    BBL::SlotMappingsSyncParams empty_mappings;
    empty_mappings.devId = "22E8BJ610801473";
    CHECK_EQ(obn::cloud_filament::detail::build_slot_mappings_body(empty_mappings),
             R"({"devId":"22E8BJ610801473","mappings":[]})");
    CHECK(obn::cloud_filament::detail::slot_mappings_valid(empty_mappings));

    BBL::SlotMappingsSyncParams empty_dev;
    empty_dev.mappings.push_back(make_item());
    CHECK_EQ(obn::cloud_filament::detail::build_slot_mappings_body(empty_dev),
             R"({"devId":"","mappings":[{"amsId":0,)"
             R"("amsSn":"19C06A610109584","amsType":3,)"
             R"("rfid":"C0150FF4913D492495F86923A61F8195",)"
             R"("slotId":"1","spoolId":6498430}]})");
    CHECK(obn::cloud_filament::detail::slot_mappings_valid(empty_dev));
}

// Bisected against stock: these five shapes make it refuse to issue any
// HTTP request at all and return -33 straight away.
static void test_validation_matches_stock()
{
    auto with = [](void (*mutate)(BBL::SlotMappingItem&)) {
        BBL::SlotMappingsSyncParams p;
        p.devId = "22E8BJ610801473";
        auto it = make_item();
        mutate(it);
        p.mappings.push_back(it);
        return obn::cloud_filament::detail::slot_mappings_valid(p);
    };

    CHECK(with([](BBL::SlotMappingItem& i) { (void)i; }));
    CHECK(!with([](BBL::SlotMappingItem& i) { i.amsSn.clear(); }));
    CHECK(!with([](BBL::SlotMappingItem& i) { i.slotId.clear(); }));
    CHECK(!with([](BBL::SlotMappingItem& i) { i.amsId = -1; }));
    CHECK(!with([](BBL::SlotMappingItem& i) { i.amsType = -1; }));
    CHECK(!with([](BBL::SlotMappingItem& i) { i.spoolId = -1; }));
    // Zero is a valid sentinel, not a rejected value.
    CHECK(with([](BBL::SlotMappingItem& i) { i.spoolId = 0; i.amsType = 0; }));
}

#endif // ABI_VERSION >= 0x020802

#if ABI_VERSION >= 0x020801

// The sibling endpoint deliberately does *not* null-map: an empty RFID and
// a zero netWeight go out verbatim. Captured side by side with the
// slot-mapping requests above.
static void test_ams_sync_keeps_empty_strings()
{
    BBL::AmsSyncParams p;
    p.devId = "22E8BJ610801473";
    BBL::AmsSyncItem it;
    it.amsSn   = "19C06A610109584";
    it.slotId  = "1";
    it.amsId   = 0;
    it.amsType = 3;
    p.items.push_back(it);

    CHECK_EQ(obn::cloud_filament::detail::build_ams_sync_body(p),
             R"({"devId":"22E8BJ610801473","items":[{"RFID":"","amsId":0,)"
             R"("amsSn":"19C06A610109584","amsType":3,"color":"","colorType":0,)"
             R"("colors":[],"createNew":false,"filamentId":"","filamentName":"",)"
             R"("filamentType":"","filamentVendor":"","isSupport":false,)"
             R"("netWeight":0,"note":"","slotId":"1","totalNetWeight":0,)"
             R"("trayIdName":""}]})");
}

#endif // ABI_VERSION >= 0x020801

#if ABI_VERSION >= 0x020803

// Capture S1 (stock 02.08.03.52): both keys present, percent-encoded, in
// devId-then-amsSn order.
static void test_soft_match_query()
{
    BBL::SoftMatchPendingParams p;
    p.devId = "22E8BJ610801473";
    p.amsSn = "OBNPROBEAMSSN";

    CHECK_EQ(obn::cloud_filament::detail::build_soft_match_pending_query(p),
             "?devId=22E8BJ610801473&amsSn=OBNPROBEAMSSN");
}

// Capture S2: an empty value drops its key entirely, so a params struct
// with nothing set produces no query string at all — and stock still
// issues that request (the cloud answers 200 with the whole queue).
static void test_soft_match_query_skips_empty()
{
    BBL::SoftMatchPendingParams none;
    CHECK_EQ(obn::cloud_filament::detail::build_soft_match_pending_query(none), "");

    // Capture S3: only amsSn set, so it takes the '?' separator. The value
    // is RFC3986-encoded (space, '+' and '&' all escaped).
    BBL::SoftMatchPendingParams ams_only;
    ams_only.amsSn = "A B+C&d";
    CHECK_EQ(obn::cloud_filament::detail::build_soft_match_pending_query(ams_only),
             "?amsSn=A%20B%2BC%26d");
}

// Capture S1: all three keys always go out, in declaration order.
static void test_soft_match_action_bodies()
{
    BBL::SoftMatchPendingActionParams p;
    p.action        = "accept";
    p.spoolId       = 999000001;
    p.targetSpoolId = 999000002;
    CHECK_EQ(obn::cloud_filament::detail::build_soft_match_action_body(p),
             R"({"action":"accept","spoolId":999000001,"targetSpoolId":999000002})");

    p.action = "link_other";
    CHECK_EQ(obn::cloud_filament::detail::build_soft_match_action_body(p),
             R"({"action":"link_other","spoolId":999000001,"targetSpoolId":999000002})");

    p.action = "create_new";
    CHECK_EQ(obn::cloud_filament::detail::build_soft_match_action_body(p),
             R"({"action":"create_new","spoolId":999000001,"targetSpoolId":999000002})");
}

// Capture S2: the actions that don't use targetSpoolId still carry it as a
// literal 0 — stock neither drops the key nor renders it as null.
static void test_soft_match_zero_target_stays()
{
    BBL::SoftMatchPendingActionParams p;
    p.action  = "accept";
    p.spoolId = 999000001;

    CHECK_EQ(obn::cloud_filament::detail::build_soft_match_action_body(p),
             R"({"action":"accept","spoolId":999000001,"targetSpoolId":0})");
}

#endif // ABI_VERSION >= 0x020803

int main()
{
#if ABI_VERSION >= 0x020802
    test_bind_body();
    test_unbind_nulls();
    test_batch_body();
    test_empty_dev_and_mappings_still_serialize();
    test_validation_matches_stock();
#endif
#if ABI_VERSION >= 0x020801
    test_ams_sync_keeps_empty_strings();
#endif
#if ABI_VERSION >= 0x020803
    test_soft_match_query();
    test_soft_match_query_skips_empty();
    test_soft_match_action_bodies();
    test_soft_match_zero_target_stays();
#endif

    if (fail_count) {
        std::fprintf(stderr, "filament_body_test: %d failure(s)\n", fail_count);
        return 1;
    }
    std::puts("filament_body_test: all checks passed");
    return 0;
}
