#include "runtime_safety.h"

#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

static int g_failures = 0;

#define CHECK(cond, message) do { \
    if (!(cond)) { \
        std::fprintf(stderr, "FAIL: %s\n", message); \
        ++g_failures; \
    } \
} while (0)

static void AppendDisp32(std::vector<uint8_t>& code, size_t at,
                         const std::vector<uint8_t>& prefix, uint32_t displacement,
                         const std::vector<uint8_t>& suffix) {
    std::memcpy(code.data() + at, prefix.data(), prefix.size());
    at += prefix.size();
    std::memcpy(code.data() + at, &displacement, sizeof(displacement));
    at += sizeof(displacement);
    std::memcpy(code.data() + at, suffix.data(), suffix.size());
}

static std::vector<uint8_t> MakeSendFunction(uint32_t conn, uint32_t session,
                                              uint32_t steamId) {
    std::vector<uint8_t> code(0x140, 0x90);
    AppendDisp32(code, 0x1a, {0x8b, 0x96}, conn,
                 {0x89, 0x44, 0x24, 0x0c, 0x85, 0xd2});
    AppendDisp32(code, 0x2f, {0x8b, 0xbe}, session,
                 {0x8b, 0x50, 0x48, 0x85, 0xd2});
    AppendDisp32(code, 0x77, {0xf3, 0x0f, 0x7e, 0x86}, steamId,
                 {0x66, 0x0f, 0xef, 0xc8});
    return code;
}

static void TestClientLayout(uint32_t conn, uint32_t session, uint32_t steamId) {
    auto code = MakeSendFunction(conn, session, steamId);
    auto got = LinuxRuntimeSafety::ResolveCcmOffsets(code.data(), code.size());
    CHECK(static_cast<bool>(got), "valid CCM layout must resolve");
    CHECK(got.connHandle == conn, "connection-handle displacement must match code");
    CHECK(got.sessionId == session, "session-id displacement must match code");
    CHECK(got.steamId == steamId, "SteamID displacement must match code");
}

static void TestInvalidLayoutRejected() {
    std::vector<uint8_t> code(0x140, 0x90);
    auto got = LinuxRuntimeSafety::ResolveCcmOffsets(code.data(), code.size());
    CHECK(!static_cast<bool>(got), "noise must not resolve as a CCM layout");
}

static void TestInvalidCandidateSkipped() {
    auto code = MakeSendFunction(0x4f8, 0xd8, 0x15a);
    AppendDisp32(code, 0, {0x8b, 0x96}, 0x2000,
                 {0x89, 0x44, 0x24, 0x0c, 0x85, 0xd2});
    auto got = LinuxRuntimeSafety::ResolveCcmOffsets(code.data(), code.size());
    CHECK(got.connHandle == 0x4f8,
          "an out-of-range candidate must not hide a later valid displacement");
}

static void TestAmbiguousLayoutRejected() {
    auto code = MakeSendFunction(0x4f8, 0xd8, 0x15a);
    AppendDisp32(code, 0xa0, {0x8b, 0x96}, 0x4fc,
                 {0x89, 0x44, 0x24, 0x0c, 0x85, 0xd2});
    auto got = LinuxRuntimeSafety::ResolveCcmOffsets(code.data(), code.size());
    CHECK(!static_cast<bool>(got),
          "conflicting CCM displacements must fail closed");
}

static void TestCurlTimeoutsDisableSignals() {
    std::vector<std::pair<int, long>> options;
    bool configured = LinuxRuntimeSafety::ApplySignalSafeCurlTimeouts(
        [&options](int option, long value) {
            options.emplace_back(option, value);
            return 0;
        },
        30L, 5L);

    CHECK(configured, "supported signal-safe timeout setup must succeed");
    CHECK(options.size() == 3, "signal-safe timeout setup must apply three options");
    if (options.size() == 3) {
        CHECK(options[0] == std::make_pair(99, 1L),
              "CURLOPT_NOSIGNAL must be enabled before timeout options");
        CHECK(options[1] == std::make_pair(13, 30L),
              "CURLOPT_TIMEOUT must keep the request timeout");
        CHECK(options[2] == std::make_pair(78, 5L),
              "CURLOPT_CONNECTTIMEOUT must keep the connection timeout");
    }
}

static void TestCurlNosignalFailureStopsSetup() {
    std::vector<std::pair<int, long>> options;
    bool configured = LinuxRuntimeSafety::ApplySignalSafeCurlTimeouts(
        [&options](int option, long value) {
            options.emplace_back(option, value);
            return option == 99 ? 1 : 0;
        },
        30L, 5L);

    CHECK(!configured, "rejected CURLOPT_NOSIGNAL must fail the setup");
    CHECK(options.size() == 1,
          "timeout options must not be enabled after CURLOPT_NOSIGNAL fails");
}

static void TestPublishedOffsets() {
    LinuxRuntimeSafety::PublishedCcmOffsets published;
    CHECK(!published.Load(), "CCM offsets must start unpublished");
    published.Publish({0x4f8, 0xd8, 0x15a});
    auto got = published.Load();
    CHECK(got.connHandle == 0x4f8 && got.sessionId == 0xd8 && got.steamId == 0x15a,
          "published CCM offsets must be observed as one ready layout");
}

static void TestUnalignedLoad() {
    std::vector<uint8_t> bytes(16, 0);
    const uint64_t expected = 0x11000013ebc27f9ull;
    std::memcpy(bytes.data() + 1, &expected, sizeof(expected));
    CHECK(LinuxRuntimeSafety::LoadUnaligned<uint64_t>(bytes.data(), 1) == expected,
          "unaligned CCM fields must be copied safely");
}

static void TestSteamIdValidation() {
    constexpr uint32_t accountId = 0x3ebc27f9;
    constexpr uint64_t steamId = (1ull << 56) | (1ull << 52) |
                                 (1ull << 32) | accountId;
    CHECK(LinuxRuntimeSafety::IsExpectedIndividualSteamId(steamId, accountId),
          "logged-in individual SteamID must validate");
    CHECK(LinuxRuntimeSafety::IsExpectedIndividualSteamId(steamId, 0),
          "SteamID may validate before the expected account is known");
    CHECK(!LinuxRuntimeSafety::IsExpectedIndividualSteamId(steamId, accountId + 1),
          "SteamID for another account must be rejected");
    CHECK(!LinuxRuntimeSafety::IsExpectedIndividualSteamId(steamId << 16, 0),
          "shifted SteamID bytes must be rejected");
    CHECK(!LinuxRuntimeSafety::IsExpectedIndividualSteamId(
              (5ull << 56) | (steamId & 0x00ffffffffffffffull), accountId),
          "max/sentinel Steam universe must be rejected");
    CHECK(!LinuxRuntimeSafety::IsExpectedIndividualSteamId(
              (steamId & ~(0xfull << 52)) | (7ull << 52), accountId),
          "non-individual Steam account type must be rejected");
    CHECK(!LinuxRuntimeSafety::IsExpectedIndividualSteamId(
              (steamId & ~(0xfffffull << 32)) | (2ull << 32), accountId),
          "non-desktop individual instance must be rejected");
}

static void TestSessionRefresh() {
    CHECK(LinuxRuntimeSafety::ShouldUpdateCapturedSession(false, 0, 0),
          "the current Steam client may initially publish session zero");
    CHECK(!LinuxRuntimeSafety::ShouldUpdateCapturedSession(true, 0, 0),
          "repeated zero sessions must not be republished");
    CHECK(LinuxRuntimeSafety::ShouldUpdateCapturedSession(true, 0, 42),
          "a later nonzero session must replace an initial zero");
    CHECK(!LinuxRuntimeSafety::ShouldUpdateCapturedSession(true, 42, 43),
          "an established session must remain stable");
}

static void TestSteamclientBinary(const char* path, const char* offsetText,
                                  const char* connText, const char* sessionText,
                                  const char* steamIdText) {
    std::ifstream input(path, std::ios::binary);
    CHECK(input.good(), "steamclient fixture must open");
    if (!input.good()) return;

    const auto offset = static_cast<std::streamoff>(std::strtoull(offsetText, nullptr, 0));
    std::vector<uint8_t> code(0x140);
    input.seekg(offset);
    input.read(reinterpret_cast<char*>(code.data()), code.size());
    CHECK(input.gcount() == static_cast<std::streamsize>(code.size()),
          "steamclient fixture must contain the full function window");
    if (input.gcount() != static_cast<std::streamsize>(code.size())) return;

    auto got = LinuxRuntimeSafety::ResolveCcmOffsets(code.data(), code.size());
    CHECK(got.connHandle == std::strtoul(connText, nullptr, 0),
          "live connection-handle displacement must resolve");
    CHECK(got.sessionId == std::strtoul(sessionText, nullptr, 0),
          "live session-id displacement must resolve");
    CHECK(got.steamId == std::strtoul(steamIdText, nullptr, 0),
          "live SteamID displacement must resolve");
}

int main(int argc, char** argv) {
    TestClientLayout(0x4fc, 0xd8, 0x15c);
    TestClientLayout(0x4f8, 0xd8, 0x15a);
    TestInvalidLayoutRejected();
    TestInvalidCandidateSkipped();
    TestAmbiguousLayoutRejected();
    TestCurlTimeoutsDisableSignals();
    TestCurlNosignalFailureStopsSetup();
    TestPublishedOffsets();
    TestUnalignedLoad();
    TestSteamIdValidation();
    TestSessionRefresh();
    if (argc == 6)
        TestSteamclientBinary(argv[1], argv[2], argv[3], argv[4], argv[5]);

    if (g_failures != 0) {
        std::fprintf(stderr, "%d test(s) failed\n", g_failures);
        return 1;
    }
    std::puts("linux runtime safety tests passed");
    return 0;
}
