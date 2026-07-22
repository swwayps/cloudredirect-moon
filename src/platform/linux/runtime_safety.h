#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace LinuxRuntimeSafety {

struct CcmOffsets {
    uint32_t connHandle = 0;
    uint32_t sessionId = 0;
    uint32_t steamId = 0;

    explicit operator bool() const {
        return connHandle != 0 && sessionId != 0 && steamId != 0;
    }
};

class PublishedCcmOffsets {
public:
    void Publish(CcmOffsets offsets) {
        if (!offsets) {
            m_ready.store(false, std::memory_order_release);
            return;
        }
        m_connHandle.store(offsets.connHandle, std::memory_order_relaxed);
        m_sessionId.store(offsets.sessionId, std::memory_order_relaxed);
        m_steamId.store(offsets.steamId, std::memory_order_relaxed);
        m_ready.store(true, std::memory_order_release);
    }

    CcmOffsets Load() const {
        if (!m_ready.load(std::memory_order_acquire))
            return {};
        return {
            m_connHandle.load(std::memory_order_relaxed),
            m_sessionId.load(std::memory_order_relaxed),
            m_steamId.load(std::memory_order_relaxed),
        };
    }

private:
    std::atomic<uint32_t> m_connHandle{0};
    std::atomic<uint32_t> m_sessionId{0};
    std::atomic<uint32_t> m_steamId{0};
    std::atomic<bool> m_ready{false};
};

template <typename T>
inline T LoadUnaligned(const void* base, uint32_t offset) {
    T value{};
    std::memcpy(&value, static_cast<const uint8_t*>(base) + offset,
                sizeof(value));
    return value;
}

inline bool IsExpectedIndividualSteamId(uint64_t steamId,
                                        uint32_t expectedAccountId) {
    const uint8_t universe = static_cast<uint8_t>(steamId >> 56);
    const uint8_t accountType = static_cast<uint8_t>((steamId >> 52) & 0x0f);
    const uint32_t instance = static_cast<uint32_t>((steamId >> 32) & 0x000fffff);
    const uint32_t accountId = static_cast<uint32_t>(steamId);
    return universe >= 1 && universe < 5 && accountType == 1 && instance == 1 &&
           (expectedAccountId == 0 || accountId == expectedAccountId);
}

inline bool ShouldUpdateCapturedSession(bool alreadyCaptured,
                                        uint32_t currentSessionId,
                                        uint32_t candidateSessionId) {
    return !alreadyCaptured ||
           (currentSessionId == 0 && candidateSessionId != 0);
}

inline bool MatchBytes(const uint8_t* code, size_t size, size_t at,
                       const uint8_t* bytes, size_t count) {
    return at <= size && count <= size - at &&
           std::memcmp(code + at, bytes, count) == 0;
}

inline bool FindDisplacement(const uint8_t* code, size_t size,
                             const uint8_t* prefix, size_t prefixSize,
                             const uint8_t* suffix, size_t suffixSize,
                             uint32_t& displacement) {
    if (!code || size < prefixSize + sizeof(uint32_t) + suffixSize)
        return false;

    const size_t span = prefixSize + sizeof(uint32_t) + suffixSize;
    bool found = false;
    uint32_t resolved = 0;
    for (size_t at = 0; at <= size - span; ++at) {
        if (!MatchBytes(code, size, at, prefix, prefixSize) ||
            !MatchBytes(code, size, at + prefixSize + sizeof(uint32_t),
                        suffix, suffixSize))
            continue;

        uint32_t candidate = 0;
        std::memcpy(&candidate, code + at + prefixSize, sizeof(candidate));
        if (candidate == 0 || candidate >= 0x1000)
            continue;
        if (found && candidate != resolved)
            return false;
        resolved = candidate;
        found = true;
    }
    displacement = resolved;
    return found;
}

inline CcmOffsets ResolveCcmOffsets(const uint8_t* code, size_t size) {
    static constexpr uint8_t connPrefix[] = {0x8b, 0x96};
    static constexpr uint8_t connSuffix[] = {0x89, 0x44, 0x24, 0x0c, 0x85, 0xd2};
    static constexpr uint8_t sessionPrefix[] = {0x8b, 0xbe};
    static constexpr uint8_t sessionSuffix[] = {0x8b, 0x50, 0x48, 0x85, 0xd2};
    static constexpr uint8_t steamIdPrefix[] = {0xf3, 0x0f, 0x7e, 0x86};
    static constexpr uint8_t steamIdSuffix[] = {0x66, 0x0f, 0xef, 0xc8};

    CcmOffsets out;
    if (!FindDisplacement(code, size, connPrefix, sizeof(connPrefix),
                          connSuffix, sizeof(connSuffix), out.connHandle) ||
        !FindDisplacement(code, size, sessionPrefix, sizeof(sessionPrefix),
                          sessionSuffix, sizeof(sessionSuffix), out.sessionId) ||
        !FindDisplacement(code, size, steamIdPrefix, sizeof(steamIdPrefix),
                          steamIdSuffix, sizeof(steamIdSuffix), out.steamId))
        return {};
    return out;
}

template <typename Setter>
inline bool ApplySignalSafeCurlTimeouts(Setter&& setter, long timeout,
                                        long connectTimeout) {
    // Stable libcurl ABI values. The hook resolves libcurl dynamically and
    // intentionally does not depend on curl headers.
    if (setter(99, 1L) != 0) return false; // CURLOPT_NOSIGNAL
    if (setter(13, timeout) != 0) return false; // CURLOPT_TIMEOUT
    return setter(78, connectTimeout) == 0; // CURLOPT_CONNECTTIMEOUT
}

} // namespace LinuxRuntimeSafety
