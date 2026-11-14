#include "steam_kv_injector.h"
#include "log.h"

#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <dlfcn.h>
#include <link.h>
#include <cstdio>
#include <cstring>
#include <csetjmp>
#include <csignal>
#endif

namespace SteamKvInjector {

// Plausibility bounds for UFS quota; reject pointer-sized garbage reads.
static constexpr uint64_t kMaxPlausibleQuotaBytes = 1024ULL * 1024 * 1024 * 1024; // 1 TiB
static constexpr uint64_t kMaxPlausibleMaxFiles   = 10ULL * 1000 * 1000;          // 10M

static bool QuotaValueLooksValid(uint64_t quota, uint64_t files) {
    if (quota == 0 || files == 0) return false;
    if (quota > kMaxPlausibleQuotaBytes) return false;
    if (files > kMaxPlausibleMaxFiles)   return false;
    return true;
}

#ifdef _WIN32

using GetAppInfoFn = void* (__fastcall*)(void* cache, uint32_t appId);
using GetSectionFn = void* (__fastcall*)(void* appInfo, uint32_t sectionId);
using KvFindKeyFn = void* (__fastcall*)(void* parent, const char* name, uint8_t bCreate, void* outChild);
using ReadConfigU64Fn = uint64_t (__fastcall*)(void* cache, uint64_t appId, uint32_t sectionId, const char* keyName, uint64_t defaultVal);
using KvGetUint64Fn = uint64_t (__fastcall*)(void* kvNode, uint64_t defaultVal, void* outStatus);
using KvGetIntFn = int (__fastcall*)(void* kvNode, int defaultVal, void* outStatus);
using KvSetUint64Fn = void (__fastcall*)(void* kvNode, uint64_t value);
using KvSetIntFn = void (__fastcall*)(void* kvNode, int value);
using KvSetStringFn = void (__fastcall*)(void* kvNode, const char* value);

struct Resolved {
    void** globalEnginePtrPtr = nullptr;
    GetAppInfoFn     getAppInfo = nullptr;
    GetSectionFn     getSection = nullptr;
    ReadConfigU64Fn  readConfigU64 = nullptr;
    KvFindKeyFn      kvFindKey = nullptr;
    KvGetUint64Fn    kvGetUint64 = nullptr;
    KvGetIntFn       kvGetInt = nullptr;
    KvSetUint64Fn    kvSetUint64 = nullptr;
    KvSetIntFn       kvSetInt = nullptr;
    KvSetStringFn    kvSetString = nullptr;
    uint32_t         appInfoCacheOffset = 0;
};

static Resolved g_r;
static ResolvedKvAddrs g_configured;
static std::atomic<bool> g_configuredSet{false};
static std::atomic<bool> g_ready{false};
static std::once_flag g_initOnce;

// sectionId 10 = "ufs" in the app config KV tree.
static constexpr uint32_t kSectionUfs = 10;

static void* GetCachePtr() {
    if (!g_r.globalEnginePtrPtr) return nullptr;
    void* engine = *g_r.globalEnginePtrPtr;
    if (!engine) return nullptr;
    return reinterpret_cast<uint8_t*>(engine) + g_r.appInfoCacheOffset;
}

void Configure(const ResolvedKvAddrs& addrs) {
    g_configured = addrs;
    g_configuredSet.store(true, std::memory_order_release);
}

bool Init() {
    bool success = false;
    std::call_once(g_initOnce, [&]() {
        if (!g_configuredSet.load(std::memory_order_acquire)) {
            LOG("[KvInjector] Init: Configure() not called; resolver addresses required");
            return;
        }

        const ResolvedKvAddrs& c = g_configured;
        if (!c.globalEnginePtrPtr || !c.getAppInfo || !c.getSection ||
            !c.readConfigU64 || !c.kvFindKey || !c.kvGetUint64 || !c.kvGetInt ||
            !c.kvSetUint64 || !c.kvSetInt || !c.kvSetString || !c.appInfoCacheOffset) {
            LOG("[KvInjector] Init: resolver supplied incomplete addresses "
                "(engine=%p getAppInfo=0x%llX getSection=0x%llX readCfg=0x%llX "
                "find=0x%llX getU64=0x%llX getInt=0x%llX setU64=0x%llX setInt=0x%llX "
                "setStr=0x%llX cacheOff=0x%X); aborting",
                c.globalEnginePtrPtr, (uint64_t)c.getAppInfo, (uint64_t)c.getSection,
                (uint64_t)c.readConfigU64, (uint64_t)c.kvFindKey, (uint64_t)c.kvGetUint64,
                (uint64_t)c.kvGetInt, (uint64_t)c.kvSetUint64, (uint64_t)c.kvSetInt,
                (uint64_t)c.kvSetString, c.appInfoCacheOffset);
            return;
        }

        g_r.globalEnginePtrPtr = c.globalEnginePtrPtr;
        g_r.getAppInfo    = reinterpret_cast<GetAppInfoFn>(c.getAppInfo);
        g_r.getSection    = reinterpret_cast<GetSectionFn>(c.getSection);
        g_r.readConfigU64 = reinterpret_cast<ReadConfigU64Fn>(c.readConfigU64);
        g_r.kvFindKey     = reinterpret_cast<KvFindKeyFn>(c.kvFindKey);
        g_r.kvGetUint64   = reinterpret_cast<KvGetUint64Fn>(c.kvGetUint64);
        g_r.kvGetInt      = reinterpret_cast<KvGetIntFn>(c.kvGetInt);
        g_r.kvSetUint64   = reinterpret_cast<KvSetUint64Fn>(c.kvSetUint64);
        g_r.kvSetInt      = reinterpret_cast<KvSetIntFn>(c.kvSetInt);
        g_r.kvSetString   = reinterpret_cast<KvSetStringFn>(c.kvSetString);
        g_r.appInfoCacheOffset = c.appInfoCacheOffset;

        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery((LPCVOID)g_r.getAppInfo, &mbi, sizeof(mbi)) == 0 ||
            mbi.State != MEM_COMMIT ||
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                            PAGE_EXECUTE_WRITECOPY)) == 0) {
            LOG("[KvInjector] Init: getAppInfo at %p not in executable memory; aborting",
                g_r.getAppInfo);
            return;
        }

        LOG("[KvInjector] Init: using resolver addresses (engine global @ %p, cacheOff 0x%X)",
            g_r.globalEnginePtrPtr, g_r.appInfoCacheOffset);
        g_ready.store(true, std::memory_order_release);
        success = true;
    });
    return success || g_ready.load(std::memory_order_acquire);
}

bool IsReady() {
    return g_ready.load(std::memory_order_acquire);
}

bool ReadAppQuota(uint32_t appId, uint64_t& outQuotaBytes, uint32_t& outMaxNumFiles) {
    if (!g_ready.load(std::memory_order_acquire)) return false;

    void* cache = GetCachePtr();
    if (!cache) return false;

    uint64_t quota = g_r.readConfigU64(cache, appId, kSectionUfs, "quota", 0);
    uint64_t files = g_r.readConfigU64(cache, appId, kSectionUfs, "maxnumfiles", 0);

    if (!QuotaValueLooksValid(quota, files)) {
        if (quota != 0 || files != 0) {
            LOG("[KvInjector] ReadAppQuota app=%u: implausible quota=%llu files=%llu",
                appId, (unsigned long long)quota, (unsigned long long)files);
        }
        outQuotaBytes = 0;
        outMaxNumFiles = 0;
        return true;
    }

    outQuotaBytes  = quota;
    outMaxNumFiles = static_cast<uint32_t>(files);
    return true;
}

bool InjectAppQuota(uint32_t appId, uint64_t quotaBytes, uint32_t maxNumFiles) {
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (quotaBytes == 0 || maxNumFiles == 0) {
        LOG("[KvInjector] InjectAppQuota app=%u: refusing zero values "
            "(quota=%llu files=%u)",
            appId, (unsigned long long)quotaBytes, maxNumFiles);
        return false;
    }

    void* cache = GetCachePtr();
    if (!cache) {
        LOG("[KvInjector] InjectAppQuota app=%u: cache pointer null", appId);
        return false;
    }

    void* appInfo = g_r.getAppInfo(cache, appId);
    if (!appInfo) {
        LOG("[KvInjector] InjectAppQuota app=%u: no app info entry "
            "(PICS has never returned for this app)", appId);
        return false;
    }

    void* ufs = g_r.getSection(appInfo, kSectionUfs);
    if (!ufs) {
        LOG("[KvInjector] InjectAppQuota app=%u: ufs section missing "
            "(app config has no cloud config at all)", appId);
        // No ufs section -> AutoCloud short-circuits with "no config data"; saves stay intact
        return false;
    }

    // Preserve Steam's PICS values only if plausible; overwrite garbage.
    uint64_t existingQuota = g_r.readConfigU64(cache, appId, kSectionUfs, "quota", 0);
    uint64_t existingFiles = g_r.readConfigU64(cache, appId, kSectionUfs, "maxnumfiles", 0);
    bool existingValid = QuotaValueLooksValid(existingQuota, existingFiles);

    bool wroteQuota = false;
    bool wroteFiles = false;

    bool quotaNeedsWrite = (existingQuota == 0) ||
                           (existingQuota > kMaxPlausibleQuotaBytes) || !existingValid;
    bool filesNeedsWrite = (existingFiles == 0) ||
                           (existingFiles > kMaxPlausibleMaxFiles) || !existingValid;

    if (quotaNeedsWrite) {
        void* quotaKv = g_r.kvFindKey(ufs, "quota", 1, nullptr);
        if (quotaKv) {
            g_r.kvSetUint64(quotaKv, quotaBytes);
            wroteQuota = true;
        }
    }
    if (filesNeedsWrite) {
        void* filesKv = g_r.kvFindKey(ufs, "maxnumfiles", 1, nullptr);
        if (filesKv) {
            g_r.kvSetInt(filesKv, static_cast<int>(maxNumFiles));
            wroteFiles = true;
        }
    }

    if (wroteQuota || wroteFiles) {
        LOG("[KvInjector] InjectAppQuota app=%u: injected quota=%llu files=%u "
            "(wroteQuota=%d wroteFiles=%d, existingQuota=%llu existingFiles=%llu)",
            appId, (unsigned long long)quotaBytes, maxNumFiles,
            wroteQuota ? 1 : 0, wroteFiles ? 1 : 0,
            (unsigned long long)existingQuota, (unsigned long long)existingFiles);
    } else {
        LOG("[KvInjector] InjectAppQuota app=%u: skipped (Steam already has "
            "quota=%llu files=%llu)", appId,
            (unsigned long long)existingQuota, (unsigned long long)existingFiles);
    }
    return true;
}

bool EnsureMaxNumFilesFloor(uint32_t appId, uint32_t floorFiles, uint64_t floorBytes) {
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (floorFiles == 0) return false;
    if (floorFiles > kMaxPlausibleMaxFiles) return false;  // guard pathological input

    void* cache = GetCachePtr();
    if (!cache) return false;
    void* appInfo = g_r.getAppInfo(cache, appId);
    if (!appInfo) return false;
    void* ufs = g_r.getSection(appInfo, kSectionUfs);
    if (!ufs) return false;

    uint64_t curFiles = g_r.readConfigU64(cache, appId, kSectionUfs, "maxnumfiles", 0);
    uint64_t curQuota = g_r.readConfigU64(cache, appId, kSectionUfs, "quota", 0);

    bool wrote = false;
    if (curFiles < floorFiles) {
        void* filesKv = g_r.kvFindKey(ufs, "maxnumfiles", 1, nullptr);
        if (filesKv) {
            g_r.kvSetInt(filesKv, static_cast<int>(floorFiles));
            wrote = true;
            LOG("[KvInjector] EnsureMaxNumFilesFloor app=%u: raised maxnumfiles %llu -> %u",
                appId, (unsigned long long)curFiles, floorFiles);
        }
    }
    // Cap (not skip): floorBytes derives from real PICS facts; silently dropping
    // the quota raise while still raising maxnumfiles would reopen byte-quota
    // eviction in exactly the multi-root scenario the floor protects.
    if (floorBytes > kMaxPlausibleQuotaBytes) floorBytes = kMaxPlausibleQuotaBytes;
    if (floorBytes > 0 && curQuota < floorBytes) {
        void* quotaKv = g_r.kvFindKey(ufs, "quota", 1, nullptr);
        if (quotaKv) {
            g_r.kvSetUint64(quotaKv, floorBytes);
            wrote = true;
            LOG("[KvInjector] EnsureMaxNumFilesFloor app=%u: raised quota %llu -> %llu",
                appId, (unsigned long long)curQuota, (unsigned long long)floorBytes);
        }
    }
    return wrote;
}

bool InjectSaveFiles(uint32_t appId, const std::vector<SaveFileRule>& rules) {
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (rules.empty()) return false;

    void* cache = GetCachePtr();
    if (!cache) {
        LOG("[KvInjector] InjectSaveFiles app=%u: cache pointer null", appId);
        return false;
    }

    void* appInfo = g_r.getAppInfo(cache, appId);
    if (!appInfo) {
        LOG("[KvInjector] InjectSaveFiles app=%u: no app info entry", appId);
        return false;
    }

    void* ufs = g_r.getSection(appInfo, kSectionUfs);
    if (!ufs) {
        LOG("[KvInjector] InjectSaveFiles app=%u: ufs section missing", appId);
        return false;
    }

    // Check if savefiles already exists with children. If so, don't clobber.
    void* existing = g_r.kvFindKey(ufs, "savefiles", 0, nullptr);
    if (existing) {
        // KV node exists -- check if it has children by trying to find child "0"
        void* child0 = g_r.kvFindKey(existing, "0", 0, nullptr);
        if (child0) {
            LOG("[KvInjector] InjectSaveFiles app=%u: savefiles already populated, skipping",
                appId);
            return true;
        }
    }

    // Create or get the savefiles subsection
    void* savefiles = g_r.kvFindKey(ufs, "savefiles", 1, nullptr);
    if (!savefiles) {
        LOG("[KvInjector] InjectSaveFiles app=%u: failed to create savefiles key", appId);
        return false;
    }

    int injected = 0;
    for (size_t i = 0; i < rules.size(); ++i) {
        const auto& rule = rules[i];
        std::string idxStr = std::to_string(i);

        // Create numbered subsection: savefiles/"0", savefiles/"1", etc.
        void* entry = g_r.kvFindKey(savefiles, idxStr.c_str(), 1, nullptr);
        if (!entry) continue;

        // Set root
        void* rootKv = g_r.kvFindKey(entry, "root", 1, nullptr);
        if (rootKv) g_r.kvSetString(rootKv, rule.root.c_str());

        // Set path
        if (!rule.path.empty()) {
            void* pathKv = g_r.kvFindKey(entry, "path", 1, nullptr);
            if (pathKv) g_r.kvSetString(pathKv, rule.path.c_str());
        }

        // Set pattern
        void* patternKv = g_r.kvFindKey(entry, "pattern", 1, nullptr);
        if (patternKv) g_r.kvSetString(patternKv, rule.pattern.c_str());

        // Set recursive (only if true, since Steam defaults to false)
        if (rule.recursive) {
            void* recursiveKv = g_r.kvFindKey(entry, "recursive", 1, nullptr);
            if (recursiveKv) g_r.kvSetInt(recursiveKv, 1);
        }

        // Set platforms (only if not all-platforms)
        if (rule.platforms != 0xFFFFFFFFu) {
            void* platformsKv = g_r.kvFindKey(entry, "platforms", 1, nullptr);
            if (platformsKv) {
                // Steam iterates "platforms" children as named strings ("windows", "macos", etc.).
                if (rule.platforms & 1) {
                    void* k = g_r.kvFindKey(platformsKv, "1", 1, nullptr);
                    if (k) g_r.kvSetString(k, "windows");
                }
                if (rule.platforms & 2) {
                    void* k = g_r.kvFindKey(platformsKv, "2", 1, nullptr);
                    if (k) g_r.kvSetString(k, "macos");
                }
                if (rule.platforms & 8) {
                    void* k = g_r.kvFindKey(platformsKv, "3", 1, nullptr);
                    if (k) g_r.kvSetString(k, "linux");
                }
            }
        }

        ++injected;
    }

    LOG("[KvInjector] InjectSaveFiles app=%u: injected %d savefiles rules", appId, injected);
    return injected > 0;
}

#else // !_WIN32 -- Linux 32-bit steamclient.so

// Linux steamclient.so -- runtime signature scanning only (no hardcoded fallback RVAs)

// Offset from CSteamEngine* to CAppInfoCache instance.
#if defined(__x86_64__)
// steamrt64: IsCloudEnabledForApp and EvaluateConfigChanges both pass
// `lea rbp,[rax+13D8h]` (rax = the engine global) to the config readers.
static constexpr uintptr_t APPINFOCACHE_OFFSET = 0x13D8;
#else
static constexpr uintptr_t APPINFOCACHE_OFFSET = 2952; // 0xB88
#endif

// Inline BST node layout (read off CAppInfoCache at offset 96, stride 24):
//   +0   uint32   left child index
//   +4   uint32   right child index
//   +16  uint32   appId  (key)
//   +20  uint32*  appInfo pointer  (value)
// Root index is at (manager + 76), -1 means empty tree.

using ReadConfigU64Fn = uint64_t(*)(void* cache, uint32_t appId, uint32_t sectionId,
                                    const char* keyName, uint64_t defaultVal);
using GetSectionFn   = void*(*)(void* appInfo, uint32_t sectionId);
using KvFindKeyFn    = void*(*)(void* parent, const char* name, uint8_t bCreate, void* outArr);
#if defined(__x86_64__)
using KvSetUint64Fn  = void (*)(void* kv, uint64_t value);
#else
// cdecl: the uint64 argument occupies two stack words.
using KvSetUint64Fn  = void (*)(void* kv, uint32_t lo, uint32_t hi);
#endif
using KvSetInt32Fn   = void (*)(void* kv, int32_t value);
using KvSetStringFn  = void (*)(void* kv, const char* value);

struct Resolved {
    void**          globalEnginePtr  = nullptr;
    ReadConfigU64Fn readConfigU64    = nullptr;
    GetSectionFn    getSection       = nullptr;
    KvFindKeyFn     kvFindKey        = nullptr;
    KvSetUint64Fn   kvSetUint64      = nullptr;
    KvSetInt32Fn    kvSetInt32       = nullptr;
    KvSetStringFn   kvSetString      = nullptr;
};

static Resolved g_r;
static std::atomic<bool> g_ready{false};
static std::once_flag g_initOnce;

static constexpr uint32_t kSectionUfs = 10;

// Crash guard for calls into steamclient.so internals. The KV injector resolves
// steamclient.so functions and struct offsets by signature scan; if a Steam
// client update shifts them in a way the scanner can't catch, a call could
// dereference a bad pointer and SIGSEGV on a Steam worker thread, taking the
// whole client down. We catch SIGSEGV/SIGBUS for the duration of the call,
// longjmp out, and permanently disable the KV injector for this session.
//
// IMPORTANT: this only guards QUOTA-METADATA calls (ReadAppQuota /
// InjectAppQuota / InjectSaveFiles). It does NOT touch save data. When the
// injector is disabled the caller simply falls back to a default quota; cloud
// and local saves are unaffected.
static std::atomic<bool> g_kvBroken{false};
static sigjmp_buf g_kvJmpBuf;
static volatile sig_atomic_t g_inKvCall = 0;

static void KvCrashHandler(int sig) {
    if (g_inKvCall) {
        siglongjmp(g_kvJmpBuf, sig);
    }
    raise(sig);
}

class KvCrashGuard {
public:
    KvCrashGuard() {
        struct sigaction sa = {};
        sa.sa_handler = KvCrashHandler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESETHAND;
        sigaction(SIGSEGV, &sa, &m_oldSegv);
        sigaction(SIGBUS, &sa, &m_oldBus);
        g_inKvCall = 1;
    }
    ~KvCrashGuard() {
        g_inKvCall = 0;
        sigaction(SIGSEGV, &m_oldSegv, nullptr);
        sigaction(SIGBUS, &m_oldBus, nullptr);
    }
private:
    struct sigaction m_oldSegv = {};
    struct sigaction m_oldBus = {};
};

struct MemRegion { uintptr_t start; uintptr_t end; };

// Find steamclient.so base and executable region via dl_iterate_phdr.
struct FindSteamCtx {
    uintptr_t base = 0;
    uintptr_t textStart = 0;
    uintptr_t textEnd = 0;
    uintptr_t moduleEnd = 0; // highest mapped VA across all PT_LOAD segments
    // PT_LOAD ranges [start, start+memsz): the only addresses a decoded
    // reference may be dereferenced at (the module has unmapped gaps).
    MemRegion segs[8] = {};
    int segCount = 0;
};

[[maybe_unused]] static bool InSegment(const FindSteamCtx& ctx, uintptr_t addr, size_t len) {
    for (int i = 0; i < ctx.segCount; ++i)
        if (addr >= ctx.segs[i].start && addr + len <= ctx.segs[i].end) return true;
    return false;
}

static int FindSteamPhdrCb(struct dl_phdr_info* info, size_t, void* data) {
    if (!info || !info->dlpi_name) return 0;
    const char* name = info->dlpi_name;
    const char* slash = strrchr(name, '/');
    const char* leaf = slash ? slash + 1 : name;
    if (strcmp(leaf, "steamclient.so") != 0) return 0;

    auto* ctx = static_cast<FindSteamCtx*>(data);
    ctx->base = info->dlpi_addr;

    // Largest PF_X segment is .text; track the highest mapped VA for bounds checks.
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const auto& ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_LOAD) continue;
        uintptr_t segStart = info->dlpi_addr + ph.p_vaddr;
        uintptr_t segEnd = segStart + ph.p_memsz;
        if (segEnd > ctx->moduleEnd) ctx->moduleEnd = segEnd;
        if (ctx->segCount < 8) ctx->segs[ctx->segCount++] = {segStart, segEnd};
        if ((ph.p_flags & PF_X) &&
            (segEnd - segStart) > (ctx->textEnd - ctx->textStart)) {
            ctx->textStart = segStart;
            ctx->textEnd = segEnd;
        }
    }
    return 1;
}

// Pattern match with '?' as wildcard byte. Pattern is a string like
// "55 57 56 53 E8 ? ? ? ? 81 C3 ? ? ? ? 83 EC 1C".
// Returns absolute address of first match, or 0 on failure.
static uintptr_t ScanPattern(uintptr_t start, uintptr_t end,
                             const uint8_t* pattern, const uint8_t* mask,
                             size_t patLen) {
    if (patLen == 0 || start >= end) return 0;
    size_t scanLen = end - start - patLen;
    const uint8_t* mem = reinterpret_cast<const uint8_t*>(start);
    for (size_t i = 0; i <= scanLen; ++i) {
        bool match = true;
        for (size_t j = 0; j < patLen; ++j) {
            if (mask[j] && mem[i + j] != pattern[j]) {
                match = false;
                break;
            }
        }
        if (match) return start + i;
    }
    return 0;
}

static uintptr_t DecodeRelCall(uintptr_t addr) {
    const uint8_t* p = reinterpret_cast<const uint8_t*>(addr);
    if (p[0] != 0xE8) return 0;
    int32_t rel;
    memcpy(&rel, p + 1, 4);
    return addr + 5 + rel;
}

// Match "lea reg, [ebx + disp32]" (8D /r with mod=10, rm=011); returns dest reg.
static bool IsLeaEbxDisp32(const uint8_t* p, uint8_t& outReg) {
    if (p[0] != 0x8D || (p[1] & 0xC7) != 0x83) return false;
    outReg = (p[1] >> 3) & 7;
    return true;
}

// Search for "add reg, 0xB88" (81 C0-C7 88 0B 00 00) in a range, then
// back-trace to find the GOT-relative lea that loads the global engine ptr.
// Returns the absolute address of the global (the dereferenced GOT entry).
static uintptr_t FindGlobalEnginePtr(uintptr_t textStart, uintptr_t textEnd,
                                     uintptr_t soBase, uintptr_t soEnd) {
    // Pattern: 81 Cx 88 0B 00 00 where x is C0-C7 (add eax..edi, 0xB88)
    const uint8_t* mem = reinterpret_cast<const uint8_t*>(textStart);
    size_t len = textEnd - textStart;

    for (size_t i = 8; i + 6 <= len; ++i) {
        if (mem[i] != 0x81) continue;
        uint8_t modrm = mem[i + 1];
        if (modrm < 0xC0 || modrm > 0xC7) continue;
        if (mem[i + 2] != 0x88 || mem[i + 3] != 0x0B ||
            mem[i + 4] != 0x00 || mem[i + 5] != 0x00) continue;

        // Found add reg, 0xB88. Back-trace: expect "mov reg, [reg2]" (2 bytes)
        // and before that "lea reg2, [ebx + disp32]" (6 bytes: 8D /r xx xx xx xx).
        // The lea loads the address of the global from GOT-relative addressing.
        uintptr_t addAddr = textStart + i;

        // 2 bytes before: "mov reg, [reg2]" (8B /r, mod=00). Accept any base reg
        // except esp(4)/ebp(5), whose modrm=00 encodings mean SIB/disp32 instead.
        if (mem[i - 2] != 0x8B) continue;
        uint8_t movModrm = mem[i - 1];
        if ((movModrm >> 6) != 0) continue;          // require mod=00 ([reg])
        uint8_t movBase = movModrm & 7;
        if (movBase == 4 || movBase == 5) continue;

        // 6 bytes before that: "lea reg2, [ebx + disp32]"; reg2 must feed the mov.
        uint8_t leaReg = 0;
        if (!IsLeaEbxDisp32(&mem[i - 8], leaReg)) continue;
        if (leaReg != movBase) continue;

        // 32-bit PIC: ebx = _GLOBAL_OFFSET_TABLE_; the lea computes the .bss global's
        // absolute address. Decode it.
        int32_t leaDisp;
        memcpy(&leaDisp, &mem[i - 6], 4);            // disp32 of lea reg2,[ebx+disp]

        LOG("[KvInjector] SigScan: found 'add reg, 0xB88' at 0x%lx (base+0x%lx), "
            "lea disp=0x%lx",
            (unsigned long)addAddr, (unsigned long)(addAddr - soBase),
            (unsigned long)(uint32_t)leaDisp);

        // Resolve ebx (GOT base): scan back for "add ebx, imm32" (81 C3), ebx = addr + imm32.
        uintptr_t leaAddr = textStart + (i - 8);
        uintptr_t scanBack = (leaAddr > 0x1000) ? leaAddr - 0x1000 : textStart;
        const uint8_t* sb = reinterpret_cast<const uint8_t*>(scanBack);
        size_t sbLen = leaAddr - scanBack;
        uintptr_t gotBase = 0;
        for (size_t k = sbLen; k-- > 0;) {
            if (sb[k] == 0x81 && sb[k + 1] == 0xC3) {
                int32_t imm;
                memcpy(&imm, &sb[k + 2], 4);
                uintptr_t addEbxAddr = scanBack + k;
                gotBase = addEbxAddr + (uint32_t)imm;   // ebx after thunk
                break;
            }
        }
        if (!gotBase) {
            LOG("[KvInjector] SigScan: could not resolve GOT base (ebx) for engine global");
            return 0;
        }

        uintptr_t engineVar = gotBase + (uint32_t)leaDisp;
        if (engineVar <= soBase || (soEnd != 0 && engineVar >= soEnd)) {
            // Decoded address outside the module's mapped range -- a false match;
            // keep scanning rather than dereferencing garbage.
            LOG("[KvInjector] SigScan: engine-global 0x%lx out of module bounds "
                "[0x%lx,0x%lx); skipping match",
                (unsigned long)engineVar, (unsigned long)soBase, (unsigned long)soEnd);
            continue;
        }
        LOG("[KvInjector] SigScan: decoded engine-global var at 0x%lx (base+0x%lx)",
            (unsigned long)engineVar, (unsigned long)(engineVar - soBase));
        return engineVar;
    }
    return 0;
}

#if defined(__x86_64__)
// ── x86_64 resolution (steamrt64 build 1794536281) ──────────────────────────
//
// ReadConfigU64(cache, appId, section, key, default) is the function Steam
// calls right after loading the "quota" key (three sites, all one target).
// Its body pins the app-info tree layout and leads to GetSection (first call)
// and FindKey (second call: `xor ecx,ecx; xor edx,edx; jmp FindKey`).
//   55 53 4C 89 C3 48 83 EC 08      push rbp/rbx; mov rbx,r8; sub rsp,8
//   48 63 47 28 83 F8 FF 74 ??      movsxd rax,[rdi+28h]; cmp eax,-1; jz   ; root index
//   48 8B 7F 40                     mov rdi,[rdi+40h]                      ; nodes
//   41 89 D1 48 89 CD EB            mov r9d,edx; mov rbp,rcx; jmp
// The int32 sibling ReadConfigInt starts `44 89 C3` and is never the target of
// a "quota" load, so the vote below cannot pick it.
static const uint8_t kSigReadConfigU64X64[] = {
    0x55,0x53,0x4C,0x89,0xC3,0x48,0x83,0xEC,0x08, 0x48,0x63,0x47,0x28,0x83,0xF8,0xFF,0x74,0,
    0x48,0x8B,0x7F,0x40, 0x41,0x89,0xD1,0x48,0x89,0xCD,0xEB
};
static const uint8_t kMaskReadConfigU64X64[] = {
    1,1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,0,
    1,1,1,1, 1,1,1,1,1,1,1
};

// KeyValues setters: if (kv) { ClearValue(kv); value = arg; type bits = T }.
// The type lives in bits 1-4 of byte +0x13 (i386: +0x0B).
static const uint8_t kSigKvSetInt32X64[] = {
    0x48,0x85,0xFF,0x74,0, 0x55,0x89,0xF5,0x53,0x48,0x89,0xFB,0x48,0x83,0xEC,0x08,
    0xE8,0,0,0,0, 0x0F,0xB6,0x43,0x13, 0x89,0x2B, 0x83,0xE0,0xE1,0x83,0xC8,0x04,0x88,0x43,0x13
};
static const uint8_t kMaskKvSetInt32X64[] = {
    1,1,1,1,0, 1,1,1,1,1,1,1,1,1,1,1,
    1,0,0,0,0, 1,1,1,1, 1,1, 1,1,1,1,1,1,1,1,1
};
static const uint8_t kSigKvSetUint64X64[] = {
    0x48,0x85,0xFF,0x74,0, 0x55,0x48,0x89,0xF5,0x53,0x48,0x89,0xFB,0x48,0x83,0xEC,0x08,
    0xE8,0,0,0,0, 0x0F,0xB6,0x43,0x13, 0x48,0x89,0x2B, 0x83,0xE0,0xE1,0x83,0xC8,0x0E,0x88,0x43,0x13
};
static const uint8_t kMaskKvSetUint64X64[] = {
    1,1,1,1,0, 1,1,1,1,1,1,1,1,1,1,1,1,
    1,0,0,0,0, 1,1,1,1, 1,1,1, 1,1,1,1,1,1,1,1,1
};
// SetString(kv, const char*): same guard and ClearValue call; its string-type
// tail (and eax,0E1h; or eax,2; mov [rbx+13h],al) is checked separately.
static const uint8_t kSigKvSetStringX64[] = {
    0x48,0x85,0xFF,0x74,0, 0x41,0x54,0x55,0x48,0x89,0xF5,0x53,0x48,0x89,0xFB,
    0xE8,0,0,0,0, 0x48,0x85,0xED,0x74,0, 0x48,0x89,0xEF,0xE8
};
static const uint8_t kMaskKvSetStringX64[] = {
    1,1,1,1,0, 1,1,1,1,1,1,1,1,1,1,
    1,0,0,0,0, 1,1,1,1,0, 1,1,1,1
};
static_assert(sizeof(kSigReadConfigU64X64) == sizeof(kMaskReadConfigU64X64), "mask");
static_assert(sizeof(kSigKvSetInt32X64) == sizeof(kMaskKvSetInt32X64), "mask");
static_assert(sizeof(kSigKvSetUint64X64) == sizeof(kMaskKvSetUint64X64), "mask");
static_assert(sizeof(kSigKvSetStringX64) == sizeof(kMaskKvSetStringX64), "mask");

static bool MatchAt(uintptr_t addr, const uint8_t* sig, const uint8_t* mask, size_t len) {
    const uint8_t* p = reinterpret_cast<const uint8_t*>(addr);
    for (size_t i = 0; i < len; ++i)
        if (mask[i] && p[i] != sig[i]) return false;
    return true;
}

// `lea r64,[rip+disp32]` (REX.W 8D /r, mod=00 rm=101): its target, or 0.
static uintptr_t DecodeLeaRip(uintptr_t addr) {
    const uint8_t* p = reinterpret_cast<const uint8_t*>(addr);
    if ((p[0] != 0x48 && p[0] != 0x4C) || p[1] != 0x8D || (p[2] & 0xC7) != 0x05) return 0;
    int32_t disp;
    memcpy(&disp, p + 3, sizeof(disp));
    return addr + 7 + (intptr_t)disp;
}

// The address with the most votes, or 0 when it has fewer than minVotes or
// another candidate ties it.
struct Vote { uintptr_t addr; int count; };
static uintptr_t Winner(const Vote* votes, int n, int minVotes) {
    int best = -1, second = 0;
    for (int i = 0; i < n; ++i) {
        if (best < 0 || votes[i].count > votes[best].count) {
            if (best >= 0) second = votes[best].count;
            best = i;
        } else if (votes[i].count > second) {
            second = votes[i].count;
        }
    }
    if (best < 0 || votes[best].count < minVotes || votes[best].count == second) return 0;
    return votes[best].addr;
}

static void AddVote(Vote* votes, int& n, int cap, uintptr_t addr) {
    for (int i = 0; i < n; ++i)
        if (votes[i].addr == addr) { ++votes[i].count; return; }
    if (n < cap) votes[n++] = {addr, 1};
}

static bool ResolveX64(const FindSteamCtx& ctx, Resolved& out) {
    const uintptr_t lo = ctx.textStart, hi = ctx.textEnd;
    Vote readVotes[16]; int readN = 0;
    Vote engVotes[16];  int engN = 0;

    for (uintptr_t a = lo; a + 32 <= hi; ++a) {
        const uint8_t* p = reinterpret_cast<const uint8_t*>(a);
        if ((p[0] != 0x48 && p[0] != 0x4C) || p[1] != 0x8D) continue;

        // lea rcx,[rip+"quota"] ... call ReadConfigU64
        if ((p[2] & 0xC7) == 0x05) {
            const uintptr_t t = DecodeLeaRip(a);
            if (InSegment(ctx, t, 6) && memcmp(reinterpret_cast<const void*>(t), "quota", 6) == 0) {
                for (size_t k = 7; k < 27; ++k) {
                    if (p[k] != 0xE8) continue;
                    const uintptr_t c = DecodeRelCall(a + k);
                    if (c >= lo && c < hi) AddVote(readVotes, readN, 16, c);
                    break;
                }
            }
            continue;
        }
        // lea reg,[rax+13D8h] preceded by lea reg2,[rip+engine global]
        if ((p[2] & 0xC7) == 0x80 && p[3] == 0xD8 && p[4] == 0x13 && p[5] == 0 && p[6] == 0) {
            for (size_t back = 4; back <= 16 && a - back >= lo; ++back) {
                const uintptr_t g = DecodeLeaRip(a - back);
                if (g && InSegment(ctx, g, sizeof(void*))) { AddVote(engVotes, engN, 16, g); break; }
            }
        }
    }

    const uintptr_t readCfg = Winner(readVotes, readN, 2);
    const uintptr_t engine  = Winner(engVotes, engN, 3);
    if (!readCfg || !MatchAt(readCfg, kSigReadConfigU64X64, kMaskReadConfigU64X64,
                             sizeof(kSigReadConfigU64X64))) {
        LOG("[KvInjector] x86_64: ReadConfigU64 not resolved (candidates=%d)", readN);
        return false;
    }
    if (!engine) {
        LOG("[KvInjector] x86_64: engine global not resolved (candidates=%d)", engN);
        return false;
    }

    // GetSection = first call in ReadConfigU64, FindKey = the jmp inside the
    // wrapper the second call reaches.
    uintptr_t getSect = 0, kvFind = 0;
    for (uintptr_t a = readCfg; a < readCfg + 0x120 && a + 5 <= hi; ++a) {
        if (*reinterpret_cast<const uint8_t*>(a) != 0xE8) continue;
        const uintptr_t c = DecodeRelCall(a);
        if (c < lo || c >= hi) continue;
        if (!getSect) { getSect = c; a += 4; continue; }
        const uint8_t* w = reinterpret_cast<const uint8_t*>(c);
        if (w[0] == 0x31 && w[1] == 0xC9 && w[2] == 0x31 && w[3] == 0xD2 && w[4] == 0xE9) {
            int32_t rel;
            memcpy(&rel, w + 5, sizeof(rel));
            const uintptr_t f = c + 9 + (intptr_t)rel;
            if (f >= lo && f < hi) kvFind = f;
        }
        break;
    }

    const uintptr_t setI32 = ScanPattern(lo, hi, kSigKvSetInt32X64, kMaskKvSetInt32X64,
                                         sizeof(kSigKvSetInt32X64));
    const uintptr_t setU64 = ScanPattern(lo, hi, kSigKvSetUint64X64, kMaskKvSetUint64X64,
                                         sizeof(kSigKvSetUint64X64));
    uintptr_t setStr = ScanPattern(lo, hi, kSigKvSetStringX64, kMaskKvSetStringX64,
                                   sizeof(kSigKvSetStringX64));
    if (setStr) {
        static const uint8_t kStrType[] = {0x83, 0xE0, 0xE1, 0x83, 0xC8, 0x02, 0x88, 0x43, 0x13};
        bool tail = false;
        for (uintptr_t a = setStr; a < setStr + 0xA0 && a + sizeof(kStrType) <= hi; ++a)
            if (memcmp(reinterpret_cast<const void*>(a), kStrType, sizeof(kStrType)) == 0) { tail = true; break; }
        if (!tail) setStr = 0;
    }

    auto rva = [&](uintptr_t a) { return (unsigned long)(a ? a - ctx.base : 0); };
    LOG("[KvInjector] x86_64: readCfg=+0x%lx engine=+0x%lx getSect=+0x%lx kvFind=+0x%lx "
        "setI32=+0x%lx setU64=+0x%lx setStr=+0x%lx",
        rva(readCfg), rva(engine), rva(getSect), rva(kvFind), rva(setI32), rva(setU64), rva(setStr));
    if (!getSect || !kvFind || !setI32 || !setU64 || !setStr) return false;

    out.globalEnginePtr = reinterpret_cast<void**>(engine);
    out.readConfigU64   = reinterpret_cast<ReadConfigU64Fn>(readCfg);
    out.getSection      = reinterpret_cast<GetSectionFn>(getSect);
    out.kvFindKey       = reinterpret_cast<KvFindKeyFn>(kvFind);
    out.kvSetUint64     = reinterpret_cast<KvSetUint64Fn>(setU64);
    out.kvSetInt32      = reinterpret_cast<KvSetInt32Fn>(setI32);
    out.kvSetString     = reinterpret_cast<KvSetStringFn>(setStr);
    return true;
}
#endif

static void KvSetU64(void* kv, uint64_t value) {
#if defined(__x86_64__)
    g_r.kvSetUint64(kv, value);
#else
    g_r.kvSetUint64(kv, static_cast<uint32_t>(value & 0xFFFFFFFFu),
                    static_cast<uint32_t>(value >> 32));
#endif
}

static void* GetCachePtr() {
    if (!g_r.globalEnginePtr) return nullptr;
    void* engine = *g_r.globalEnginePtr;
    if (!engine) return nullptr;
    return reinterpret_cast<uint8_t*>(engine) + APPINFOCACHE_OFFSET;
}

// ReadConfigU64: push ebp; push edi; push esi; push ebx; call thunk;
//   add ebx,<GOT>; sub esp,1Ch; mov eax,[esp+40h]; mov ebp,[esp+...]
// Unique: "55 57 56 53 E8 ?? ?? ?? ?? 81 C3 ?? ?? ?? ?? 83 EC 1C 8B 44 24 40"
static const uint8_t kSigReadConfigU64[] = {
    0x55, 0x57, 0x56, 0x53, 0xE8, 0x00, 0x00, 0x00, 0x00,
    0x81, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x83, 0xEC, 0x1C,
    0x8B, 0x44, 0x24, 0x40
};
static const uint8_t kMaskReadConfigU64[] = {
    1, 1, 1, 1, 1, 0, 0, 0, 0,  // push*4 + call rel32 (wildcard offset)
    1, 1, 0, 0, 0, 0, 1, 1, 1,  // add ebx,<GOT> (wildcard imm) + sub esp,1Ch
    1, 1, 1, 1                   // mov eax,[esp+40h]
};

// KvSetUint64: push edi; push esi; push ebx; mov ebx,[esp+10];
//   mov esi,[esp+14]; mov edi,[esp+18]; test ebx,ebx; jz short
static const uint8_t kSigKvSetUint64[] = {
    0x57, 0x56, 0x53, 0x8B, 0x5C, 0x24, 0x10,
    0x8B, 0x74, 0x24, 0x14, 0x8B, 0x7C, 0x24, 0x18,
    0x85, 0xDB, 0x74
};
static const uint8_t kMaskKvSetUint64[] = {
    1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1
};

// KvSetInt32: push ebx; sub esp,8; mov ebx,[esp+10]; test ebx,ebx; jz short;
// then sub esp,0Ch; push ebx; call type-clear-helper; mov eax,[esp+24].
// The "8B 44 24 24" (mov eax,[esp+24]) at offset +0x15 distinguishes int from
// the same-shape KvSetFloat which has "D9 44 24 0C" (fld dword [esp+0Ch]).
static const uint8_t kSigKvSetInt32[] = {
    0x53, 0x83, 0xEC, 0x08, 0x8B, 0x5C, 0x24, 0x10,
    0x85, 0xDB, 0x74, 0x00, 0x83, 0xEC, 0x0C, 0x53,
    0xE8, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x44, 0x24, 0x24
};
static const uint8_t kMaskKvSetInt32[] = {
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 0, 1, 1, 1, 1,
    1, 0, 0, 0, 0, 1, 1, 1, 1
};

// Offset from ReadConfigU64 start to the "call GetSection" instruction.
// In the current build: 0xF49C8B - 0xF49BD0 = 0xBB.
// We scan nearby (+/- 32 bytes) for the call to handle minor recompilation shifts.
static constexpr size_t kReadConfigGetSectionCallMin = 0xA0;
static constexpr size_t kReadConfigGetSectionCallMax = 0xD0;

// Extract a call target by scanning for E8 in [minOff, maxOff] within funcStart.
static uintptr_t FindCallInRange(uintptr_t funcStart, size_t minOff, size_t maxOff,
                                 uintptr_t minTarget, uintptr_t maxTarget) {
    const uint8_t* mem = reinterpret_cast<const uint8_t*>(funcStart);
    for (size_t off = minOff; off <= maxOff; ++off) {
        if (mem[off] != 0xE8) continue;
        uintptr_t target = DecodeRelCall(funcStart + off);
        if (target >= minTarget && target < maxTarget) return target;
    }
    return 0;
}

void Configure(const ResolvedKvAddrs&) {}

bool Init() {
    bool success = false;
    std::call_once(g_initOnce, [&]() {
        FindSteamCtx ctx;
        dl_iterate_phdr(FindSteamPhdrCb, &ctx);
        if (!ctx.base) {
            LOG("[KvInjector] Init: steamclient.so not yet loaded");
            return;
        }
        uintptr_t base = ctx.base;
        LOG("[KvInjector] Init: steamclient.so base 0x%lx, text 0x%lx-0x%lx (%lu MB)",
            (unsigned long)base,
            (unsigned long)ctx.textStart, (unsigned long)ctx.textEnd,
            (unsigned long)((ctx.textEnd - ctx.textStart) / (1024*1024)));

#if defined(__x86_64__)
        if (!ResolveX64(ctx, g_r)) {
            g_r = Resolved{};
            LOG("[KvInjector] x86_64: resolution incomplete -- DISABLED");
            return;
        }
        LOG("[KvInjector] Init: resolved x86_64 pointers (engine global @ %p)",
            g_r.globalEnginePtr);
        g_ready.store(true, std::memory_order_release);
        success = true;
        return;
#endif
        bool usedSigs = false;

        uintptr_t readCfg = ScanPattern(ctx.textStart, ctx.textEnd,
                                        kSigReadConfigU64, kMaskReadConfigU64,
                                        sizeof(kSigReadConfigU64));
        if (readCfg) {
            LOG("[KvInjector] SigScan: ReadConfigU64 at 0x%lx (base+0x%lx)",
                (unsigned long)readCfg, (unsigned long)(readCfg - base));
        }

        // GetSection: within 64KB before ReadConfigU64 (rejects far PLT thunks).
        uintptr_t getSect = 0;
        if (readCfg) {
            uintptr_t minTarget = (readCfg > 0x10000) ? readCfg - 0x10000 : ctx.textStart;
            getSect = FindCallInRange(readCfg,
                                      kReadConfigGetSectionCallMin,
                                      kReadConfigGetSectionCallMax,
                                      minTarget, readCfg);
            if (getSect) {
                LOG("[KvInjector] SigScan: GetSection at 0x%lx (base+0x%lx)",
                    (unsigned long)getSect, (unsigned long)(getSect - base));
            }
        }

        // Match "push 0; push 0; push eax; push esi; call" (the 4-arg
        // FindKey call) to skip the earlier string-normalize call.
        uintptr_t kvFind = 0;
        if (getSect) {
            const uint8_t kCallPrefix[] = { 0x6A, 0x00, 0x6A, 0x00, 0x50, 0x56, 0xE8 };
            const uint8_t* mem = reinterpret_cast<const uint8_t*>(getSect);
            constexpr size_t kSearchLen = 0x80; // enough for the dispatch arm
            for (size_t i = 0; i + sizeof(kCallPrefix) + 4 <= kSearchLen; ++i) {
                if (memcmp(mem + i, kCallPrefix, sizeof(kCallPrefix)) == 0) {
                    uintptr_t callAddr = getSect + i + sizeof(kCallPrefix) - 1;
                    kvFind = DecodeRelCall(callAddr);
                    break;
                }
            }
            if (kvFind) {
                LOG("[KvInjector] SigScan: KvFindKey at 0x%lx (base+0x%lx)",
                    (unsigned long)kvFind, (unsigned long)(kvFind - base));
            }
        }

        uintptr_t kvSetU64 = ScanPattern(ctx.textStart, ctx.textEnd,
                                         kSigKvSetUint64, kMaskKvSetUint64,
                                         sizeof(kSigKvSetUint64));
        if (kvSetU64) {
            LOG("[KvInjector] SigScan: KvSetUint64 at 0x%lx (base+0x%lx)",
                (unsigned long)kvSetU64, (unsigned long)(kvSetU64 - base));
        }

        uintptr_t kvSetI32 = ScanPattern(ctx.textStart, ctx.textEnd,
                                         kSigKvSetInt32, kMaskKvSetInt32,
                                         sizeof(kSigKvSetInt32));
        if (kvSetI32) {
            LOG("[KvInjector] SigScan: KvSetInt32 at 0x%lx (base+0x%lx)",
                (unsigned long)kvSetI32, (unsigned long)(kvSetI32 - base));
        }

        uintptr_t globalEng = FindGlobalEnginePtr(ctx.textStart, ctx.textEnd, base,
                                                  ctx.moduleEnd);
        if (globalEng) {
            LOG("[KvInjector] SigScan: globalEnginePtr at 0x%lx (base+0x%lx)",
                (unsigned long)globalEng, (unsigned long)(globalEng - base));
        }

        // KvSetString: scan backward from KvSetInt32 for the type=2 tail
        // (and eax,0xE1; or eax,2; mov [esi+0Bh],al), then walk back to the
        // push ebp/edi/esi/ebx prologue.
        uintptr_t kvSetStr = 0;
        if (kvSetI32) {
            const uint8_t kTyp2[] = { 0x83, 0xE0, 0xE1, 0x83, 0xC8, 0x02, 0x88, 0x46, 0x0B };
            uintptr_t scanStart = (kvSetI32 > 0x400) ? kvSetI32 - 0x400 : ctx.textStart;
            const uint8_t* mem = reinterpret_cast<const uint8_t*>(scanStart);
            size_t scanLen = kvSetI32 - scanStart;
            for (size_t i = 0; i + sizeof(kTyp2) <= scanLen; ++i) {
                if (memcmp(mem + i, kTyp2, sizeof(kTyp2)) == 0) {
                    uintptr_t matchAddr = scanStart + i;
                    for (size_t back = 0x20; back < 0xB0; ++back) {
                        uintptr_t candidate = matchAddr - back;
                        const uint8_t* fb = reinterpret_cast<const uint8_t*>(candidate);
                        if (fb[0] == 0x55 && fb[1] == 0x57 && fb[2] == 0x56 &&
                            fb[3] == 0x53 && fb[4] == 0xE8) {
                            kvSetStr = candidate;
                            break;
                        }
                    }
                    if (kvSetStr) break;
                }
            }
        }
        if (kvSetStr) {
            LOG("[KvInjector] SigScan: KvSetString at 0x%lx (base+0x%lx)",
                (unsigned long)kvSetStr, (unsigned long)(kvSetStr - base));
        }

        if (readCfg && getSect && kvFind && kvSetU64 && kvSetI32 && kvSetStr && globalEng) {
            g_r.globalEnginePtr = reinterpret_cast<void**>(globalEng);
            g_r.readConfigU64   = reinterpret_cast<ReadConfigU64Fn>(readCfg);
            g_r.getSection      = reinterpret_cast<GetSectionFn>(getSect);
            g_r.kvFindKey       = reinterpret_cast<KvFindKeyFn>(kvFind);
            g_r.kvSetUint64     = reinterpret_cast<KvSetUint64Fn>(kvSetU64);
            g_r.kvSetInt32      = reinterpret_cast<KvSetInt32Fn>(kvSetI32);
            g_r.kvSetString     = reinterpret_cast<KvSetStringFn>(kvSetStr);
            usedSigs = true;
            LOG("[KvInjector] Init: all signatures resolved successfully");
        } else {
            LOG("[KvInjector] SigScan: partial (readCfg=%d getSect=%d kvFind=%d "
                "kvSetU64=%d kvSetI32=%d kvSetStr=%d global=%d) -- DISABLED (no fallback RVAs)",
                readCfg ? 1 : 0, getSect ? 1 : 0, kvFind ? 1 : 0,
                kvSetU64 ? 1 : 0, kvSetI32 ? 1 : 0, kvSetStr ? 1 : 0, globalEng ? 1 : 0);
            return;
        }

        LOG("[KvInjector] Init: resolved Linux pointers (engine global @ %p, sigs=%d)",
            g_r.globalEnginePtr, usedSigs ? 1 : 0);
        g_ready.store(true, std::memory_order_release);
        success = true;
    });
    return success || g_ready.load(std::memory_order_acquire);
}

bool IsReady() {
    return g_ready.load(std::memory_order_acquire);
}

bool ReadAppQuota(uint32_t appId, uint64_t& outQuotaBytes, uint32_t& outMaxNumFiles) {
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (g_kvBroken.load(std::memory_order_acquire)) return false;
    void* cache = GetCachePtr();
    if (!cache) return false;

    uint64_t quota = 0, files = 0;
    {
        // Guard the steamclient.so calls: a layout/RVA mismatch after a Steam
        // update would otherwise SIGSEGV here and abort the client. On a fault
        // we disable the injector for the session and report "no quota", which
        // the caller handles by injecting a safe default. Saves are untouched.
        KvCrashGuard guard;
        int sig = sigsetjmp(g_kvJmpBuf, 1);
        if (sig != 0) {
            g_kvBroken.store(true, std::memory_order_release);
            LOG("[KvInjector] ReadAppQuota app=%u: steamclient call faulted "
                "(signal %d); disabling KV injector, quota falls back to default",
                appId, sig);
            return false;
        }
        quota = g_r.readConfigU64(cache, appId, kSectionUfs, "quota", 0);
        files = g_r.readConfigU64(cache, appId, kSectionUfs, "maxnumfiles", 0);
    }

    if (!QuotaValueLooksValid(quota, files)) {
        if (quota != 0 || files != 0) {
            LOG("[KvInjector] ReadAppQuota app=%u: implausible quota=%llu files=%llu",
                appId, (unsigned long long)quota, (unsigned long long)files);
        }
        outQuotaBytes = 0;
        outMaxNumFiles = 0;
        return true;
    }

    outQuotaBytes  = quota;
    outMaxNumFiles = static_cast<uint32_t>(files);
    return true;
}

// Inline BST walk: manager+76=rootIndex, manager+96=nodes (24-byte stride).
// node+16=appId, node+20=appInfo. Returns null if appId not in cache.
static void* ResolveAppInfo(void* cache, uint32_t appId) {
    if (!cache) return nullptr;
#if defined(__x86_64__)
    // Same walk ReadConfigU64 does: root index at +0x28, nodes at +0x40
    // (32-byte stride: left/right index +0/+4, appId +0x10, appInfo +0x18).
    // An entry flagged at +0x14 is one Steam itself refuses to read.
    uint8_t* c = static_cast<uint8_t*>(cache);
    int32_t idx = *reinterpret_cast<int32_t*>(c + 0x28);
    uint8_t* nodes = *reinterpret_cast<uint8_t**>(c + 0x40);
    if (idx < 0 || !nodes) return nullptr;
    while (idx >= 0) {
        uint8_t* node = nodes + static_cast<size_t>(idx) * 0x20;
        uint32_t key = *reinterpret_cast<uint32_t*>(node + 0x10);
        if (appId < key) idx = *reinterpret_cast<int32_t*>(node + 0);
        else if (appId > key) idx = *reinterpret_cast<int32_t*>(node + 4);
        else {
            uint8_t* info = *reinterpret_cast<uint8_t**>(node + 0x18);
            if (!info || info[0x14] != 0) return nullptr;
            return info;
        }
    }
    return nullptr;
#else
    uint8_t* cacheBytes = static_cast<uint8_t*>(cache);
    int32_t  rootIdx = *reinterpret_cast<int32_t*>(cacheBytes + 76);
    uint8_t* nodes   = *reinterpret_cast<uint8_t**>(cacheBytes + 96);
    if (rootIdx < 0 || !nodes) return nullptr;

    int32_t idx = rootIdx;
    while (idx >= 0) {
        uint8_t* node = nodes + static_cast<size_t>(idx) * 24;
        uint32_t nodeAppId = *reinterpret_cast<uint32_t*>(node + 16);
        if (appId < nodeAppId) {
            idx = *reinterpret_cast<int32_t*>(node + 0);
        } else if (appId > nodeAppId) {
            idx = *reinterpret_cast<int32_t*>(node + 4);
        } else {
            return *reinterpret_cast<void**>(node + 20);
        }
    }
    return nullptr;
#endif
}

bool InjectAppQuota(uint32_t appId, uint64_t quotaBytes, uint32_t maxNumFiles) {
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (g_kvBroken.load(std::memory_order_acquire)) return false;
    if (quotaBytes == 0 || maxNumFiles == 0) {
        LOG("[KvInjector] InjectAppQuota app=%u: refusing zero values "
            "(quota=%llu files=%u)",
            appId, (unsigned long long)quotaBytes, maxNumFiles);
        return false;
    }

    // Guard every steamclient.so access below (cache walk, getSection,
    // readConfigU64, kvFindKey/Set*). A post-update layout mismatch faults
    // here otherwise and aborts the client. On a fault we disable the injector
    // for the session and report failure; the caller degrades to a default
    // quota. No save data is touched on this path.
    KvCrashGuard guard;
    int sig = sigsetjmp(g_kvJmpBuf, 1);
    if (sig != 0) {
        g_kvBroken.store(true, std::memory_order_release);
        LOG("[KvInjector] InjectAppQuota app=%u: steamclient call faulted "
            "(signal %d); disabling KV injector", appId, sig);
        return false;
    }

    void* cache = GetCachePtr();
    if (!cache) {
        LOG("[KvInjector] InjectAppQuota app=%u: cache pointer null", appId);
        return false;
    }

    void* appInfo = ResolveAppInfo(cache, appId);
    if (!appInfo) {
        LOG("[KvInjector] InjectAppQuota app=%u: no app info entry "
            "(PICS has never returned for this app)", appId);
        return false;
    }

    void* ufs = g_r.getSection(appInfo, kSectionUfs);
    if (!ufs) {
        LOG("[KvInjector] InjectAppQuota app=%u: ufs section missing "
            "(app config has no cloud config at all)", appId);
        return false;
    }

    // Preserve Steam's PICS values only if plausible; overwrite garbage.
    uint64_t existingQuota = g_r.readConfigU64(cache, appId, kSectionUfs, "quota", 0);
    uint64_t existingFiles = g_r.readConfigU64(cache, appId, kSectionUfs, "maxnumfiles", 0);
    bool existingValid = QuotaValueLooksValid(existingQuota, existingFiles);

    bool wroteQuota = false;
    bool wroteFiles = false;

    bool quotaNeedsWrite = (existingQuota == 0) ||
                           (existingQuota > kMaxPlausibleQuotaBytes) || !existingValid;
    bool filesNeedsWrite = (existingFiles == 0) ||
                           (existingFiles > kMaxPlausibleMaxFiles) || !existingValid;

    if (quotaNeedsWrite) {
        void* quotaKv = g_r.kvFindKey(ufs, "quota", 1, nullptr);
        if (quotaKv) {
            KvSetU64(quotaKv, quotaBytes);
            wroteQuota = true;
        }
    }
    if (filesNeedsWrite) {
        void* filesKv = g_r.kvFindKey(ufs, "maxnumfiles", 1, nullptr);
        if (filesKv) {
            g_r.kvSetInt32(filesKv, static_cast<int32_t>(maxNumFiles));
            wroteFiles = true;
        }
    }

    if (wroteQuota || wroteFiles) {
        LOG("[KvInjector] InjectAppQuota app=%u: injected quota=%llu files=%u "
            "(wroteQuota=%d wroteFiles=%d, existingQuota=%llu existingFiles=%llu)",
            appId, (unsigned long long)quotaBytes, maxNumFiles,
            wroteQuota ? 1 : 0, wroteFiles ? 1 : 0,
            (unsigned long long)existingQuota, (unsigned long long)existingFiles);
    } else {
        LOG("[KvInjector] InjectAppQuota app=%u: skipped (Steam already has "
            "quota=%llu files=%llu)", appId,
            (unsigned long long)existingQuota, (unsigned long long)existingFiles);
    }
    return true;
}

bool EnsureMaxNumFilesFloor(uint32_t appId, uint32_t floorFiles, uint64_t floorBytes) {
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (floorFiles == 0) return false;
    if (floorFiles > kMaxPlausibleMaxFiles) return false;

    void* cache = GetCachePtr();
    if (!cache) return false;
    void* appInfo = ResolveAppInfo(cache, appId);
    if (!appInfo) return false;
    void* ufs = g_r.getSection(appInfo, kSectionUfs);
    if (!ufs) return false;

    uint64_t curFiles = g_r.readConfigU64(cache, appId, kSectionUfs, "maxnumfiles", 0);
    uint64_t curQuota = g_r.readConfigU64(cache, appId, kSectionUfs, "quota", 0);

    bool wrote = false;
    if (curFiles < floorFiles) {
        void* filesKv = g_r.kvFindKey(ufs, "maxnumfiles", 1, nullptr);
        if (filesKv) {
            g_r.kvSetInt32(filesKv, static_cast<int32_t>(floorFiles));
            wrote = true;
            LOG("[KvInjector] EnsureMaxNumFilesFloor app=%u: raised maxnumfiles %llu -> %u",
                appId, (unsigned long long)curFiles, floorFiles);
        }
    }
    // Cap (not skip): see Windows impl -- dropping the quota raise while raising
    // maxnumfiles would reopen byte-quota eviction for multi-root apps.
    if (floorBytes > kMaxPlausibleQuotaBytes) floorBytes = kMaxPlausibleQuotaBytes;
    if (floorBytes > 0 && curQuota < floorBytes) {
        void* quotaKv = g_r.kvFindKey(ufs, "quota", 1, nullptr);
        if (quotaKv) {
            KvSetU64(quotaKv, floorBytes);
            wrote = true;
            LOG("[KvInjector] EnsureMaxNumFilesFloor app=%u: raised quota %llu -> %llu",
                appId, (unsigned long long)curQuota, (unsigned long long)floorBytes);
        }
    }
    return wrote;
}

bool InjectSaveFiles(uint32_t appId, const std::vector<SaveFileRule>& rules) {
    if (!g_ready.load(std::memory_order_acquire)) return false;
    if (g_kvBroken.load(std::memory_order_acquire)) return false;
    if (rules.empty()) return false;

    // Guard the steamclient.so accesses (see InjectAppQuota). On a fault we
    // disable the injector and bail; save data is never touched here.
    KvCrashGuard guard;
    int sig = sigsetjmp(g_kvJmpBuf, 1);
    if (sig != 0) {
        g_kvBroken.store(true, std::memory_order_release);
        LOG("[KvInjector] InjectSaveFiles app=%u: steamclient call faulted "
            "(signal %d); disabling KV injector", appId, sig);
        return false;
    }

    void* cache = GetCachePtr();
    if (!cache) {
        LOG("[KvInjector] InjectSaveFiles app=%u: cache pointer null", appId);
        return false;
    }

    void* appInfo = ResolveAppInfo(cache, appId);
    if (!appInfo) {
        LOG("[KvInjector] InjectSaveFiles app=%u: no app info entry", appId);
        return false;
    }

    void* ufs = g_r.getSection(appInfo, kSectionUfs);
    if (!ufs) {
        LOG("[KvInjector] InjectSaveFiles app=%u: ufs section missing", appId);
        return false;
    }

    // Check if savefiles already exists with children. If so, don't clobber.
    void* existing = g_r.kvFindKey(ufs, "savefiles", 0, nullptr);
    if (existing) {
        void* child0 = g_r.kvFindKey(existing, "0", 0, nullptr);
        if (child0) {
            LOG("[KvInjector] InjectSaveFiles app=%u: savefiles already populated, skipping",
                appId);
            return true;
        }
    }

    void* savefiles = g_r.kvFindKey(ufs, "savefiles", 1, nullptr);
    if (!savefiles) {
        LOG("[KvInjector] InjectSaveFiles app=%u: failed to create savefiles key", appId);
        return false;
    }

    int injected = 0;
    for (size_t i = 0; i < rules.size(); ++i) {
        const auto& rule = rules[i];
        std::string idxStr = std::to_string(i);

        void* entry = g_r.kvFindKey(savefiles, idxStr.c_str(), 1, nullptr);
        if (!entry) continue;

        void* rootKv = g_r.kvFindKey(entry, "root", 1, nullptr);
        if (rootKv) g_r.kvSetString(rootKv, rule.root.c_str());

        if (!rule.path.empty()) {
            void* pathKv = g_r.kvFindKey(entry, "path", 1, nullptr);
            if (pathKv) g_r.kvSetString(pathKv, rule.path.c_str());
        }

        void* patternKv = g_r.kvFindKey(entry, "pattern", 1, nullptr);
        if (patternKv) g_r.kvSetString(patternKv, rule.pattern.c_str());

        if (rule.recursive) {
            void* recursiveKv = g_r.kvFindKey(entry, "recursive", 1, nullptr);
            if (recursiveKv) g_r.kvSetInt32(recursiveKv, 1);
        }

        if (rule.platforms != 0xFFFFFFFFu) {
            void* platformsKv = g_r.kvFindKey(entry, "platforms", 1, nullptr);
            if (platformsKv) {
                if (rule.platforms & 1) {
                    void* k = g_r.kvFindKey(platformsKv, "1", 1, nullptr);
                    if (k) g_r.kvSetString(k, "windows");
                }
                if (rule.platforms & 2) {
                    void* k = g_r.kvFindKey(platformsKv, "2", 1, nullptr);
                    if (k) g_r.kvSetString(k, "macos");
                }
                if (rule.platforms & 8) {
                    void* k = g_r.kvFindKey(platformsKv, "3", 1, nullptr);
                    if (k) g_r.kvSetString(k, "linux");
                }
            }
        }

        ++injected;
    }

    LOG("[KvInjector] InjectSaveFiles app=%u: injected %d savefiles rules", appId, injected);
    return injected > 0;
}

#endif // _WIN32

void** GetEngineGlobalPtr() {
#ifdef _WIN32
    return nullptr; // Windows uses a different resolution path
#else
    return g_r.globalEnginePtr;
#endif
}

} // namespace SteamKvInjector
