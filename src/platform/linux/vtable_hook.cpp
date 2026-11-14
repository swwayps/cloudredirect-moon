#include "vtable_hook.h"
#include "init_stop.h"
#include "log.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <cinttypes>
#include <mutex>
#include <vector>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

// RTTI typestring for CClientUnifiedServiceTransport (Itanium ABI mangled)
static constexpr const char RTTI_NAME[] = "30CClientUnifiedServiceTransport";

// Steam's loader hides libraries from dl_iterate_phdr; parse /proc/self/maps.

// Mapping snapshot of the steamclient.so scan window.
//
// These were fixed 64-entry arrays, filled in ascending address order and
// silently truncated once full. steamclient.so's mapping is fragmented while
// the client starts, and past 64 readable ranges in the scan window the
// *highest* addresses were the ones dropped -- which is exactly where
// .data.rel.ro lives (vaddr ~0x2e57ae0 of a ~0x2f38000 module), while the RTTI
// name strings sit far lower in .rodata (~0xb38020). The scan therefore found
// the type string and then failed to find its typeinfo, and every such log
// reported "64 readable ranges" because the counter could not exceed the cap.
// Growable storage removes the cap: no range in the window is ever dropped.
struct MemRange { uintptr_t start; uintptr_t end; };
static std::vector<MemRange> g_readableRanges;
static std::vector<MemRange> g_writableRanges;

// Module bounds from the last maps snapshot, for RefreshRanges().
static uintptr_t g_scanBase = 0;
static uintptr_t g_scanLabeledMax = 0;

// Set while ResolveTransportVtable() still has attempts left, so a miss on a
// non-final pass logs as a warning instead of a hard error.
static bool g_scanRetryPending = false;

// Probe readability via write() to /dev/null. Used before g_readableRanges is populated.
static bool CanReadMemory(const void* addr, size_t len);

// Walk backward page-by-page to find ELF magic (true load base).
// Labeled-min may be offset into the file due to split PT_LOAD mappings.
static uintptr_t FindElfBaseBackward(uintptr_t hint)
{
    const long pageSize = sysconf(_SC_PAGESIZE);
    const uintptr_t pageMask = ~(uintptr_t)(pageSize - 1);
    uintptr_t page = hint & pageMask;
    // Cap at 64 MiB backward to avoid sweeping into adjacent modules.
    const uintptr_t limit = (page > (64ULL * 1024 * 1024)) ? page - (64ULL * 1024 * 1024) : 0;
    while (page >= limit && page != 0)
    {
        if (CanReadMemory(reinterpret_cast<void*>(page), 4))
        {
            const uint8_t* p = reinterpret_cast<const uint8_t*>(page);
            if (p[0] == 0x7F && p[1] == 'E' && p[2] == 'L' && p[3] == 'F')
                return page;
        }
        if (page < (uintptr_t)pageSize) break;
        page -= pageSize;
    }
    return 0;
}

// Snapshot readable/writable mappings within +/-16 MiB of the module span.
// .data.rel.ro may live in anonymous mappings inside the span, and the
// adjacency margin tolerates a labeled span that has not finished growing.
static void CaptureRanges(uintptr_t base, uintptr_t labeledMax)
{
    g_readableRanges.clear();
    g_writableRanges.clear();
    g_readableRanges.reserve(256);
    g_writableRanges.reserve(64);

    const uintptr_t adjacency = 16ULL * 1024 * 1024;
    const uintptr_t scanLo = (base > adjacency) ? base - adjacency : 0;
    const uintptr_t scanHi = labeledMax + adjacency;

    FILE* f = fopen("/proc/self/maps", "r");
    if (!f)
    {
        Log::Error("cannot open /proc/self/maps for range capture");
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), f))
    {
        uintptr_t start_addr, end_addr;
        char perms[5] = {};
        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s", &start_addr, &end_addr, perms) < 3)
            continue;
        if (end_addr <= scanLo || start_addr >= scanHi) continue;
        if (perms[0] != 'r') continue;

        g_readableRanges.push_back({start_addr, end_addr});
        if (perms[1] == 'w')
            g_writableRanges.push_back({start_addr, end_addr});
    }
    fclose(f);

    g_scanBase = base;
    g_scanLabeledMax = labeledMax;
}

// Ranges that actually intersect the module span -- the only ones the scans
// consider. Logged so a shortfall here is visible instead of silent.
static size_t CountInModule(const std::vector<MemRange>& ranges,
                            uintptr_t base, uintptr_t end)
{
    size_t n = 0;
    for (const MemRange& r : ranges)
        if (r.end > base && r.start < end) n++;
    return n;
}

bool VtableHook::RefreshRanges()
{
    if (g_scanBase == 0) return false;
    CaptureRanges(g_scanBase, g_scanLabeledMax);
    return !g_readableRanges.empty();
}

uintptr_t VtableHook::FindSteamclient(size_t& outSize)
{
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f)
    {
        Log::Error("cannot open /proc/self/maps");
        return 0;
    }

    uintptr_t labeledMin = 0;
    uintptr_t labeledMax = 0;
    char line[512];

    while (fgets(line, sizeof(line), f))
    {
        uintptr_t start_addr, end_addr;
        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR, &start_addr, &end_addr) < 2)
            continue;
        if (strstr(line, "steamclient.so"))
        {
            if (labeledMin == 0 || start_addr < labeledMin)
                labeledMin = start_addr;
            if (end_addr > labeledMax)
                labeledMax = end_addr;
        }
    }

    if (labeledMin == 0)
    {
        fclose(f);
        Log::Error("steamclient.so not found in /proc/self/maps");
        return 0;
    }

    // Anchor base on ELF magic to correct for labeled-min offset.
    uintptr_t base = FindElfBaseBackward(labeledMin);
    if (base == 0)
    {
        Log::Warn("ELF magic not found backward from labeled steamclient.so start %p, using labeled min",
                  (void*)labeledMin);
        base = labeledMin;
    }
    else if (base != labeledMin)
    {
        Log::Info("corrected steamclient.so base from labeled %p to ELF-magic %p (gap=0x%zx)",
                  (void*)labeledMin, (void*)base, labeledMin - base);
    }

    fclose(f);

    // Slot-pointer validation still uses the tight labeled span.
    CaptureRanges(base, labeledMax);

    outSize = labeledMax - base;
    Log::Info("steamclient.so base=%p end=%p size=0x%zx (%zu readable, %zu writable ranges)",
              (void*)base, (void*)labeledMax, outSize,
              g_readableRanges.size(), g_writableRanges.size());
    Log::Debug("labeledMin=%p labeledMax=%p inModuleReadable=%zu inModuleWritable=%zu",
               (void*)labeledMin, (void*)labeledMax,
               CountInModule(g_readableRanges, base, labeledMax),
               CountInModule(g_writableRanges, base, labeledMax));
    return base;
}

// Safe memory probe using write() to /dev/null -- avoids SIGSEGV
static bool CanReadMemory(const void* addr, size_t len)
{
    static std::once_flag devnullOnce;
    static int devnull = -1;
    std::call_once(devnullOnce, []() {
        devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
    });
    if (devnull < 0)
        return false;
    return (write(devnull, addr, len) == (ssize_t)len);
}

// Scan readable ranges within steamclient for a byte sequence.
static const uint8_t* FindBytes(const void* needle, size_t needleLen,
                                uintptr_t steamBase, size_t steamSize)
{
    const uint8_t firstByte = *static_cast<const uint8_t*>(needle);

    for (const MemRange& range : g_readableRanges)
    {
        if (range.end <= steamBase || range.start >= steamBase + steamSize)
            continue;
        size_t rangeSize = range.end - range.start;
        if (rangeSize < needleLen) continue;

        // memchr on the first byte, then confirm: the module is ~47 MiB and this
        // runs on every scan attempt, so a byte-at-a-time memcmp is wasteful.
        const uint8_t* p = reinterpret_cast<const uint8_t*>(range.start);
        const uint8_t* last = reinterpret_cast<const uint8_t*>(range.end) - needleLen;
        while (p <= last)
        {
            const uint8_t* hit = static_cast<const uint8_t*>(
                memchr(p, firstByte, static_cast<size_t>(last - p) + 1));
            if (!hit) break;
            if (memcmp(hit, needle, needleLen) == 0)
                return hit;
            p = hit + 1;
        }
    }
    return nullptr;
}

// Search steamclient ranges for a pointer value; tries `primary` first,
// falls back to `fallback` to avoid false positives on small values.
static const uintptr_t* FindPointerValue(uintptr_t primary, uintptr_t fallback,
                                         uintptr_t steamBase, size_t steamSize)
{
    for (int pass = 0; pass < 2; pass++)
    {
        uintptr_t target = (pass == 0) ? primary : fallback;
        if (pass == 1 && primary == fallback) break;  // same value, no second pass

        for (const MemRange& range : g_readableRanges)
        {
            if (range.end <= steamBase || range.start >= steamBase + steamSize)
                continue;

            const uintptr_t* scanStart = reinterpret_cast<const uintptr_t*>(
                (range.start + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1));
            const uintptr_t* scanEnd = reinterpret_cast<const uintptr_t*>(
                range.end & ~(sizeof(uintptr_t) - 1));

            for (const uintptr_t* p = scanStart; p < scanEnd; p++)
            {
                if (*p == target)
                    return p;
            }
        }
    }
    return nullptr;
}

void** VtableHook::FindTransportVtable(uintptr_t steamBase, size_t steamSize)
{
    const size_t nameLen = strlen(RTTI_NAME);

    // Find RTTI string in .rodata (never relocated)
    const uint8_t* rttiStr = FindBytes(RTTI_NAME, nameLen + 1, steamBase, steamSize);
    if (!rttiStr)
    {
        Log::Error("RTTI string '%s' not found in steamclient.so", RTTI_NAME);
        return nullptr;
    }
    uintptr_t rttiStrAddr = reinterpret_cast<uintptr_t>(rttiStr);
    uintptr_t rttiStrVaddr = rttiStrAddr - steamBase;  // file vaddr (pre-relocation value)
    Log::Debug("RTTI typestring at %p (vaddr 0x%zx)", rttiStr, (size_t)rttiStrVaddr);

    // Find typeinfo: name_ptr is raw vaddr (unrelocated) or absolute (relocated)
    const uintptr_t* nameField = FindPointerValue(rttiStrAddr, rttiStrVaddr,
                                                  steamBase, steamSize);
    if (!nameField)
    {
        if (g_scanRetryPending)
            Log::Warn("typeinfo for CClientUnifiedServiceTransport not found, will retry");
        else
            Log::Error("typeinfo for CClientUnifiedServiceTransport not found");
        Log::Debug("  searched for 0x%zx (relocated) and 0x%zx (unrelocated) across %zu ranges (%zu in module)",
                   (size_t)rttiStrAddr, (size_t)rttiStrVaddr, g_readableRanges.size(),
                   CountInModule(g_readableRanges, steamBase, steamBase + steamSize));
        return nullptr;
    }
    const uintptr_t* typeinfo = nameField - 1;  // typeinfo starts one slot before name
    uintptr_t typeinfoAddr = reinterpret_cast<uintptr_t>(typeinfo);
    bool relocated = (*nameField == rttiStrAddr);
    Log::Debug("typeinfo at %p (vaddr 0x%zx, %s)",
               typeinfo, typeinfoAddr - steamBase, relocated ? "relocated" : "unrelocated");

    // Poll until .data.rel.ro relocations are applied
    if (!relocated)
    {
        Log::Info("Relocations pending for .data.rel.ro, waiting...");
        volatile uintptr_t* nameSlot = const_cast<volatile uintptr_t*>(nameField);
        int waitMs = 0;
        const int maxWaitMs = 30000;  // 30 seconds max
        while (*nameSlot != rttiStrAddr && waitMs < maxWaitMs)
        {
            // Sleeping on the stop signal so an exiting process cancels the wait
            // instead of holding OnUnload's join open for the rest of it.
            if (LinuxInitStop::ProcessStop().WaitFor(std::chrono::milliseconds(50)))
            {
                Log::Info("Relocation wait stopped early after %dms (process exiting)", waitMs);
                return nullptr;
            }
            waitMs += 50;
        }
        if (*nameSlot != rttiStrAddr)
        {
            Log::Error("Relocations did not complete after %dms (name_ptr=%p, expected %p)",
                       waitMs, (void*)*nameSlot, (void*)rttiStrAddr);
            return nullptr;
        }
        Log::Info("Relocations completed after %dms", waitMs);
    }

    // Find vtable: scan for [offset_to_top=0, typeinfo_ptr] header
    void** vtableFuncs = nullptr;
    for (size_t r = 0; r < g_readableRanges.size() && !vtableFuncs; r++)
    {
        const MemRange& range = g_readableRanges[r];
        if (range.end <= steamBase || range.start >= steamBase + steamSize)
            continue;

        const uintptr_t* scanStart = reinterpret_cast<const uintptr_t*>(
            (range.start + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1));
        const uintptr_t* scanEnd = reinterpret_cast<const uintptr_t*>(
            range.end & ~(sizeof(uintptr_t) - 1));

        for (const uintptr_t* p = scanStart; p + 1 < scanEnd; p++)
        {
            if (*p == 0 && *(p + 1) == typeinfoAddr)
            {
                vtableFuncs = reinterpret_cast<void**>(const_cast<uintptr_t*>(p + 2));
                Log::Debug("Found vtable at %p (header at %p) in range %zu",
                           vtableFuncs, p, r);
                break;
            }
        }
    }

    if (!vtableFuncs)
    {
        if (g_scanRetryPending)
            Log::Warn("vtable for CClientUnifiedServiceTransport not found (typeinfo=%p), will retry", typeinfo);
        else
            Log::Error("vtable for CClientUnifiedServiceTransport not found (typeinfo=%p)", typeinfo);
        return nullptr;
    }

    // Validate function pointer slots
    if (!CanReadMemory(vtableFuncs, 9 * sizeof(void*)))
    {
        Log::Error("CClientUnifiedServiceTransport vtable at %p but slots not readable", vtableFuncs);
        return nullptr;
    }

    for (int slot : {5, 7, 8}) {
        uintptr_t fn = reinterpret_cast<uintptr_t>(vtableFuncs[slot]);
        if (fn < steamBase || fn >= steamBase + steamSize) {
            Log::Error("vtable slot %d (%p) outside steamclient range [%p, %p)",
                       slot, (void*)fn, (void*)steamBase, (void*)(steamBase + steamSize));
            return nullptr;
        }
    }

    Log::Info("CClientUnifiedServiceTransport vtable at %p (offset 0x%zx)",
              vtableFuncs, reinterpret_cast<uintptr_t>(vtableFuncs) - steamBase);
    Log::Debug("  slot5=%p  slot7=%p  slot8=%p",
               vtableFuncs[5], vtableFuncs[7], vtableFuncs[8]);
    return vtableFuncs;
}

void** VtableHook::ResolveTransportVtable(uintptr_t& outBase, size_t& outSize,
                                         int maxAttempts, int retryDelayMs)
{
    if (maxAttempts < 1) maxAttempts = 1;
    outBase = 0;
    outSize = 0;

    for (int attempt = 1; attempt <= maxAttempts; attempt++)
    {
        g_scanRetryPending = (attempt < maxAttempts);

        // Re-resolved every attempt, not just re-snapshotted: while the client
        // starts, the labeled span itself can still be growing, and a span that
        // stops short of .data.rel.ro excludes the typeinfo from every scan.
        size_t size = 0;
        uintptr_t base = FindSteamclient(size);
        if (base)
        {
            outBase = base;
            outSize = size;

            void** vtable = FindTransportVtable(base, size);
            if (vtable)
            {
                g_scanRetryPending = false;
                if (attempt > 1)
                    Log::Info("transport vtable resolved on attempt %d/%d", attempt, maxAttempts);
                return vtable;
            }
        }

        if (attempt == maxAttempts) break;

        Log::Info("transport vtable scan attempt %d/%d incomplete, re-reading /proc/self/maps in %dms",
                  attempt, maxAttempts, retryDelayMs);
        if (LinuxInitStop::ProcessStop().WaitFor(std::chrono::milliseconds(retryDelayMs)))
        {
            g_scanRetryPending = false;
            Log::Info("transport vtable scan stopped early on attempt %d (process exiting)", attempt);
            return nullptr;
        }
    }

    g_scanRetryPending = false;
    Log::Error("transport vtable not resolved after %d attempts", maxAttempts);
    return nullptr;
}

static bool MakeWritable(void* addr, size_t len)
{
    long pageSize = sysconf(_SC_PAGESIZE);
    uintptr_t page = reinterpret_cast<uintptr_t>(addr) & ~(pageSize - 1);
    uintptr_t endAddr = reinterpret_cast<uintptr_t>(addr) + len;
    size_t pageLen = ((endAddr - page) + (pageSize - 1)) & ~(pageSize - 1);
    return mprotect(reinterpret_cast<void*>(page), pageLen, PROT_READ | PROT_WRITE) == 0;
}

static bool MakeReadOnly(void* addr, size_t len)
{
    long pageSize = sysconf(_SC_PAGESIZE);
    uintptr_t page = reinterpret_cast<uintptr_t>(addr) & ~(pageSize - 1);
    uintptr_t endAddr = reinterpret_cast<uintptr_t>(addr) + len;
    size_t pageLen = ((endAddr - page) + (pageSize - 1)) & ~(pageSize - 1);
    return mprotect(reinterpret_cast<void*>(page), pageLen, PROT_READ) == 0;
}

// Defined in cloud_hooks.cpp
extern "C" {
    int hook_BYieldingSend(void* pThis, const char* methodName, void* request, void* response, int* flags);
    int hook_NotificationDirect(void* pThis, const char* methodName, void* body, int* flags);
    int hook_SyncSend2(void* pThis, const char* methodName, void* buf, unsigned int bufLen, void* response, int* flags);
    bool hook_IsCloudEnabledForApp(void* pThis, unsigned int appId);
}

bool VtableHook::InstallHooks(void** vtable, VtableInfo& info)
{
    info.vtable = vtable;
    info.origSlot5 = vtable[5];
    info.origSlot7 = vtable[7];
    info.origSlot8 = vtable[8];

    // The vtable lives in .data.rel.ro -- need to make it writable
    void* slotBase = &vtable[5];
    size_t span = reinterpret_cast<uintptr_t>(&vtable[8]) - reinterpret_cast<uintptr_t>(&vtable[5]) + 8;

    if (!MakeWritable(slotBase, span))
    {
        Log::Error("mprotect RW failed on vtable");
        return false;
    }

    vtable[5] = reinterpret_cast<void*>(&hook_BYieldingSend);
    vtable[7] = reinterpret_cast<void*>(&hook_NotificationDirect);
    vtable[8] = reinterpret_cast<void*>(&hook_SyncSend2);

    // Restore read-only (non-fatal if it fails).
    MakeReadOnly(slotBase, span);

    Log::Info("Vtable hooks installed: slot5=%p slot7=%p slot8=%p",
              vtable[5], vtable[7], vtable[8]);
    return true;
}

void VtableHook::RemoveHooks(const VtableInfo& info)
{
    if (!info.vtable) return;

    void* slotBase = &info.vtable[5];
    size_t span = reinterpret_cast<uintptr_t>(&info.vtable[8]) - reinterpret_cast<uintptr_t>(&info.vtable[5]) + 8;

    if (MakeWritable(slotBase, span))
    {
        info.vtable[5] = info.origSlot5;
        info.vtable[7] = info.origSlot7;
        info.vtable[8] = info.origSlot8;
        MakeReadOnly(slotBase, span);
        Log::Info("Vtable hooks removed");
    }
    else
    {
        Log::Warn("mprotect RW failed during hook removal");
    }
}

static constexpr const char RTTI_REMOTE_STORAGE[] = "18CUserRemoteStorage";

static bool IsWithinSteamclient(uintptr_t ptr, uintptr_t steamBase, size_t steamSize)
{
    return ptr >= steamBase && ptr < steamBase + steamSize;
}

#if defined(__x86_64__)
// True when the first `scan` bytes at `code` hold a `lea r64,[rip+disp32]`
// (REX.W 8D /r, mod=00 rm=101) whose target is the NUL-terminated `text`.
static bool FunctionLoadsString(const uint8_t* code, size_t scan, const char* text,
                                uintptr_t steamBase, size_t steamSize)
{
    if (!CanReadMemory(code, scan + 7)) return false;
    const size_t len = strlen(text) + 1;
    for (size_t i = 0; i + 7 <= scan; ++i)
    {
        if ((code[i] != 0x48 && code[i] != 0x4C) || code[i + 1] != 0x8D ||
            (code[i + 2] & 0xC7) != 0x05)
            continue;
        int32_t disp;
        memcpy(&disp, code + i + 3, sizeof(disp));
        const uintptr_t target = reinterpret_cast<uintptr_t>(code + i + 7) + (intptr_t)disp;
        if (!IsWithinSteamclient(target, steamBase, steamSize) ||
            !CanReadMemory(reinterpret_cast<const void*>(target), len))
            continue;
        if (memcmp(reinterpret_cast<const void*>(target), text, len) == 0)
            return true;
    }
    return false;
}
#endif

static bool IsLikelyAppCloudEnabledSlot(void** vtable, size_t slotIndex, uintptr_t steamBase, size_t steamSize)
{
    uintptr_t fn = reinterpret_cast<uintptr_t>(vtable[slotIndex]);
    if (!IsWithinSteamclient(fn, steamBase, steamSize) || !CanReadMemory(reinterpret_cast<void*>(fn), 30))
        return false;

    const uint8_t* p = reinterpret_cast<const uint8_t*>(fn);

#if defined(__x86_64__)
    // x86_64: the prologue carries no PIC thunk to anchor on, so identify the
    // method by what it reads. IsCloudEnabledForApp (slot 24 on steamrt64 build
    // 1794536281) checks the per-app cloud toggle map, then the app's
    // "ignoreexternalfiles" and "hidecloudui" UFS keys; no other slot loads both.
    return FunctionLoadsString(p, 0x200, "ignoreexternalfiles", steamBase, steamSize) &&
           FunctionLoadsString(p, 0x200, "hidecloudui", steamBase, steamSize);
#else
    // Pattern A (older builds): args passed via esp offsets
    //   +0:  55 57 56 53 E8 ?? ?? ?? ??  (push ebp/edi/esi/ebx + call PIC thunk)
    //   +9:  81 C3 ?? ?? ?? ??          (add ebx, imm32)
    //   +15: 83 EC 0C                   (sub esp, 0x0C)
    //   +18: 8B 74 24 24                (mov esi, [esp+0x24] - appId)
    //   +22: 8B 7C 24 20                (mov edi, [esp+0x20] - this)
    if (p[0] == 0x55 && p[1] == 0x57 && p[2] == 0x56 && p[3] == 0x53 && p[4] == 0xE8 &&
        p[15] == 0x83 && p[16] == 0xEC && p[17] == 0x0C &&
        p[18] == 0x8B && p[19] == 0x74 && p[20] == 0x24 && p[21] == 0x24 &&
        p[22] == 0x8B && p[23] == 0x7C && p[24] == 0x24 && p[25] == 0x20)
        return true;

    // Pattern B (May 2026+): esi/ebx pushed after PIC fixup, args via ebp
    //   +0:  55 89 E5 57 E8 ?? ?? ?? ??  (push ebp; mov ebp,esp; push edi; call PIC)
    //   +9:  81 C7/C3 ?? ?? ?? ??       (add edi/ebx, imm32)
    //   +15: 56 53                      (push esi; push ebx)
    //   +17: 83 EC                      (sub esp, imm8)
    //   +20: 8B 45 0C                   (mov eax, [ebp+0Ch] - appId arg)
    //   +23: 85 C0                      (test eax, eax - appId null check)
    //   +25: 0F 84                      (jz near - distinct from jnz in other methods)
    if (p[0] == 0x55 && p[1] == 0x89 && p[2] == 0xE5 && p[3] == 0x57 && p[4] == 0xE8 &&
        p[9] == 0x81 &&
        p[15] == 0x56 && p[16] == 0x53 &&
        p[17] == 0x83 && p[18] == 0xEC &&
        p[20] == 0x8B && p[21] == 0x45 && p[22] == 0x0C &&
        p[23] == 0x85 && p[24] == 0xC0 &&
        p[25] == 0x0F && p[26] == 0x84)
        return true;

    return false;
#endif
}

static size_t ResolveCloudEnabledSlot(void** vtable, uintptr_t steamBase, size_t steamSize)
{
    for (size_t slot = 0; slot < 32; ++slot) {
        if (IsLikelyAppCloudEnabledSlot(vtable, slot, steamBase, steamSize))
            return slot;
    }
    return SIZE_MAX;
}

void** VtableHook::FindRemoteStorageVtable(uintptr_t steamBase, size_t steamSize)
{
    const size_t nameLen = strlen(RTTI_REMOTE_STORAGE);

    // Find RTTI string
    const uint8_t* rttiStr = FindBytes(RTTI_REMOTE_STORAGE, nameLen + 1, steamBase, steamSize);
    if (!rttiStr)
    {
        Log::Error("RTTI string '%s' not found in steamclient.so", RTTI_REMOTE_STORAGE);
        return nullptr;
    }
    uintptr_t rttiStrAddr = reinterpret_cast<uintptr_t>(rttiStr);
    uintptr_t rttiStrVaddr = rttiStrAddr - steamBase;
    Log::Debug("CUserRemoteStorage RTTI at %p (vaddr 0x%zx)", rttiStr, (size_t)rttiStrVaddr);

    // Find typeinfo (relocations already waited on by Transport)
    const uintptr_t* nameField = FindPointerValue(rttiStrAddr, rttiStrVaddr,
                                                  steamBase, steamSize);
    if (!nameField && RefreshRanges())
    {
        // Same failure class as the transport scan: the snapshot can predate the
        // mapping that holds .data.rel.ro. The RTTI string address stays valid.
        Log::Warn("typeinfo for CUserRemoteStorage not found, re-reading /proc/self/maps and retrying");
        nameField = FindPointerValue(rttiStrAddr, rttiStrVaddr, steamBase, steamSize);
    }
    if (!nameField)
    {
        Log::Error("typeinfo for CUserRemoteStorage not found");
        return nullptr;
    }
    const uintptr_t* typeinfo = nameField - 1;
    uintptr_t typeinfoAddr = reinterpret_cast<uintptr_t>(typeinfo);
    Log::Debug("CUserRemoteStorage typeinfo at %p", typeinfo);

    // Find vtable: [offset_to_top=0, typeinfo_ptr]
    void** vtableFuncs = nullptr;
    for (size_t r = 0; r < g_readableRanges.size() && !vtableFuncs; r++)
    {
        const MemRange& range = g_readableRanges[r];
        if (range.end <= steamBase || range.start >= steamBase + steamSize)
            continue;

        const uintptr_t* scanStart = reinterpret_cast<const uintptr_t*>(
            (range.start + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1));
        const uintptr_t* scanEnd = reinterpret_cast<const uintptr_t*>(
            range.end & ~(sizeof(uintptr_t) - 1));

        for (const uintptr_t* p = scanStart; p + 1 < scanEnd; p++)
        {
            if (*p == 0 && *(p + 1) == typeinfoAddr)
            {
                vtableFuncs = reinterpret_cast<void**>(const_cast<uintptr_t*>(p + 2));
                break;
            }
        }
    }

    if (!vtableFuncs)
    {
        Log::Error("vtable for CUserRemoteStorage not found");
        return nullptr;
    }

    if (!CanReadMemory(vtableFuncs, 25 * sizeof(void*)))
    {
        Log::Error("CUserRemoteStorage vtable at %p but slots not readable", vtableFuncs);
        return nullptr;
    }

    size_t cloudEnabledSlot = ResolveCloudEnabledSlot(vtableFuncs, steamBase, steamSize);
    if (cloudEnabledSlot == SIZE_MAX)
    {
        Log::Error("CUserRemoteStorage vtable at %p but could not resolve cloud-enabled slot", vtableFuncs);
        return nullptr;
    }

    Log::Info("CUserRemoteStorage vtable at %p (cloud-enabled slot%zu=%p)",
              vtableFuncs, cloudEnabledSlot, vtableFuncs[cloudEnabledSlot]);
    return vtableFuncs;
}

void** VtableHook::FindVtableByRTTIName(const char* mangledName,
                                       uintptr_t steamBase, size_t steamSize)
{
    const size_t nameLen = strlen(mangledName);

    // 1) RTTI type-name string (.rodata, never relocated).
    const uint8_t* rttiStr = FindBytes(mangledName, nameLen + 1, steamBase, steamSize);
    if (!rttiStr)
    {
        Log::Error("RTTI string '%s' not found in steamclient.so", mangledName);
        return nullptr;
    }
    uintptr_t rttiStrAddr = reinterpret_cast<uintptr_t>(rttiStr);
    uintptr_t rttiStrVaddr = rttiStrAddr - steamBase;  // file vaddr (pre-relocation)
    Log::Debug("RTTI '%s' at %p (vaddr 0x%zx)", mangledName, rttiStr, (size_t)rttiStrVaddr);

    // 2) typeinfo: name_ptr holds relocated absolute or unrelocated file vaddr.
    const uintptr_t* nameField = FindPointerValue(rttiStrAddr, rttiStrVaddr,
                                                  steamBase, steamSize);
    if (!nameField)
    {
        Log::Error("typeinfo for '%s' not found (rel=0x%zx unrel=0x%zx)",
                   mangledName, (size_t)rttiStrAddr, (size_t)rttiStrVaddr);
        return nullptr;
    }
    const uintptr_t* typeinfo = nameField - 1;  // typeinfo starts one slot before name
    uintptr_t typeinfoAddr = reinterpret_cast<uintptr_t>(typeinfo);
    bool relocated = (*nameField == rttiStrAddr);
    Log::Debug("typeinfo for '%s' at %p (%s)", mangledName, typeinfo,
               relocated ? "relocated" : "unrelocated");

    // 3) Wait for .data.rel.ro relocations if pending (vtable typeinfo ptr is
    // the runtime absolute typeinfoAddr only once relocated).
    if (!relocated)
    {
        volatile uintptr_t* nameSlot = const_cast<volatile uintptr_t*>(nameField);
        int waitMs = 0;
        const int maxWaitMs = 30000;
        while (*nameSlot != rttiStrAddr && waitMs < maxWaitMs)
        {
            // Same cancellable sleep as the transport-vtable relocation wait.
            if (LinuxInitStop::ProcessStop().WaitFor(std::chrono::milliseconds(50)))
            {
                Log::Info("relocation wait for '%s' stopped early after %dms (process exiting)",
                          mangledName, waitMs);
                return nullptr;
            }
            waitMs += 50;
        }
        if (*nameSlot != rttiStrAddr)
        {
            Log::Error("relocations did not complete for '%s' after %dms", mangledName, waitMs);
            return nullptr;
        }
    }

    // 4) vtable: scan for [offset_to_top=0, typeinfo_ptr] header.
    for (const MemRange& range : g_readableRanges)
    {
        if (range.end <= steamBase || range.start >= steamBase + steamSize)
            continue;

        const uintptr_t* scanStart = reinterpret_cast<const uintptr_t*>(
            (range.start + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1));
        const uintptr_t* scanEnd = reinterpret_cast<const uintptr_t*>(
            range.end & ~(sizeof(uintptr_t) - 1));

        for (const uintptr_t* p = scanStart; p + 1 < scanEnd; p++)
        {
            if (*p == 0 && *(p + 1) == typeinfoAddr)
            {
                void** vtableFuncs = reinterpret_cast<void**>(const_cast<uintptr_t*>(p + 2));
                if (!CanReadMemory(vtableFuncs, sizeof(void*)))
                    continue;
                Log::Info("vtable for '%s' at %p (offset 0x%zx)", mangledName,
                          vtableFuncs, reinterpret_cast<uintptr_t>(vtableFuncs) - steamBase);
                return vtableFuncs;
            }
        }
    }

    Log::Error("vtable for '%s' not found (typeinfo=%p)", mangledName, typeinfo);
    return nullptr;
}

void* VtableHook::FindGlobalWithVtable(void* vtablePtr,
                                       uintptr_t steamBase, size_t steamSize)
{
    uintptr_t target = reinterpret_cast<uintptr_t>(vtablePtr);

    // Default instances live in writable .data/.bss. Scan writable ranges.
    for (const MemRange& range : g_writableRanges)
    {
        if (range.end <= steamBase || range.start >= steamBase + steamSize)
            continue;

        const uintptr_t* scanStart = reinterpret_cast<const uintptr_t*>(
            (range.start + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1));
        const uintptr_t* scanEnd = reinterpret_cast<const uintptr_t*>(
            range.end & ~(sizeof(uintptr_t) - 1));

        for (const uintptr_t* p = scanStart; p + 2 < scanEnd; p++)
        {
            // First word == vtable, next two words == 0 (arena / has_bits).
            if (*p == target && *(p + 1) == 0 && *(p + 2) == 0)
            {
                void* inst = reinterpret_cast<void*>(const_cast<uintptr_t*>(p));
                Log::Info("default instance for vtable %p at %p (offset 0x%zx)",
                          vtablePtr, inst, reinterpret_cast<uintptr_t>(inst) - steamBase);
                return inst;
            }
        }
    }

    Log::Error("default instance for vtable %p not found", vtablePtr);
    return nullptr;
}

bool VtableHook::InstallCloudEnabledHook(void** vtable, CloudEnabledHookInfo& info)
{
    size_t slotIndex = ResolveCloudEnabledSlot(vtable, 0, UINTPTR_MAX);
    if (slotIndex == SIZE_MAX)
    {
        Log::Error("Could not resolve CUserRemoteStorage cloud-enabled slot");
        return false;
    }

    info.vtable = vtable;
    info.slotIndex = slotIndex;
    info.origSlot = vtable[slotIndex];

    void* slotAddr = &vtable[slotIndex];
    if (!MakeWritable(slotAddr, sizeof(void*)))
    {
        Log::Error("mprotect RW failed on RemoteStorage vtable slot %zu", slotIndex);
        return false;
    }

    vtable[slotIndex] = reinterpret_cast<void*>(&hook_IsCloudEnabledForApp);
    MakeReadOnly(slotAddr, sizeof(void*));

    Log::Info("IsCloudEnabledForApp hook installed at slot %zu (orig=%p)", slotIndex, info.origSlot);
    return true;
}

void VtableHook::RemoveCloudEnabledHook(const CloudEnabledHookInfo& info)
{
    if (!info.vtable) return;

    void* slotAddr = &info.vtable[info.slotIndex];
    if (MakeWritable(slotAddr, sizeof(void*)))
    {
        info.vtable[info.slotIndex] = info.origSlot;
        MakeReadOnly(slotAddr, sizeof(void*));
        Log::Info("IsCloudEnabledForApp hook removed");
    }
}
