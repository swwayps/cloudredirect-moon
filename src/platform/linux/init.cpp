// cloud_redirect.so entry point

#include "vtable_hook.h"

// Exported version string for update detection by UI
#ifndef CR_VERSION_STRING
#define CR_VERSION_STRING "0.0.0+unknown"
#endif
extern "C" __attribute__((visibility("default")))
const char* CR_GetVersion() { return CR_VERSION_STRING; }
#include "cloud_hooks.h"
#include "cloud_intercept.h"
#include "cloud_storage.h"
#include "http_server.h"
#include "init_stop.h"
#include "legacy_metadata_cleanup.h"
#include "log.h"
#include "rpc_handlers.h"
#include "steam_kv_injector.h"
#include "xdg.h"

#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <setjmp.h>
#include <ucontext.h>
#include <execinfo.h>
#include <cstring>
#include <cstdio>
#include <atomic>
#include <string>
#include <cstdint>
#include <pthread.h>

static VtableHook::VtableInfo g_vtableInfo{};
static VtableHook::CloudEnabledHookInfo g_cloudEnabledInfo{};
static std::atomic<bool> g_initialized{false};
static std::atomic<bool> g_hookAttempted{false};
static std::atomic<bool> g_logInitialized{false};
static pthread_t g_initThread{};
static std::atomic<bool> g_initThreadCreated{false};

// Raw diagnostic logging (survives even if C++ runtime is broken)

static int g_debugFd = -1;
static char g_crashContext[192] = "none";

static void DebugLog(const char* msg)
{
    if (g_debugFd < 0) {
        std::string path = XdgConfigHome() + "/CloudRedirect/cr_debug.log";
        g_debugFd = open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    }
    if (g_debugFd < 0)
        return;

    // Every `steam` process shares this file, so an OnUnload from one interleaves
    // with an OnLoad from another and blocks cannot be attributed without
    // guessing. Stamp the pid, and emit each line with a single write so
    // concurrent processes cannot interleave mid-line.
    const char* body = msg;
    if (strncmp(msg, "[CR] ", 5) == 0)
        body = msg + 5;

    char buf[512];
    int n = snprintf(buf, sizeof(buf), "[CR][%d] %s", (int)getpid(), body);
    if (n <= 0)
        return;
    if (n > (int)sizeof(buf) - 1)
        n = (int)sizeof(buf) - 1;
    write(g_debugFd, buf, (size_t)n);
}

extern "C" void CR_SetCrashContext(const char* hook, const char* method, uint32_t appId)
{
    if (!hook) hook = "unknown";
    if (!method) method = "(null)";
    snprintf(g_crashContext, sizeof(g_crashContext), "%s method=%s app=%u",
             hook, method, appId);
    g_crashContext[sizeof(g_crashContext) - 1] = '\0';
}

extern "C" void CR_ClearCrashContext()
{
    g_crashContext[0] = '\0';
}



static void EnsureLogInit()
{
    bool expected = false;
    if (g_logInitialized.compare_exchange_strong(expected, true))
        Log::Init();
}

// Quick JSON bool lookup for early-init config reads (before the full JSON
// parser is available). Returns defaultVal if the key is absent.
static bool ReadConfigBool(const char* key, bool defaultVal)
{
    std::string configPath = XdgConfigHome() + "/CloudRedirect/config.json";
    FILE* f = fopen(configPath.c_str(), "r");
    if (!f) return defaultVal;

    char buf[65536] = {};
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';

    std::string needle = std::string("\"") + key + "\"";
    const char* pos = strstr(buf, needle.c_str());
    if (!pos) return defaultVal;

    const char* p = pos + needle.size();
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ':') ++p;

    if (strncmp(p, "false", 5) == 0) return false;
    if (strncmp(p, "true", 4) == 0) return true;
    return defaultVal;
}

static bool NotificationsEnabled() { return ReadConfigBool("notifications_enabled", true); }
static bool StatsSyncEnabled()     { return ReadConfigBool("stats_sync_enabled", true); }

static void Notify(const char* msg, bool critical = false)
{
    if (!NotificationsEnabled()) return;

    pid_t pid = fork();
    if (pid == 0) {
        // Child: exec notify-send and exit
        if (critical)
            execlp("notify-send", "notify-send", "-u", "critical", "CloudRedirect", msg, nullptr);
        else
            execlp("notify-send", "notify-send", "-t", "5000", "-u", "normal", "CloudRedirect", msg, nullptr);
        _exit(1);
    }
    // Parent: don't wait -- reap asynchronously via SIGCHLD (default ignore)
}

static std::string GetProcessName()
{
    char buf[256] = {};
    FILE* f = fopen("/proc/self/comm", "r");
    if (f) {
        if (fgets(buf, sizeof(buf), f)) {
            size_t len = strlen(buf);
            if (len > 0 && buf[len-1] == '\n') buf[len-1] = '\0';
        }
        fclose(f);
    }
    return buf;
}

static bool ExeEndsWith(const char* suffix)
{
    char exe[4096];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n <= 0) return false;
    exe[n] = '\0';
    const size_t len = strlen(suffix);
    return (size_t)n >= len && strcmp(exe + n - len, suffix) == 0;
}

// True in the host-side steamrt64/steam launcher (see OnLoad).
static bool IsSteamrt64Launcher()
{
    return !getenv("PRESSURE_VESSEL_RUNTIME") && ExeEndsWith("/steamrt64/steam");
}

static void CleanLdPreload()
{
    char* preload = getenv("LD_PRELOAD");
    if (!preload) return;

    std::string val(preload);
    std::string cleaned;
    size_t pos = 0;
    while (pos < val.size())
    {
        size_t sep = val.find_first_of(": ", pos);
        if (sep == std::string::npos) sep = val.size();
        std::string entry = val.substr(pos, sep - pos);
        if (!entry.empty() && entry.find("cloud_redirect") == std::string::npos)
        {
            if (!cleaned.empty()) cleaned += ':';
            cleaned += entry;
        }
        pos = sep + 1;
    }
    if (cleaned.empty())
        unsetenv("LD_PRELOAD");
    else
        setenv("LD_PRELOAD", cleaned.c_str(), 1);
}

static void DoInit()
{
    DebugLog("[CR] DoInit: version=" CR_VERSION_STRING " finding steamclient.so in /proc/self/maps\n");
    Log::Info("=== CloudRedirect loaded [BUILD:" CR_RELEASE_VERSION "] ===");
    Log::Info("CloudRedirect build %s", CR_VERSION_STRING);

    // Kill-switch: if disable file exists, bail without hooking
    {
        std::string disablePath = XdgConfigHome() + "/CloudRedirect/disable";
        if (access(disablePath.c_str(), F_OK) == 0) {
            DebugLog("[CR] DoInit: kill-switch active (CloudRedirect/disable exists), aborting\n");
            Log::Warn("Kill-switch active, skipping all hooks");
            return;
        }
    }

    DebugLog("[CR] DoInit: finding transport vtable\n");
    size_t steamSize = 0;
    uintptr_t steamBase = 0;
    void** vtable = VtableHook::ResolveTransportVtable(steamBase, steamSize);
    if (!steamBase)
    {
        DebugLog("[CR] DoInit: FAILED - steamclient.so not found\n");
        Log::Error("Init failed: steamclient.so not found in maps");
        Notify("Failed: steamclient.so not found", true);
        return;
    }
    Log::Info("steamclient.so base=%p size=0x%zx", (void*)steamBase, steamSize);

    if (!vtable)
    {
        // A stop request means the process is exiting mid-scan, not that the
        // client is incompatible -- don't alarm the user about a shutdown.
        if (LinuxInitStop::ProcessStop().Requested())
        {
            DebugLog("[CR] DoInit: aborted - process exiting during vtable scan\n");
            Log::Info("Init aborted: process exiting during vtable scan");
            return;
        }
        DebugLog("[CR] DoInit: FAILED - transport vtable not found\n");
        Log::Error("Init failed: transport vtable not found");
        Notify("Incompatible Steam client - hooks disabled", true);
        return;
    }
    Log::Info("Transport vtable at %p, slots: [5]=%p [7]=%p [8]=%p",
              (void*)vtable, vtable[5], vtable[7], vtable[8]);

    DebugLog("[CR] DoInit: saving originals\n");
    CloudHooks::SetOriginals(vtable[5], vtable[7], vtable[8]);

    DebugLog("[CR] DoInit: installing transport hooks\n");
    if (!VtableHook::InstallHooks(vtable, g_vtableInfo))
    {
        DebugLog("[CR] DoInit: FAILED - hook installation failed\n");
        Log::Error("Init failed: transport hook installation failed");
        return;
    }
    Log::Info("Transport hooks installed on slots 5/7/8");

    DebugLog("[CR] DoInit: looking for RemoteStorage vtable\n");
    void** rsVtable = VtableHook::FindRemoteStorageVtable(steamBase, steamSize);
    if (rsVtable)
    {
        if (VtableHook::InstallCloudEnabledHook(rsVtable, g_cloudEnabledInfo))
        {
            CloudHooks::SetOriginalIsCloudEnabled(g_cloudEnabledInfo.origSlot);
            Log::Info("IsCloudEnabledForApp hook installed");
        }
        else
            Log::Warn("IsCloudEnabledForApp hook install failed (cloud toggle may not work)");
    }
    else
        Log::Warn("CUserRemoteStorage vtable not found (cloud toggle may not work)");

    DebugLog("[CR] DoInit: resolving protobuf helpers\n");
    bool pbOk = CloudHooks::ResolveProtobufHelpers(reinterpret_cast<void*>(steamBase), steamSize);
    if (!pbOk)
        Log::Error("Protobuf helpers not fully resolved -- cloud RPCs may fail");

    // Observe outbound CMsgClientGamesPlayed to track namespace-app playtime.
    // Skipped entirely when stats_sync_enabled=false in config.json -- avoids
    // patching steamclient.so when the user doesn't want stats/achievements.
    if (pbOk && StatsSyncEnabled())
    {
        CloudHooks::InstallGamesPlayedObserver(steamBase, steamSize);
    }
    else if (pbOk)
    {
        Log::Info("Stats/achievement sync disabled (stats_sync_enabled=false) -- hooks not installed");
    }

    // Sweep stray *.cloudredirect metadata from userdata/{app}/remote/.
    {
        std::string steamPath = CloudIntercept::GetSteamPath();
        if (!steamPath.empty())
            LegacyMetadataCleanup::PruneSteamUserdata(steamPath);
    }

    DebugLog("[CR] DoInit: initializing KV injector\n");
    SteamKvInjector::Init();

    g_initialized.store(true, std::memory_order_release);
    DebugLog("[CR] DoInit: SUCCESS\n");
    Log::Info("CloudRedirect initialized successfully (all hooks active)");
    // Suppress the "Loaded successfully" desktop popup. The host stack already
    // shows its own load notification on every Steam start, so a second popup
    // here is redundant noise. The critical/error Notify() calls elsewhere are
    // kept so genuine init failures still surface to the user.
}



static sigjmp_buf g_crashJmpBuf;
static volatile sig_atomic_t g_inScan = 0;

static void ScanCrashHandler(int sig)
{
    if (g_inScan)
        siglongjmp(g_crashJmpBuf, 1);
    // Not our crash -- SA_RESETHAND already restored default, just re-raise
    raise(sig);
}

// ── Post-init crash handler: dumps backtrace to log ─────────────────────
static volatile sig_atomic_t g_inCrashHandler = 0;

static char* AppendLiteral(char* out, char* end, const char* s)
{
    while (out < end && *s) *out++ = *s++;
    return out;
}

static char* AppendUInt(char* out, char* end, unsigned int v)
{
    char tmp[16];
    int n = 0;
    do {
        tmp[n++] = char('0' + (v % 10));
        v /= 10;
    } while (v && n < (int)sizeof(tmp));
    while (n > 0 && out < end) *out++ = tmp[--n];
    return out;
}

static char* AppendHex(char* out, char* end, uintptr_t v)
{
    static const char hex[] = "0123456789abcdef";
    out = AppendLiteral(out, end, "0x");
    bool started = false;
    for (int shift = (int)(sizeof(uintptr_t) * 8) - 4; shift >= 0; shift -= 4) {
        unsigned int nibble = (unsigned int)((v >> shift) & 0xF);
        if (nibble || started || shift == 0) {
            started = true;
            if (out < end) *out++ = hex[nibble];
        }
    }
    return out;
}

static uintptr_t FaultInstructionPointer(void* ctx)
{
    if (!ctx) return 0;
    ucontext_t* uc = static_cast<ucontext_t*>(ctx);
#if defined(__i386__)
    return static_cast<uintptr_t>(uc->uc_mcontext.gregs[14]); // REG_EIP
#elif defined(__x86_64__)
    return static_cast<uintptr_t>(uc->uc_mcontext.gregs[16]); // REG_RIP
#elif defined(__aarch64__)
    return static_cast<uintptr_t>(uc->uc_mcontext.pc);
#else
    return 0;
#endif
}

// Async-signal-safe: scan /proc/self/maps via raw read() for the mapping containing
// `addr`. Returns its base (0 if not found); dladdr is unreliable on stripped i386.
static uintptr_t ResolveModule(uintptr_t addr, char* nameOut, size_t nameCap)
{
    if (nameCap) nameOut[0] = '\0';
    int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    char buf[8192];
    char line[512];
    size_t lineLen = 0;
    uintptr_t result = 0;
    ssize_t n;
    bool done = false;
    while (!done && (n = read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < n; ++i) {
            char c = buf[i];
            if (c != '\n') {
                if (lineLen < sizeof(line) - 1) line[lineLen++] = c;
                continue;
            }
            line[lineLen] = '\0';
            // Parse "start-end perms ... path"
            uintptr_t start = 0, e = 0;
            const char* p = line;
            while (*p && *p != '-') { start = start * 16 + (*p <= '9' ? *p - '0' : (*p | 0x20) - 'a' + 10); ++p; }
            if (*p == '-') ++p;
            while (*p && *p != ' ') { e = e * 16 + (*p <= '9' ? *p - '0' : (*p | 0x20) - 'a' + 10); ++p; }
            if (addr >= start && addr < e) {
                // path is the last token after the final space
                const char* path = line;
                for (const char* q = line; *q; ++q) if (*q == ' ' && q[1] && q[1] != ' ') path = q + 1;
                const char* slash = path;
                for (const char* q = path; *q; ++q) if (*q == '/') slash = q + 1;
                size_t j = 0;
                if (*slash && *slash != ' ')
                    for (; slash[j] && j < nameCap - 1; ++j) nameOut[j] = slash[j];
                nameOut[j] = '\0';
                result = start;
                done = true;
                break;
            }
            lineLen = 0;
        }
    }
    close(fd);
    return result;
}

static void WriteFrame(uintptr_t retAddr)
{
    char buf[256];
    char* out = buf;
    char* end = buf + sizeof(buf);
    char mod[128];
    uintptr_t base = ResolveModule(retAddr, mod, sizeof(mod));
    out = AppendLiteral(out, end, "[CR]   ");
    out = AppendHex(out, end, retAddr);
    if (base) {
        out = AppendLiteral(out, end, " ");
        out = AppendLiteral(out, end, mod[0] ? mod : "?");
        out = AppendLiteral(out, end, "+");
        out = AppendHex(out, end, retAddr - base);
    }
    out = AppendLiteral(out, end, "\n");
    if (g_debugFd >= 0) write(g_debugFd, buf, (size_t)(out - buf));
}

// Find steamclient.so's executable mapping (r-xp) range by scanning /proc/self/maps.
static bool SteamclientExecRange(uintptr_t& lo, uintptr_t& hi)
{
    lo = hi = 0;
    int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char buf[8192], line[512];
    size_t lineLen = 0;
    ssize_t n;
    bool found = false;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        for (ssize_t i = 0; i < n; ++i) {
            char c = buf[i];
            if (c != '\n') { if (lineLen < sizeof(line) - 1) line[lineLen++] = c; continue; }
            line[lineLen] = '\0'; lineLen = 0;
            // need executable + steamclient.so
            bool isExec = false;
            for (const char* q = line; *q && *q != '\n'; ++q) {
                if (q[0] == ' ' && q[1] == 'r') { isExec = (q[3] == 'x'); break; }
            }
            bool isSc = false;
            for (const char* q = line; *q; ++q)
                if (q[0]=='s'&&q[1]=='t'&&q[2]=='e'&&q[3]=='a'&&q[4]=='m'&&q[5]=='c') { isSc = true; break; }
            if (isExec && isSc) {
                uintptr_t s = 0, e = 0; const char* p = line;
                while (*p && *p != '-') { s = s*16 + (*p<='9'?*p-'0':(*p|0x20)-'a'+10); ++p; }
                if (*p=='-') ++p;
                while (*p && *p != ' ') { e = e*16 + (*p<='9'?*p-'0':(*p|0x20)-'a'+10); ++p; }
                if (!found) { lo = s; hi = e; found = true; }
                else { if (s < lo) lo = s; if (e > hi) hi = e; }
            }
        }
    }
    close(fd);
    return found;
}

// Recover the call chain on stripped, fomit-frame-pointer i386 code: EBP-chaining is
// unreliable, so also scan the stack for words pointing into steamclient.so's .text.
static void ManualBacktrace(void* ctx)
{
#if defined(__i386__)
    ucontext_t* uc = static_cast<ucontext_t*>(ctx);
    uintptr_t ip  = (uintptr_t)uc->uc_mcontext.gregs[14]; // REG_EIP
    uintptr_t ebp = (uintptr_t)uc->uc_mcontext.gregs[6];  // REG_EBP
    uintptr_t esp = (uintptr_t)uc->uc_mcontext.gregs[7];  // REG_ESP
    WriteFrame(ip); // frame 0 = faulting instruction

    // Pass 1: EBP chain (works when frame pointers are present).
    const char* h1 = "[CR]  -- ebp chain --\n";
    if (g_debugFd >= 0) write(g_debugFd, h1, strlen(h1));
    uintptr_t prev = 0, bp = ebp;
    for (int depth = 0; depth < 32; ++depth) {
        if (bp < 0x1000 || (bp & 3) || bp <= prev) break;
        uintptr_t* fp = (uintptr_t*)bp;
        uintptr_t ret = fp[1];
        if (ret < 0x1000) break;
        WriteFrame(ret);
        prev = bp; bp = fp[0];
    }

    // Pass 2: stack scan for return addresses into steamclient.so .text.
    uintptr_t lo, hi;
    if (SteamclientExecRange(lo, hi)) {
        const char* h2 = "[CR]  -- stack scan (steamclient .text return addrs) --\n";
        if (g_debugFd >= 0) write(g_debugFd, h2, strlen(h2));
        uintptr_t scanEnd = esp + 0x4000; // 16KB window up the stack
        int printed = 0;
        for (uintptr_t s = esp & ~3u; s < scanEnd && printed < 48; s += 4) {
            uintptr_t w = *(uintptr_t*)s;
            if (w >= lo && w < hi) { WriteFrame(w); ++printed; }
        }
    }
#else
    (void)ctx;
#endif
}

static void CrashDumpHandler(int sig, siginfo_t* info, void* ctx)
{
    if (g_inCrashHandler) { _exit(128 + sig); }
    g_inCrashHandler = 1;

    char buf[512];
    char* out = buf;
    char* end = buf + sizeof(buf);
    out = AppendLiteral(out, end, "\n[CR] *** CRASH: signal ");
    out = AppendUInt(out, end, (unsigned int)sig);
    out = AppendLiteral(out, end, ", fault addr=");
    out = AppendHex(out, end, (uintptr_t)(info ? info->si_addr : nullptr));
    out = AppendLiteral(out, end, ", ip=");
    out = AppendHex(out, end, FaultInstructionPointer(ctx));
    if (g_crashContext[0]) {
        out = AppendLiteral(out, end, ", context=");
        out = AppendLiteral(out, end, g_crashContext);
    }
    out = AppendLiteral(out, end, ", pid=");
    out = AppendUInt(out, end, (unsigned int)getpid());
    out = AppendLiteral(out, end, " ***\n");
    if (g_debugFd >= 0)
        write(g_debugFd, buf, (size_t)(out - buf));


    // Manual EBP-chain unwind -> module+offset (glibc backtrace() is useless on
    // stripped, -fomit-frame-pointer i386 steamclient code).
    const char* btHeader = "[CR] Backtrace (manual ebp-walk, addr module+off):\n";
    if (g_debugFd >= 0) write(g_debugFd, btHeader, strlen(btHeader));
    ManualBacktrace(ctx);
    const char* btFooter = "[CR] End backtrace\n";
    if (g_debugFd >= 0) write(g_debugFd, btFooter, strlen(btFooter));

    // SA_RESETHAND already restored default - just re-raise for core dump
    raise(sig);
}

static void InstallCrashDumpHandler()
{
    struct sigaction sa = {};
    sa.sa_sigaction = CrashDumpHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;  // one-shot, with siginfo
    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGBUS, &sa, nullptr);
    sigaction(SIGABRT, &sa, nullptr);
}

static bool SteamclientMapped()
{
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return false;
    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "steamclient.so")) {
            found = true;
            break;
        }
    }
    fclose(f);
    return found;
}

static void* DeferredInitThread(void*)
{
    // Poll for steamclient.so. Under LD_PRELOAD we load before Steam has mapped
    // steamclient, so a fixed short delay is insufficient. Upstream uses a fixed
    // 10s window, which is too short on distros where steamclient.so maps late
    // (e.g. Arch/CachyOS mapped it >10s after start in testing) -- there the hook
    // would time out and never attach. Poll with a generous bound instead so the
    // single LD_PRELOAD load path works universally, only initialising once
    // steamclient is present.
    //
    // The sleep between probes runs on the stop signal so a process that exits
    // before steamclient appears (bootstrapper/updater, -shutdown, handover)
    // cancels the remaining window instead of holding OnUnload's join open.
    DebugLog("[CR] DeferredInit: waiting for steamclient.so\n");
    const auto outcome = LinuxInitStop::PollUntilReady(
        LinuxInitStop::ProcessStop(), 240, std::chrono::milliseconds(500),
        SteamclientMapped);  // 240 x 500ms = up to 120 seconds
    if (outcome == LinuxInitStop::PollOutcome::Stopped) {
        DebugLog("[CR] DeferredInit: stopped early, process is exiting before steamclient.so mapped\n");
        Log::Info("Init stopped early: process exiting before steamclient.so mapped");
        return nullptr;
    }
    if (outcome != LinuxInitStop::PollOutcome::Ready) {
        DebugLog("[CR] DeferredInit: steamclient.so never mapped within window, aborting\n");
        Log::Error("Init aborted: steamclient.so not mapped within wait window");
        return nullptr;
    }
    DebugLog("[CR] DeferredInit: starting\n");

    // Install crash guard so a bad memory read aborts correctly
    struct sigaction sa = {}, old_segv = {}, old_bus = {};
    sa.sa_handler = ScanCrashHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESETHAND;  // Reset to default on signal (async-signal-safe)
    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGBUS, &sa, &old_bus);

    g_inScan = 1;
    if (sigsetjmp(g_crashJmpBuf, 1) == 0) {
        DoInit();
    } else {
        DebugLog("[CR] DeferredInit: CRASHED during init, aborting safely\n");
        Log::Error("Caught signal during init - incompatible steamclient? Hooks NOT installed.");
        Notify("Crashed during init - hooks disabled", true);
    }
    g_inScan = 0;

    // Restore original handlers and install crash dump handler if init succeeded
    sigaction(SIGSEGV, &old_segv, nullptr);
    sigaction(SIGBUS, &old_bus, nullptr);

    if (g_initialized.load(std::memory_order_acquire)) {
        InstallCrashDumpHandler();
    }

    return nullptr;
}



__attribute__((constructor))
static void OnLoad()
{
    std::string proc = GetProcessName();
    if (proc != "steam" && !SteamclientMapped())
        return;
    // The shell running steam.sh is also named "steam"; stripping LD_PRELOAD
    // there would keep us out of every process it starts.
    if (!SteamclientMapped() && !ExeEndsWith("/steam"))
        return;

    // The steamrt64 client is two processes: steam.sh starts steamrt64/steam on
    // the host, which re-launches itself inside the pressure-vessel container
    // (PRESSURE_VESSEL_RUNTIME set there) and only that inner process maps
    // steamclient.so. Stripping LD_PRELOAD in the outer launcher would keep us
    // out of the real client, so leave the environment alone there and do not
    // start an init thread that could only time out.
    if (IsSteamrt64Launcher()) {
        DebugLog("[CR] OnLoad: steamrt64 launcher, deferring to the containerised client\n");
        return;
    }

    // Clean ourselves from LD_PRELOAD so child processes don't inherit us
    CleanLdPreload();

    EnsureLogInit();
    DebugLog("[CR] OnLoad: target process (steam), spawning deferred init thread\n");
    Log::Info("cloud_redirect.so active in process 'steam' (pid=%d)", getpid());

    bool expected = false;
    if (g_hookAttempted.compare_exchange_strong(expected, true))
    {
        if (pthread_create(&g_initThread, nullptr, DeferredInitThread, nullptr) != 0) {
            DebugLog("[CR] OnLoad: FAILED to create init thread\n");
        } else {
            g_initThreadCreated.store(true, std::memory_order_release);
        }
    }
}

__attribute__((destructor))
static void OnUnload()
{
    DebugLog("[CR] OnUnload: shutting down\n");

    if (g_hookAttempted.load(std::memory_order_acquire)) {
        // Tell the init thread's wait loops to give up before joining it: the
        // attach poll alone runs up to 120s, so an unsignalled join would keep
        // this process alive for the rest of that window. The join itself is
        // kept so we never unmap code the thread is still executing.
        LinuxInitStop::ProcessStop().Request();
        // A joinable pthread must be joined even after its entry point reports
        // completion. Otherwise the library can unload during the worker's
        // return epilogue, leaving its instruction pointer in unmapped code.
        if (g_initThreadCreated.exchange(false, std::memory_order_acq_rel)) {
            DebugLog("[CR] OnUnload: waiting for init thread\n");
            pthread_join(g_initThread, nullptr);
        }
    }

    // No-op (sync-icon state writer was never wired up); kept for contract.
    CloudIntercept::FlushPendingSyncStates();

    // Shut down cloud storage (signals workers, drains queue with timeout)
    CloudStorage::Shutdown();

    // Stop the HTTP server (joins accept + client threads)
    HttpServer::Stop();

    if (g_initialized.load(std::memory_order_acquire))
    {
        CloudHooks::BeginShutdown();
        VtableHook::RemoveHooks(g_vtableInfo);
        VtableHook::RemoveCloudEnabledHook(g_cloudEnabledInfo);
        Log::Info("cloud_redirect.so unloaded");
    }
    if (g_debugFd >= 0)
        close(g_debugFd);
}
