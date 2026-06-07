#pragma once
// Third-party client API for CloudRedirect cloud save.
// Host hooks CClientUnifiedServiceTransport, extracts method/appId/body,
// calls CR_HandleCloudRpc, writes the response back into Steam's objects.
// Non-cloud-save features (manifest pinning, parental) are disabled.

#include <cstdint>

#ifdef _WIN32
#  ifdef CR_API_EXPORTS
#    define CR_API extern "C" __declspec(dllexport)
#  else
#    define CR_API extern "C" __declspec(dllimport)
#  endif
#else
#  define CR_API extern "C" __attribute__((visibility("default")))
#endif

#define CR_NOTIFY_INFO  0
#define CR_NOTIFY_WARN  1
#define CR_NOTIFY_ERROR 2

// Host-provided notification callback. Called instead of MessageBoxA.
// Must be thread-safe. Pass NULL for default (MessageBoxA).
typedef void (*CR_NotifyFn)(int level, const char* title, const char* message);

// steamPath: Steam install dir with trailing separator.
CR_API bool CR_InitCloudSave(const char* steamPath, CR_NotifyFn notify);

// Dispatch a Cloud.* RPC. Returns false if appId is not a namespace app
// or method is unrecognized -- caller should chain to the original.
// respBuf is caller-allocated; respLen receives actual size written.
CR_API bool CR_HandleCloudRpc(const char* method, uint32_t appId,
                              uint32_t accountId,
                              const uint8_t* reqBody, uint32_t reqLen,
                              uint8_t* respBuf, uint32_t respMaxLen,
                              uint32_t* respLen, int32_t* eresult);

CR_API void CR_AddApp(uint32_t appId);
CR_API void CR_RemoveApp(uint32_t appId);
CR_API bool CR_IsApp(uint32_t appId);

// Replace the namespace-app set with the given list. NULL/0 clears it.
CR_API void CR_SetApps(const uint32_t* appIds, uint32_t count);

CR_API void CR_Shutdown(void);
