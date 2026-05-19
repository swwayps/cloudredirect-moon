#pragma once
// Inject ufs.quota/maxnumfiles into Steam's in-memory KV for namespace apps
// missing PICS data. Without this, AutoCloud exit evicts all files as over-quota.

#include <cstdint>

namespace SteamKvInjector {

bool Init();

bool IsReady();

// Read current ufs.quota/maxnumfiles from KV. False if injector not ready.
bool ReadAppQuota(uint32_t appId, uint64_t& outQuotaBytes, uint32_t& outMaxNumFiles);

// Trigger PICS fetch and poll for results. False on timeout.
bool TriggerPicsAndWait(uint32_t appId,
                        uint64_t& outQuotaBytes,
                        uint32_t& outMaxNumFiles,
                        int timeoutMs = 500);

// Write quota/maxnumfiles into KV. Won't clobber existing non-zero values.
bool InjectAppQuota(uint32_t appId, uint64_t quotaBytes, uint32_t maxNumFiles);

} // namespace SteamKvInjector
