#pragma once
#include <stdint.h>
#include <IOKit/IOMessage.h>
// Clang cannot import IOKit's function-like message macros into Swift.
static const uint32_t PFSCanSystemSleep = kIOMessageCanSystemSleep;
static const uint32_t PFSSystemWillSleep = kIOMessageSystemWillSleep;
static const uint32_t PFSSystemWillPowerOn = kIOMessageSystemWillPowerOn;
static const uint32_t PFSSystemHasPoweredOn = kIOMessageSystemHasPoweredOn;
static const uint32_t PFSSystemWillNotSleep = kIOMessageSystemWillNotSleep;
const char *PFSWorkspaceCommit(void);
