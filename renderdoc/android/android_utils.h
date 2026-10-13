/******************************************************************************
 * The MIT License (MIT)
 *
 * Copyright (c) 2018-2026 Baldur Karlsson
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 ******************************************************************************/

#pragma once

#include "api/replay/stringise.h"
#include "android.h"

// internal functions, shouldn't be used outside the android implementation - anything public goes
// in android.h

namespace Android
{
Process::ProcessResult execScript(const rdcstr &script, const rdcstr &args,
                                  const rdcstr &workDir = ".", bool silent = false);
// timeoutMS of 0 waits forever. Anything running adb should pass a timeout - see
// Android_AdbTimeoutMS - because adb can wedge and would otherwise block the caller.
Process::ProcessResult execCommand(const rdcstr &exe, const rdcstr &args,
                                   const rdcstr &workDir = ".", bool silent = false,
                                   uint32_t timeoutMS = 0);

// Issues 'adb root' at most once per device per session. The result is also persisted to disk so
// restarting the application doesn't re-issue it against every device - 'adb root' restarts adbd,
// which is slow and disruptive. A persisted result is only trusted while the device's build
// fingerprint still matches the one stored with it, so reflashing a device re-checks it.
//
// 'executed' (optional) is set to true when this call actually issued 'adb root'. A successful
// root restarts adbd, and on devices that can't be rooted the daemon can end up wedged - callers
// that want to run further adb commands should hold off until the next check when this is set.
Process::ProcessResult adbRootOnce(const rdcstr &deviceID, bool *executed = nullptr);

// true when adbRootOnce returned a result loaded from the persistent cache rather than one
// freshly obtained by running 'adb root' this session
bool adbRootResultCached(const rdcstr &deviceID);

// Discards the cached 'adb root' result for the device so the next adbRootOnce call issues the
// command again. Call this when the device state contradicts the cached result, e.g. the cached
// result said root was available but 'whoami' reports a non-root user.
void adbRootCacheInvalidate(const rdcstr &deviceID);

// true while a device's adb channel is considered broken because several consecutive adb commands
// timed out (see Android_AdbFailFastThreshold/Android_AdbFailFastCooldownMS). Commands for such a
// device fail immediately instead of waiting for the timeout again.
bool adbChannelUnusable(const rdcstr &deviceID);

enum class ToolDir
{
  None,
  Java,
  BuildTools,
  BuildToolsLib,
  PlatformTools,
};
rdcstr getToolPath(ToolDir subdir, const rdcstr &toolname, bool checkExist);
bool toolExists(const rdcstr &path);

bool IsDebuggable(const rdcstr &deviceID, const rdcstr &packageName);
bool HasRootAccess(const rdcstr &deviceID);
rdcstr GetFirstMatchingLine(const rdcstr &haystack, const rdcstr &needle);

bool IsSupported(rdcstr deviceID);
bool SupportsNativeLayers(const rdcstr &deviceID);
rdcstr DetermineInstalledABI(const rdcstr &deviceID, const rdcstr &packageName);
rdcstr GetFriendlyName(const rdcstr &deviceID);

// supported ABIs
enum class ABI
{
  unknown,
  armeabi_v7a,
  arm64_v8a,
  x86,
  x86_64,
};

ABI GetABI(const rdcstr &abiName);
rdcstr GetPlainABIName(ABI abi);
rdcarray<ABI> GetSupportedABIs(const rdcstr &deviceID);
rdcstr GetRenderDocPackageForABI(ABI abi);
rdcstr GetPathForPackage(const rdcstr &deviceID, const rdcstr &packageName);
rdcstr GetFolderName(const rdcstr &deviceID);
};

DECLARE_REFLECTION_ENUM(Android::ABI);
