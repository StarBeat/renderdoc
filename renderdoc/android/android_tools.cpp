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

#include "common/formatting.h"
#include "common/threading.h"
#include "core/core.h"
#include "core/settings.h"
#include "os/os_specific.h"
#include "strings/string_utils.h"
#include "android_utils.h"
#include <map>

RDOC_CONFIG(rdcstr, Android_SDKDirPath, "",
            "The location of the root of the Android SDK. This path "
            "should contain folders such as build-tools and platform-tools.");

RDOC_CONFIG(rdcstr, Android_JDKDirPath, "",
            "The location of the root of the Java JDK. This path "
            "should contain folders such as bin and lib.");

RDOC_CONFIG(uint32_t, Android_AdbTimeoutMS, 10000,
            "Maximum time in milliseconds to wait for an adb command before killing it. adb can "
            "wedge indefinitely (for example while a device serial is offline or stale), and "
            "without a timeout that blocks the calling thread - freezing the UI.");

RDOC_CONFIG(uint32_t, Android_AdbFailFastThreshold, 3,
            "How many consecutive adb commands may time out before a device's adb channel is "
            "treated as broken. While broken the device is ignored instead of waiting for the "
            "command timeout over and over. Replugging the USB cable recovers immediately.");

RDOC_CONFIG(uint32_t, Android_AdbFailFastCooldownMS, 60000,
            "How long in milliseconds a device with a broken adb channel (see "
            "Android.AdbFailFastThreshold) is ignored before adb is tried against it again.");

namespace Android
{
static bool adbKillServer = false;

// Per-device adb state. Two things are tracked:
//  * consecutive command timeouts, so a device whose adb channel has wedged (the classic
//    "adb devices lists it as 'device' but every shell command hangs" case) is ignored for a
//    cooldown instead of making every caller wait for the full timeout again and again.
//  * the result of the 'adb root' attempt. It is issued at most once per device per session, and
//    the result is also persisted to disk so that restarting the application doesn't re-issue
//    'adb root' against every device - it restarts adbd, which is slow and disruptive. The
//    device's build fingerprint is used to detect when a reflash has invalidated the persisted
//    result.
struct AdbDeviceState
{
  uint32_t consecutiveTimeouts = 0;
  uint64_t unusableUntilTick = 0;
  // how many times in a row the channel has been declared broken - the cooldown doubles on each
  // consecutive break (capped), so a persistently wedged device is poked less and less often
  // instead of being hammered with timing-out commands every cycle.
  uint32_t failStreak = 0;
  bool rootAttempted = false;
  // true when rootResult was loaded from the persistent cache rather than a fresh 'adb root' run
  bool rootFromDiskCache = false;
  // set once the cached result has been invalidated this session, so a device whose 'adb root'
  // result is ambiguous (e.g. exits 0 but the device never actually becomes root) can't cause an
  // invalidate -> re-issue -> invalidate loop. At most one extra 'adb root' per device per session.
  bool rootCacheInvalidated = false;
  Process::ProcessResult rootResult = {};
  // ro.build.fingerprint, fetched at most once per device per session
  bool fingerprintChecked = false;
  rdcstr fingerprint;
};

// A cached 'adb root' result, persisted to the app data folder. The fingerprint is the device's
// ro.build.fingerprint when the result was stored. Reflashing the device changes the fingerprint,
// which is the only way a cached failure could become a success, so an entry is only trusted
// while the current fingerprint still matches.
struct AdbRootCacheEntry
{
  Process::ProcessResult result = {};
  rdcstr fingerprint;
};

static Threading::CriticalSection adbStateLock;
static std::map<rdcstr, AdbDeviceState> adbStates;
static std::map<rdcstr, AdbRootCacheEntry> adbRootDiskCache;
static bool adbRootDiskCacheLoaded = false;

static rdcstr GetAdbRootCacheFilename()
{
  return FileIO::GetAppFolderFilename("adbroot.cache");
}

static void ReplaceAll(rdcstr &s, const rdcstr &needle, const rdcstr &replacement)
{
  if(needle.empty())
    return;

  int32_t offset = 0;
  while((offset = s.find(needle, offset)) >= 0)
  {
    s.replace((size_t)offset, needle.size(), replacement);
    offset += (int32_t)replacement.size();
  }
}

static void EscapeCacheString(rdcstr &s)
{
  ReplaceAll(s, "\\", "\\\\");
  ReplaceAll(s, "\n", "\\n");
  ReplaceAll(s, "\r", "\\r");
  ReplaceAll(s, "\t", "\\t");
}

static void UnescapeCacheString(rdcstr &s)
{
  rdcstr out;
  out.reserve(s.size());

  for(size_t i = 0; i < s.size(); i++)
  {
    if(s[i] == '\\' && i + 1 < s.size())
    {
      i++;
      switch(s[i])
      {
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        default: out.push_back('\\'); out.push_back(s[i]); break;
      }
      continue;
    }

    out.push_back(s[i]);
  }

  s = out;
}

// The cache file is one line per device with tab separated fields:
// serial, retCode, timedOut, stdout, stderr, build fingerprint
// (stdout/stderr and the fingerprint are escaped so they can't contain tabs or newlines).
static void LoadAdbRootCacheLocked()
{
  adbRootDiskCache.clear();

  FILE *f = FileIO::fopen(GetAdbRootCacheFilename(), FileIO::ReadText);
  if(f == NULL)
    return;

  rdcstr contents;
  FileIO::fseek64(f, 0, SEEK_END);
  contents.resize((size_t)FileIO::ftell64(f));
  FileIO::fseek64(f, 0, SEEK_SET);
  FileIO::fread(contents.data(), 1, contents.size(), f);
  FileIO::fclose(f);

  rdcarray<rdcstr> lines;
  split(contents, lines, '\n');

  for(rdcstr &line : lines)
  {
    line.trim();

    if(line.empty() || line[0] == '#')
      continue;

    rdcarray<rdcstr> fields;
    split(line, fields, '\t');

    if(fields.size() < 4)
      continue;

    UnescapeCacheString(fields[0]);

    AdbRootCacheEntry entry;
    entry.result.retCode = atoi(fields[1].c_str());
    entry.result.timedOut = (fields[2] == "1");
    if(fields.size() > 3)
    {
      UnescapeCacheString(fields[3]);
      entry.result.strStdout = fields[3];
    }
    if(fields.size() > 4)
    {
      UnescapeCacheString(fields[4]);
      entry.result.strStderror = fields[4];
    }
    if(fields.size() > 5)
    {
      UnescapeCacheString(fields[5]);
      entry.fingerprint = fields[5];
    }

    adbRootDiskCache[fields[0]] = entry;
  }
}

// must be called with adbStateLock held
static void SaveAdbRootCacheLocked()
{
  rdcstr contents = "# renderdoc adb root cache v1 - one line per device, tab separated fields:\n";
  contents += "# serial, retCode, timedOut, stdout, stderr, build fingerprint\n";

  for(const auto &it : adbRootDiskCache)
  {
    rdcstr serial = it.first;
    rdcstr stdoutStr = it.second.result.strStdout;
    rdcstr stderrStr = it.second.result.strStderror;
    rdcstr fingerprint = it.second.fingerprint;

    EscapeCacheString(serial);
    EscapeCacheString(stdoutStr);
    EscapeCacheString(stderrStr);
    EscapeCacheString(fingerprint);

    contents += serial + "\t" + ToStr(it.second.result.retCode) + "\t" +
                (it.second.result.timedOut ? "1" : "0") + "\t" + stdoutStr + "\t" + stderrStr +
                "\t" + fingerprint + "\n";
  }

  rdcstr path = GetAdbRootCacheFilename();
  rdcstr tmp = path + ".tmp";

  // write to a temporary file and move it into place so a crashed writer can't leave a
  // half-written cache behind
  FileIO::CreateParentDirectory(tmp);
  if(FileIO::WriteAll(tmp, contents.data(), contents.size()))
    FileIO::Move(tmp, path, true);
}

static bool adbChannelUnusableLocked(const rdcstr &device, uint64_t now)
{
  auto it = adbStates.find(device);
  if(it == adbStates.end())
    return false;

  return it->second.unusableUntilTick > now;
}
bool toolExists(const rdcstr &path)
{
  if(path.empty())
    return false;
  return FileIO::exists(path) || FileIO::exists(path + ".exe");
}
rdcstr getToolInSDK(ToolDir subdir, const rdcstr &jdkroot, const rdcstr &sdkroot,
                    const rdcstr &toolname)
{
  rdcstr toolpath;

  switch(subdir)
  {
    case ToolDir::None:
    {
      // This indicates the file is not a standard tool and will not exist anywhere but our
      // distributed folder.
      break;
    }
    case ToolDir::Java:
    {
      // if no path is configured, abort
      if(jdkroot.empty())
        break;

      toolpath = jdkroot + "/bin/" + toolname;

      if(toolExists(toolpath))
        return toolpath;

      break;
    }
    case ToolDir::BuildTools:
    case ToolDir::BuildToolsLib:
    case ToolDir::PlatformTools:
    {
      // if no path is configured, abort
      if(sdkroot.empty())
        break;

      // if it's in platform tools it's easy, just concatenate the path
      if(subdir == ToolDir::PlatformTools)
      {
        toolpath = sdkroot + "/platform-tools/" + toolname;
      }
      else
      {
        // otherwise we need to find the build-tools versioned folder
        toolpath = sdkroot + "/build-tools/";

        rdcarray<PathEntry> paths;
        FileIO::GetFilesInDirectory(toolpath, paths);

        if(paths.empty())
          break;

        uint32_t bestversion = 0;
        rdcstr bestpath;

        for(const PathEntry &path : paths)
        {
          // skip non-directories
          if(!(path.flags & PathProperty::Directory))
            continue;

          uint32_t version = 0;
          bool valid = true;
          for(char c : path.filename)
          {
            // add digits to the version
            if(c >= '0' && c <= '9')
            {
              int digit = int(c) - int('0');
              version *= 10;
              version += digit;
              continue;
            }

            // ignore .s
            if(c == '.')
              continue;

            // if any char is not in [.0-9] then this filename is invalid
            valid = false;
            break;
          }

          // skip non-valid directories
          if(!valid)
            continue;

          // if this directory is a higher version, prefer it
          if(version > bestversion)
          {
            bestversion = version;
            bestpath = path.filename;
          }
        }

        // if we didn't find a version at all, abort
        if(bestversion == 0)
          break;

        toolpath += bestpath + "/";

        if(subdir == ToolDir::BuildToolsLib)
          toolpath += "lib/";

        toolpath += toolname;
      }

      if(toolExists(toolpath))
        return toolpath;

      break;
    }
  }

  return "";
}

struct ToolPathCache
{
  rdcstr sdk, jdk;
  std::map<rdcstr, rdcstr> paths;
};

static ToolPathCache &getCache()
{
  static ToolPathCache *cache = new ToolPathCache;
  return *cache;
}

rdcstr getToolPath(ToolDir subdir, const rdcstr &toolname, bool checkExist)
{
  // search path for tools:
  // 1. First look relative to the configured paths, these come from the user manually setting them
  //    so they always have priority.
  // 2. Next we try to auto-locate it.
  //    - First check if the tool is in the path, assuming the user configured it to their system.
  //    - Otherwise check environment variables or default locations
  // 3. Finally if those paths don't exist or the tool isn't found, we search relative to our
  //    executable looking for an android/ subfolder, and look for the tool in there.
  //
  // The main reason we check our bundled folder last is because adb requires a *precise* match in
  // its client-server setup, so if we run our bundled adb that might be newer than the user's, they
  // will then get fighting back and forth when trying to run their own.

  rdcstr sdk = Android_SDKDirPath();
  rdcstr jdk = Android_JDKDirPath();

  ToolPathCache &cache = getCache();

  // invalidate the cache when these settings change
  if(sdk != cache.sdk || jdk != cache.jdk)
  {
    cache.paths.clear();
    cache.sdk = sdk;
    cache.jdk = jdk;
  }

  // if we have the path cached and it's still valid, return it
  if(toolExists(cache.paths[toolname]))
    return cache.paths[toolname];

  rdcstr &toolpath = cache.paths[toolname];

  // first try according to the configured paths
  toolpath = getToolInSDK(subdir, jdk, sdk, toolname);

  if(toolExists(toolpath))
    return toolpath;

  // need to try to auto-guess the tool's location

  // first try in PATH
  if(subdir != ToolDir::None)
  {
    toolpath = FileIO::FindFileInPath(toolname);

    if(toolExists(toolpath))
      return toolpath;

    // if the tool name contains a .jar then try stripping that and look for the non-.jar version in
    // the PATH.
    if(toolname.contains(".jar"))
    {
      toolpath = strip_extension(toolname);
      toolpath = FileIO::FindFileInPath(toolpath);

      if(toolExists(toolpath))
        return toolpath;
    }
  }

  // now try to find it based on heuristics/environment variables
  jdk = Process::GetEnvVariable("JAVA_HOME");
  sdk = Process::GetEnvVariable("ANDROID_HOME");

  if(sdk.empty() || !FileIO::exists(sdk))
  {
    sdk = Process::GetEnvVariable("ANDROID_SDK_ROOT");
  }

  if(sdk.empty() || !FileIO::exists(sdk))
  {
    sdk = Process::GetEnvVariable("ANDROID_SDK");
  }

  if(sdk.empty() || !FileIO::exists(sdk))
  {
    sdk = Process::GetEnvVariable("ANDROID_SDK_HOME");
  }

#if ENABLED(RDOC_APPLE)
  // on macOS it's common not to have the environment variable globally available, so try the home
  // Library folder first, then the global folder
  if(sdk.empty() || !FileIO::exists(sdk))
  {
    rdcstr librarySDK = FileIO::GetHomeFolderFilename() + "/Library/Android/sdk";
    sdk = FileIO::exists(librarySDK) ? librarySDK : "";
  }

  if(sdk.empty() || !FileIO::exists(sdk))
  {
    rdcstr librarySDK = "/Library/Android/sdk";
    sdk = FileIO::exists(librarySDK) ? librarySDK : "";
  }
#endif

  // maybe in future we can try to search in common install locations.

  toolpath = getToolInSDK(subdir, jdk, sdk, toolname);

  if(toolExists(toolpath))
    return toolpath;

  // finally try to locate it in our own distributed android subfolder
  {
    rdcstr libpath;
    FileIO::GetLibraryFilename(libpath);
    rdcstr libdir = get_dirname(FileIO::GetFullPathname(libpath));

    toolpath = libdir + "/plugins/android/" + toolname;
    if(toolExists(toolpath))
    {
      if(toolname == "adb")
      {
        // if we're using our own adb, we should kill the server upon shutdown
        adbKillServer = true;
      }

      return toolpath;
    }
  }

  toolpath = "";

  // if we're checking for existence, we have failed so return empty string.
  if(checkExist)
    return toolpath;

  // otherwise we at least return the tool name so that there's something to try and run
  return toolname;
}
Process::ProcessResult execScript(const rdcstr &script, const rdcstr &args, const rdcstr &workDir,
                                  bool silent)
{
  if(!silent)
    RDCLOG("SCRIPT: %s", script.c_str());

  Process::ProcessResult result;
  Process::LaunchScript(script, workDir, args, true, &result);
  return result;
}
Process::ProcessResult execCommand(const rdcstr &exe, const rdcstr &args, const rdcstr &workDir,
                                   bool silent, uint32_t timeoutMS)
{
  if(!silent)
    RDCLOG("COMMAND: %s '%s'", exe.c_str(), args.c_str());

  Process::ProcessResult result;
  Process::LaunchProcess(exe, workDir, args, true, &result, timeoutMS);
  return result;
}

// One-shot attempt to reset a device's USB transport after its channel has been declared broken.
// Runs through execCommand directly rather than adbExecCommand: the device has just been marked
// unusable, so adbExecCommand would refuse to run anything for it. 'adb reconnect' is handled by
// the local adb server (it re-opens the USB interface), so it normally returns quickly even when
// the device itself is unresponsive - and a timed-out reconnect costs nothing since the result is
// discarded. On Windows this often clears the half-open transport session left behind when a
// timed-out adb client was killed mid-transfer, which is what wedges subsequent shell commands.
static void resetAdbTransport(const rdcstr &device)
{
  rdcstr adb = getToolPath(ToolDir::PlatformTools, "adb", false);
  if(adb.empty())
    return;

  Process::ProcessResult res = {};
  Process::LaunchProcess(adb, ".", StringFormat::Fmt("-s %s reconnect", device.c_str()), true,
                         &res, Android_AdbTimeoutMS());

  if(res.retCode != 0 || res.timedOut)
    RDCWARN("Failed to reset adb transport for %s (ret %d, timedOut %d)", device.c_str(),
            res.retCode, (int)res.timedOut);
}
Process::ProcessResult adbExecCommand(const rdcstr &device, const rdcstr &args,
                                      const rdcstr &workDir, bool silent, uint32_t timeoutMS)
{
  rdcstr adb = getToolPath(ToolDir::PlatformTools, "adb", false);
  Process::ProcessResult result;
  rdcstr deviceArgs;
  if(device.empty())
    deviceArgs = args;
  else
    deviceArgs = StringFormat::Fmt("-s %s %s", device.c_str(), args.c_str());

  // if this device's adb channel is already known to be wedged, fail immediately rather than
  // spawning adb and waiting for the timeout again on every single command.
  if(!device.empty())
  {
    SCOPED_LOCK(adbStateLock);
    if(adbChannelUnusableLocked(device, Timing::GetTick()))
    {
      Process::ProcessResult unusable = {};
      unusable.retCode = -1;
      unusable.timedOut = true;
      return unusable;
    }
  }

  // 0 means the caller didn't pick a bound - use the default short one. adb wedges easily (a
  // stale/offline serial is the usual cause) and without any timeout that blocks the caller
  // forever, which freezes the UI.
  const uint32_t effectiveTimeout = timeoutMS > 0 ? timeoutMS : Android_AdbTimeoutMS();

  result = execCommand(adb, deviceArgs, workDir, silent, effectiveTimeout);

  if(result.timedOut)
    RDCERR("adb command timed out after %u ms: %s", effectiveTimeout, deviceArgs.c_str());

  if(!device.empty())
  {
    bool resetTransport = false;

    {
      SCOPED_LOCK(adbStateLock);

      AdbDeviceState &state = adbStates[device];

      if(result.timedOut)
      {
        state.consecutiveTimeouts++;

        const uint32_t threshold = RDCMAX(1U, Android_AdbFailFastThreshold());

        if(state.consecutiveTimeouts >= threshold &&
           !adbChannelUnusableLocked(device, Timing::GetTick()))
        {
          // exponential backoff: the cooldown doubles on each consecutive break, capped at 8
          // minutes, so a persistently wedged device is poked less and less often. Note the
          // units: Timing::GetTick() is raw counter ticks and GetTickFrequency() is ticks per
          // millisecond, so the ms value must be scaled - adding it raw would make the cooldown
          // microseconds long, i.e. no cooldown at all.
          const uint32_t shift = RDCMIN(state.failStreak, 3U);
          const uint64_t cooldownMS = (uint64_t)Android_AdbFailFastCooldownMS() << shift;

          state.unusableUntilTick =
              Timing::GetTick() + (uint64_t)((double)cooldownMS * Timing::GetTickFrequency());
          state.failStreak = RDCMIN(state.failStreak + 1, 3U);
          resetTransport = true;

          RDCERR("Device %s: %u consecutive adb commands timed out - treating its adb channel as "
                 "broken and ignoring the device for %llu ms. Replug the USB cable (or restart "
                 "adb) to recover it.",
                 device.c_str(), state.consecutiveTimeouts, (unsigned long long)cooldownMS);
        }
      }
      else
      {
        // any successful command means the channel works again
        state.consecutiveTimeouts = 0;
        state.failStreak = 0;
        state.unusableUntilTick = 0;
      }
    }

    // Declaring the channel broken just killed a client mid-transfer, which on Windows can leave
    // the server's transport session half-open - exactly what wedges every shell command that
    // follows. Make one attempt to reset the transport. This deliberately runs outside the lock
    // and outside the fail-fast gate (which was just tripped above).
    if(resetTransport)
      resetAdbTransport(device);
  }

  return result;
}

Process::ProcessResult adbRootOnce(const rdcstr &device, bool *executed)
{
  if(executed)
    *executed = false;

  if(device.empty())
  {
    if(executed)
      *executed = true;
    return adbExecCommand(device, "root");
  }

  bool hasDiskEntry = false;
  AdbRootCacheEntry diskEntry;
  bool fetchFingerprint = false;
  rdcstr fingerprint;

  {
    SCOPED_LOCK(adbStateLock);

    if(!adbRootDiskCacheLoaded)
    {
      LoadAdbRootCacheLocked();
      adbRootDiskCacheLoaded = true;
    }

    AdbDeviceState &state = adbStates[device];

    if(state.rootAttempted)
      return state.rootResult;

    // mark it before running so a slow call isn't repeated from another thread
    state.rootAttempted = true;

    auto it = adbRootDiskCache.find(device);
    if(it != adbRootDiskCache.end())
    {
      diskEntry = it->second;
      hasDiskEntry = true;
    }

    if(state.fingerprintChecked)
    {
      fingerprint = state.fingerprint;
    }
    else
    {
      // claim the fetch before doing it (it's a slow adb round trip) so a concurrent caller
      // doesn't fetch it a second time
      state.fingerprintChecked = true;
      fetchFingerprint = true;
    }
  }

  if(fetchFingerprint)
  {
    fingerprint = adbExecCommand(device, "shell getprop ro.build.fingerprint").strStdout.trimmed();

    SCOPED_LOCK(adbStateLock);
    adbStates[device].fingerprint = fingerprint;
  }

  // If the build hasn't changed since the cached result was stored, return it without running
  // 'adb root' again - that's the whole point of persisting it.
  if(hasDiskEntry && !fingerprint.empty() && fingerprint == diskEntry.fingerprint)
  {
    SCOPED_LOCK(adbStateLock);
    AdbDeviceState &state = adbStates[device];
    state.rootResult = diskEntry.result;
    state.rootFromDiskCache = true;
    return state.rootResult;
  }

  // An empty fingerprint means the channel couldn't answer a trivial getprop. Running 'adb root'
  // into it would only restart adbd and kill every in-flight shell session - the exact scenario
  // the cache exists to prevent. So in this state:
  //  * a cached result is KEPT and trusted (a reflash happening while the channel is wedged is
  //    far less likely than a wedged channel), and
  //  * no 'adb root' is issued at all - a later call once the channel recovers can still try.
  if(fingerprint.empty())
  {
    SCOPED_LOCK(adbStateLock);
    AdbDeviceState &state = adbStates[device];

    if(hasDiskEntry)
    {
      state.rootResult = diskEntry.result;
      state.rootFromDiskCache = true;
      return state.rootResult;
    }

    // no cached result to fall back on: refuse with a synthetic timeout result, and don't pin
    // "root attempted" or the empty fingerprint for the whole session, so a later call on a
    // recovered channel retries instead of being stuck with the refusal forever.
    state.rootAttempted = false;
    state.fingerprintChecked = false;

    Process::ProcessResult refuse = {};
    refuse.retCode = -1;
    refuse.timedOut = true;
    return refuse;
  }

  // fingerprint is known and differs from the cached one: the device was reflashed (or the cache
  // belongs to another build), so the entry is stale - discard it and make a fresh attempt.
  if(hasDiskEntry)
  {
    SCOPED_LOCK(adbStateLock);
    adbRootDiskCache.erase(device);
    SaveAdbRootCacheLocked();
  }

  if(executed)
    *executed = true;

  Process::ProcessResult result = adbExecCommand(device, "root");

  {
    SCOPED_LOCK(adbStateLock);
    AdbDeviceState &state = adbStates[device];
    state.rootResult = result;
    state.rootFromDiskCache = false;

    // store the fresh result alongside the fingerprint so the next session can validate it. If
    // the fingerprint couldn't be read, don't persist anything - a later session couldn't tell
    // whether the entry was stale and would re-run 'adb root' anyway.
    if(!fingerprint.empty())
    {
      AdbRootCacheEntry entry;
      entry.result = result;
      entry.fingerprint = fingerprint;
      adbRootDiskCache[device] = entry;
      SaveAdbRootCacheLocked();
    }
  }

  return result;
}

bool adbRootResultCached(const rdcstr &device)
{
  if(device.empty())
    return false;

  SCOPED_LOCK(adbStateLock);

  auto it = adbStates.find(device);
  return it != adbStates.end() && it->second.rootFromDiskCache;
}

void adbRootCacheInvalidate(const rdcstr &device)
{
  if(device.empty())
    return;

  SCOPED_LOCK(adbStateLock);

  AdbDeviceState &state = adbStates[device];

  // only invalidate once per device per session - a device whose 'adb root' is ambiguous (e.g.
  // it exits 0 but the device never actually becomes root) would otherwise loop forever:
  // invalidate, re-issue root, cache the bogus success, invalidate again... Each re-issue also
  // restarts adbd, wedging the adb shell commands that follow.
  if(state.rootCacheInvalidated)
    return;
  state.rootCacheInvalidated = true;

  // drop the persisted entry and let the next adbRootOnce call re-issue 'adb root' this session
  auto it = adbRootDiskCache.find(device);
  if(it != adbRootDiskCache.end())
  {
    adbRootDiskCache.erase(it);
    SaveAdbRootCacheLocked();
  }

  state.rootAttempted = false;
  state.rootFromDiskCache = false;
  state.rootResult = {};
}

bool adbChannelUnusable(const rdcstr &device)
{
  if(device.empty())
    return false;

  SCOPED_LOCK(adbStateLock);
  return adbChannelUnusableLocked(device, Timing::GetTick());
}
void initAdb()
{
  // we don't use adbExecCommand because we need to be sure we don't wait for it to exit
  rdcstr adb = getToolPath(ToolDir::PlatformTools, "adb", false);
  rdcstr workdir = ".";
  if(adb.contains('/') || adb.contains('\\'))
    workdir = get_dirname(adb);

  RDCLOG("Initialising adb using '%s'", adb.c_str());

  if(adb.empty() || (!FileIO::exists(adb) && !FileIO::exists(adb + ".exe")))
  {
    if(FileIO::FindFileInPath(adb) == "")
      RDCWARN(
          "Couldn't locate adb. Ensure adb is in PATH, ANDROID_SDK or ANDROID_HOME is set, or you "
          "configure your SDK location");
  }

  Process::ProcessResult res = {};
  Process::LaunchProcess(adb, workdir, "start-server", true, &res);

  if(res.strStdout.find("daemon") >= 0 || res.strStderror.find("daemon") >= 0)
  {
    RDCLOG("Started adb server");
  }
}
void shutdownAdb()
{
  if(adbKillServer)
    adbExecCommand("", "kill-server", ".", false);
}
};
