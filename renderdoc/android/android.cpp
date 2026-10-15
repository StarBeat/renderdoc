/******************************************************************************
 * The MIT License (MIT)
 *
 * Copyright (c) 2017-2026 Baldur Karlsson
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

#include "android.h"
#include <ctype.h>
#include <set>
#include "api/replay/version.h"
#include "common/formatting.h"
#include "common/threading.h"
#include "core/core.h"
#include "core/remote_server.h"
#include "core/settings.h"
#include "replay/replay_driver.h"
#include "strings/string_utils.h"
#include "android_utils.h"

RDOC_CONFIG(uint32_t, Android_MaxConnectTimeout, 30,
            "Maximum time in seconds to try connecting to the target app before giving up. "
            "Useful primarily for apps that take a very long time to start up.");

// Installing or removing a large APK legitimately takes far longer than the default adb timeout,
// so those commands get a much bigger bound rather than being killed mid-transfer.
static const uint32_t kAdbLongCommandTimeoutMS = 10 * 60 * 1000;

RDOC_CONFIG(bool, Android_Debug_ProcessLaunch, false,
            "Output verbose debug logging messages when launching android apps.");

namespace Android
{
void adbForwardPorts(uint16_t portbase, const rdcstr &deviceID, uint16_t jdwpPort, int pid,
                     bool silent)
{
  const char *forwardCommand = "forward tcp:%i localabstract:sock_%i";

  adbExecCommand(deviceID,
                 StringFormat::Fmt(forwardCommand, portbase + RenderDoc_ForwardRemoteServerOffset,
                                   RenderDoc_RemoteServerPort),
                 ".", silent);
  adbExecCommand(deviceID,
                 StringFormat::Fmt(forwardCommand, portbase + RenderDoc_ForwardTargetControlOffset,
                                   RenderDoc_FirstTargetControlPort),
                 ".", silent);

  if(jdwpPort && pid)
    adbExecCommand(deviceID, StringFormat::Fmt("forward tcp:%hu jdwp:%i", jdwpPort, pid));
}

uint16_t GetJdwpPort()
{
  // we loop over a number of ports to try and avoid previous failed attempts from leaving sockets
  // open and messing with subsequent attempts
  const uint16_t portBase = 39500;

  static uint16_t portIndex = 0;

  portIndex++;
  portIndex %= 100;

  return portBase + portIndex;
}

rdcstr GetDefaultActivityForPackage(const rdcstr &deviceID, const rdcstr &packageName)
{
  Process::ProcessResult activity =
      adbExecCommand(deviceID, StringFormat::Fmt("shell cmd package resolve-activity"
                                                 " -c android.intent.category.LAUNCHER %s",
                                                 packageName.c_str()));

  if(activity.strStdout.empty())
  {
    RDCERR("Failed to resolve default activity of APK. STDERR: %s", activity.strStderror.c_str());
    return "";
  }

  rdcarray<rdcstr> lines;
  split(activity.strStdout, lines, '\n');

  for(rdcstr &line : lines)
  {
    line.trim();

    if(line.beginsWith("name=") && !line.contains("com.android"))
    {
      return line.substr(5);
    }
  }

  // when failed to find default activiy with cmd package on Android 6.0
  // try using pm dump like in this example:
  // $ adb shell pm dump com.android.gles3jni
  // DUMP OF SERVICE package:
  //  Activity Resolver Table:
  //    Non-Data Actions:
  //        android.intent.action.MAIN:
  //          d97b36a com.android.gles3jni/.GLES3JNIActivity filter fa39fb9
  // ...

  activity = adbExecCommand(deviceID, StringFormat::Fmt("shell pm dump %s", packageName.c_str()));

  lines.clear();
  split(activity.strStdout, lines, '\n');

  size_t numOfLines = lines.size();
  const char *intentFilter = "android.intent.action.MAIN:";

  for(size_t idx = 0; idx < numOfLines; idx++)
  {
    lines[idx].trim();

    if(lines[idx].beginsWith(intentFilter) && idx + 1 < numOfLines)
    {
      rdcstr activityName = lines[idx + 1].trimmed();
      int startPos = activityName.find('/');
      if(startPos < 0)
      {
        RDCWARN("Failed to find default activity");
        return "";
      }
      int endPos = activityName.find(' ', startPos + 1);
      if(endPos < 0)
        endPos = activityName.count();
      return activityName.substr(startPos + 1, endPos - startPos - 1);
    }
  }

  RDCERR("Didn't find default activity in adb output");
  return "";
}

rdcstr GetProcessNameForActivity(const rdcstr &deviceID, const rdcstr &packageName,
                                 const rdcstr &activityName)
{
  Process::ProcessResult activity =
      adbExecCommand(deviceID, StringFormat::Fmt("shell cmd package resolve-activity %s/%s",
                                                 packageName.c_str(), activityName.c_str()));

  if(activity.strStdout.empty())
  {
    RDCERR("Failed to resolve activity %s/%s. STDERR: %s", packageName.c_str(),
           activityName.c_str(), activity.strStderror.c_str());
    return packageName;
  }

  rdcarray<rdcstr> lines;
  split(activity.strStdout, lines, '\n');

  for(rdcstr &line : lines)
  {
    line.trim();

    if(line.beginsWith("processName="))
    {
      return line.substr(12);
    }
  }

  return packageName;
}

int GetCurrentPID(const rdcstr &deviceID, const rdcstr &processName)
{
  if(Android_Debug_ProcessLaunch())
  {
    RDCLOG("Getting PID from device %s for process '%s'", deviceID.c_str(), processName.c_str());
  }

  // try 15 times, 200ms apart to find the pid, for a total of 3 seconds timeout waiting for the
  // process to even be alive
  for(int i = 0; i < 15; i++)
  {
    Process::ProcessResult pidOutput =
        adbExecCommand(deviceID, StringFormat::Fmt("shell ps -A | grep %s", processName.c_str()));

    rdcstr &output = pidOutput.strStdout;

    output.trim();
    int space = output.find_first_of("\t ");

    if(Android_Debug_ProcessLaunch())
    {
      RDCLOG("Output from ps -A: '%s'", output.c_str());
    }

    // if we didn't get a response, try without the -A as some android devices don't support that
    // parameter
    if(output.empty() || output.find(processName) == -1 || space == -1)
    {
      pidOutput =
          adbExecCommand(deviceID, StringFormat::Fmt("shell ps | grep %s", processName.c_str()));

      output.trim();
      space = output.find_first_of("\t ");

      if(Android_Debug_ProcessLaunch())
      {
        RDCLOG("Output from ps: '%s'", output.c_str());
      }
    }

    if(Android_Debug_ProcessLaunch())
    {
      RDCLOG("Final output is '%s' and first space is at char %d", output.c_str(), space);
    }

    // if we still didn't get a response, sleep and try again next time
    if(output.empty() || output.find(processName) == -1 || space == -1)
    {
      if(Android_Debug_ProcessLaunch())
      {
        RDCLOG("Didn't get valid PID line, waiting");
      }

      Threading::Sleep(200);
      continue;
    }

    char *pid = &output[space];
    while(*pid == ' ' || *pid == '\t')
      pid++;

    if(Android_Debug_ProcessLaunch())
    {
      RDCLOG("Expecting PID starting at '%s'", pid);
    }

    char *end = pid;
    while(*end >= '0' && *end <= '9')
      end++;

    *end = 0;

    if(Android_Debug_ProcessLaunch())
    {
      RDCLOG("Truncated PID string: '%s'", pid);
    }

    int pidInt = atoi(pid);

    if(Android_Debug_ProcessLaunch())
    {
      RDCLOG("Parsed integer PID: %d", pidInt);
    }

    return pidInt;
  }

  if(Android_Debug_ProcessLaunch())
  {
    RDCLOG("Failed to get a PID after several retries");
  }

  return 0;
}

enum class AndroidVersionCheckResult
{
  Correct,
  WrongVersion,
  NotInstalled,
};

enum class AndroidInstallPermissionCheckResult
{
  Correct,
  NotQueryable,
};

AndroidVersionCheckResult CheckAndroidServerVersion(const rdcstr &deviceID, ABI abi)
{
  // assume all servers are updated at the same rate. Only check first ABI's version
  rdcstr packageName = GetRenderDocPackageForABI(abi);
  RDCLOG("Checking installed version of %s on %s", packageName.c_str(), deviceID.c_str());

  rdcstr dump = adbExecCommand(deviceID, "shell pm dump " + packageName).strStdout;
  if(dump.empty())
  {
    RDCWARN("Unable to pm dump %s", packageName.c_str());
    return AndroidVersionCheckResult::NotInstalled;
  }

  rdcstr versionCode = GetFirstMatchingLine(dump, "versionCode=").trimmed();
  rdcstr versionName = GetFirstMatchingLine(dump, "versionName=").trimmed();

  // versionCode is not alone in this line, isolate it
  if(versionCode != "")
  {
    int32_t spaceOffset = versionCode.find(' ');
    if(spaceOffset >= 0)
      versionCode.erase(spaceOffset, ~0U);

    versionCode.erase(0, strlen("versionCode="));
  }
  else
  {
    RDCWARN("Unable to determine versionCode for: %s", packageName.c_str());
  }

  if(versionName != "")
  {
    versionName.erase(0, strlen("versionName="));
  }
  else
  {
    RDCWARN("Unable to determine versionName for: %s", packageName.c_str());
  }

  if(versionCode.empty() && versionName.empty())
    return AndroidVersionCheckResult::NotInstalled;

  // Compare the server's versionCode and versionName with the host's for compatibility
  rdcstr hostVersionCode =
      rdcstr(STRINGIZE(RENDERDOC_VERSION_MAJOR)) + rdcstr(STRINGIZE(RENDERDOC_VERSION_MINOR));
  rdcstr hostVersionName = GitVersionHash;

  // False positives will hurt us, so check for explicit matches
  if((hostVersionCode == versionCode) && (hostVersionName == versionName))
  {
    RDCLOG("Installed server version (%s:%s) is compatible", versionCode.c_str(),
           versionName.c_str());
    return AndroidVersionCheckResult::Correct;
  }

  RDCWARN("RenderDoc server versionCode:versionName (%s:%s) is incompatible with host (%s:%s)",
          versionCode.c_str(), versionName.c_str(), hostVersionCode.c_str(), hostVersionName.c_str());

  return AndroidVersionCheckResult::WrongVersion;
}

Process::ProcessResult InstallAPK(const rdcstr &deviceID, const rdcstr &apk, int apiVersion)
{
  Process::ProcessResult adbInstall;
  if(apiVersion >= 30)
  {
    adbInstall = adbExecCommand(deviceID, "install -r -g --force-queryable \"" + apk + "\"", ".",
                                false, kAdbLongCommandTimeoutMS);
  }
  else
  {
    adbInstall =
        adbExecCommand(deviceID, "install -r -g \"" + apk + "\"", ".", false, kAdbLongCommandTimeoutMS);
  }

  return adbInstall;
}

AndroidInstallPermissionCheckResult CheckAndroidServerInstallPermissions(const rdcstr &deviceID,
                                                                         rdcstr packageName,
                                                                         int apiVersion)
{
  // Permissions check only applicable to API >= 30
  if(apiVersion < 30)
  {
    return AndroidInstallPermissionCheckResult::Correct;
  }
  // Command to check that the Android Server is queryable by other APKs (API>=30)
  Process::ProcessResult adbCheck =
      adbExecCommand(deviceID, "shell dumpsys package queries " + packageName, ".", true);
  // parse command output
  int32_t sectionStart = adbCheck.strStdout.find("forceQueryable");
  int32_t sectionEnd = adbCheck.strStdout.find("queries via package name", sectionStart);
  int32_t isPackageQueryable = adbCheck.strStdout.find(packageName, sectionStart, sectionEnd);
  if(isPackageQueryable == -1)
  {
    RDCERR("Failed to install with 'force queryable' permissions.");
    return AndroidInstallPermissionCheckResult::NotQueryable;
  }

  return AndroidInstallPermissionCheckResult::Correct;
}

Process::ProcessResult ListPackages(const rdcstr &deviceID, const rdcstr &parameters)
{
  Process::ProcessResult result = adbExecCommand(deviceID, "shell getprop ro.build.version.sdk");

  int sdkVersion = -1;
  if(result.retCode == 0)
    sdkVersion = atoi(result.strStdout.c_str());

  // Android 13 and higher
  if(sdkVersion >= 33)
    result = adbExecCommand(deviceID,
                            "shell pm list packages --user $(am get-current-user) " + parameters);

  if(result.retCode != 0 || sdkVersion < 33)
    result = adbExecCommand(deviceID, "shell pm list packages " + parameters);

  return result;
}

RDResult InstallRenderDocServer(const rdcstr &deviceID)
{
  ResultCode result = ResultCode::Succeeded;

  rdcarray<ABI> abis = GetSupportedABIs(deviceID);

  if(abis.empty())
  {
    RETURN_ERROR_RESULT(ResultCode::AndroidABINotFound,
                        "Couldn't determine supported ABIs for device %s", deviceID.c_str());
  }

  // Check known paths for RenderDoc server
  rdcstr libPath;
  FileIO::GetLibraryFilename(libPath);
  rdcstr libDir = get_dirname(FileIO::GetFullPathname(libPath));

  rdcarray<rdcstr> paths;

#if defined(RENDERDOC_APK_PATH)
  rdcstr customPath(RENDERDOC_APK_PATH);
#else
  rdcstr customPath;
#endif

  if(!customPath.empty())
  {
    RDCLOG("Custom APK path: %s", customPath.c_str());

    if(FileIO::IsRelativePath(customPath))
      customPath = libDir + "/" + customPath;

    if(customPath.back() != '/')
      customPath += '/';

    paths.push_back(customPath);
  }

  rdcstr suff = GetPlainABIName(abis[0]);

  paths.push_back(libDir + "/plugins/android/");                                  // Windows install
  paths.push_back(libDir + "/../share/renderdoc/plugins/android/");               // Linux install
  paths.push_back(libDir + "/../plugins/android/");                               // macOS install
  paths.push_back(libDir + "/../../build-android/bin/");                          // Local build
  paths.push_back(libDir + "/../../build-android-" + suff + "/bin/");             // Local ABI build
  paths.push_back(libDir + "/../../../../../build-android/bin/");                 // macOS build
  paths.push_back(libDir + "/../../../../../build-android-" + suff + "/bin/");    // macOS ABI build

  // use the first ABI for searching
  rdcstr apk = GetRenderDocPackageForABI(abis[0]);
  rdcstr apksFolder;

  for(uint32_t i = 0; i < paths.size(); i++)
  {
    RDCLOG("Checking for server APK in %s", paths[i].c_str());

    rdcstr apkpath = paths[i] + apk + ".apk";

    if(FileIO::exists(apkpath))
    {
      apksFolder = paths[i];
      RDCLOG("APKs found: %s", apksFolder.c_str());
      break;
    }
  }

  if(apksFolder.empty())
  {
#if RENDERDOC_OFFICIAL_BUILD
    RETURN_ERROR_RESULT(ResultCode::AndroidAPKFolderNotFound,
                        "RenderDoc APK not found. Your build of RenderDoc may be incomplete.\n"
                        "Check that your device is ARM based, other ABIs are not supported.");
#else
    RETURN_ERROR_RESULT(ResultCode::AndroidAPKFolderNotFound,
                        "RenderDoc APK not found. Your build of RenderDoc is incomplete.\n"
                        "If this is a development build, consult the documentation for building "
                        "the Android package.\n"
                        "If this is a release build check that your device is ARM based, other "
                        "ABIs are not supported.");
#endif
  }

  // install the best ABI first, so that for arm64 only devices we can know by the time we go to
  // install arm32 whether arm64 installed correctly
  if(abis.size() == 2)
    std::swap(abis[0], abis[1]);

  for(ABI abi : abis)
  {
    apk = apksFolder;

    int abiSuffix = apk.find(suff);
    if(abiSuffix >= 0)
      apk.replace(abiSuffix, suff.size(), GetPlainABIName(abi));

    apk += GetRenderDocPackageForABI(abi) + ".apk";

    if(!FileIO::exists(apk))
      RDCWARN(
          "%s missing - ensure you build all ABIs your device can support for full compatibility",
          apk.c_str());

    rdcstr api =
        Android::adbExecCommand(deviceID, "shell getprop ro.build.version.sdk").strStdout.trimmed();

    int apiVersion = atoi(api.c_str());

    Process::ProcessResult adbInstall = InstallAPK(deviceID, apk, apiVersion);

    // if adb produces this message we can be reasonably sure this is a 32-bit version that failed
    // to install on a 64-bit only device. However we need to account for the possibility that adb
    // might not produce this error even if that's the problem, so we still handle that below as well.
    if((adbInstall.strStderror.contains("INSTALL_FAILED_NO_MATCHING_ABIS") ||
        adbInstall.strStdout.contains("INSTALL_FAILED_NO_MATCHING_ABIS")) &&
       abi == ABI::armeabi_v7a && abis.contains(ABI::arm64_v8a))
    {
      RDCWARN(
          "ARM32 package failed to install on ARM64 device with no matching ABIs error. Assuming "
          "64-bit only ARM device and ignoring.");
      continue;
    }

    RDCLOG("Installed package '%s', checking for success...", apk.c_str());

    AndroidVersionCheckResult versionCheck = CheckAndroidServerVersion(deviceID, abi);

    if(versionCheck != AndroidVersionCheckResult::Correct)
    {
      RDCLOG("Failed to install APK. stdout: %s, stderr: %s",
             adbInstall.strStdout.trimmed().c_str(), adbInstall.strStderror.trimmed().c_str());
      RDCLOG("Retrying...");
      adbExecCommand(deviceID, "install -r \"" + apk + "\"", ".", false, kAdbLongCommandTimeoutMS);

      versionCheck = CheckAndroidServerVersion(deviceID, abi);

      // if the apk came back as not installed (rather than wrong version code)
      // AND it's arm32 in an arm64 environment
      // AND the previous install (the arm64 install) succeeded
      // AND we're on Android 12
      // then we assume that this device is 64-bit only and doesn't support arm32 at all,
      // so we ignore the problem
      if(versionCheck == AndroidVersionCheckResult::NotInstalled && abi == ABI::armeabi_v7a &&
         abis.contains(ABI::arm64_v8a) && result == ResultCode::Succeeded && apiVersion >= 31)
      {
        RDCWARN(
            "ARM32 package failed to install but ARM64 package succeeded. Assuming 64-bit only ARM "
            "device and ignoring.");
        continue;
      }
      else if(versionCheck == AndroidVersionCheckResult::Correct)
      {
        // if it succeeded this time, then it was the permission grant that failed
        result = ResultCode::AndroidGrantPermissionsFailed;
      }
      else
      {
        // otherwise something went wrong with verifying. If the install failed completely we'll
        // return AndroidAPKInstallFailed below, otherwise return a code indicating we couldn't
        // verify the install properly.
        result = ResultCode::AndroidAPKVerifyFailed;
      }
    }

    // Only verify permissions if we are otherwise happy with the installation
    if(result != ResultCode::AndroidAPKVerifyFailed)
    {
      AndroidInstallPermissionCheckResult permissionsCheck =
          CheckAndroidServerInstallPermissions(deviceID, GetRenderDocPackageForABI(abi), apiVersion);
      if(permissionsCheck != AndroidInstallPermissionCheckResult::Correct)
      {
        RDCWARN("Failed to verify APK installation permissions. Retrying...");
        // Some devices will only grant permissions with a second installation attempt
        InstallAPK(deviceID, apk, apiVersion);
        // Check permission and version again - version was correct last time so should ok here
        if((CheckAndroidServerVersion(deviceID, abi) != AndroidVersionCheckResult::Correct) ||
           (CheckAndroidServerInstallPermissions(deviceID, GetRenderDocPackageForABI(abi), apiVersion) !=
            AndroidInstallPermissionCheckResult::Correct))
        {
          RDCWARN("Failed to verify APK installation");
          result = ResultCode::AndroidAPKVerifyFailed;
        }
      }
    }
  }

  // Ensure installation succeeded. We should have as many lines as abis we installed
  Process::ProcessResult adbCheck = ListPackages(deviceID, RENDERDOC_ANDROID_PACKAGE_BASE);

  if(adbCheck.strStdout.empty())
  {
    RETURN_ERROR_RESULT(ResultCode::AndroidAPKInstallFailed, "Couldn't install APK(s). stderr: %s",
                        adbCheck.strStderror.c_str());
  }

  size_t lines = adbCheck.strStdout.find('\n') == -1 ? 1 : 2;

  if(lines != abis.size())
    RDCWARN("Installation of some apks failed!");

  return result;
}

bool RemoveRenderDocAndroidServer(const rdcstr &deviceID)
{
  rdcarray<ABI> abis = GetSupportedABIs(deviceID);

  if(abis.empty())
    return false;

  // remove the old package, if it's still there. Ignore any errors
  adbExecCommand(deviceID, "uninstall " RENDERDOC_ANDROID_PACKAGE_BASE, ".", false,
                 kAdbLongCommandTimeoutMS);

  for(ABI abi : abis)
  {
    rdcstr packageName = GetRenderDocPackageForABI(abi);

    adbExecCommand(deviceID, "uninstall " + packageName, ".", false, kAdbLongCommandTimeoutMS);

    // Ensure uninstall succeeded
    rdcstr adbCheck = ListPackages(deviceID, packageName).strStdout;

    if(!adbCheck.empty())
    {
      RDCERR("Uninstall of %s failed!", packageName.c_str());
      return false;
    }
  }

  return true;
}

// tracks the last package that had wrap.sh preload injection staged, so ResetCaptureSettings
// can remove its wrap property when the device session ends
static rdcstr g_lastWrapPackage;

// resolves the numeric uid that owns the app's data directory from the package manager. Only used
// for logging which app the files were staged for, since SELinux denies chown on app_data_file
// even to a KernelSU root shell.
static rdcstr GetPackageUID(const rdcstr &deviceID, const rdcstr &packageName)
{
  Process::ProcessResult res =
      adbExecCommand(deviceID, "shell pm list packages -U --user 0 " + packageName, ".", true);

  int idx = res.strStdout.find("uid:");
  if(idx < 0)
    return rdcstr();

  rdcstr uid = res.strStdout.substr(idx + 4).trimmed();

  // strip any trailing non-numeric garbage (newlines, secondary user entries)
  for(size_t i = 0; i < uid.size(); i++)
  {
    if(uid[i] < '0' || uid[i] > '9')
    {
      uid.resize(i);
      break;
    }
  }

  return uid;
}

// copies a staged file into the target app's data directory. run-as only works for debuggable
// apps, which release games typically aren't - when it fails and a su root shell is available
// (KernelSU/Magisk su works from adb shell even on production builds where 'adb root' fails),
// copy as root and rely on world permissions for the app to access the file. SELinux denies
// chown on app_data_file even to the ksu domain, so re-owning to the app uid is not possible -
// 644/755 with the inherited app_data_file label is sufficient for both dlopen (library) and
// exec-through-zygote (wrap script).
static bool CopyIntoAppData(const rdcstr &deviceID, const rdcstr &packageName, const rdcstr &src,
                            const rdcstr &dst)
{
  Process::ProcessResult cp =
      adbExecCommand(deviceID, "shell run-as " + packageName + " cp " + src + " " + dst, ".", true);

  if(cp.strStderror.empty() && cp.retCode == 0)
    return true;

  // run each root operation as its own su invocation - KernelSU's su -c tokenises its argument in
  // ways that mangle shell chains and quoted strings, so keep every command a single word list.
  Process::ProcessResult cpRoot =
      adbExecCommand(deviceID, "shell su -c \"cp " + src + " " + dst + "\"", ".", true);

  if(!cpRoot.strStderror.empty() || cpRoot.retCode != 0)
  {
    RDCERR("Failed to copy %s into %s - run-as: %s, su: %s", src.c_str(), dst.c_str(),
           cp.strStderror.trimmed().c_str(), cpRoot.strStderror.trimmed().c_str());
    return false;
  }

  Process::ProcessResult chmodRoot =
      adbExecCommand(deviceID, "shell su -c \"chmod 755 " + dst + "\"", ".", true);

  if(!chmodRoot.strStderror.empty() || chmodRoot.retCode != 0)
  {
    RDCERR("Failed to chmod %s via root shell: %s", dst.c_str(),
           chmodRoot.strStderror.trimmed().c_str());
    return false;
  }

  rdcstr uid = GetPackageUID(deviceID, packageName);
  RDCLOG("Copied %s into app data via root shell, world-executable (app uid %s)", dst.c_str(),
         uid.empty() ? "?" : uid.c_str());
  return true;
}

// wrap.sh + LD_PRELOAD injection. The capture library lives in the renderdoc package's lib dir
// which the target app's uid can't read, and /data/local/tmp files aren't executable by apps
// under SELinux, so we stage the library and a wrapper script through the device shell into the
// app's own data directory. Setting wrap.<package> makes the runtime execute the script in place
// of the app's normal start, and the script LD_PRELOADs the library - it loads before any
// graphics driver and hooks it via PLT patching. This path doesn't depend on the ROM honouring
// the gpu_debug_* settings and doesn't involve a JDWP debugger session.
RDResult PrepareWrapInjection(const rdcstr &deviceID, const rdcstr &packageName)
{
  rdcstr abiName = DetermineInstalledABI(deviceID, packageName);
  ABI abi = GetABI(abiName);

  if(abi == ABI::unknown)
  {
    RDCERR("Couldn't determine ABI for %s to prepare wrap injection", packageName.c_str());
    return RDResult(ResultCode::AndroidABINotFound);
  }

  const rdcstr serverPkg = GetRenderDocPackageForABI(abi);
  const rdcstr abiDir = (abi == ABI::arm64_v8a) ? "arm64" : "arm";
  const rdcstr serverLib =
      GetPathForPackage(deviceID, serverPkg) + "/lib/" + abiDir + "/" + RENDERDOC_ANDROID_LIBRARY;

  const rdcstr stageDir = "/data/local/tmp/rdwrap";
  const rdcstr appDataDir = "/data/user/0/" + packageName;

  // The capture library must be loadable both as the LD_PRELOAD entry (phase 2 wrap.sh
  // injection) and as the vulkan debug layer (phase 1 gpu_debug_layers_gles). If those resolve
  // to two different file paths the library is mapped twice and the two copies keep separate
  // static state - wrapped handles from one copy are foreign to the other, which crashes the
  // vulkan loader dispatch. The vulkan loader searches (in order) the app data dir and the
  // app's nativeLibraryDir, and looks there for libVkLayer_<layer>.so. We therefore stage the
  // library into the app's nativeLibraryDir under the layer name and point LD_PRELOAD at that
  // exact same path, so the linker loads it once.
  rdcstr nativeLibDir = GetPathForPackage(deviceID, packageName) + "/lib/" + abiDir;
  // the layer file name is the vulkan layer name with the VK_LAYER_ prefix stripped and the
  // libVkLayer_ android prefix added: VK_LAYER_RENDERDOC_Capture -> libVkLayer_RENDERDOC_Capture.so
  const rdcstr layerLibName = "libVkLayer_RENDERDOC_Capture.so";

  adbExecCommand(deviceID, "shell rm -rf " + stageDir, ".", true);
  adbExecCommand(deviceID, "shell mkdir -p " + stageDir, ".", true);
  adbExecCommand(deviceID, "shell chmod 755 " + stageDir, ".", true);

  Process::ProcessResult cat = adbExecCommand(
      deviceID,
      "shell run-as " + serverPkg + " cat " + serverLib + " > " + stageDir + "/" +
          RENDERDOC_ANDROID_LIBRARY,
      ".", true, kAdbLongCommandTimeoutMS);

  if(!cat.strStderror.empty() || cat.retCode != 0)
  {
    // the server APK may not be debuggable (run-as refused) - retry through a root shell if one
    // is available, so wrap injection also works when neither the server nor the target APK is
    // debuggable.
    Process::ProcessResult catRoot = adbExecCommand(
        deviceID,
        "shell su -c \"cat " + serverLib + " > " + stageDir + "/" + RENDERDOC_ANDROID_LIBRARY +
            "\"",
        ".", true, kAdbLongCommandTimeoutMS);

    if(!catRoot.strStderror.empty() || catRoot.retCode != 0)
    {
      RDCERR("Failed to export %s from %s: %s", RENDERDOC_ANDROID_LIBRARY, serverPkg.c_str(),
             cat.strStderror.trimmed().c_str());
      return RDResult(ResultCode::InjectionFailed,
                      "Failed to stage the capture library for wrap injection.");
    }
  }

  adbExecCommand(deviceID, "shell chmod 644 " + stageDir + "/" + RENDERDOC_ANDROID_LIBRARY, ".",
                 true);

  // copy the library into the app's nativeLibraryDir under the vulkan layer file name, and
  // point LD_PRELOAD at that exact path. The vulkan loader searches the nativeLibraryDir for
  // libVkLayer_<name>.so and will find it there; because LD_PRELOAD already loaded that same
  // path, the linker returns the existing (single) copy instead of mapping the library twice.
  // run-as can't write into nativeLibraryDir (owned by system), so this needs a root shell;
  // fall back to the legacy data-dir staging if root isn't available.
  rdcstr preloadPath = appDataDir + "/" + RENDERDOC_ANDROID_LIBRARY;
  {
    Process::ProcessResult install = adbExecCommand(
        deviceID,
        "shell su -c \"cp " + stageDir + "/" + RENDERDOC_ANDROID_LIBRARY + " " + nativeLibDir +
            "/" + layerLibName + " && chmod 755 " + nativeLibDir + "/" + layerLibName +
            " && chcon u:object_r:apk_data_file:s0 " + nativeLibDir + "/" + layerLibName + "\"",
        ".", true, kAdbLongCommandTimeoutMS);

    if(install.retCode == 0 && !install.strStderror.contains("denied") &&
       !install.strStderror.contains("not found"))
    {
      preloadPath = nativeLibDir + "/" + layerLibName;
      // the data-dir copy of the layer is no longer needed - and it must NOT be present, or
      // the loader would pick it up first (the data dir is searched before nativeLibraryDir)
      // and map a second copy of the library.
      adbExecCommand(deviceID,
                     "shell su -c \"rm -f " + appDataDir + "/" + layerLibName + "\"",
                     ".", true);
      RDCLOG("Staged capture library as both preload and vulkan layer at %s",
             preloadPath.c_str());
    }
    else
    {
      RDCLOG("Couldn't stage into nativeLibraryDir (%s) - keeping data-dir layer staging; "
             "the vulkan layer may load as a second copy",
             install.strStderror.trimmed().c_str());
    }
  }

  // copy the library into the app's own data directory, as the app's uid so it can dlopen it.
  // run-as only works for debuggable apps - on release builds this goes through a root shell
  // when su is available.
  if(!CopyIntoAppData(deviceID, packageName, stageDir + "/" + RENDERDOC_ANDROID_LIBRARY,
                      appDataDir + "/" + RENDERDOC_ANDROID_LIBRARY))
  {
    return RDResult(ResultCode::InjectionFailed,
                    "Failed to copy the capture library into the application data directory.");
  }

  adbExecCommand(deviceID,
                 "shell run-as " + packageName + " chmod 755 " + appDataDir + "/" +
                     RENDERDOC_ANDROID_LIBRARY,
                 ".", true);

  // generate the wrap script on the host and stage it into the app's data directory the same way
  rdcstr script = "#!/system/bin/sh\n";
  script += "export LD_PRELOAD=" + preloadPath + "\n";
  script += "exec \"$@\"\n";

  rdcstr localScript = FileIO::GetTempFolderFilename() + "/rdwrap.sh";
  // write in binary mode: on Windows, text mode would translate each '\n' into '\r\n' and the
  // shebang line would become '#!/system/bin/sh\r'. The kernel then fails to find the interpreter
  // '/system/bin/sh\r' and the wrapped process dies with exit code 126 before RenderDoc can
  // attach ("Error reading pid from wrapped process" / injection failed).
  FILE *f = FileIO::fopen(localScript, FileIO::WriteBinary);
  if(!f)
  {
    RDCERR("Couldn't write wrap script to %s", localScript.c_str());
    return RDResult(ResultCode::InjectionFailed, "Failed to create the wrap.sh script.");
  }
  FileIO::fwrite(script.c_str(), 1, script.size(), f);
  FileIO::fclose(f);

  Process::ProcessResult push =
      adbExecCommand(deviceID, "push \"" + localScript + "\" " + stageDir + "/wrap.sh", ".",
                     true, kAdbLongCommandTimeoutMS);
  FileIO::Delete(localScript);

  // adb push reports its progress ("1 file pushed, 0 skipped. ...") on stderr even on success,
  // so only a non-zero exit code or an explicit error string counts as failure.
  if(push.retCode != 0 || push.strStderror.contains("error") ||
     push.strStderror.contains("Permission denied"))
  {
    RDCERR("Failed to push wrap.sh: %s", push.strStderror.trimmed().c_str());
    return RDResult(ResultCode::InjectionFailed, "Failed to push the wrap.sh script.");
  }

  adbExecCommand(deviceID, "shell chmod 755 " + stageDir + "/wrap.sh", ".", true);

  if(!CopyIntoAppData(deviceID, packageName, stageDir + "/wrap.sh", appDataDir + "/rdwrap.sh"))
  {
    return RDResult(ResultCode::InjectionFailed,
                    "Failed to copy the wrap.sh script into the application data directory.");
  }

  adbExecCommand(deviceID, "shell run-as " + packageName + " chmod 755 " + appDataDir + "/rdwrap.sh",
                 ".", true);

  Process::ProcessResult wrapSet = adbExecCommand(
      deviceID,
      "shell setprop wrap." + packageName + " \"" + appDataDir + "/rdwrap.sh\"", ".", true);

  // some hardened ROMs (ColorOS among them) reject setting wrap.* properties entirely from the
  // shell and app contexts. If a root shell is available (KernelSU/Magisk su works even where
  // 'adb root' fails on production builds) set the property from the root context instead, and
  // only fall back to JDWP injection when that fails too.
  if(wrapSet.strStderror.contains("Failed to set property") || wrapSet.retCode != 0)
  {
    Process::ProcessResult wrapSetRoot = adbExecCommand(
        deviceID,
        "shell su -c \"setprop wrap." + packageName + " " + appDataDir + "/rdwrap.sh\"", ".",
        true);

    if(wrapSetRoot.strStderror.contains("Failed to set property") || wrapSetRoot.retCode != 0)
    {
      RDCERR("Failed to set wrap.%s: %s - the ROM blocks the wrap property and no root shell is "
             "available, wrap injection is not possible on this device.",
             packageName.c_str(), wrapSet.strStderror.trimmed().c_str());
      return RDResult(ResultCode::InjectionFailed,
                      "The device blocked setting the wrap property needed for preload injection.");
    }

    RDCLOG("wrap.%s set via root shell (the ROM blocks shell from writing wrap properties)",
           packageName.c_str());
  }

  // Hardened-ROM fixups, best-effort through the root shell:
  //
  // * Android 14+ SELinux denies the app domain execute_no_trans on app_data_file, so a wrap
  //   script staged in the app's own data directory never runs and the preloaded capture library
  //   can't be dlopened. Re-labelling both files as shell_exec lets the app execute them exactly
  //   the way it executes /system/bin/sh - allowed by the default policy, no sepolicy patch
  //   needed and nothing to re-apply after a reboot.
  // * The wrap exec-chain replaces the process image, which resets the linker namespaces the
  //   zygote prepared. hwui's VulkanManager then fails to load libvulkan and aborts the process
  //   ("Assertion failed: err < 0") when its render thread preloads a Vk context. Forcing hwui
  //   to the OpenGL pipeline sidesteps that preload; the app's own renderer is unaffected.
  const rdcstr fixups[] = {
      "chcon u:object_r:shell_exec:s0 " + appDataDir + "/rdwrap.sh",
      "chcon u:object_r:shell_exec:s0 " + appDataDir + "/" + RENDERDOC_ANDROID_LIBRARY,
      "setprop debug.hwui.renderer opengl",
  };

  for(const rdcstr &fixup : fixups)
  {
    Process::ProcessResult res =
        adbExecCommand(deviceID, "shell su -c \"" + fixup + "\"", ".", true);

    if(res.retCode != 0 || res.strStderror.contains("Permission denied"))
      RDCWARN("Root fixup '%s' failed: %s", fixup.c_str(), res.strStderror.trimmed().c_str());
  }

  g_lastWrapPackage = packageName;

  RDCLOG("Staged wrap.sh preload injection for %s", packageName.c_str());
  return RDResult(ResultCode::Succeeded);
}

void ClearWrapInjection(const rdcstr &deviceID, const rdcstr &packageName)
{
  Android::adbExecCommand(deviceID, "shell setprop wrap." + packageName + " \"\"", ".", true);

  // On ROMs that block shell from writing wrap.* properties the set above fails silently (and a
  // property that was set from a root context can't be cleared by shell either). Delete it via
  // resetprop through a root shell if one is available - otherwise the property lingers until
  // reboot and the app stays wrapped.
  Android::adbExecCommand(deviceID,
                          "shell su -c \"resetprop --delete wrap." + packageName + "\"", ".", true);
}

void ResetCaptureSettings(const rdcstr &deviceID)
{
  if(!g_lastWrapPackage.empty())
  {
    ClearWrapInjection(deviceID, g_lastWrapPackage);
    g_lastWrapPackage.clear();
  }

  Android::adbExecCommand(deviceID, "shell setprop debug.vulkan.layers :", ".", true);
  Android::adbExecCommand(deviceID, "shell settings delete global enable_gpu_debug_layers", ".",
                          true);
  Android::adbExecCommand(deviceID, "shell settings delete global gpu_debug_app", ".", true);
  Android::adbExecCommand(deviceID, "shell settings delete global gpu_debug_layer_app", ".", true);
  Android::adbExecCommand(deviceID, "shell settings delete global gpu_debug_layers", ".", true);
  Android::adbExecCommand(deviceID, "shell settings delete global gpu_debug_layers_gles", ".", true);
}

rdcarray<rdcstr> EnumerateDevices()
{
  rdcarray<rdcstr> ret;

  rdcstr adbStdout = Android::adbExecCommand("", "devices", ".", true).strStdout;

  rdcarray<rdcstr> lines;
  split(adbStdout, lines, '\n');
  for(const rdcstr &line : lines)
  {
    rdcarray<rdcstr> tokens;
    split(line, tokens, '\t');
    if(tokens.size() == 2 && tokens[1].trimmed() == "device")
      ret.push_back(tokens[0]);
  }

  return ret;
}
};    // namespace Android

struct AndroidRemoteServer : public RemoteServer
{
  AndroidRemoteServer(Network::Socket *sock, const rdcstr &deviceID, uint16_t portbase)
      : RemoteServer(sock, deviceID), m_portbase(portbase)
  {
  }

  virtual ~AndroidRemoteServer() override
  {
    if(m_LogcatThread)
      m_LogcatThread->Finish();
  }

  virtual void ShutdownConnection() override;

  virtual void ShutdownServerAndConnection() override
  {
    ResetAndroidSettings();
    RemoteServer::ShutdownServerAndConnection();
  }

  virtual ResultDetails Ping() override
  {
    if(!Connected())
      return RDResult(ResultCode::RemoteServerConnectionLost);

    LazilyStartLogcatThread();

    return RemoteServer::Ping();
  }

  virtual rdcpair<ResultDetails, IReplayController *> OpenCapture(
      uint32_t proxyid, const rdcstr &filename, const ReplayOptions &opts,
      RENDERDOC_ProgressCallback progress) override
  {
    ResetAndroidSettings();

    // enable profiling to measure hardware counters
    Android::adbExecCommand(m_deviceID, "shell setprop security.perf_harden 0");

    LazilyStartLogcatThread();

    return RemoteServer::OpenCapture(proxyid, filename, opts, progress);
  }

  virtual void CloseCapture(IReplayController *rend) override
  {
    // disable profiling
    Android::adbExecCommand(m_deviceID, "shell setprop security.perf_harden 1");

    RemoteServer::CloseCapture(rend);
  }

  virtual rdcstr GetHomeFolder() override { return ""; }
  virtual rdcarray<PathEntry> ListFolder(const rdcstr &path) override
  {
    if(path.empty() || (path[0] == '/' && path.size() == 1))
    {
      SCOPED_TIMER("Fetching android packages and activities");

      rdcstr adbStdout = Android::ListPackages(m_deviceID, "-3").strStdout;

      rdcarray<rdcstr> lines;
      split(adbStdout, lines, '\n');
      for(rdcstr &line : lines)
        while(!line.empty() && isspace(line.back()))
          line.pop_back();

      rdcarray<PathEntry> packages;
      for(const rdcstr &line : lines)
      {
        // hide our own internal packages
        if(strstr(line.c_str(), "package:org.renderdoc."))
          continue;

        if(!strncmp(line.c_str(), "package:", 8))
        {
          PathEntry pkg;
          pkg.filename = line.substr(8).trimmed();
          pkg.size = 0;
          pkg.lastmod = 0;
          pkg.flags = PathProperty::Directory;

          packages.push_back(pkg);
        }
      }

      // also fetch the system packages but mark them as hidden folders
      adbStdout = Android::ListPackages(m_deviceID, "-s").strStdout;

      split(adbStdout, lines, '\n');
      for(rdcstr &line : lines)
        while(!line.empty() && isspace(line.back()))
          line.pop_back();

      for(const rdcstr &line : lines)
      {
        if(!strncmp(line.c_str(), "package:", 8))
        {
          PathEntry pkg;
          pkg.filename = line.substr(8).trimmed();
          pkg.size = 0;
          pkg.lastmod = 0;
          pkg.flags = PathProperty::Directory | PathProperty::Hidden;

          packages.push_back(pkg);
        }
      }

      // Android is a completely garbage platform, and the command below can take several orders of
      // magnitude more time than is reasonable and hit the remote server timeout. To give the best
      // chance of that not happening, we ping before and after running it.
      RemoteServer::Ping();

      adbStdout = Android::adbExecCommand(m_deviceID, "shell dumpsys package").strStdout;

      RemoteServer::Ping();

      split(adbStdout, lines, '\n');
      for(rdcstr &line : lines)
        while(!line.empty() && isspace(line.back()))
          line.pop_back();

      // not everything that looks like it's an activity is actually an activity, because of course
      // nothing is ever simple on Android. Watch out for the activity sections and only parse
      // activities found within them.

      bool activitySection = false;
      bool nonDataSection = false;

      for(const rdcstr &line : lines)
      {
        // if this is the start of the activity section, set the flag to true
        if(line.contains("Activity Resolver Table:"))
          activitySection = true;

        // the activity section ends when we reach a line that starts at column 0, which is the
        // start of a section. Reset the flag to false
        else if(!line.empty() && !isspace(line[0]))
          activitySection = false;

        // if this is the start of the non-data action section, set the flag to true
        if(line.contains("Non-Data Actions:"))
          nonDataSection = true;

        // a blank line indicates the end of the non-data action section
        else if(line.empty())
          nonDataSection = false;

        // if the flag is false, skip
        if(!activitySection || !nonDataSection)
          continue;

        // quick check, look for a /
        if(!line.contains('/'))
          continue;

        // line should be something like: '    78f9sba com.package.name/.NameOfActivity .....'

        const char *c = line.c_str();

        // expect whitespace
        while(*c && isspace(*c))
          c++;

        // expect hex
        while(*c && ((*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'f')))
          c++;

        // expect space
        if(*c != ' ')
          continue;

        c++;

        // expect the package now. Search to see if it's one of the ones we listed above
        rdcstr package;

        for(const PathEntry &p : packages)
          if(!strncmp(c, p.filename.c_str(), p.filename.size()))
            package = p.filename;

        // didn't find a matching package
        if(package.empty())
          continue;

        c += package.size();

        // expect a /
        if(*c != '/')
          continue;

        c++;

        const char *end = strchr(c, ' ');

        if(end == NULL)
          end = c + strlen(c);

        while(isspace(*(end - 1)))
          end--;

        m_AndroidActivities.insert({package, rdcstr(c, end - c)});
      }

      return packages;
    }
    else
    {
      rdcstr package = path;

      if(!package.empty() && package[0] == '/')
        package.erase(0, 1);

      rdcarray<PathEntry> activities;

      for(const Activity &act : m_AndroidActivities)
      {
        if(act.package == package)
        {
          PathEntry activity;
          if(act.activity[0] == '.')
            activity.filename = package + act.activity;
          else
            activity.filename = act.activity;
          activity.size = 0;
          activity.lastmod = 0;
          activity.flags = PathProperty::Executable;
          activities.push_back(activity);
        }
      }

      PathEntry defaultActivity;
      defaultActivity.filename = "#DefaultActivity";
      defaultActivity.size = 0;
      defaultActivity.lastmod = 0;
      defaultActivity.flags = PathProperty::Executable;

      // if there's only one activity listed, assume it's the default and don't add a virtual
      // entry
      if(activities.size() != 1)
        activities.push_back(defaultActivity);

      return activities;
    }
  }

  virtual ExecuteResult ExecuteAndInject(const rdcstr &packageAndActivity, const rdcstr &,
                                         const rdcstr &intentArgs,
                                         const rdcarray<EnvironmentModification> &env,
                                         const CaptureOptions &opts) override;

private:
  void ResetAndroidSettings() { Android::ResetCaptureSettings(m_deviceID); }
  void LazilyStartLogcatThread()
  {
    if(m_LogcatThread)
      return;

    m_LogcatThread = Android::ProcessLogcat(m_deviceID);
  }

  uint16_t m_portbase = 0;
  Android::LogcatThread *m_LogcatThread = NULL;

  struct Activity
  {
    rdcstr package;
    rdcstr activity;

    bool operator<(const Activity &o) const
    {
      if(package != o.package)
        return package < o.package;
      return activity < o.activity;
    }
  };

  std::set<Activity> m_AndroidActivities;
};

struct AndroidController : public IDeviceProtocolHandler
{
  void Start()
  {
    if(running == 0)
    {
      Atomic::Inc32(&running);

      {
        SCOPED_LOCK(lock);
        Android::initAdb();
      }

      thread = Threading::CreateThread([]() { m_Inst.ThreadEntry(); });
      RenderDoc::Inst().RegisterShutdownFunction([]() { m_Inst.Shutdown(); });
    }
  }

  void Shutdown()
  {
    Atomic::Dec32(&running);
    Threading::JoinThread(thread);
    Threading::CloseThread(thread);
    thread = 0;

    {
      SCOPED_LOCK(lock);
      Android::shutdownAdb();
    }
  }

  struct Command
  {
    std::function<void()> meth;
    int32_t done = 0;
    bool selfdelete = false;
  };

  rdcarray<Command *> cmdqueue;

  void ThreadEntry()
  {
    Threading::SetCurrentThreadName("AndroidController");

    while(Atomic::CmpExch32(&running, 1, 1) == 1)
    {
      Threading::Sleep(5);
      Command *cmd = NULL;

      {
        SCOPED_LOCK(lock);
        if(cmdqueue.empty())
          continue;

        cmd = cmdqueue[0];
        cmdqueue.erase(0);
      }

      cmd->meth();

      if(cmd->selfdelete)
      {
        delete cmd;
      }
      else
      {
        Atomic::Inc32(&cmd->done);
      }
    }
  }

  void Invoke(std::function<void()> method)
  {
    Command cmd;
    cmd.meth = method;

    {
      SCOPED_LOCK(lock);
      cmdqueue.push_back(&cmd);
    }

    while(Atomic::CmpExch32(&cmd.done, 0, 0) == 0)
      Threading::Sleep(5);
  }

  void AsyncInvoke(std::function<void()> method)
  {
    Command *cmd = new Command;
    cmd->meth = method;
    cmd->selfdelete = true;

    {
      SCOPED_LOCK(lock);
      cmdqueue.push_back(cmd);
    }
  }

  rdcstr GetProtocolName() override { return "adb"; }
  rdcarray<rdcstr> GetDevices() override
  {
    rdcarray<rdcstr> ret;

    Invoke([this, &ret]() {
      rdcarray<rdcstr> activedevices = Android::EnumerateDevices();

      // reset all devices to inactive
      for(auto it = devices.begin(); it != devices.end(); ++it)
        it->second.active = false;

      // process the list of active devices, find matches and activate them, or add a new entry
      for(const rdcstr &d : activedevices)
      {
        // A device whose adb channel has wedged is treated as not present: otherwise every
        // enumeration cycle repeats the same timing-out commands and the device keeps reappearing
        // in the UI with an empty name. It comes back once the cooldown expires and a command
        // succeeds (or after a replug). See Android_AdbFailFastThreshold.
        if(Android::adbChannelUnusable(d))
          continue;

        auto it = devices.find(d);
        if(it != devices.end())
        {
          it->second.active = true;

          // silently forward the ports now. These may be refreshed but this will allow us to
          // connect
          Android::adbForwardPorts(it->second.portbase, d, 0, 0, true);
          continue;
        }

        // not found - add a new device
        Device dev;
        dev.active = true;
        dev.name = Android::GetFriendlyName(d);
        if(!Android::IsSupported(d))
          dev.name += " - (Android 5.x)";
        dev.portbase = uint16_t(RenderDoc_ForwardPortBase + RenderDoc::Inst().GetForwardedPortSlot() *
                                                                RenderDoc_ForwardPortStride);

        // silently forward the ports now. These may be refreshed but this will allow us to connect
        Android::adbForwardPorts(dev.portbase, d, 0, 0, true);

        devices[d] = dev;
      }

      for(auto it = devices.begin(); it != devices.end(); ++it)
      {
        if(it->second.active)
          ret.push_back(it->first);
      }
    });

    return ret;
  }

  rdcstr GetFriendlyName(const rdcstr &URL) override
  {
    rdcstr ret;

    {
      SCOPED_LOCK(lock);
      auto it = devices.find(GetDeviceID(URL));
      if(it != devices.end())
        ret = it->second.name;
    }

    return ret;
  }

  bool SupportsMultiplePrograms(const rdcstr &URL) override { return false; }
  bool IsSupported(const rdcstr &URL) override
  {
    bool ret = false;

    {
      SCOPED_LOCK(lock);
      ret = Android::IsSupported(GetDeviceID(URL));
    }

    return ret;
  }

  ResultDetails StartRemoteServer(const rdcstr &URL) override
  {
    RDResult result = ResultCode::Succeeded;

    Invoke([this, &result, URL]() {
      rdcstr deviceID = GetDeviceID(URL);

      auto it = devices.find(deviceID);
      if(it == devices.end())
      {
        SET_ERROR_RESULT(result, ResultCode::InternalError,
                         "Android device %s is not a valid device ID, can't launch server",
                         Android::GetFriendlyName(deviceID).c_str());
        return;
      }

      Device &dev = it->second;

      if(!dev.active)
      {
        SET_ERROR_RESULT(result, ResultCode::InternalError,
                         "Android device %s is not active, can't launch server",
                         Android::GetFriendlyName(deviceID).c_str());
        return;
      }

      rdcstr packagesOutput =
          Android::ListPackages(deviceID, RENDERDOC_ANDROID_PACKAGE_BASE).strStdout.trimmed();

      rdcarray<rdcstr> packages;
      split(packagesOutput, packages, '\n');

      rdcarray<Android::ABI> abis = Android::GetSupportedABIs(deviceID);

      RDCLOG("Starting RenderDoc server, supported ABIs:");
      for(Android::ABI abi : abis)
        RDCLOG("  - %s", ToStr(abi).c_str());

      if(abis.empty())
      {
        SET_ERROR_RESULT(result, ResultCode::AndroidABINotFound,
                         "Can't determine supported ABIs for device %s",
                         Android::GetFriendlyName(deviceID).c_str());
        return;
      }

      rdcstr api =
          Android::adbExecCommand(deviceID, "shell getprop ro.build.version.sdk").strStdout.trimmed();

      int apiVersion = atoi(api.c_str());

      // To account for awkward 64-bit only devices, sometimes need to check ABIs independently. If
      // ARM32 is *missing completely* and ARM64 is present and on the right version, we allow that
      // case on Android 12+ assuming it's a 64-bit only device. Since our installer should always
      // update both packages in lockstep we don't expect 64-bit to be installed only if we could
      // have installed 32-bit.

      // the installed version is OK if...
      bool installedOK =
          // ...we have exactly the right number of packages installed and the best ABI is on the
          // right version. This covers normal 64-bit devices and also covers the 32-bit only case
          // trivially.
          (packages.size() == abis.size() &&
           Android::CheckAndroidServerVersion(deviceID, abis.back()) ==
               Android::AndroidVersionCheckResult::Correct)
          // OR
          ||
          // ...we're a 64-bit capable device on Android 12+ and only 64-bit is installed and up
          // to date, 32-bit is not installed at all
          (abis.contains(Android::ABI::arm64_v8a) && apiVersion >= 31 &&
           Android::CheckAndroidServerVersion(deviceID, Android::ABI::arm64_v8a) ==
               Android::AndroidVersionCheckResult::Correct &&
           Android::CheckAndroidServerVersion(deviceID, Android::ABI::armeabi_v7a) ==
               Android::AndroidVersionCheckResult::NotInstalled);

      if(!installedOK)
      {
        // if there was any existing package, remove it
        if(!packages.empty())
        {
          if(Android::RemoveRenderDocAndroidServer(deviceID))
            RDCLOG("Uninstall of old server succeeded");
          else
            RDCERR("Uninstall of old server failed");
        }

        // If server is not detected or has been removed due to incompatibility, install it
        result = Android::InstallRenderDocServer(deviceID);
        if(result != ResultCode::Succeeded && result != ResultCode::AndroidGrantPermissionsFailed &&
           result != ResultCode::AndroidAPKVerifyFailed)
        {
          RDCERR("Failed to install RenderDoc server app");
          return;
        }
      }

      // stop all servers of any ABI
      for(Android::ABI abi : abis)
        Android::adbExecCommand(deviceID, "shell am force-stop " + GetRenderDocPackageForABI(abi));

      // Attempt to prevent the user needing to click through on permissions
      rdcstr auto_grant_permissions =
          Android::adbExecCommand(deviceID, "shell getprop debug.renderdoc.autograntpermissions")
              .strStdout.trimmed();
      if(apiVersion >= 30 && atoi(auto_grant_permissions.c_str()) == 1)
      {
        for(Android::ABI abi : abis)
          Android::adbExecCommand(deviceID, "shell pm grant " + GetRenderDocPackageForABI(abi) +
                                                " android.permission.MANAGE_EXTERNAL_STORAGE");
      }

      Android::adbForwardPorts(dev.portbase, deviceID, 0, 0, false);
      Android::ResetCaptureSettings(deviceID);

      // make Oculus' on device vulkan validation layer available for load
      Android::adbExecCommand(
          deviceID,
          "shell setprop debug.oculus.usepackagedvvl." RENDERDOC_ANDROID_PACKAGE_BASE ".arm32 1");
      Android::adbExecCommand(
          deviceID,
          "shell setprop debug.oculus.usepackagedvvl." RENDERDOC_ANDROID_PACKAGE_BASE ".arm64 1");

      rdcstr package = GetRenderDocPackageForABI(abis.back());

      rdcstr folderName = Android::GetFolderName(deviceID);

      // push settings file into our folder
      Android::adbExecCommand(deviceID, "push \"" + FileIO::GetAppFolderFilename("renderdoc.conf") +
                                            "\" /sdcard/Android/" + folderName + package +
                                            "/files/renderdoc.conf");

      // launch the last ABI, as the 64-bit version where possible, or 32-bit version where not.
      // Captures are portable across bitness and in some cases a 64-bit capture can't replay on a
      // 32-bit remote server.
      Android::adbExecCommand(
          deviceID, "shell am start -n " + package + "/.Loader -e renderdoccmd remoteserver");
    });

    // allow the package to start and begin listening before we return
    Threading::Sleep(8000);

    return result;
  }

  rdcstr RemapHostname(const rdcstr &deviceID) override
  {
    // we always connect to localhost
    return "127.0.0.1";
  }

  uint16_t RemapPort(const rdcstr &deviceID, uint16_t srcPort) override
  {
    uint16_t portbase = 0;

    {
      SCOPED_LOCK(lock);
      auto it = devices.find(deviceID);
      if(it != devices.end())
        portbase = it->second.portbase;
    }

    if(portbase == 0)
      return 0;

    if(srcPort == RenderDoc_RemoteServerPort)
      return portbase + RenderDoc_ForwardRemoteServerOffset;
    // we only support a single target control connection on android
    else if(srcPort == RenderDoc_FirstTargetControlPort)
      return portbase + RenderDoc_ForwardTargetControlOffset;

    return 0;
  }

  IRemoteServer *CreateRemoteServer(Network::Socket *sock, const rdcstr &deviceID) override
  {
    uint16_t portbase = 0;

    {
      SCOPED_LOCK(lock);
      auto it = devices.find(deviceID);
      if(it == devices.end())
      {
        SAFE_DELETE(sock);
        return NULL;
      }
      portbase = it->second.portbase;
    }

    return new AndroidRemoteServer(sock, deviceID, portbase);
  }

  int32_t running = 0;
  struct Device
  {
    rdcstr name;
    uint16_t portbase;
    bool active;
  };
  std::map<rdcstr, Device> devices;
  Threading::CriticalSection lock;
  Threading::ThreadHandle thread;
  static AndroidController m_Inst;

  static IDeviceProtocolHandler *Get()
  {
    m_Inst.Start();
    return &m_Inst;
  };
};

void AndroidRemoteServer::ShutdownConnection()
{
  rdcstr deviceID = m_deviceID;
  AndroidController::m_Inst.AsyncInvoke([deviceID]() { Android::ResetCaptureSettings(deviceID); });
  RemoteServer::ShutdownConnection();
}

ExecuteResult AndroidRemoteServer::ExecuteAndInject(const rdcstr &packageAndActivity,
                                                    const rdcstr &, const rdcstr &intentArgs,
                                                    const rdcarray<EnvironmentModification> &env,
                                                    const CaptureOptions &opts)
{
  LazilyStartLogcatThread();

  // we spin up a thread to Ping() every second, since starting a package can block for a long time.
  int32_t done = 0;
  Threading::ThreadHandle pingThread = Threading::CreateThread([&done, this]() {
    Threading::SetCurrentThreadName("Android Ping");

    ResultDetails ok;
    ok.code = ResultCode::Succeeded;
    while(ok.OK() && Atomic::CmpExch32(&done, 0, 0) == 0)
      ok = Ping();
  });

  RDResult result;
  uint32_t ident = RenderDoc_FirstTargetControlPort;

  AndroidController::m_Inst.Invoke([this, &result, &ident, packageAndActivity, intentArgs, opts]() {
    rdcstr packageName = Android::GetPackageName(packageAndActivity);    // Remove leading '/' if any

    // adb shell cmd package resolve-activity -c android.intent.category.LAUNCHER com.jake.cube1
    rdcstr activityName = Android::GetActivityName(packageAndActivity);

    // if the activity name isn't specified, get the default one
    if(activityName.empty() || activityName == "#DefaultActivity")
      activityName = Android::GetDefaultActivityForPackage(m_deviceID, packageName);

    rdcstr processName = Android::GetProcessNameForActivity(m_deviceID, packageName, activityName);

    if(Android_Debug_ProcessLaunch())
    {
      RDCLOG("Launching package '%s' with activity '%s' and process name '%s'", packageName.c_str(),
             activityName.c_str(), processName.c_str());
    }

    uint16_t jdwpPort = Android::GetJdwpPort();

    // remove any previous jdwp port forward on this port
    Android::adbExecCommand(m_deviceID, StringFormat::Fmt("forward --remove tcp:%i", jdwpPort));
    // force stop the package if it was running before
    Android::adbExecCommand(m_deviceID, "shell am force-stop " + processName);
    Android::adbExecCommand(m_deviceID, "shell setprop debug.vulkan.layers :", ".", true);

    bool hookWithJDWP = true;

    rdcstr info;

    rdcstr installedPath = Android::GetPathForPackage(m_deviceID, packageName);

    rdcstr RDCLib = Android::adbExecCommand(m_deviceID, "shell ls " + installedPath +
                                                            "/lib/*/" RENDERDOC_ANDROID_LIBRARY)
                        .strStdout.trimmed();

    if(Android_Debug_ProcessLaunch())
    {
      RDCLOG("Checking for existing library, found '%s'", RDCLib.c_str());
    }
    // some versions of adb/android return the error message on stdout, so try to detect those and
    // clear the output.
    if(RDCLib.size() < installedPath.size() || RDCLib.substr(0, installedPath.size()) != installedPath)
      RDCLib.clear();

    // some versions of adb/android also don't print any error message at all! Look to see if the
    // wildcard glob is still present.
    if(RDCLib.find("/lib/*/" RENDERDOC_ANDROID_LIBRARY) >= 0)
      RDCLib.clear();

    if(RDCLib.empty())
    {
      RDCLOG("No library found in %s/lib/*/" RENDERDOC_ANDROID_LIBRARY
             " for %s - assuming injection is required.",
             installedPath.c_str(), packageName.c_str());
    }
    else
    {
      hookWithJDWP = false;
      RDCLOG("Library found, no injection required: %s", RDCLib.c_str());
    }

    if(RDCLib.empty() && Android::SupportsNativeLayers(m_deviceID))
    {
      RDCLOG("Using Android 10 native GPU layering");

      // if we have Android 10 native layering, don't use JDWP hooking
      hookWithJDWP = false;

      // set up environment variables for the package, and point to ourselves for vulkan and GLES
      // layers
      rdcstr installedABI = Android::DetermineInstalledABI(m_deviceID, packageName);

      Android::ABI abi = Android::ABI::unknown;

      if(installedABI == "null" || installedABI.empty())
      {
        RDCLOG("Can't determine installed ABI, falling back to device preferred ABI");

        // pick the last ABI
        rdcarray<Android::ABI> abis = Android::GetSupportedABIs(m_deviceID);

        if(abis.empty())
          RDCWARN("No ABIs listed as supported");
        else
          abi = abis.back();
      }
      else
      {
        abi = Android::GetABI(installedABI);
      }

      rdcstr layerPackage = GetRenderDocPackageForABI(abi);
      Android::adbExecCommand(m_deviceID, "shell settings put global enable_gpu_debug_layers 1");
      Android::adbExecCommand(m_deviceID, "shell settings put global gpu_debug_app " + packageName);
      Android::adbExecCommand(m_deviceID,
                              "shell settings put global gpu_debug_layer_app " + layerPackage);
      Android::adbExecCommand(
          m_deviceID, "shell settings put global gpu_debug_layers " RENDERDOC_VULKAN_LAYER_NAME);
      Android::adbExecCommand(
          m_deviceID, "shell settings put global gpu_debug_layers_gles " RENDERDOC_ANDROID_LIBRARY);

      // don't ignore the layers by default, only if we encounter an error
      Android::adbExecCommand(m_deviceID, "shell setprop debug.rdoc.IGNORE_LAYERS 0");

      Process::ProcessResult check =
          Android::adbExecCommand(m_deviceID, "shell settings list global");

      // check both since we don't know which one it will come out in
      rdcstr inString = check.strStdout + check.strStderror;

      // remove all whitespace. Our package and layer doesn't contain spaces, and the user's package
      // name can't contain spaces. This makes what we're searching for less subject to change (e.g.
      // if some adb versions print 'setting = value' instead of 'setting=value'
      // This will even work if there are new lines
      rdcstr checkString;
      checkString.reserve(inString.size());
      for(const char &c : inString)
      {
        if(c == ' ' || c == '\t' || c == '\r' || c == '\n')
          continue;

        checkString.push_back(c);
      }

      if(!checkString.contains("enable_gpu_debug_layers=1") ||
         !checkString.contains("gpu_debug_app=" + packageName) ||
         !checkString.contains("gpu_debug_layer_app=" + layerPackage) ||
         !checkString.contains("gpu_debug_layers=" RENDERDOC_VULKAN_LAYER_NAME) ||
         !checkString.contains("gpu_debug_layers_gles=" RENDERDOC_ANDROID_LIBRARY))
      {
        info =
            "Do you have a strange device that requires extra setup?\n"
            "E.g. Xiaomi requires a developer account and \"USB debugging (Security Settings)\"";

        RDCERR("Couldn't verify that debug settings are set:\n%s\n%s", inString.c_str(),
               info.c_str());

        result = RDResult(ResultCode::AndroidLayerConfFailed);
        result.message = info;

        hookWithJDWP = true;

        // need to tell the hooks to ignore the fact that layers are present because they're not
        // working.
        Android::adbExecCommand(m_deviceID, "shell setprop debug.rdoc.IGNORE_LAYERS 1");
      }
    }

    if(hookWithJDWP)
    {
      RDCLOG("Using pre-Android 10 Vulkan layering and JDWP injection");

      // enable the vulkan layer (will only be used by vulkan programs)
      Android::adbExecCommand(m_deviceID,
                              "shell setprop debug.vulkan.layers " RENDERDOC_VULKAN_LAYER_NAME);
    }

    rdcstr folderName = Android::GetFolderName(m_deviceID);

    // if in VR mode, enable frame delimiter markers
    Android::adbExecCommand(m_deviceID, "shell setprop debug.vr.profiler 1");

    // create the data directory we will use for storing, in case the application doesn't
    // NOTE: if processName != packageName, process may not be able to write to this directory
    // unless
    // it also has the WRITE_EXTERNAL_STORAGE permission. Under sdcardfs, only
    // Android/data/<package>
    // has the permissions set correctly, and we don't have a convenient way to get the package name
    // from native code.
    Android::adbExecCommand(m_deviceID, "shell mkdir -p /sdcard/Android/" + folderName + processName);
    Android::adbExecCommand(
        m_deviceID, "shell mkdir -p /sdcard/Android/" + folderName + processName + "/files");
    // set our property with the capture options encoded, to be picked up by the library on the
    // device
    Android::adbExecCommand(m_deviceID,
                            StringFormat::Fmt("shell setprop debug.rdoc.RENDERDOC_CAPOPTS %s",
                                              opts.EncodeAsString().c_str()));

    // try to push our settings file into the appdata folder
    Android::adbExecCommand(m_deviceID, "push \"" + FileIO::GetAppFolderFilename("renderdoc.conf") +
                                            "\" /sdcard/Android/" + folderName + processName +
                                            "/files/renderdoc.conf");

    int pid = 0;

    RDCLOG("Launching package '%s' with activity '%s' and intent args '%s'", packageName.c_str(),
           activityName.c_str(), intentArgs.c_str());

    if(hookWithJDWP)
    {
      RDCLOG("Setting up to launch the application as a debugger to inject.");

      // start the activity in this package with debugging enabled and force-stop after starting
      Android::adbExecCommand(
          m_deviceID, StringFormat::Fmt("shell am start -S -D -n %s/%s %s", packageName.c_str(),
                                        activityName.c_str(), intentArgs.c_str()));
    }
    else
    {
      RDCLOG("Launching APK with no debugger or direct injection.");

      // start the activity in this package with debugging enabled and force-stop after starting
      Android::adbExecCommand(
          m_deviceID, StringFormat::Fmt("shell am start -S -n %s/%s %s", packageName.c_str(),
                                        activityName.c_str(), intentArgs.c_str()));

      // don't connect JDWP
      jdwpPort = 0;
    }

    // adb shell ps | grep $PACKAGE | awk '{print $2}')
    pid = Android::GetCurrentPID(m_deviceID, processName);

    if(pid == 0)
    {
      result = RDResult(ResultCode::InjectionFailed);
      ident = 0;

      RDCERR("Couldn't get PID");

      if(!info.empty())
        result.message =
            "Couldn't locate the launched activity, either it failed to launch or crashed."
            "\n\nAdditional information:\n" +
            info;
      else
        result.message =
            "Couldn't locate the launched activity, either it failed to launch or crashed.";

      return;
    }

    Android::adbForwardPorts(m_portbase, m_deviceID, jdwpPort, pid, false);

    // sleep a little to let the ports initialise
    Threading::Sleep(500);

    if(jdwpPort)
    {
      // use a JDWP connection to inject our libraries
      bool injected = Android::InjectWithJDWP(m_deviceID, jdwpPort);
      if(!injected)
      {
        RDCERR("Failed to inject using JDWP");
        ident = 0;

        // If layer configuration failed first, then report that to the user as it is usually easier
        // to fix
        if(result.code != ResultCode::AndroidLayerConfFailed)
        {
          result = RDResult(ResultCode::JDWPFailure);
          result.message = StringFormat::Fmt(
              "Failed to inject using JDWP when launching '%s' with activity '%s' and intent args "
              "'%s'",
              packageName.c_str(), activityName.c_str(), intentArgs.c_str());
        }
        return;
      }
    }

    result = RDResult(ResultCode::InjectionFailed, "Timeout was reached waiting for app to start.");

    uint32_t elapsed = 0, timeout = 1000 * RDCMAX(5U, Android_MaxConnectTimeout());

    // Some ROMs accept the gpu_debug_* settings writes but silently ignore them - the verification
    // above only proves the settings stuck, not that the GPU drivers honour them (ColorOS is one
    // such ROM). The interceptor then never loads and no target control connection will ever
    // appear. If we launched via native layering and nothing has connected within a short grace
    // period, restart the app under a JDWP debugger and inject the library with Runtime.load()
    // instead - that path doesn't depend on the ROM's layer support at all, only on the app being
    // debuggable.
    const uint32_t nativeLayerGraceMS = 1000 * RDCMIN(10U, RDCMAX(5U, Android_MaxConnectTimeout()));

    // if the original launch already used JDWP injection, there's nothing to fall back to
    bool jdwpFallbackAttempted = (jdwpPort != 0);
    bool wrapInjectionAttempted = false;
    uint32_t wrapAttemptElapsed = 0;

    // restarts the app under a JDWP debugger and injects via Runtime.load(). Returns true if the
    // wait loop should stop.
    auto tryJDWPFallback = [&]() -> bool {
      jdwpFallbackAttempted = true;

      if(!Android::IsDebuggable(m_deviceID, packageName))
      {
        RDCLOG(
            "No connection from native GPU layering and '%s' is not debuggable - can't retry "
            "with JDWP injection.",
            packageName.c_str());
        return false;
      }

      RDCLOG("Restarting '%s' with JDWP injection.", packageName.c_str());

      uint16_t jdwpFallbackPort = Android::GetJdwpPort();

      Android::adbExecCommand(m_deviceID, "shell am force-stop " + processName);

      // start the activity with debugging enabled
      Android::adbExecCommand(
          m_deviceID, StringFormat::Fmt("shell am start -S -D -n %s/%s %s", packageName.c_str(),
                                        activityName.c_str(), intentArgs.c_str()));

      // sleep a little to let the activity start
      Threading::Sleep(500);

      int jdwpPid = Android::GetCurrentPID(m_deviceID, processName);

      if(jdwpPid == 0)
      {
        SET_ERROR_RESULT(result, ResultCode::InjectionFailed,
                         "APK failed to restart for JDWP injection.");
        return true;
      }

      Android::adbForwardPorts(m_portbase, m_deviceID, jdwpFallbackPort, jdwpPid, false);

      // sleep a little to let the ports initialise
      Threading::Sleep(500);

      bool injected = Android::InjectWithJDWP(m_deviceID, jdwpFallbackPort);

      if(!injected)
      {
        result = RDResult(ResultCode::JDWPFailure);
        result.message = StringFormat::Fmt(
            "Failed to inject using JDWP when retrying '%s' with activity '%s'",
            packageName.c_str(), activityName.c_str());
        return true;
      }

      RDCLOG("JDWP injection succeeded, waiting for the target control connection.");
      return false;
    };

    while(elapsed < timeout)
    {
      // Check if the target app has started yet and we can connect to it.
      ITargetControl *control = RENDERDOC_CreateTargetControl(
          AndroidController::m_Inst.GetProtocolName() + "://" + m_deviceID, ident, "testConnection",
          false);
      if(control)
      {
        control->Shutdown();
        result = ResultCode::Succeeded;
        break;
      }

      // check to see if the PID is still there. If it was before and isn't now, the APK has
      // exited
      // without ever opening a connection.
      int curpid = Android::GetCurrentPID(m_deviceID, processName);

      if(curpid == 0)
      {
        SET_ERROR_RESULT(
            result, ResultCode::InjectionFailed,
            "APK has crashed or never opened target control connection before closing.");
        break;
      }

      if(!jdwpFallbackAttempted)
      {
        if(!wrapInjectionAttempted && elapsed >= nativeLayerGraceMS)
        {
          // Phase 2: wrap.sh + LD_PRELOAD. Stage the library and wrapper script into the app's
          // data directory, point wrap.<package> at it and restart the app normally - no debug
          // layers and no debugger involved, the library loads before any graphics driver.
          wrapInjectionAttempted =
              (Android::PrepareWrapInjection(m_deviceID, packageName).code == ResultCode::Succeeded);

          if(wrapInjectionAttempted)
          {
            RDCLOG(
                "No connection from native GPU layering within %u ms - the ROM may be ignoring "
                "the debug layer settings. Restarting '%s' with wrap.sh preload injection.",
                nativeLayerGraceMS, packageName.c_str());

            wrapAttemptElapsed = elapsed;

            Android::adbExecCommand(m_deviceID, "shell am force-stop " + processName);

            Android::adbExecCommand(
                m_deviceID, StringFormat::Fmt("shell am start -S -n %s/%s %s", packageName.c_str(),
                                              activityName.c_str(), intentArgs.c_str()));

            Threading::Sleep(3000);

            // The wrap property has done its job once the zygote has forked the wrapped process;
            // from here on it only betrays the injection - security SDKs (e.g. NetEase ntunisdk)
            // check wrap.<package> and abort when it is set. Remove it before the app's own code
            // and anti-tamper modules initialise (which happens well after the fork).
            Android::adbExecCommand(
                m_deviceID,
                "shell su -c \"resetprop --delete wrap." + packageName + "\"");
          }
          else
          {
            RDCLOG("wrap.sh staging failed, falling back to JDWP injection.");
            if(tryJDWPFallback())
              break;
          }
        }
        else if(wrapInjectionAttempted && elapsed >= wrapAttemptElapsed + nativeLayerGraceMS)
        {
          // wrap injection also never connected - reset the wrap property and use JDWP instead.
          Android::ClearWrapInjection(m_deviceID, packageName);
          wrapInjectionAttempted = false;

          RDCLOG("No connection from wrap.sh preload injection - trying JDWP injection.");
          if(tryJDWPFallback())
            break;
        }
      }

      Threading::Sleep(1000);
      elapsed += 1000;
    }

    // if the connection never appeared, reset the wrap property so the application doesn't get
    // the library preloaded the next time it's launched outside RenderDoc. On success the
    // property is intentionally left in place for the session and cleared by
    // ResetCaptureSettings when the device disconnects.
    if(result.code != ResultCode::Succeeded && wrapInjectionAttempted)
      Android::ClearWrapInjection(m_deviceID, packageName);

    // we leave the setprop in case the application later initialises a vulkan device. It's
    // impossible to tell if it will or not, since many applications will init and present from GLES
    // and then later use vulkan.

    return;
  });

  Atomic::Inc32(&done);

  Threading::JoinThread(pingThread);
  Threading::CloseThread(pingThread);

  ExecuteResult ret = {};

  ret.result = result;
  ret.ident = ident;

  return ret;
}

AndroidController AndroidController::m_Inst;

DeviceProtocolRegistration androidProtocol("adb", &AndroidController::Get);

extern "C" RENDERDOC_API void RENDERDOC_CC RENDERDOC_CheckAndroidPackage(
    const rdcstr &URL, const rdcstr &packageAndActivity, AndroidFlags *flags)
{
  IDeviceProtocolHandler *adb = RenderDoc::Inst().GetDeviceProtocol("adb");

  rdcstr deviceID = adb->GetDeviceID(URL);

  // Reset the flags each time we check
  *flags = AndroidFlags::NoFlags;

  if(Android::IsDebuggable(deviceID, Android::GetPackageName(packageAndActivity)))
  {
    *flags |= AndroidFlags::Debuggable;
  }
  else
  {
    RDCLOG("%s is not debuggable", packageAndActivity.c_str());
  }

  if(Android::HasRootAccess(deviceID))
  {
    RDCLOG("Root access detected");
    *flags |= AndroidFlags::RootAccess;
  }

  return;
}
