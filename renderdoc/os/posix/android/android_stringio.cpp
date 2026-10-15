/******************************************************************************
 * The MIT License (MIT)
 *
 * Copyright (c) 2016-2026 Baldur Karlsson
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

#include <android/log.h>
#include <ctype.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include "common/common.h"
#include "common/formatting.h"
#include "os/os_specific.h"

#define LOGCAT_TAG "renderdoc"

namespace Keyboard
{
void Init()
{
}

bool PlatformHasKeyInput()
{
  return false;
}

void AddInputWindow(WindowingSystem windowSystem, void *wnd)
{
}

void RemoveInputWindow(WindowingSystem windowSystem, void *wnd)
{
}

bool GetKeyState(int key)
{
  return false;
}
}

namespace FileIO
{
// cached copy of our own library path. The hide mechanism re-maps our library as anonymous
// memory (so it no longer appears in /proc/self/maps) after initialisation, so we must resolve
// the path once up-front and return the cached value afterwards - otherwise we'd fall back to
// dladdr and spam warnings on every call.
static rdcstr librenderdoc_cached_path;

rdcstr GetTempRootPath()
{
  // Save captures in the app's private /sdcard directory, which doesnt require
  // WRITE_EXTERNAL_STORAGE permissions. There is no security enforced here,
  // so the replay server can load it as it has READ_EXTERNAL_STORAGE.
  // This is the same as returned by getExternalFilesDir(). It might possibly change in the future.
  rdcstr package;
  GetExecutableFilename(package);

  char platformVersionChar[PROP_VALUE_MAX];
  __system_property_get("ro.build.version.sdk", platformVersionChar);
  int platformVersion = atoi(platformVersionChar);

  if(platformVersion < 30)
    return "/sdcard/Android/data/" + package + "/files";
  else
    return "/sdcard/Android/media/" + package + "/files";
}

rdcstr GetAppFolderFilename(const rdcstr &filename)
{
  return GetTempRootPath() + rdcstr("/") + filename;
}

rdcstr FindFileInPath(const rdcstr &fileName)
{
  return fileName;
}

// For RenderDoc's apk, this returns our package name
// For other APKs, we use it to get the writable temp directory.
struct WrapPropSearch
{
  rdcstr package;
};

static void WrapPropForeach(const prop_info *pi, void *cookie)
{
  WrapPropSearch *search = (WrapPropSearch *)cookie;
  char name[PROP_NAME_MAX];
  char value[PROP_VALUE_MAX];

  if(search->package.empty() && __system_property_read(pi, name, value) > 0 &&
     !strncmp(name, "wrap.", 5) && value[0] != '\0')
  {
    // the wrap property is named wrap.<package> and holds the wrapper script path - the package
    // part of the name is the application package of the process being wrapped
    search->package = name + 5;
  }
}

void GetExecutableFilename(rdcstr &selfName)
{
  int fd = open(StringFormat::Fmt("/proc/%u/cmdline", getpid()).c_str(), O_RDONLY);
  if(fd < 0)
    return;

  char buf[4096];
  ssize_t len = read(fd, buf, sizeof(buf));
  close(fd);
  if(len < 0 || len == sizeof(buf))
  {
    return;
  }
  buf[len] = 0;

  // Strip any process name from cmdline (android:process)
  rdcstr cmdline = buf;
  rdcstr filename = cmdline.substr(0, cmdline.find(":"));

  // When we are injected via a wrap.<package> script the process is re-exec'd through
  // app_process64, so the cmdline no longer starts with the package name - it becomes the
  // app_process64 executable path instead. That breaks the /sdcard/Android/media/<pkg>/files
  // capture path, so recover the package name: the zygote keeps it in the --nice-name argument,
  // and the wrap property that launched us is itself named after the package.
  if(filename.empty() || filename[0] == '/' || filename.find('.') < 0)
  {
    rdcstr recovered;

    // scan the NUL-separated argument list for --nice-name=<package>
    const char *tok = buf;
    while(tok < buf + len)
    {
      if(!strncmp(tok, "--nice-name=", strlen("--nice-name=")))
      {
        recovered = tok + strlen("--nice-name=");
        break;
      }
      tok += strlen(tok) + 1;
    }

    if(recovered.empty())
    {
      WrapPropSearch search;
      __system_property_foreach(&WrapPropForeach, &search);
      recovered = search.package;
    }

    if(!recovered.empty())
    {
      RDCWARN("Recovered package name '%s' (cmdline was '%s')", recovered.c_str(),
              filename.c_str());
      filename = recovered;
    }
  }

  selfName = filename;
}

int LibraryLocator = 42;

void GetLibraryFilename(rdcstr &selfName)
{
  // if we have already resolved the library path, return it. After the hide mechanism runs we
  // are no longer visible in /proc/self/maps, so only the first call (before hiding) does the
  // actual scan below.
  if(!librenderdoc_cached_path.empty())
  {
    selfName = librenderdoc_cached_path;
    return;
  }

  // this is a hack, but the only reliable way to find the absolute path to the library.
  // dladdr would be fine but it returns the wrong result for symbols in the library

  rdcstr librenderdoc_path;

  FILE *f = fopen("/proc/self/maps", FileIO::ReadText);

  if(f)
  {
    // read the whole thing in one go. There's no need to try and be tight with
    // this allocation, so just make sure we can read everything.
    char *map_string = new char[1024 * 1024];
    memset(map_string, 0, 1024 * 1024);

    ::fread(map_string, 1, 1024 * 1024, f);

    ::fclose(f);

    char *c = strstr(map_string, "/" RENDERDOC_ANDROID_LIBRARY);

    if(c)
    {
      // walk backwards until we hit the start of the line
      while(c > map_string)
      {
        c--;

        if(c[0] == '\n')
        {
          c++;
          break;
        }
      }

      // walk forwards across the address range (00400000-0040c000)
      while(isalnum(c[0]) || c[0] == '-')
        c++;

      // whitespace
      while(c[0] == ' ')
        c++;

      // permissions (r-xp)
      while(isalpha(c[0]) || c[0] == '-')
        c++;

      // whitespace
      while(c[0] == ' ')
        c++;

      // offset (0000b000)
      while(isalnum(c[0]) || c[0] == '-')
        c++;

      // whitespace
      while(c[0] == ' ')
        c++;

      // dev
      while(isalnum(c[0]) || c[0] == ':')
        c++;

      // whitespace
      while(c[0] == ' ')
        c++;

      // inode
      while(isdigit(c[0]))
        c++;

      // whitespace
      while(c[0] == ' ')
        c++;

      // FINALLY we are at the start of the actual path
      char *end = strchr(c, '\n');

      if(end)
        librenderdoc_path = rdcstr(c, end - c);
    }

    delete[] map_string;
  }

  if(librenderdoc_path.empty())
  {
    RDCWARN("Couldn't get " RENDERDOC_ANDROID_LIBRARY
            " path from /proc/self/maps, falling back to dladdr");

    Dl_info info;
    if(dladdr(&LibraryLocator, &info))
      librenderdoc_path = info.dli_fname;
  }

  librenderdoc_cached_path = librenderdoc_path;

  selfName = librenderdoc_path;
}
};

namespace StringFormat
{
rdcstr Wide2UTF8(const rdcwstr &s)
{
  RDCFATAL("Converting wide strings to UTF-8 is not supported on Android!");
  return "";
}

rdcwstr UTF82Wide(const rdcstr &s)
{
  RDCFATAL("Converting UTF-8 to wide strings is not supported on Android!");
  return L"";
}

void Shutdown()
{
}
};

namespace OSUtility
{
void WriteOutput(int channel, const char *str)
{
  static uint32_t seq = 0;
  seq++;
  if(channel == OSUtility::Output_StdOut)
    fprintf(stdout, "%s", str);
  else if(channel == OSUtility::Output_StdErr)
    fprintf(stderr, "%s", str);
  else if(channel == OSUtility::Output_DebugMon)
    __android_log_print(ANDROID_LOG_INFO, LOGCAT_TAG, "@%08x%08x@ %s",
                        uint32_t(Timing::GetUTCTime()), seq, str);
}

uint64_t GetMachineIdent()
{
  uint64_t ret = MachineIdent_Android;

#if defined(_M_ARM) || defined(__arm__) || defined(__aarch64__)
  ret |= MachineIdent_Arch_ARM;
#else
  ret |= MachineIdent_Arch_x86;
#endif

#if ENABLED(RDOC_X64)
  ret |= MachineIdent_64bit;
#else
  ret |= MachineIdent_32bit;
#endif

  return ret;
}
};
