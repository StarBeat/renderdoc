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

#include "common/common.h"
#include "common/threading.h"
#include "hooks/hooks.h"
#include "plthook/plthook.h"

#define VK_NO_PROTOTYPES
#include <vulkan/vulkan.h>

#include <android/dlext.h>
#include <dlfcn.h>
#include <errno.h>
#include <jni.h>
#include <link.h>
#include <stddef.h>
#include <sys/mman.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include <algorithm>
#include <map>
#include <set>

// uncomment the following to print (very verbose) debugging prints for the android PLT hooking
// #define HOOK_DEBUG_PRINT(...) RDCLOG(__VA_ARGS__)

#if !defined(HOOK_DEBUG_PRINT)
#define HOOK_DEBUG_PRINT(...) \
  do                          \
  {                           \
  } while(0)
#endif

// from plthook_elf.c
#if defined __x86_64__ || defined __x86_64
#define R_JUMP_SLOT R_X86_64_JUMP_SLOT
#define R_GLOB_DAT R_X86_64_GLOB_DAT
#define Elf_Rel ElfW(Rela)
#define ELF_R_TYPE ELF64_R_TYPE
#define ELF_R_SYM ELF64_R_SYM
#elif defined __i386__ || defined __i386
#define R_JUMP_SLOT R_386_JMP_SLOT
#define R_GLOB_DAT R_386_GLOB_DAT
#define Elf_Rel ElfW(Rel)
#define ELF_R_TYPE ELF32_R_TYPE
#define ELF_R_SYM ELF32_R_SYM
#elif defined __arm__ || defined __arm
#define R_JUMP_SLOT R_ARM_JUMP_SLOT
#define R_GLOB_DAT R_ARM_GLOB_DAT
#define Elf_Rel ElfW(Rel)
#define ELF_R_TYPE ELF32_R_TYPE
#define ELF_R_SYM ELF32_R_SYM
#elif defined __aarch64__ || defined __aarch64 /* ARM64 */
#define R_JUMP_SLOT R_AARCH64_JUMP_SLOT
#define R_GLOB_DAT R_AARCH64_GLOB_DAT
#define Elf_Rel ElfW(Rela)
#define ELF_R_TYPE ELF64_R_TYPE
#define ELF_R_SYM ELF64_R_SYM
#else
#error unsupported OS
#endif

class HookingInfo
{
public:
  void AddFunctionHook(const FunctionHook &hook)
  {
    SCOPED_LOCK(lock);
    funchooks.push_back(hook);

    // add to map to speed-up lookup in GetFunctionHook
    funchook_map[hook.function] = hook;
  }

  void AddLibHook(const rdcstr &name)
  {
    SCOPED_LOCK(lock);
    if(!libhooks.contains(name))
      libhooks.push_back(name);
  }

  void AddHookCallback(const rdcstr &name, FunctionLoadCallback callback)
  {
    SCOPED_LOCK(lock);
    hookcallbacks[name].push_back(callback);
  }

  rdcarray<FunctionHook> GetFunctionHooks()
  {
    SCOPED_LOCK(lock);
    return funchooks;
  }

  void ClearHooks()
  {
    SCOPED_LOCK(lock);
    libhooks.clear();
    funchooks.clear();
    funchook_map.clear();
  }

  rdcarray<rdcstr> GetLibHooks()
  {
    SCOPED_LOCK(lock);
    return libhooks;
  }

  std::map<rdcstr, rdcarray<FunctionLoadCallback>> GetHookCallbacks()
  {
    SCOPED_LOCK(lock);
    return hookcallbacks;
  }

  FunctionHook GetFunctionHook(const rdcstr &name)
  {
    SCOPED_LOCK(lock);
    return funchook_map[name];
  }

  bool IsLibHook(const rdcstr &path)
  {
    SCOPED_LOCK(lock);
    for(const rdcstr &filename : libhooks)
    {
      if(path.contains(filename))
      {
        HOOK_DEBUG_PRINT("Intercepting and returning ourselves for %s (matches %s)", path.c_str(),
                         filename.c_str());
        return true;
      }
    }

    return false;
  }

  bool IsLibHook(void *handle)
  {
    SCOPED_LOCK(lock);
    for(const rdcstr &lib : libhooks)
    {
      void *libHandle = dlopen(lib.c_str(), RTLD_NOLOAD);
      HOOK_DEBUG_PRINT("%s is %p", lib.c_str(), libHandle);
      if(libHandle == handle)
        return true;
    }

    return false;
  }

  bool IsHooked(void *handle)
  {
    SCOPED_LOCK(lock);
    bool ret = hooked_handle_already.find(handle) != hooked_handle_already.end();
    return ret;
  }

  bool IsHooked(const rdcstr &soname)
  {
    SCOPED_LOCK(lock);
    if(hooked_soname_already.find(soname) != hooked_soname_already.end())
      return true;

    // above will be absolute path, allow substring matches
    for(const rdcstr &fn : hooked_soname_already)
      if(soname.contains(fn))
        return true;

    return false;
  }

  void SetHooked(void *handle)
  {
    SCOPED_LOCK(lock);
    hooked_handle_already.insert(handle);
  }

  void SetHooked(const rdcstr &soname)
  {
    SCOPED_LOCK(lock);
    hooked_soname_already.insert(soname);
  }

private:
  std::set<rdcstr> hooked_soname_already;
  std::set<void *> hooked_handle_already;

  rdcarray<FunctionHook> funchooks;
  std::map<rdcstr, FunctionHook> funchook_map;
  rdcarray<rdcstr> libhooks;

  std::map<rdcstr, rdcarray<FunctionLoadCallback>> hookcallbacks;

  Threading::CriticalSection lock;
};

HookingInfo &GetHookInfo()
{
  static HookingInfo hookinfo;
  return hookinfo;
}

void *intercept_dlopen(const char *filename, int flag)
{
  if(filename)
  {
    // if this is a library we're hooking, or a request for our own library in any form, return our
    // own library.
    // We need to intercept requests for our own library, because the android loader makes the
    // completely ridiculous decision to load multiple copies of the same library into a process if
    // it's dlopen'd with different paths. This obviously breaks with our hook install.
    if(strstr(filename, RENDERDOC_ANDROID_LIBRARY) || GetHookInfo().IsLibHook(rdcstr(filename)))
    {
      HOOK_DEBUG_PRINT("Intercepting dlopen for %s", filename);
      return dlopen(RENDERDOC_ANDROID_LIBRARY, flag);
    }
  }

  return NULL;
}

// defined further down, next to the stealth filters: records the real vulkan loader entry point
// whenever we interpose on one (see the comment on the definition for why this is needed).
static void RememberRealVulkanEntry(const char *name, void *func);

// we need this on both paths since interceptor-lib is unable to hook dlopen in libvulkan.so
static int dl_iterate_callback(struct dl_phdr_info *info, size_t size, void *data)
{
  if(info->dlpi_name == NULL)
  {
    HOOK_DEBUG_PRINT("Skipping NULL entry!");
    return 0;
  }
  rdcstr soname = info->dlpi_name;

  if(GetHookInfo().IsHooked(soname))
    return 0;

  HOOK_DEBUG_PRINT("Hooking %s", soname.c_str());
  GetHookInfo().SetHooked(soname);

  for(int ph = 0; ph < info->dlpi_phnum; ph++)
  {
    if(info->dlpi_phdr[ph].p_type != PT_DYNAMIC)
      continue;

    ElfW(Dyn) *dynamic = (ElfW(Dyn) *)(info->dlpi_addr + info->dlpi_phdr[ph].p_vaddr);

    ElfW(Sym) *dynsym = NULL;
    const char *strtab = NULL;
    size_t strtabcount = 0;
    Elf_Rel *pltbase = NULL;
    ElfW(Sword) pltcount = 0;
    Elf_Rel *relbase = NULL;
    size_t relcount = 0;

    while(dynamic->d_tag != DT_NULL)
    {
      if(dynamic->d_tag == DT_SYMTAB)
        dynsym = (ElfW(Sym) *)(info->dlpi_addr + dynamic->d_un.d_ptr);
      else if(dynamic->d_tag == DT_STRTAB)
        strtab = (const char *)(info->dlpi_addr + dynamic->d_un.d_ptr);
      else if(dynamic->d_tag == DT_STRSZ)
        strtabcount = dynamic->d_un.d_val;
      else if(dynamic->d_tag == DT_JMPREL)
        pltbase = (Elf_Rel *)(info->dlpi_addr + dynamic->d_un.d_ptr);
      else if(dynamic->d_tag == DT_PLTRELSZ)
        pltcount = dynamic->d_un.d_val / sizeof(Elf_Rel);
      else if(dynamic->d_tag == DT_RELA || dynamic->d_tag == DT_REL)
        relbase = (Elf_Rel *)(info->dlpi_addr + dynamic->d_un.d_ptr);
      else if(dynamic->d_tag == DT_RELASZ || dynamic->d_tag == DT_RELSZ)
        relcount = dynamic->d_un.d_val / sizeof(Elf_Rel);

      /*
      if(dynamic->d_tag == DT_NEEDED)
        HOOK_DEBUG_PRINT("NEEDED [%i, %s]", dynamic->d_un.d_val, strtab + dynamic->d_un.d_val);
        */

      dynamic++;
    }

    if(!dynsym || !strtab || !pltbase || pltcount == 0 || strtabcount == 0)
    {
      RDCWARN("Missing required section to hook %s", info->dlpi_name);
      continue;
    }

    void **relro_base = NULL;
    void **relro_end = NULL;
    bool relro_failed = false;

    FILE *f = FileIO::fopen(info->dlpi_name, FileIO::ReadText);

    // read the file on disk to get the .relro section
    if(f)
    {
      ElfW(Ehdr) ehdr;
      size_t read = FileIO::fread(&ehdr, sizeof(ehdr), 1, f);

      if(read == 1 && ehdr.e_ident[0] == ELFMAG0 && ehdr.e_ident[1] == 'E' &&
         ehdr.e_ident[2] == 'L' && ehdr.e_ident[3] == 'F')
      {
        FileIO::fseek64(f, ehdr.e_phoff, SEEK_SET);
        for(ElfW(Half) idx = 0; idx < ehdr.e_phnum; idx++)
        {
          ElfW(Phdr) phdr;
          read = FileIO::fread(&phdr, sizeof(phdr), 1, f);
          if(read != 1)
          {
            RDCWARN("Failed reading section");
            break;
          }

          if(phdr.p_type == PT_GNU_RELRO)
          {
            relro_base = (void **)(info->dlpi_addr + phdr.p_vaddr);
            relro_end = (void **)(info->dlpi_addr + phdr.p_vaddr + phdr.p_memsz);
          }
        }
      }
      else
      {
        RDCWARN("Didn't get valid ELF header");
      }

      FileIO::fclose(f);
    }
    else
    {
      RDCWARN("Couldn't open '%s' to look for relro!", info->dlpi_name);
      relro_failed = true;
    }

    if(relro_base)
      HOOK_DEBUG_PRINT("Got relro %p -> %p", relro_base, relro_end);
    HOOK_DEBUG_PRINT("Got %i PLT entries", pltcount);

    int pagesize = sysconf(_SC_PAGE_SIZE);

    for(ElfW(Sword) i = 0; i < pltcount; i++)
    {
      Elf_Rel *plt = pltbase + i;
      if(ELF_R_TYPE(plt->r_info) != R_JUMP_SLOT)
      {
        HOOK_DEBUG_PRINT("[%i]: Mismatched type %i vs %i", i, ELF_R_TYPE(plt->r_info), R_JUMP_SLOT);
        continue;
      }

      size_t idx = ELF_R_SYM(plt->r_info);
      size_t name = dynsym[idx].st_name;
      if(name + 1 > strtabcount)
      {
        HOOK_DEBUG_PRINT("[%i] name out of boundstoo big section header string table index: %zu", i,
                         name);
        continue;
      }

      const char *importname = strtab + name;
      void **import = (void **)(info->dlpi_addr + plt->r_offset);

      HOOK_DEBUG_PRINT("[%i] %s at %p (ptr to %p)", i, importname, import, *import);

      const FunctionHook repl = GetHookInfo().GetFunctionHook(importname);
      if(repl.hook)
      {
        HOOK_DEBUG_PRINT("replacing %s!", importname);

        uintptr_t pagebase = 0;

        if(relro_failed || (relro_base <= import && import <= relro_end))
        {
          if(relro_failed)
            HOOK_DEBUG_PRINT("Couldn't get relro sections - mapping read/write");
          else
            HOOK_DEBUG_PRINT("In relro range - %p <= %p <= %p", relro_base, import, relro_end);
          pagebase = uintptr_t(import) & ~(pagesize - 1);

          int ret = mprotect((void *)pagebase, pagesize, PROT_READ | PROT_WRITE);
          if(ret != 0)
          {
            RDCERR("Couldn't read/write the page: %d %d", ret, errno);
            return 0;
          }

          HOOK_DEBUG_PRINT("Marked page read/write");
        }
        else
        {
          HOOK_DEBUG_PRINT("Not in relro! - %p vs %p vs %p", relro_base, import, relro_end);
        }

        // note we don't save the orig function here, since we want to apply our library priorities
        // and we don't know what order these headers will be iterated in. See EndHookRegistration
        // for where we iterate and fetch all the function pointers we want.
        //
        // the only exception is the vulkan loader entry points we filter for stealth reasons: for
        // those we keep the real pointer (dladdr-guarded, see RememberRealVulkanEntry) so the
        // filter can always forward, even when the loader is not in the global symbol scope.
        RememberRealVulkanEntry(importname, *import);
        *import = repl.hook;

        if(pagebase)
        {
          if(relro_failed)
          {
            HOOK_DEBUG_PRINT(
                "Couldn't find relro sections - being conservative and leaving read-write");
          }
          else
          {
            HOOK_DEBUG_PRINT("Moving back to read-only");
            mprotect((void *)pagebase, pagesize, PROT_READ);
          }
        }

        HOOK_DEBUG_PRINT("[%i*] %s at %p (ptr to %p)", i, importname, import, *import);
      }
    }

    // GLOB_DAT relocations: imports that have no PLT entry (the importing code took the
    // symbol's address, or the linker coalesced the call) are resolved straight into the GOT.
    // Patch those too, otherwise an app that links against the loader and stores the
    // enumeration entry point's address would bypass the filter.
    for(size_t i = 0; i < relcount; i++)
    {
      Elf_Rel *rel = relbase + i;
      if(ELF_R_TYPE(rel->r_info) != R_GLOB_DAT)
        continue;

      size_t idx = ELF_R_SYM(rel->r_info);
      size_t name = dynsym[idx].st_name;
      if(name + 1 > strtabcount)
        continue;

      const char *importname = strtab + name;
      void **import = (void **)(info->dlpi_addr + rel->r_offset);

      const FunctionHook repl = GetHookInfo().GetFunctionHook(importname);
      if(repl.hook)
      {
        HOOK_DEBUG_PRINT("replacing GLOB_DAT %s!", importname);

        uintptr_t pagebase = 0;

        if(relro_failed || (relro_base <= import && import <= relro_end))
        {
          pagebase = uintptr_t(import) & ~(pagesize - 1);

          int ret = mprotect((void *)pagebase, pagesize, PROT_READ | PROT_WRITE);
          if(ret != 0)
          {
            RDCERR("Couldn't read/write the page: %d %d", ret, errno);
            return 0;
          }
        }

        // see RememberRealVulkanEntry: a GOT slot always holds an already-resolved address, so
        // this is a second reliable source for the real loader entry point.
        RememberRealVulkanEntry(importname, *import);
        *import = repl.hook;

        if(pagebase && !relro_failed)
          mprotect((void *)pagebase, pagesize, PROT_READ);
      }
    }
  }

  return 0;
}

// android has a special dlopen that passes the caller address in.
typedef void *(*pfn__loader_dlopen)(const char *filename, int flags, const void *caller_addr);

typedef void *(*pfnandroid_dlopen_ext)(const char *__filename, int __flags,
                                       const android_dlextinfo *__info);

pfnandroid_dlopen_ext real_android_dlopen_ext = NULL;

pfn__loader_dlopen loader_dlopen = NULL;
uint64_t suppressTLS = 0;

void process_dlopen(const char *filename, int flag)
{
  if(filename && !GetHookInfo().IsHooked(rdcstr(filename)))
  {
    HOOK_DEBUG_PRINT("iterating after %s", filename);
    dl_iterate_phdr(dl_iterate_callback, NULL);
    GetHookInfo().SetHooked(filename);
  }
  else
  {
    HOOK_DEBUG_PRINT("Ignoring");
  }
}

// stealth: real entry points of the vulkan loader, resolved lazily (see RegisterStealthHooks
// below for why there is no dlopen here).
static PFN_vkEnumerateInstanceLayerProperties Real_vkEnumerateInstanceLayerProperties = NULL;
static PFN_vkGetInstanceProcAddr Real_vkGetInstanceProcAddr = NULL;
static PFN_vkCreateInstance Real_vkCreateInstance = NULL;
static PFN_vkCreateDevice Real_vkCreateDevice = NULL;
static PFN_vkGetDeviceProcAddr Real_vkGetDeviceProcAddr = NULL;
static void RegisterStealthHooks();

// capture layer entry points exported by vk_layer.cpp for the no-layer (PLT) capture path. The
// filters below call these to drive the same wrapping code the loader's layer chain normally
// drives.
extern "C" int RDCAndroidVKCaptureMode(void);
extern "C" void RDCAndroidSetVKPLTMode(int active);
extern "C" VkResult RDCAndroidPLTCreateInstance(const VkInstanceCreateInfo *pCreateInfo,
                                                const VkAllocationCallbacks *pAllocator,
                                                VkInstance *pInstance);
extern "C" VkResult RDCAndroidPLTCreateDevice(VkPhysicalDevice physicalDevice,
                                              const VkDeviceCreateInfo *pCreateInfo,
                                              const VkAllocationCallbacks *pAllocator,
                                              VkDevice *pDevice);
extern "C" PFN_vkVoidFunction RDCAndroidLayerGetInstanceProcAddr(VkInstance instance,
                                                                 const char *pName);
extern "C" PFN_vkVoidFunction RDCAndroidLayerGetDeviceProcAddr(VkDevice device, const char *pName);
extern "C" VkInstance RDCAndroidInstanceRealHandle(VkInstance instance);
extern "C" VkDevice RDCAndroidDeviceRealHandle(VkDevice device);

// loader chain link structs - local mirrors of official/vk_layer.h (must match the loader ABI).
// In the no-layer mode there is no loader layer chain to provide them, so the create filters
// synthesize the link info the wrapping code expects before calling into vk_layer.cpp.
typedef struct VkLayerInstanceLink_ {
  struct VkLayerInstanceLink_ *pNext;
  PFN_vkGetInstanceProcAddr pfnNextGetInstanceProcAddr;
  PFN_vkVoidFunction(VKAPI_PTR *pfnNextGetPhysicalDeviceProcAddr)(VkInstance instance,
                                                                  const char *pName);
} VkLayerInstanceLink;

typedef struct VkLayerDeviceLink_ {
  struct VkLayerDeviceLink_ *pNext;
  PFN_vkGetInstanceProcAddr pfnNextGetInstanceProcAddr;
  PFN_vkGetDeviceProcAddr pfnNextGetDeviceProcAddr;
} VkLayerDeviceLink;

typedef enum VkLayerFunction_ {
  VK_LAYER_LINK_INFO = 0,
} VkLayerFunction;

typedef struct VkLayerInstanceCreateInfo_ {
  VkStructureType sType;    // VK_STRUCTURE_TYPE_LOADER_INSTANCE_CREATE_INFO
  const void *pNext;
  VkLayerFunction function;
  union {
    VkLayerInstanceLink *pLayerInfo;
  } u;
} VkLayerInstanceCreateInfo;

typedef struct VkLayerDeviceCreateInfo_ {
  VkStructureType sType;    // VK_STRUCTURE_TYPE_LOADER_DEVICE_CREATE_INFO
  const void *pNext;
  VkLayerFunction function;
  union {
    VkLayerDeviceLink *pLayerInfo;
  } u;
} VkLayerDeviceCreateInfo;

// The host activates the loader's layer path via system properties (and the gpu_debug_*
// settings, which can't be read from inside the app process). If any of the properties is set,
// we must stay in layer mode even before negotiation with our own layer has happened
// (negotiation occurs when the loader loads us during the first instance creation, which is
// after the app has already made queries through these filters).
static bool AndroidVKLayerSettingsActive()
{
  char value[PROP_VALUE_MAX];

  // the host sets this when activating the loader's layer path
  if(__system_property_get("debug.vulkan.layers", value) > 0 && value[0] != '\0' &&
     strcmp(value, ":") != 0)
    return true;

  // some loaders read this one instead
  if(__system_property_get("debug.vulkan.gpu_debug_layers", value) > 0 && value[0] != '\0')
    return true;

  return false;
}

// true while the loader is activating us as a layer (RDCAndroidVKCaptureMode() == 0) - in that
// case the create filters must forward untouched so the loader inserts its own chain. When the
// loader never negotiates with us and the debug-layer settings are off, the PLT path activates
// the no-layer capture (mode 1).
static bool AndroidVKPLTMode()
{
  if(RDCAndroidVKCaptureMode() < 0)
  {
    if(!AndroidVKLayerSettingsActive())
      RDCAndroidSetVKPLTMode(1);
  }
  return RDCAndroidVKCaptureMode() > 0;
}

static void EnsureRealVulkanEntries()
{
  if(!Real_vkGetInstanceProcAddr)
    Real_vkGetInstanceProcAddr = (PFN_vkGetInstanceProcAddr)dlsym(RTLD_DEFAULT, "vkGetInstanceProcAddr");
  if(!Real_vkCreateInstance)
    Real_vkCreateInstance = (PFN_vkCreateInstance)dlsym(RTLD_DEFAULT, "vkCreateInstance");
  if(!Real_vkCreateDevice)
    Real_vkCreateDevice = (PFN_vkCreateDevice)dlsym(RTLD_DEFAULT, "vkCreateDevice");
  if(!Real_vkGetDeviceProcAddr)
    Real_vkGetDeviceProcAddr = (PFN_vkGetDeviceProcAddr)dlsym(RTLD_DEFAULT, "vkGetDeviceProcAddr");

  // if the loader was loaded RTLD_LOCAL its symbols are not in the global scope - resolve
  // through its handle instead. By this point the app has already made vulkan calls, so the
  // loader is definitely loaded and this RTLD_NOLOAD dlopen is just a handle lookup.
  if(!Real_vkGetInstanceProcAddr || !Real_vkCreateInstance || !Real_vkCreateDevice ||
     !Real_vkGetDeviceProcAddr)
  {
    void *vulkanHandle = dlopen("libvulkan.so", RTLD_NOLOAD | RTLD_NOW);
    if(vulkanHandle)
    {
      if(!Real_vkGetInstanceProcAddr)
        Real_vkGetInstanceProcAddr =
            (PFN_vkGetInstanceProcAddr)dlsym(vulkanHandle, "vkGetInstanceProcAddr");
      if(!Real_vkCreateInstance)
        Real_vkCreateInstance = (PFN_vkCreateInstance)dlsym(vulkanHandle, "vkCreateInstance");
      if(!Real_vkCreateDevice)
        Real_vkCreateDevice = (PFN_vkCreateDevice)dlsym(vulkanHandle, "vkCreateDevice");
      if(!Real_vkGetDeviceProcAddr)
        Real_vkGetDeviceProcAddr =
            (PFN_vkGetDeviceProcAddr)dlsym(vulkanHandle, "vkGetDeviceProcAddr");
    }
  }

  if(!Real_vkGetInstanceProcAddr || !Real_vkCreateInstance || !Real_vkCreateDevice ||
     !Real_vkGetDeviceProcAddr)
    RDCERR("Couldn't resolve the real vulkan loader entry points!");
}

// stealth: the filters below have to forward to the *real* loader entry points. Resolving them
// with dlsym(RTLD_DEFAULT, ...) alone is not reliable: applications very commonly
// dlopen("libvulkan.so") without RTLD_GLOBAL (that is bionic's default), in which case the
// loader's symbols are not in the global scope at all and the lookup fails. A filter that then
// returns NULL makes engines such as UE4 report "No Vulkan entry points found!" and silently
// fall back to OpenGL ES.
//
// Every time we interpose on one of these symbols we already hold its real address - the dlsym
// result the app would have got, or the value the linker resolved into a GOT slot - so record it
// here. dladdr() guards the capture: a PLT stub (which would jump through the slot we are about
// to overwrite and recurse) or one of our own functions is never recorded.
static void RememberRealVulkanEntry(const char *name, void *func)
{
  if(name == NULL || func == NULL)
    return;

  const bool isGIPA = (strcmp(name, "vkGetInstanceProcAddr") == 0);
  const bool isEnumLayer = (strcmp(name, "vkEnumerateInstanceLayerProperties") == 0);
  const bool isCreateInstance = (strcmp(name, "vkCreateInstance") == 0);
  const bool isCreateDevice = (strcmp(name, "vkCreateDevice") == 0);
  const bool isGDPA = (strcmp(name, "vkGetDeviceProcAddr") == 0);

  if(!isGIPA && !isEnumLayer && !isCreateInstance && !isCreateDevice && !isGDPA)
    return;

  Dl_info info = {};
  if(dladdr(func, &info) == 0 || info.dli_fname == NULL ||
     strstr(info.dli_fname, "libvulkan") == NULL)
    return;

  if(isGIPA && Real_vkGetInstanceProcAddr == NULL)
  {
    Real_vkGetInstanceProcAddr = (PFN_vkGetInstanceProcAddr)func;
    RDCLOG("Captured real vkGetInstanceProcAddr %p from %s", func, info.dli_fname);
  }
  else if(isEnumLayer && Real_vkEnumerateInstanceLayerProperties == NULL)
  {
    Real_vkEnumerateInstanceLayerProperties = (PFN_vkEnumerateInstanceLayerProperties)func;
    RDCLOG("Captured real vkEnumerateInstanceLayerProperties %p from %s", func, info.dli_fname);
  }
  else if(isCreateInstance && Real_vkCreateInstance == NULL)
  {
    Real_vkCreateInstance = (PFN_vkCreateInstance)func;
    RDCLOG("Captured real vkCreateInstance %p from %s", func, info.dli_fname);
  }
  else if(isCreateDevice && Real_vkCreateDevice == NULL)
  {
    Real_vkCreateDevice = (PFN_vkCreateDevice)func;
    RDCLOG("Captured real vkCreateDevice %p from %s", func, info.dli_fname);
  }
  else if(isGDPA && Real_vkGetDeviceProcAddr == NULL)
  {
    Real_vkGetDeviceProcAddr = (PFN_vkGetDeviceProcAddr)func;
    RDCLOG("Captured real vkGetDeviceProcAddr %p from %s", func, info.dli_fname);
  }
}

extern "C" __attribute__((visibility("default"))) void *hooked_dlopen(const char *filename, int flag)
{
  // get caller address immediately.
  const void *caller_addr = __builtin_return_address(0);

  HOOK_DEBUG_PRINT("hooked_dlopen for %s | %d", filename, flag);
  void *ret = intercept_dlopen(filename, flag);

  // if we intercepted, return immediately
  if(ret)
    return ret;

  ret = loader_dlopen(filename, flag, caller_addr);
  HOOK_DEBUG_PRINT("Got %p", ret);

  if(filename && ret)
  {
    // the vulkan loader wasn't loaded when our hooks were registered - if it is being loaded
    // now, register the enumeration-filtering hooks before we patch the new library's PLT.
    if(strstr(filename, "libvulkan") && !Real_vkGetInstanceProcAddr)
      RegisterStealthHooks();

    process_dlopen(filename, flag);
  }

  return ret;
}

extern "C" __attribute__((visibility("default"))) void *hooked_android_dlopen_ext(
    const char *__filename, int __flags, const android_dlextinfo *__info)
{
  HOOK_DEBUG_PRINT("hooked_android_dlopen_ext for %s | %d", __filename, __flags);

  void *ret = intercept_dlopen(__filename, __flags);

  // if we intercepted, return immediately
  if(ret)
    return ret;

  // otherwise return the 'real' result.
  if(real_android_dlopen_ext == NULL)
    ret = real_android_dlopen_ext(__filename, __flags, __info);
  else
    ret = android_dlopen_ext(__filename, __flags, __info);
  HOOK_DEBUG_PRINT("Got %p", ret);

  if(__filename && ret)
  {
    if(strstr(__filename, "libvulkan") && !Real_vkGetInstanceProcAddr)
      RegisterStealthHooks();

    process_dlopen(__filename, __flags);
  }

  return ret;
}

bool hooks_suppressed();

// dlvsym exists in bionic at runtime but is only declared in the NDK headers at API levels
// higher than our minimum target - declare it ourselves so we can interpose on it
extern "C" void *dlvsym(void *handle, const char *symbol, const char *version);

extern "C" __attribute__((visibility("default"))) void *hooked_dlvsym(void *handle,
                                                                      const char *symbol,
                                                                      const char *version);

extern "C" __attribute__((visibility("default"))) void *hooked_dlsym(void *handle, const char *symbol)
{
  if(handle == NULL || symbol == NULL || hooks_suppressed())
    return dlsym(handle, symbol);

  const FunctionHook repl = GetHookInfo().GetFunctionHook(symbol);

  if(repl.hook == NULL)
    return dlsym(handle, symbol);

  if(!GetHookInfo().IsHooked(handle))
  {
    dl_iterate_phdr(dl_iterate_callback, NULL);
    GetHookInfo().SetHooked(handle);
  }

  HOOK_DEBUG_PRINT("Got dlsym for %s which we want in %p...", symbol, handle);

  if(GetHookInfo().IsLibHook(handle))
  {
    HOOK_DEBUG_PRINT("identified dlsym(%s) we want to interpose! returning %p", symbol, repl.hook);
    return repl.hook;
  }

  void *ret = dlsym(handle, symbol);
  Dl_info info = {};
  dladdr(ret, &info);
  HOOK_DEBUG_PRINT("real ret is %p in %s", ret, info.dli_fname);

  // if the app asks for the versioned lookup itself, give it our interposed version so the
  // stealth enumeration filter can't be bypassed through it either
  if(!strcmp(symbol, "dlvsym"))
    return (void *)&hooked_dlvsym;

  // stealth/no-layer capture: if the app resolves the vulkan loader's entry points via dlsym
  // (bypassing the PLT hooks), give it the filtered versions. The create/device-proc filters
  // forward untouched in layer mode and drive the no-layer capture in PLT mode.
  if(info.dli_fname && strstr(info.dli_fname, "libvulkan") &&
     (!strcmp(symbol, "vkEnumerateInstanceLayerProperties") ||
      !strcmp(symbol, "vkGetInstanceProcAddr") || !strcmp(symbol, "vkCreateInstance") ||
      !strcmp(symbol, "vkCreateDevice") || !strcmp(symbol, "vkGetDeviceProcAddr")))
  {
    HOOK_DEBUG_PRINT("returning filtered %s for dlsym in %s", symbol, info.dli_fname);
    // remember the real entry point we are standing in front of - this is the resolution the
    // application asked for and it is always valid, unlike a later RTLD_DEFAULT lookup
    RememberRealVulkanEntry(symbol, ret);
    return repl.hook;
  }

  return ret;
}

extern "C" __attribute__((visibility("default"))) void *hooked_dlvsym(void *handle,
                                                                      const char *symbol,
                                                                      const char *version)
{
  // dlvsym was only added to bionic in API 24 while we link against API 21, so resolve it at
  // runtime. dlsym(RTLD_DEFAULT, ...) here passes straight through hooked_dlsym (RTLD_DEFAULT is
  // NULL on android), so this gets the real libc implementation.
  static void *(*real_dlvsym)(void *, const char *, const char *) = NULL;

  if(real_dlvsym == NULL)
    real_dlvsym = (void *(*)(void *, const char *, const char *))dlsym(RTLD_DEFAULT, "dlvsym");

  if(handle == NULL || symbol == NULL || hooks_suppressed())
    return real_dlvsym ? real_dlvsym(handle, symbol, version) : NULL;

  const FunctionHook repl = GetHookInfo().GetFunctionHook(symbol);

  if(repl.hook == NULL)
    return real_dlvsym ? real_dlvsym(handle, symbol, version) : NULL;

  if(!GetHookInfo().IsHooked(handle))
  {
    dl_iterate_phdr(dl_iterate_callback, NULL);
    GetHookInfo().SetHooked(handle);
  }

  HOOK_DEBUG_PRINT("Got dlvsym for %s which we want in %p...", symbol, handle);

  if(GetHookInfo().IsLibHook(handle))
  {
    HOOK_DEBUG_PRINT("identified dlvsym(%s) we want to interpose! returning %p", symbol, repl.hook);
    return repl.hook;
  }

  void *ret = real_dlvsym ? real_dlvsym(handle, symbol, version) : NULL;
  Dl_info info = {};
  dladdr(ret, &info);
  HOOK_DEBUG_PRINT("real ret is %p in %s", ret, info.dli_fname);

  // stealth/no-layer capture: same filtering as hooked_dlsym, for apps that use the versioned
  // lookup instead
  if(info.dli_fname && strstr(info.dli_fname, "libvulkan") &&
     (!strcmp(symbol, "vkEnumerateInstanceLayerProperties") ||
      !strcmp(symbol, "vkGetInstanceProcAddr") || !strcmp(symbol, "vkCreateInstance") ||
      !strcmp(symbol, "vkCreateDevice") || !strcmp(symbol, "vkGetDeviceProcAddr")))
  {
    HOOK_DEBUG_PRINT("returning filtered %s for dlvsym in %s", symbol, info.dli_fname);
    RememberRealVulkanEntry(symbol, ret);
    return repl.hook;
  }

  return ret;
}

static void InstallHooksCommon()
{
  suppressTLS = Threading::AllocateTLSSlot();

  // blacklist hooking certain system libraries or ourselves
  GetHookInfo().SetHooked(RENDERDOC_ANDROID_LIBRARY);
  GetHookInfo().SetHooked("libc.so");
  GetHookInfo().SetHooked("libvndksupport.so");

  // our link_map name may have been disguised by the hide constructor (the name string is
  // rewritten in place). Blacklist whatever name we currently present under, otherwise the
  // PLT hooking pass would treat our own library as a foreign one and patch its imports.
  {
    Dl_info selfInfo = {};
    if(dladdr((const void *)&InstallHooksCommon, &selfInfo) && selfInfo.dli_fbase)
    {
      auto findOurName = [](struct dl_phdr_info *info, size_t size, void *data) -> int {
        if((void *)info->dlpi_addr == ((Dl_info *)data)->dli_fbase && info->dlpi_name &&
           info->dlpi_name[0])
        {
          GetHookInfo().SetHooked(info->dlpi_name);
          HOOK_DEBUG_PRINT("Blacklisted our disguised link_map name %s", info->dlpi_name);
          return 1;
        }
        return 0;
      };
      dl_iterate_phdr(findOurName, &selfInfo);
    }
  }

  real_android_dlopen_ext = &android_dlopen_ext;

  loader_dlopen = (pfn__loader_dlopen)dlsym(RTLD_NEXT, "__loader_dlopen");

  if(loader_dlopen)
  {
    LibraryHooks::RegisterFunctionHook("", FunctionHook("dlopen", NULL, (void *)&hooked_dlopen));
  }
  else
  {
    RDCWARN("Couldn't find __loader_dlopen, falling back to slow path for dlopen hooking");
  }

  // always hook dlsym: apps resolve loader entry points through dlsym as well as through
  // vkGetInstanceProcAddr, and the stealth vulkan enumeration filter relies on intercepting both
  LibraryHooks::RegisterFunctionHook("", FunctionHook("dlsym", NULL, (void *)&hooked_dlsym));

  // dlvsym is the versioned equivalent of dlsym - hook it too so the stealth enumeration filter
  // can't be bypassed with a versioned lookup
  LibraryHooks::RegisterFunctionHook("", FunctionHook("dlvsym", NULL, (void *)&hooked_dlvsym));

  LibraryHooks::RegisterFunctionHook(
      "", FunctionHook("android_dlopen_ext", NULL, (void *)&hooked_android_dlopen_ext));
}

#if defined(RENDERDOC_HAVE_INTERCEPTOR_LIB)

void intercept_error(void *, const char *error_msg)
{
  RDCERR("intercept_error: %s", error_msg);
}

#include "interceptor-lib/include/interceptor.h"

void PatchHookedFunctions()
{
  RDCLOG("Applying hooks with interceptor-lib");

// see below - Huawei workaround
#if defined(__LP64__)
  LibraryHooks::RegisterLibraryHook("/system/lib64/libhwgl.so", NULL);
#else
  LibraryHooks::RegisterLibraryHook("/system/lib/libhwgl.so", NULL);
#endif

  rdcarray<rdcstr> libs = GetHookInfo().GetLibHooks();
  rdcarray<FunctionHook> funchooks = GetHookInfo().GetFunctionHooks();

  // we just leak this
  void *intercept = InitializeInterceptor();

  std::set<rdcstr> fallbacklibs;
  std::set<FunctionHook> fallbackhooks;

  for(const rdcstr &lib : libs)
  {
    void *handle = dlopen(lib.c_str(), RTLD_NOW);

    bool huawei = lib.contains("libhwgl.so");

    if(!handle)
    {
      HOOK_DEBUG_PRINT("Didn't get handle for %s", lib.c_str());
      continue;
    }

    HOOK_DEBUG_PRINT("Hooking %s = %p", lib.c_str(), handle);

    std::set<void *> foundfunctions;

    for(const FunctionHook &hook : funchooks)
    {
      void *oldfunc = dlsym(handle, hook.function.c_str());

      // UNTESTED workaround taken directly from GAPID, in installer.cpp. Quoted comment:
      /*
            // Huawei implements all functions in this library with prefix,
            // all GL functions in libGLES*.so are just trampolines to his.
            // However, we do not support trampoline interception for now,
            // so try to intercept the internal implementation instead.
      */
      if(huawei && oldfunc == NULL)
        oldfunc = dlsym(handle, ("hw_" + hook.function).c_str());

      if(GetHookInfo().IsHooked(oldfunc))
        continue;

      if(!oldfunc)
      {
        HOOK_DEBUG_PRINT("%s didn't have %s", lib.c_str(), hook.function.c_str());
        continue;
      }

      HOOK_DEBUG_PRINT("Hooking %s::%s = %p with %p", lib.c_str(), hook.function.c_str(), oldfunc,
                       hook.hook);

      void *trampoline = NULL;

      bool success = InterceptFunction(intercept, oldfunc, hook.hook, &trampoline, &intercept_error);

      if(!hook.orig)
        RDCWARN("No original pointer for hook of '%s' - trampoline will be lost!",
                hook.function.c_str());

      if(hook.orig && *hook.orig == NULL)
        *hook.orig = trampoline;

      if(success)
      {
        HOOK_DEBUG_PRINT("Hooked successfully, trampoline is %p", trampoline);
      }
      else
      {
        RDCERR("Failed to hook %s::%s!", lib.c_str(), hook.function.c_str());
        fallbacklibs.insert(lib);
        fallbackhooks.insert(hook);
      }

      GetHookInfo().SetHooked(oldfunc);
    }
  }

  // we still need to hook android_dlopen_ext with interceptor-lib so that we can intercept the
  // vulkan loader's attempts to load our library and prevent it from loading a second copy (!!)
  // into the process.
  // Unfortunately, interceptor-lib can't hook this function so we need to set up the PLT hooking.
  // This is just a minimal setup to intercept that one function.
  GetHookInfo().ClearHooks();

  for(const rdcstr &l : fallbacklibs)
  {
    RDCLOG("Falling back to PLT hooking for %s", l.c_str());
    GetHookInfo().AddLibHook(l);
  }

  for(const FunctionHook &hook : fallbackhooks)
  {
    RDCLOG("Falling back to PLT hooking for %s", hook.function.c_str());
    GetHookInfo().AddFunctionHook(hook);
  }
}

#else

void PatchHookedFunctions()
{
  RDCLOG("Applying hooks with PLT hooks");
}

#endif

bool LibraryHooks::Detect(const char *identifier)
{
  const bool symbol = (dlsym(RTLD_DEFAULT, identifier) != NULL);
  const bool env = (getenv(identifier) != NULL);

  RDCLOG("Detecting symbol %s by dlsym: %s", identifier, symbol ? "yes" : "no");
  RDCLOG("Detecting symbol %s by getenv: %s", identifier, env ? "yes" : "no");

  return symbol || env;
}

void LibraryHooks::RemoveHooks()
{
  RDCERR("Removing hooks is not possible on this platform");
}

void LibraryHooks::ReplayInitialise()
{
  // nothing to do
}

void LibraryHooks::BeginHookRegistration()
{
  // nothing to do
}

void LibraryHooks::RegisterFunctionHook(const char *libraryName, const FunctionHook &hook)
{
  // we don't use the library name on android
  (void)libraryName;
  HOOK_DEBUG_PRINT("Registering function hook for %s: %p", hook.function.c_str(), hook.hook);
  GetHookInfo().AddFunctionHook(hook);
}

void LibraryHooks::RegisterLibraryHook(const char *name, FunctionLoadCallback cb)
{
  GetHookInfo().AddLibHook(name);

  HOOK_DEBUG_PRINT("Registering library hook for %s %s", name, cb ? "with callback" : "");

  // open the library immediately if we can
  dlopen(name, RTLD_NOW);

  if(cb)
    GetHookInfo().AddHookCallback(name, cb);
}

void LibraryHooks::IgnoreLibrary(const char *libraryName)
{
}

// ==== stealth: hide the Vulkan layer from application-facing enumeration ====
//
// The layer is activated by the loader through the android debug-layer settings, so the
// application never needs to see 'VK_LAYER_RENDERDOC_Capture' in vkEnumerateInstanceLayerProperties.
// These hooks sit at the application->loader boundary: the loader's own discovery of us goes
// through its internal (direct) calls and is unaffected, but every app-facing enumeration is
// filtered. We deliberately do NOT register libvulkan as a *library* hook - that would make
// every dlopen("libvulkan.so") return our own library and break the loader chain.

static VkResult VKAPI_PTR Filtered_vkEnumerateInstanceLayerProperties(
    uint32_t *pPropertyCount, VkLayerProperties *pProperties)
{
  if(!Real_vkEnumerateInstanceLayerProperties)
    Real_vkEnumerateInstanceLayerProperties = (PFN_vkEnumerateInstanceLayerProperties)dlsym(
        RTLD_DEFAULT, "vkEnumerateInstanceLayerProperties");

  if(!Real_vkEnumerateInstanceLayerProperties)
  {
    // never expose the layer by falling through to something else - but make the failure loud,
    // an app that gets a failure here will typically fall back to another graphics API.
    RDCERR("The real vkEnumerateInstanceLayerProperties couldn't be resolved - refusing to "
           "enumerate layers rather than exposing " RENDERDOC_VULKAN_LAYER_NAME);
    return VK_ERROR_INITIALIZATION_FAILED;
  }

  if(!pPropertyCount)
    return VK_ERROR_INITIALIZATION_FAILED;

  // fetch the full list from the real loader
  uint32_t fullCount = 0;
  VkResult vkr = Real_vkEnumerateInstanceLayerProperties(&fullCount, NULL);
  if(vkr != VK_SUCCESS)
    return vkr;

  rdcarray<VkLayerProperties> layers;
  layers.resize(fullCount);

  vkr = Real_vkEnumerateInstanceLayerProperties(&fullCount, layers.data());
  if(vkr != VK_SUCCESS)
    return vkr;

  // filter out our own layer
  rdcarray<VkLayerProperties> filtered;
  for(const VkLayerProperties &layer : layers)
    if(strcmp(layer.layerName, RENDERDOC_VULKAN_LAYER_NAME) != 0)
      filtered.push_back(layer);

  const uint32_t filteredCount = (uint32_t)filtered.size();

  if(!pProperties)
  {
    *pPropertyCount = filteredCount;
    return VK_SUCCESS;
  }

  const uint32_t requested = *pPropertyCount;
  const uint32_t written = RDCMIN(requested, filteredCount);

  if(written > 0)
    memcpy(pProperties, filtered.data(), written * sizeof(VkLayerProperties));

  *pPropertyCount = written;

  return (filteredCount > requested) ? VK_INCOMPLETE : VK_SUCCESS;
}

// no-layer capture path: vkCreateInstance. When the loader is chaining us as a layer the call
// must be forwarded untouched (the loader inserts its own layer chain), otherwise we synthesize
// the loader link info and drive the wrapping code in vk_layer.cpp directly.
static VkResult VKAPI_PTR Filtered_vkCreateInstance(const VkInstanceCreateInfo *pCreateInfo,
                                                    const VkAllocationCallbacks *pAllocator,
                                                    VkInstance *pInstance)
{
  if(!AndroidVKPLTMode())
  {
    // layer mode - forward untouched, the loader adds our layer to the chain itself
    if(!Real_vkCreateInstance)
      EnsureRealVulkanEntries();
    if(!Real_vkCreateInstance)
      return VK_ERROR_INITIALIZATION_FAILED;
    return Real_vkCreateInstance(pCreateInfo, pAllocator, pInstance);
  }

  // no-layer mode - synthesize the loader link info the wrapping code requires (there is no
  // layer chain to provide one) and wrap through the capture layer
  if(!Real_vkGetInstanceProcAddr)
    EnsureRealVulkanEntries();
  if(!Real_vkGetInstanceProcAddr)
    return VK_ERROR_INITIALIZATION_FAILED;

  VkLayerInstanceLink linkInfo = {};
  linkInfo.pNext = NULL;
  linkInfo.pfnNextGetInstanceProcAddr = Real_vkGetInstanceProcAddr;
  linkInfo.pfnNextGetPhysicalDeviceProcAddr = NULL;

  VkLayerInstanceCreateInfo linkCreateInfo = {};
  linkCreateInfo.sType = VK_STRUCTURE_TYPE_LOADER_INSTANCE_CREATE_INFO;
  linkCreateInfo.pNext = NULL;
  linkCreateInfo.function = VK_LAYER_LINK_INFO;
  linkCreateInfo.u.pLayerInfo = &linkInfo;

  VkInstanceCreateInfo modifiedCreateInfo = *pCreateInfo;
  // the wrapping code advances through the link's pNext when passing the chain down, so the link
  // must carry the original pNext chain
  linkInfo.pNext = (VkLayerInstanceLink *)modifiedCreateInfo.pNext;
  modifiedCreateInfo.pNext = &linkCreateInfo;

  return RDCAndroidPLTCreateInstance(&modifiedCreateInfo, pAllocator, pInstance);
}

// no-layer capture path: vkCreateDevice. Same split as the instance create: in layer mode the
// loader provides the device link info, in no-layer mode we synthesize it.
static VkResult VKAPI_PTR Filtered_vkCreateDevice(VkPhysicalDevice physicalDevice,
                                                  const VkDeviceCreateInfo *pCreateInfo,
                                                  const VkAllocationCallbacks *pAllocator,
                                                  VkDevice *pDevice)
{
  if(!AndroidVKPLTMode())
  {
    if(!Real_vkCreateDevice)
      EnsureRealVulkanEntries();
    if(!Real_vkCreateDevice)
      return VK_ERROR_INITIALIZATION_FAILED;
    return Real_vkCreateDevice(physicalDevice, pCreateInfo, pAllocator, pDevice);
  }

  if(!Real_vkGetInstanceProcAddr || !Real_vkGetDeviceProcAddr)
    EnsureRealVulkanEntries();
  if(!Real_vkGetInstanceProcAddr || !Real_vkGetDeviceProcAddr)
    return VK_ERROR_INITIALIZATION_FAILED;

  VkLayerDeviceLink linkInfo = {};
  linkInfo.pNext = NULL;
  linkInfo.pfnNextGetInstanceProcAddr = Real_vkGetInstanceProcAddr;
  linkInfo.pfnNextGetDeviceProcAddr = Real_vkGetDeviceProcAddr;

  VkLayerDeviceCreateInfo linkCreateInfo = {};
  linkCreateInfo.sType = VK_STRUCTURE_TYPE_LOADER_DEVICE_CREATE_INFO;
  linkCreateInfo.pNext = NULL;
  linkCreateInfo.function = VK_LAYER_LINK_INFO;
  linkCreateInfo.u.pLayerInfo = &linkInfo;

  VkDeviceCreateInfo modifiedCreateInfo = *pCreateInfo;
  linkInfo.pNext = (VkLayerDeviceLink *)modifiedCreateInfo.pNext;
  modifiedCreateInfo.pNext = &linkCreateInfo;

  return RDCAndroidPLTCreateDevice(physicalDevice, &modifiedCreateInfo, pAllocator, pDevice);
}

// no-layer capture path: vkGetDeviceProcAddr. The capture layer's GDPA returns NULL for anything
// it doesn't hook (the loader normally falls through to the ICD in that case) - here we forward
// those NULLs to the real loader ourselves with the real device handle.
static PFN_vkVoidFunction VKAPI_PTR Filtered_vkGetDeviceProcAddr(VkDevice device, const char *pName)
{
  if(pName && !strcmp(pName, "vkGetDeviceProcAddr"))
    return (PFN_vkVoidFunction)&Filtered_vkGetDeviceProcAddr;

  if(AndroidVKPLTMode())
  {
    PFN_vkVoidFunction fn = RDCAndroidLayerGetDeviceProcAddr(device, pName);
    if(fn)
      return fn;
  }

  if(!Real_vkGetDeviceProcAddr)
    EnsureRealVulkanEntries();
  if(!Real_vkGetDeviceProcAddr)
    return NULL;

  return Real_vkGetDeviceProcAddr(RDCAndroidDeviceRealHandle(device), pName);
}

static PFN_vkVoidFunction VKAPI_PTR Filtered_vkGetInstanceProcAddr(VkInstance instance,
                                                                   const char *pName)
{
  if(pName && AndroidVKPLTMode())
  {
    // entry points that only make sense coming from us on the no-layer capture path - engines
    // cache these and call them directly, so they must be our filters (which synthesize the
    // loader chain link info the wrapping code expects)
    if(!strcmp(pName, "vkGetDeviceProcAddr"))
      return (PFN_vkVoidFunction)&Filtered_vkGetDeviceProcAddr;
    if(!strcmp(pName, "vkCreateDevice"))
      return (PFN_vkVoidFunction)&Filtered_vkCreateDevice;

    if(instance == VK_NULL_HANDLE)
    {
      if(!strcmp(pName, "vkEnumerateInstanceLayerProperties"))
        return (PFN_vkVoidFunction)&Filtered_vkEnumerateInstanceLayerProperties;

      if(!strcmp(pName, "vkGetInstanceProcAddr"))
        return (PFN_vkVoidFunction)&Filtered_vkGetInstanceProcAddr;

      if(!strcmp(pName, "vkCreateInstance"))
        return (PFN_vkVoidFunction)&Filtered_vkCreateInstance;

      // every other NULL-instance query is a global loader query - forward it
      if(!Real_vkGetInstanceProcAddr)
        EnsureRealVulkanEntries();
      if(!Real_vkGetInstanceProcAddr)
        return NULL;
      return Real_vkGetInstanceProcAddr(VK_NULL_HANDLE, pName);
    }

    // wrapped instance: let the capture layer answer, then fall back to the real loader with the
    // real handle for anything we don't hook (or any instance we never wrapped)
    PFN_vkVoidFunction fn = RDCAndroidLayerGetInstanceProcAddr(instance, pName);
    if(fn)
      return fn;

    if(!Real_vkGetInstanceProcAddr)
      EnsureRealVulkanEntries();
    if(!Real_vkGetInstanceProcAddr)
      return NULL;
    return Real_vkGetInstanceProcAddr(RDCAndroidInstanceRealHandle(instance), pName);
  }

  if(instance == VK_NULL_HANDLE && pName)
  {
    if(!strcmp(pName, "vkEnumerateInstanceLayerProperties"))
      return (PFN_vkVoidFunction)&Filtered_vkEnumerateInstanceLayerProperties;
  }

  if(!Real_vkGetInstanceProcAddr)
    Real_vkGetInstanceProcAddr = (PFN_vkGetInstanceProcAddr)dlsym(RTLD_DEFAULT, "vkGetInstanceProcAddr");

  if(!Real_vkGetInstanceProcAddr)
  {
    // this is what makes an engine report "No Vulkan entry points found!" and drop to GLES, so
    // log it - seeing this line means a resolution source is missing, not that the driver failed.
    RDCERR("The real vkGetInstanceProcAddr couldn't be resolved - returning NULL for %s",
           pName ? pName : "<null>");
    return NULL;
  }

  return Real_vkGetInstanceProcAddr(instance, pName);
}

static void RegisterStealthHooks()
{
  // the function hooks must be registered unconditionally, even when the vulkan loader isn't
  // loaded yet: registering them keeps EndHookRegistration from taking the "no hooks" early-out,
  // so our dlopen machinery gets installed and the loader's PLT is patched as soon as it is
  // loaded. The real entry points are only resolved once the loader is present.
  static bool registered = false;
  if(!registered)
  {
    RDCLOG("Registering stealth hooks to hide " RENDERDOC_VULKAN_LAYER_NAME
           " from enumeration and drive the no-layer capture path");

    LibraryHooks::RegisterFunctionHook(
        "libvulkan.so", FunctionHook("vkEnumerateInstanceLayerProperties", NULL,
                                     (void *)&Filtered_vkEnumerateInstanceLayerProperties));
    LibraryHooks::RegisterFunctionHook("libvulkan.so", FunctionHook("vkGetInstanceProcAddr", NULL,
                                                                    (void *)&Filtered_vkGetInstanceProcAddr));
    LibraryHooks::RegisterFunctionHook(
        "libvulkan.so", FunctionHook("vkCreateInstance", NULL, (void *)&Filtered_vkCreateInstance));
    LibraryHooks::RegisterFunctionHook(
        "libvulkan.so", FunctionHook("vkCreateDevice", NULL, (void *)&Filtered_vkCreateDevice));
    LibraryHooks::RegisterFunctionHook("libvulkan.so", FunctionHook("vkGetDeviceProcAddr", NULL,
                                                                    (void *)&Filtered_vkGetDeviceProcAddr));
    registered = true;
  }

  if(Real_vkGetInstanceProcAddr && Real_vkCreateInstance && Real_vkCreateDevice &&
     Real_vkGetDeviceProcAddr)
    return;

  // resolve the real entry points with dlsym only - the vulkan loader must already be loaded
  // for this to work, so no dlopen (an explicit dlopen of libvulkan at init time is an extra
  // hazard in anti-cheat processes; see the note in EndHookRegistration). If it isn't loaded
  // yet this is retried from hooked_dlopen when a libvulkan library is loaded, and the filters
  // themselves fall back on EnsureRealVulkanEntries before first use.
  if(!Real_vkEnumerateInstanceLayerProperties)
    Real_vkEnumerateInstanceLayerProperties = (PFN_vkEnumerateInstanceLayerProperties)dlsym(
        RTLD_DEFAULT, "vkEnumerateInstanceLayerProperties");
  if(!Real_vkGetInstanceProcAddr)
    Real_vkGetInstanceProcAddr =
        (PFN_vkGetInstanceProcAddr)dlsym(RTLD_DEFAULT, "vkGetInstanceProcAddr");
  if(!Real_vkCreateInstance)
    Real_vkCreateInstance = (PFN_vkCreateInstance)dlsym(RTLD_DEFAULT, "vkCreateInstance");
  if(!Real_vkCreateDevice)
    Real_vkCreateDevice = (PFN_vkCreateDevice)dlsym(RTLD_DEFAULT, "vkCreateDevice");
  if(!Real_vkGetDeviceProcAddr)
    Real_vkGetDeviceProcAddr = (PFN_vkGetDeviceProcAddr)dlsym(RTLD_DEFAULT, "vkGetDeviceProcAddr");
}

void LibraryHooks::EndHookRegistration()
{
  HOOK_DEBUG_PRINT("EndHookRegistration");
  // ensure we load all libraries we can immediately, so they are immediately hooked and don't get
  // loaded later.
  rdcarray<rdcstr> libs = GetHookInfo().GetLibHooks();
  for(const rdcstr &lib : libs)
  {
    void *handle = dlopen(lib.c_str(), RTLD_GLOBAL);
    HOOK_DEBUG_PRINT("%s: %p", lib.c_str(), handle);
  }

  // note: we deliberately do NOT dummy-load ourselves here with dlopen(RTLD_NOLOAD) to bump
  // our refcount. On this target (a MiUI 12 game process with an active anti-cheat) that
  // RTLD_NOLOAD dlopen reliably crashes inside the dynamic linker (SIGSEGV in
  // BionicSmallObjectAllocator::alloc on the string-building path of do_dlopen), even with our
  // hiding and name-disguise fully disabled - the environment has made that path unsafe. The
  // loaders that activate us (GLES layer / Vulkan layer) hold their own references anyway, so
  // skipping the refcount bump is safe.

  // hide our vulkan layer from application-facing enumeration. This runs even when we take the
  // layered path below, where no other hooks are registered.
  RegisterStealthHooks();

  if(libs.empty() && GetHookInfo().GetFunctionHooks().empty())
  {
    RDCLOG("No library hooks registered, not doing any hooking");
    return;
  }

  PatchHookedFunctions();

  // this already hooks dlopen (if possible) and android_dlopen_ext, which is enough
  InstallHooksCommon();

  LibraryHooks::Refresh();

  // iterate our list of libraries and look up the original pointer for any that we don't already
  // have. If we have interceptor-lib this will only be for functions that failed to generate a
  // trampoline and we're PLT hooking - without interceptor-lib this will be all functions, but it
  // will allow us to control the order/priority.
  rdcarray<rdcstr> libraryHooks = GetHookInfo().GetLibHooks();
  rdcarray<FunctionHook> functionHooks = GetHookInfo().GetFunctionHooks();

  RDCLOG("Fetching %zu original function pointers over %zu libraries", functionHooks.size(),
         libraryHooks.size());

  for(auto it = libraryHooks.begin(); it != libraryHooks.end(); ++it)
  {
    void *handle = dlopen(it->c_str(), RTLD_NOLOAD | RTLD_GLOBAL);

    if(handle)
    {
      for(FunctionHook &hook : functionHooks)
      {
        if(hook.orig && *hook.orig == NULL)
          *hook.orig = dlsym(handle, hook.function.c_str());
      }
    }
  }

  RDCLOG("Finished");

  // call the callbacks for any libraries that loaded now. If the library wasn't loaded above then
  // it can't be loaded, since we only hook system libraries.
  std::map<rdcstr, rdcarray<FunctionLoadCallback>> callbacks = GetHookInfo().GetHookCallbacks();
  for(auto it = callbacks.begin(); it != callbacks.end(); ++it)
  {
    void *handle = dlopen(it->first.c_str(), RTLD_GLOBAL);
    if(handle)
    {
      HOOK_DEBUG_PRINT("Calling callbacks for %s", it->first.c_str());
      for(FunctionLoadCallback callback : it->second)
        if(callback)
          callback(handle, it->first.c_str());
    }
  }

  RDCLOG("Called library callbacks - hook registration complete");
}

void LibraryHooks::Refresh()
{
  if(suppressTLS == 0)
  {
    RDCLOG("Not refreshing android hooks with no libraries registered");
    return;
  }

  RDCLOG("Refreshing android hooks...");
  dl_iterate_phdr(dl_iterate_callback, NULL);
  RDCLOG("Refreshed");
}

ScopedSuppressHooking::ScopedSuppressHooking()
{
  if(suppressTLS == 0)
    return;

  uintptr_t old = (uintptr_t)Threading::GetTLSValue(suppressTLS);
  Threading::SetTLSValue(suppressTLS, (void *)(old + 1));
}

ScopedSuppressHooking::~ScopedSuppressHooking()
{
  if(suppressTLS == 0)
    return;

  uintptr_t old = (uintptr_t)Threading::GetTLSValue(suppressTLS);
  Threading::SetTLSValue(suppressTLS, (void *)(old - 1));
}

bool hooks_suppressed()
{
  if(suppressTLS == 0)
    return true;

  return (uintptr_t)Threading::GetTLSValue(suppressTLS) > 0;
}
