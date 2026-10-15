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

#include <stdlib.h>
#include <string.h>

#include "api/replay/version.h"
#include "common/common.h"
#include "common/threading.h"
#include "hooks/hooks.h"
#include "os/os_specific.h"
#include "strings/string_utils.h"
#include "vk_common.h"
#include "vk_core.h"
#include "vk_hookset_defs.h"
#include "vk_resources.h"

extern "C" const rdcstr VulkanLayerJSONBasename;

#if ENABLED(RDOC_ANDROID)
// set by vk_device_funcs.cpp when the loader hands us the chain link during instance creation
PFN_vkGetInstanceProcAddr gchainGPA_capture = NULL;
#endif

// this was removed from the vulkan definition header
#undef VK_LAYER_EXPORT
#define VK_LAYER_EXPORT
#if ENABLED(RDOC_WIN32)

#undef VK_LAYER_EXPORT
#define VK_LAYER_EXPORT extern "C" __declspec(dllexport)

#elif ENABLED(RDOC_LINUX) || ENABLED(RDOC_ANDROID) || ENABLED(RDOC_APPLE)

#undef VK_LAYER_EXPORT
#define VK_LAYER_EXPORT __attribute__((visibility("default")))

#endif

#if ENABLED(RDOC_ANDROID)
#include <dlfcn.h>
#include <link.h>
#include <elf.h>

// Find another loaded copy of this same library (by ELF soname) and return its base address.
// Our library exists twice on Android with the wrap.sh flow: once LD_PRELOADed as
// libgfxcore.so, and once dlopened RTLD_LOCAL by the vulkan loader as
// libVkLayer_RENDERDOC_Capture.so. Each copy has its own static pools, so a handle allocated
// by one copy is foreign to the other. dl_iterate_phdr sees RTLD_LOCAL objects too, unlike
// dlsym(RTLD_NEXT).
struct FindOtherCopyCtx
{
  const char *selfName;
  uintptr_t selfBase;
  uintptr_t otherBase;
};

static int find_other_copy_cb(struct dl_phdr_info *info, size_t, void *data)
{
  FindOtherCopyCtx *ctx = (FindOtherCopyCtx *)data;
  if(info->dlpi_name == NULL)
    return 0;
  const char *name = info->dlpi_name;
  // match either of our two deployment names - the preloaded libgfxcore.so and the vulkan
  // layer library are the same binary under different names
  const char *base = strrchr(name, '/');
  base = base ? base + 1 : name;
  bool isOurs = (strcmp(base, "libgfxcore.so") == 0 ||
                 strcmp(base, "libVkLayer_RENDERDOC_Capture.so") == 0);
  if(!isOurs)
    return 0;
  if((uintptr_t)info->dlpi_addr == ctx->selfBase)
    return 0;
  ctx->otherBase = (uintptr_t)info->dlpi_addr;
  return 1;
}

// resolve an exported symbol from another loaded copy of this library by walking its
// dynamic symbol table manually (dlsym can't reach an RTLD_LOCAL object by name)
static void *GetOtherCopyExport(const char *selfName, const char *symbol)
{
  Dl_info self = {};
  void *pivot = (void *)&GetOtherCopyExport;
  dladdr(pivot, &self);
  if(self.dli_fname == NULL)
    return NULL;

  const char *selfBaseName = strrchr(self.dli_fname, '/');
  selfBaseName = selfBaseName ? selfBaseName + 1 : self.dli_fname;

  FindOtherCopyCtx ctx = {selfBaseName, (uintptr_t)self.dli_fbase, 0};
  dl_iterate_phdr(find_other_copy_cb, &ctx);
  if(ctx.otherBase == 0)
    return NULL;

  // parse the ELF at that base: PT_DYNAMIC -> DT_SYMTAB/DT_STRTAB/DT_HASH or DT_GNU_HASH
  const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)ctx.otherBase;
  const Elf64_Phdr *phdr = (const Elf64_Phdr *)(ctx.otherBase + ehdr->e_phoff);
  const Elf64_Dyn *dyn = NULL;
  for(int i = 0; i < ehdr->e_phnum; i++)
  {
    if(phdr[i].p_type == PT_DYNAMIC)
    {
      dyn = (const Elf64_Dyn *)(ctx.otherBase + phdr[i].p_vaddr);
      break;
    }
  }
  if(!dyn)
    return NULL;

  const Elf64_Sym *symtab = NULL;
  const char *strtab = NULL;
  uint32_t symcount = 0;
  // DT_HASH gives nchain == symbol count
  for(const Elf64_Dyn *d = (const Elf64_Dyn *)dyn; d->d_tag != DT_NULL; d++)
  {
    if(d->d_tag == DT_SYMTAB)
      symtab = (const Elf64_Sym *)(ctx.otherBase + d->d_un.d_ptr);
    else if(d->d_tag == DT_STRTAB)
      strtab = (const char *)(ctx.otherBase + d->d_un.d_ptr);
    else if(d->d_tag == DT_HASH)
    {
      const uint32_t *hash = (const uint32_t *)(ctx.otherBase + d->d_un.d_ptr);
      symcount = hash[1];
    }
  }
  if(!symtab || !strtab || symcount == 0)
    return NULL;

  for(uint32_t i = 0; i < symcount; i++)
  {
    if(symtab[i].st_name == 0 || symtab[i].st_value == 0)
      continue;
    if(ELF64_ST_TYPE(symtab[i].st_info) != STT_FUNC)
      continue;
    if(strcmp(strtab + symtab[i].st_name, symbol) == 0)
      return (void *)(ctx.otherBase + symtab[i].st_value);
  }
  return NULL;
}

// On this Android setup the game's engine (libGame.so) resolves vkGetInstanceProcAddr from
// libvulkan after our layer has been inserted, and the loader dispatches its queries down the
// layer chain to us while passing the loader-internal VkInstance handle rather than the
// wrapped handle we returned from hooked_vkCreateInstance. Aborting (the historical
// behaviour) or handing back one of our hooked functions crashes, since that handle is not
// one of our WrappedVkInstance allocations.
//
// We translate the loader-internal handle back to our wrapped instance with the map
// populated during instance creation; if it isn't in the map we forward the query down the
// rest of the chain using the GPA the loader handed us in the layer chain link.
static PFN_vkGetInstanceProcAddr gchainGPA = NULL;
static PFN_vkGetDeviceProcAddr gchainGDPA = NULL;
extern PFN_vkGetInstanceProcAddr gchainGPA_capture;

// loader-internal instance handle -> our wrapped instance handle, populated in
// WrappedVulkan::vkCreateInstance (vk_device_funcs.cpp)
#include <map>
static std::map<void *, VkInstance> gloaderToWrapped;
static Threading::CriticalSection gloaderMapLock;

extern "C" VK_LAYER_EXPORT VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL
VK_LAYER_RENDERDOC_CaptureGetInstanceProcAddr(VkInstance instance, const char *pName);

extern "C" VK_LAYER_EXPORT VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL
VK_LAYER_RENDERDOC_CaptureGetInstanceProcAddr_fwd(VkInstance instance, const char *pName)
{
  return VK_LAYER_RENDERDOC_CaptureGetInstanceProcAddr(instance, pName);
}

void RDCLayerHookedInstanceCreated(void *loaderHandle, void *wrappedHandle)
{
  SCOPED_LOCK(gloaderMapLock);
  gloaderToWrapped[loaderHandle] = (VkInstance)wrappedHandle;
}

static void LogForeignCaller(const char *api, const void *instance, const char *pName)
{
  Dl_info info = {};
  void *caller = __builtin_return_address(2);
  dladdr(caller, &info);
  RDCLOG("%s sees foreign %s handle %p (asking for %s), caller %p in %s", api,
         api[0] == 'G' && strstr(api, "Device") ? "device" : "instance", instance, pName, caller,
         info.dli_fname ? info.dli_fname : "unknown");
  // walk a few frames manually to identify exactly who is dispatching to this copy
  void *frames[6] = {};
  frames[0] = __builtin_return_address(0);
  frames[1] = __builtin_return_address(1);
  frames[2] = __builtin_return_address(2);
  frames[3] = __builtin_return_address(3);
  frames[4] = __builtin_return_address(4);
  for(int i = 0; i < 5; i++)
  {
    if(frames[i] == NULL)
      break;
    Dl_info fi = {};
    dladdr(frames[i], &fi);
    RDCLOG("  frame %d: %p in %s + %llu", i, frames[i], fi.dli_fname ? fi.dli_fname : "?",
           fi.dli_fname ? (unsigned long long)((char *)frames[i] - (char *)fi.dli_fbase) : 0ULL);
  }
}

static bool ForeignInstancePassthrough(VkInstance instance, const char *pName,
                                       PFN_vkVoidFunction *outFunc)
{
  if(instance == VK_NULL_HANDLE || WrappedVkInstance::IsAlloc(instance))
    return false;

  // translate the loader-internal handle back to our wrapped instance
  {
    VkInstance wrapped = VK_NULL_HANDLE;
    {
      SCOPED_LOCK(gloaderMapLock);
      auto it = gloaderToWrapped.find((void *)instance);
      if(it != gloaderToWrapped.end())
        wrapped = it->second;
    }

    if(wrapped != VK_NULL_HANDLE)
    {
      static bool translated = false;
      if(!translated)
      {
        translated = true;
        RDCLOG("Translating loader-internal instance %p back to wrapped %p", (void *)instance,
               (void *)wrapped);
      }

      // resolve the query for the wrapped handle ourselves, as normal
      *outFunc = VK_LAYER_RENDERDOC_CaptureGetInstanceProcAddr_fwd(wrapped, pName);
      return true;
    }
  }

  static bool logged = false;
  if(!logged)
  {
    logged = true;
    Dl_info self = {};
    dladdr((void *)&ForeignInstancePassthrough, &self);
    LogForeignCaller("GetInstanceProcAddr", (const void *)instance, pName);
    RDCLOG("...GIPA running in copy at %s (base %p)", self.dli_fname ? self.dli_fname : "?",
           self.dli_fbase);
  }
  // We are likely the LD_PRELOAD copy while the layer copy (dlopened by the loader as
  // libVkLayer_RENDERDOC_Capture.so) allocated this handle in its own pool. Find that other
  // copy's exported GIPA and let it handle its own instance.
  {
    static PFN_vkVoidFunction (*otherCopyGIPA)(VkInstance, const char *) = NULL;
    static bool searched = false;
    if(!searched)
    {
      searched = true;
      otherCopyGIPA = (PFN_vkVoidFunction(*)(VkInstance, const char *))GetOtherCopyExport(
          NULL, "VK_LAYER_RENDERDOC_CaptureGetInstanceProcAddr");
      if(otherCopyGIPA)
        RDCLOG("Found other copy GIPA at %p - foreign handles will be delegated to it",
               (void *)otherCopyGIPA);
    }

    if(otherCopyGIPA)
    {
      *outFunc = otherCopyGIPA(instance, pName);
      return true;
    }
  }

  // fallback: try to resolve the symbol through the loader's own GIPA - this is the entry the
  // engine would have used without us, and the loader recognises the handle
  {
    static PFN_vkGetInstanceProcAddr realGPA = NULL;
    if(!realGPA)
    {
      void *module = Process::LoadModule("libvulkan.so");
      if(module)
        realGPA = (PFN_vkGetInstanceProcAddr)Process::GetFunctionAddress(module,
                                                                          "vkGetInstanceProcAddr");
    }
    if(realGPA)
    {
      PFN_vkVoidFunction fn = (PFN_vkVoidFunction)realGPA(instance, pName);
      static int nullCount = 0;
      if(fn == NULL && nullCount < 3)
      {
        nullCount++;
        RDCLOG("foreign GIPA(%p, %s): loader returned NULL", (void *)instance, pName);
      }
      *outFunc = fn;
      return true;
    }
  }

  *outFunc = NULL;
  return true;
}

static bool ForeignDevicePassthrough(VkDevice device, const char *pName, PFN_vkVoidFunction *outFunc)
{
  if(device == VK_NULL_HANDLE || WrappedVkDevice::IsAlloc(device))
    return false;

  static bool logged = false;
  if(!logged)
  {
    logged = true;
    LogForeignCaller("GetDeviceProcAddr", (const void *)device, pName);
  }

  // see ForeignInstancePassthrough - unknown handle, we cannot resolve for it
  *outFunc = NULL;
  return true;
}

void KeepLayerAlive()
{
  static bool done = false;
  if(done)
    return;
  done = true;

  // on Android 10 the library only gets loaded for layers. If an instance is destroyed the library
  // would be unloaded. That could cause us to drop target control connections etc.
  // we create our own instance, which increases the refcount on the layer, then leak it to prevent
  // the layer being unloaded.
  RDCLOG("Creating internal instance to bump layer refcount");
  // no dlopen here: the vulkan loader has already loaded us as a layer, so if it is present its
  // exports are in the global namespace. explicit dlopens of libvulkan are an extra hazard in
  // anti-cheat processes (see EndHookRegistration in android_hook.cpp).
  PFN_vkCreateInstance create = (PFN_vkCreateInstance)dlsym(RTLD_DEFAULT, "vkCreateInstance");

  if(create)
  {
    VkApplicationInfo app = {
        VK_STRUCTURE_TYPE_APPLICATION_INFO, NULL,
        "RenderDoc forced instance",        VK_MAKE_VERSION(1, 0, 0),
        "RenderDoc forced instance",        VK_MAKE_VERSION(1, 0, 0),
        VK_MAKE_VERSION(1, 0, 0),
    };
    VkInstanceCreateInfo info = {
        VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO, NULL, 0, &app, 0, NULL, 0, NULL,
    };
    VkInstance forceLiveInstance = VK_NULL_HANDLE;
    VkResult vkr = create(&info, NULL, &forceLiveInstance);
    RDCLOG("Created own instance %p: %s", forceLiveInstance, ToStr(vkr).c_str());
  }
  else
  {
    RDCERR("libvulkan not loaded - can't force layer to stay alive");
  }
}
#else
void KeepLayerAlive()
{
}
#endif

// we don't actually hook any modules here. This is just used so that it's called
// at the right time in initialisation (after capture options are available) to
// set environment variables
class VulkanHook : LibraryHook
{
  VulkanHook() {}
  void RegisterHooks()
  {
    RDCLOG("Registering Vulkan hooks");

    // we don't register any library or function hooks because we use the layer system

    // we assume the implicit layer is registered - the UI will prompt the user about installing it.
    Process::RegisterEnvironmentModification(
        EnvironmentModification(EnvMod::Set, EnvSep::NoSep, RENDERDOC_VULKAN_LAYER_VAR, "1"));

    // RTSS layer is buggy, disable it to avoid bug reports that are caused by it
    Process::RegisterEnvironmentModification(
        EnvironmentModification(EnvMod::Set, EnvSep::NoSep, "DISABLE_RTSS_LAYER", "1"));

    // OBS's layer causes crashes, disable it too.
    Process::RegisterEnvironmentModification(
        EnvironmentModification(EnvMod::Set, EnvSep::NoSep, "DISABLE_VULKAN_OBS_CAPTURE", "1"));

    // OverWolf is some shitty software that forked OBS and changed the layer value
    Process::RegisterEnvironmentModification(
        EnvironmentModification(EnvMod::Set, EnvSep::NoSep, "DISABLE_VULKAN_OW_OBS_CAPTURE", "1"));

    // buggy program AgaueEye which also doesn't have a proper layer configuration. As a result
    // this is likely to have side-effects but probably also on other buggy layers that duplicate
    // sample code without even changing the layer json
    Process::RegisterEnvironmentModification(
        EnvironmentModification(EnvMod::Set, EnvSep::NoSep, "DISABLE_SAMPLE_LAYER", "1"));

    // buggy overlay gamepp
    Process::RegisterEnvironmentModification(
        EnvironmentModification(EnvMod::Set, EnvSep::NoSep, "DISABLE_GAMEPP_LAYER", "1"));

    // buggy wegame cross overlay
    Process::RegisterEnvironmentModification(EnvironmentModification(
        EnvMod::Set, EnvSep::NoSep, "DISABLE_VK_LAYER_TENCENT_wegame_cross_overlay_1", "1"));

    // mesa device select layer crashes when it calls GPDP2 inside vkCreateInstance, which fails on
    // the current loader.
    Process::RegisterEnvironmentModification(
        EnvironmentModification(EnvMod::Set, EnvSep::NoSep, "NODEVICE_SELECT", "1"));

    Process::RegisterEnvironmentModification(EnvironmentModification(
        EnvMod::Set, EnvSep::NoSep, "DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1"));

    Process::RegisterEnvironmentModification(EnvironmentModification(
        EnvMod::Set, EnvSep::NoSep, "VK_LAYER_bandicam_helper_DEBUG_1", "1"));

    Process::RegisterEnvironmentModification(
        EnvironmentModification(EnvMod::Set, EnvSep::NoSep, "DISABLE_VK_LAYER_reshade_1", "1"));

    Process::RegisterEnvironmentModification(
        EnvironmentModification(EnvMod::Set, EnvSep::NoSep, "DISABLE_VK_LAYER_GPUOpen_GRS", "1"));

    // fpsmon not only has a buggy layer but it also picks an absurdly generic disable environment
    // variable :(. Hopefully no other program picks this, or if it does then it's probably not a
    // bad thing to disable too
    Process::RegisterEnvironmentModification(
        EnvironmentModification(EnvMod::Set, EnvSep::NoSep, "DISABLE_LAYER", "1"));

    // support self-hosted capture by checking our filename and tweaking the env var we set
    if(VulkanLayerJSONBasename != "renderdoc")
    {
      Process::RegisterEnvironmentModification(EnvironmentModification(
          EnvMod::Set, EnvSep::NoSep,
          "ENABLE_VULKAN_" + strupper(VulkanLayerJSONBasename) + "_CAPTURE", "1"));
    }

    // check options to set further variables, and apply
    OptionsUpdated();
  }

  void RemoveHooks()
  {
    // unset the vulkan layer environment variable
    Process::RegisterEnvironmentModification(
        EnvironmentModification(EnvMod::Set, EnvSep::NoSep, RENDERDOC_VULKAN_LAYER_VAR, "0"));
    Process::ApplyEnvironmentModification();
  }

  void OptionsUpdated()
  {
    if(RenderDoc::Inst().GetCaptureOptions().apiValidation)
    {
      Process::RegisterEnvironmentModification(EnvironmentModification(
          EnvMod::Append, EnvSep::Platform, "VK_INSTANCE_LAYERS", "VK_LAYER_KHRONOS_validation"));
      Process::RegisterEnvironmentModification(EnvironmentModification(
          EnvMod::Append, EnvSep::Platform, "VK_DEVICE_LAYERS", "VK_LAYER_KHRONOS_validation"));
    }
    else
    {
      // can't disable if APIValidation is not set
    }

    Process::ApplyEnvironmentModification();
  }

  static VulkanHook vkhooks;
};

VulkanHook VulkanHook::vkhooks;

// RenderDoc State

// RenderDoc Intercepts, these must all be entry points with a dispatchable object
// as the first parameter

#define HookDefine1(ret, function, t1, p1)                   \
  VKAPI_ATTR ret VKAPI_CALL CONCAT(hooked_, function)(t1 p1) \
  {                                                          \
    return CoreDisp(p1)->function(p1);                       \
  }
#define HookDefine2(ret, function, t1, p1, t2, p2)                  \
  VKAPI_ATTR ret VKAPI_CALL CONCAT(hooked_, function)(t1 p1, t2 p2) \
  {                                                                 \
    return CoreDisp(p1)->function(p1, p2);                          \
  }
#define HookDefine3(ret, function, t1, p1, t2, p2, t3, p3)                 \
  VKAPI_ATTR ret VKAPI_CALL CONCAT(hooked_, function)(t1 p1, t2 p2, t3 p3) \
  {                                                                        \
    return CoreDisp(p1)->function(p1, p2, p3);                             \
  }
#define HookDefine4(ret, function, t1, p1, t2, p2, t3, p3, t4, p4)                \
  VKAPI_ATTR ret VKAPI_CALL CONCAT(hooked_, function)(t1 p1, t2 p2, t3 p3, t4 p4) \
  {                                                                               \
    return CoreDisp(p1)->function(p1, p2, p3, p4);                                \
  }
#define HookDefine5(ret, function, t1, p1, t2, p2, t3, p3, t4, p4, t5, p5)               \
  VKAPI_ATTR ret VKAPI_CALL CONCAT(hooked_, function)(t1 p1, t2 p2, t3 p3, t4 p4, t5 p5) \
  {                                                                                      \
    return CoreDisp(p1)->function(p1, p2, p3, p4, p5);                                   \
  }
#define HookDefine6(ret, function, t1, p1, t2, p2, t3, p3, t4, p4, t5, p5, t6, p6)              \
  VKAPI_ATTR ret VKAPI_CALL CONCAT(hooked_, function)(t1 p1, t2 p2, t3 p3, t4 p4, t5 p5, t6 p6) \
  {                                                                                             \
    return CoreDisp(p1)->function(p1, p2, p3, p4, p5, p6);                                      \
  }
#define HookDefine7(ret, function, t1, p1, t2, p2, t3, p3, t4, p4, t5, p5, t6, p6, t7, p7)      \
  VKAPI_ATTR ret VKAPI_CALL CONCAT(hooked_, function)(t1 p1, t2 p2, t3 p3, t4 p4, t5 p5, t6 p6, \
                                                      t7 p7)                                    \
  {                                                                                             \
    return CoreDisp(p1)->function(p1, p2, p3, p4, p5, p6, p7);                                  \
  }
#define HookDefine8(ret, function, t1, p1, t2, p2, t3, p3, t4, p4, t5, p5, t6, p6, t7, p7, t8, p8) \
  VKAPI_ATTR ret VKAPI_CALL CONCAT(hooked_, function)(t1 p1, t2 p2, t3 p3, t4 p4, t5 p5, t6 p6,    \
                                                      t7 p7, t8 p8)                                \
  {                                                                                                \
    return CoreDisp(p1)->function(p1, p2, p3, p4, p5, p6, p7, p8);                                 \
  }
#define HookDefine9(ret, function, t1, p1, t2, p2, t3, p3, t4, p4, t5, p5, t6, p6, t7, p7, t8, p8, \
                    t9, p9)                                                                        \
  VKAPI_ATTR ret VKAPI_CALL CONCAT(hooked_, function)(t1 p1, t2 p2, t3 p3, t4 p4, t5 p5, t6 p6,    \
                                                      t7 p7, t8 p8, t9, p9)                        \
  {                                                                                                \
    return CoreDisp(p1)->function(p1, p2, p3, p4, p5, p6, p7, p8, p9);                             \
  }
#define HookDefine10(ret, function, t1, p1, t2, p2, t3, p3, t4, p4, t5, p5, t6, p6, t7, p7, t8, \
                     p8, t9, p9, t10, p10)                                                      \
  VKAPI_ATTR ret VKAPI_CALL CONCAT(hooked_, function)(t1 p1, t2 p2, t3 p3, t4 p4, t5 p5, t6 p6, \
                                                      t7 p7, t8 p8, t9 p9, t10 p10)             \
  {                                                                                             \
    return CoreDisp(p1)->function(p1, p2, p3, p4, p5, p6, p7, p8, p9, p10);                     \
  }
#define HookDefine11(ret, function, t1, p1, t2, p2, t3, p3, t4, p4, t5, p5, t6, p6, t7, p7, t8, \
                     p8, t9, p9, t10, p10, t11, p11)                                            \
  VKAPI_ATTR ret VKAPI_CALL CONCAT(hooked_, function)(t1 p1, t2 p2, t3 p3, t4 p4, t5 p5, t6 p6, \
                                                      t7 p7, t8 p8, t9 p9, t10 p10, t11 p11)    \
  {                                                                                             \
    return CoreDisp(p1)->function(p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11);                \
  }

DefineHooks();

// need to implement vkCreateInstance and vkDestroyInstance specially,
// to create and destroy the core WrappedVulkan object

VKAPI_ATTR VkResult VKAPI_CALL hooked_vkCreateInstance(const VkInstanceCreateInfo *pCreateInfo,
                                                       const VkAllocationCallbacks *,
                                                       VkInstance *pInstance)
{
  RDCLOG("hooked_vkCreateInstance called from app: %s",
         (pCreateInfo && pCreateInfo->pApplicationInfo &&
          pCreateInfo->pApplicationInfo->pApplicationName)
             ? pCreateInfo->pApplicationInfo->pApplicationName
             : "(no app name)");
  KeepLayerAlive();

  WrappedVulkan *core = new WrappedVulkan();
  return core->vkCreateInstance(pCreateInfo, NULL, pInstance);
}

VKAPI_ATTR void VKAPI_CALL hooked_vkDestroyInstance(VkInstance instance, const VkAllocationCallbacks *)
{
  WrappedVulkan *core = CoreDisp(instance);
  core->vkDestroyInstance(instance, NULL);
  delete core;
}

// Layer Intercepts

#if ENABLED(RDOC_WIN32) && DISABLED(RDOC_X64)

// Win32 __stdcall will still mangle even with extern "C", set up aliases

#pragma comment( \
    linker,      \
    "/EXPORT:VK_LAYER_RENDERDOC_CaptureEnumerateDeviceLayerProperties=_VK_LAYER_RENDERDOC_CaptureEnumerateDeviceLayerProperties@12")
#pragma comment( \
    linker,      \
    "/EXPORT:VK_LAYER_RENDERDOC_CaptureEnumerateDeviceExtensionProperties=_VK_LAYER_RENDERDOC_CaptureEnumerateDeviceExtensionProperties@16")
#pragma comment( \
    linker,      \
    "/EXPORT:VK_LAYER_RENDERDOC_CaptureEnumerateInstanceExtensionProperties=_VK_LAYER_RENDERDOC_CaptureEnumerateInstanceExtensionProperties@16")
#pragma comment( \
    linker,      \
    "/EXPORT:VK_LAYER_RENDERDOC_CaptureGetDeviceProcAddr=_VK_LAYER_RENDERDOC_CaptureGetDeviceProcAddr@8")
#pragma comment( \
    linker,      \
    "/EXPORT:VK_LAYER_RENDERDOC_CaptureGetInstanceProcAddr=_VK_LAYER_RENDERDOC_CaptureGetInstanceProcAddr@8")
#endif

extern "C" {

VK_LAYER_EXPORT VKAPI_ATTR VkResult VKAPI_CALL VK_LAYER_RENDERDOC_CaptureEnumerateDeviceLayerProperties(
    VkPhysicalDevice physicalDevice, uint32_t *pPropertyCount, VkLayerProperties *pProperties)
{
  // must have a property count, either to fill out or use as a size
  if(pPropertyCount == NULL)
    return VK_INCOMPLETE;

  // if we're not writing the properties, just say we have one layer
  if(pProperties == NULL)
  {
    *pPropertyCount = 1;
    return VK_SUCCESS;
  }
  else
  {
    // if the property count is somehow zero, return incomplete
    if(*pPropertyCount == 0)
      return VK_INCOMPLETE;

    const VkLayerProperties layerProperties = {
        RENDERDOC_VULKAN_LAYER_NAME,
        VK_API_VERSION_1_0,
        VK_MAKE_VERSION(RENDERDOC_VERSION_MAJOR, RENDERDOC_VERSION_MINOR, 0),
        "Debugging capture layer for RenderDoc",
    };

    // set the one layer property
    *pProperties = layerProperties;

    return VK_SUCCESS;
  }
}

VK_LAYER_EXPORT VKAPI_ATTR VkResult VKAPI_CALL
VK_LAYER_RENDERDOC_CaptureEnumerateDeviceExtensionProperties(VkPhysicalDevice physicalDevice,
                                                             const char *pLayerName,
                                                             uint32_t *pPropertyCount,
                                                             VkExtensionProperties *pProperties)
{
  // if pLayerName is NULL or not ours we're calling down through the layer chain to the ICD.
  // This is our chance to filter out any reported extensions that we don't support
  if(physicalDevice != NULL &&
     (pLayerName == NULL || strcmp(pLayerName, RENDERDOC_VULKAN_LAYER_NAME) != 0))
    return CoreDisp(physicalDevice)
        ->FilterDeviceExtensionProperties(physicalDevice, pLayerName, pPropertyCount, pProperties);

  return WrappedVulkan::GetProvidedDeviceExtensionProperties(pPropertyCount, pProperties);
}

VK_LAYER_EXPORT VKAPI_ATTR VkResult VKAPI_CALL
VK_LAYER_RENDERDOC_CaptureEnumerateInstanceExtensionProperties(
    const VkEnumerateInstanceExtensionPropertiesChain *pChain, const char *pLayerName,
    uint32_t *pPropertyCount, VkExtensionProperties *pProperties)
{
  if(pLayerName && !strcmp(pLayerName, RENDERDOC_VULKAN_LAYER_NAME))
    return WrappedVulkan::GetProvidedInstanceExtensionProperties(pPropertyCount, pProperties);

  return WrappedVulkan::FilterInstanceExtensionProperties(pChain, pLayerName, pPropertyCount,
                                                          pProperties);
}

#undef DeclExt
#define DeclExt(name) \
  bool name = false;  \
  (void)name;

#undef CheckExt
#define CheckExt(name, ver) name = instDevInfo == NULL || instDevInfo->ext_##name;

#undef HookInit
#define HookInit(function)                            \
  if(!strcmp(pName, STRINGIZE(CONCAT(vk, function)))) \
    return (PFN_vkVoidFunction)&CONCAT(hooked_vk, function);

#undef HookInitExtension
#define HookInitExtension(cond, function)                      \
  if(!strcmp(pName, STRINGIZE(CONCAT(vk, function))))          \
  {                                                            \
    if(cond)                                                   \
      return (PFN_vkVoidFunction)&CONCAT(hooked_vk, function); \
  }

// for promoted extensions, we return the function pointer for either name as an alias.
#undef HookInitPromotedExtension
#define HookInitPromotedExtension(cond, function, suffix)                     \
  if(!strcmp(pName, STRINGIZE(CONCAT(vk, function))) ||                       \
             !strcmp(pName, STRINGIZE(CONCAT(vk, CONCAT(function, suffix))))) \
  {                                                                           \
    if(cond)                                                                  \
      return (PFN_vkVoidFunction)&CONCAT(hooked_vk, function);                \
  }

#undef HookInitExtensionEXTtoKHR
#define HookInitExtensionEXTtoKHR(func) (void)0;

#undef HookInitPromotedExtensionEXTtoKHR
#define HookInitPromotedExtensionEXTtoKHR(func) (void)0;

// proc addr routines

VK_LAYER_EXPORT VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL
VK_LAYER_RENDERDOC_CaptureGetDeviceProcAddr(VkDevice device, const char *pName)
{
  if(!strcmp("vkGetDeviceProcAddr", pName))
    return (PFN_vkVoidFunction)&VK_LAYER_RENDERDOC_CaptureGetDeviceProcAddr;
  if(!strcmp("vkCreateDevice", pName))
    return (PFN_vkVoidFunction)&hooked_vkCreateDevice;
  if(!strcmp("vkDestroyDevice", pName))
    return (PFN_vkVoidFunction)&hooked_vkDestroyDevice;

#if ENABLED(RDOC_ANDROID)
  {
    PFN_vkVoidFunction passthrough = NULL;
    if(device != VK_NULL_HANDLE && ForeignDevicePassthrough(device, pName, &passthrough))
      return passthrough;
  }
#endif

  HookInitVulkanDevice();

  if(device == VK_NULL_HANDLE)
    return NULL;

  InstanceDeviceInfo *instDevInfo = GetRecord(device)->instDevInfo;

  DeclExts();

  CheckInstanceExts();
  CheckDeviceExts();

  HookInitVulkanDeviceExts();

  if(instDevInfo->brokenGetDeviceProcAddr)
  {
    HookInitVulkanInstanceExts_PhysDev();
    HookInitVulkanInstanceExts();
  }

  // unknown or not-enabled functions must return NULL
  return NULL;
}

VK_LAYER_EXPORT VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL
VK_LAYER_RENDERDOC_Capture_layerGetPhysicalDeviceProcAddr(VkInstance instance, const char *pName);

VK_LAYER_EXPORT VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL
VK_LAYER_RENDERDOC_CaptureGetInstanceProcAddr(VkInstance instance, const char *pName)
{
  // if name is NULL undefined is returned, let's return NULL
  if(pName == NULL)
    return NULL;

  // a NULL instance can return vkGetInstanceProcAddr or a global function, handle that here

  if(!strcmp("vkGetInstanceProcAddr", pName))
    return (PFN_vkVoidFunction)&VK_LAYER_RENDERDOC_CaptureGetInstanceProcAddr;
  if(!strcmp("vkEnumerateInstanceExtensionProperties", pName))
    return (PFN_vkVoidFunction)&VK_LAYER_RENDERDOC_CaptureEnumerateInstanceExtensionProperties;
  if(!strcmp("vk_layerGetPhysicalDeviceProcAddr", pName))
    return (PFN_vkVoidFunction)&VK_LAYER_RENDERDOC_Capture_layerGetPhysicalDeviceProcAddr;

  // don't implement vkEnumerateInstanceLayerProperties or vkEnumerateInstanceVersion, the loader
  // will do that

  HookInit(CreateInstance);

  if(instance == VK_NULL_HANDLE)
    return NULL;

#if ENABLED(RDOC_ANDROID)
  {
    // log the first few foreign handles only - with the single-copy staging this should never
    // trigger; if it does, the library got mapped twice (see PrepareWrapInjection)
    static int traceCount = 0;
    if(traceCount < 10 && !WrappedVkInstance::IsAlloc(instance))
    {
      traceCount++;
      RDCLOG("GIPA trace: FOREIGN instance %p for %s", (void *)instance, pName);
    }
    PFN_vkVoidFunction passthrough = NULL;
    if(ForeignInstancePassthrough(instance, pName, &passthrough))
      return passthrough;
  }
#endif

  if(!strcmp("vkEnumerateDeviceLayerProperties", pName))
    return (PFN_vkVoidFunction)&VK_LAYER_RENDERDOC_CaptureEnumerateDeviceLayerProperties;
  if(!strcmp("vkEnumerateDeviceExtensionProperties", pName))
    return (PFN_vkVoidFunction)&VK_LAYER_RENDERDOC_CaptureEnumerateDeviceExtensionProperties;
  if(!strcmp("vkGetDeviceProcAddr", pName))
    return (PFN_vkVoidFunction)&VK_LAYER_RENDERDOC_CaptureGetDeviceProcAddr;
  if(!strcmp("vkCreateDevice", pName))
    return (PFN_vkVoidFunction)&hooked_vkCreateDevice;
  if(!strcmp("vkDestroyDevice", pName))
    return (PFN_vkVoidFunction)&hooked_vkDestroyDevice;

  // we should only return a function pointer for functions that are either from a supported core
  // version, an enabled instance extension or an _available_ device extension

  HookInitVulkanInstance();

  InstanceDeviceInfo *instDevInfo = NULL;

  if(WrappedVkInstance::IsAlloc(instance))
    instDevInfo = GetRecord(instance)->instDevInfo;
  else
    RDCERR(
        "GetInstanceProcAddr passed invalid instance for %s! Possibly broken loader. "
        "Working around by assuming all extensions are enabled - WILL CAUSE SPEC-BROKEN BEHAVIOUR",
        pName);

  DeclExts();

  CheckInstanceExts();
  CheckDeviceExts();

  HookInitVulkanInstanceExts();

  // GetInstanceProcAddr must also unconditionally return all device functions

#undef HookInitExtension
#define HookInitExtension(cond, function)             \
  if(!strcmp(pName, STRINGIZE(CONCAT(vk, function)))) \
    return (PFN_vkVoidFunction)&CONCAT(hooked_vk, function);

#undef HookInitPromotedExtension
#define HookInitPromotedExtension(cond, function, suffix)                     \
  if(!strcmp(pName, STRINGIZE(CONCAT(vk, function))) ||                       \
             !strcmp(pName, STRINGIZE(CONCAT(vk, CONCAT(function, suffix))))) \
    return (PFN_vkVoidFunction)&CONCAT(hooked_vk, function);

#undef HookInitExtensionEXTtoKHR
#define HookInitExtensionEXTtoKHR(func) (void)0;

#undef HookInitPromotedExtensionEXTtoKHR
#define HookInitPromotedExtensionEXTtoKHR(func) (void)0;

  HookInitVulkanDevice();

  HookInitVulkanDeviceExts();

  HookInitVulkanInstanceExts_PhysDev();

  // all other functions must return NULL so that GIPA can be used with NULL checks sensibly for
  // missing functionality

  return NULL;
}

#if ENABLED(RDOC_ANDROID)

// ==== no-layer (PLT hook) capture path ====
//
// When the vulkan calls are intercepted by the PLT hooks in android_hook.cpp instead of the
// loader inserting us as a debug layer, these exports let the hook filters drive the same
// wrapping code the layer chain normally drives.

// set to true when the loader activates us as a layer (NegotiateLoaderLayerInterfaceVersion),
// set to true when the PLT path activates the no-layer capture instead
static bool gAndroidVKLayerActive = false;
static bool gAndroidVKPLTActive = false;

extern "C" VK_LAYER_EXPORT VKAPI_ATTR int VKAPI_CALL RDCAndroidVKCaptureMode(void)
{
  if(gAndroidVKPLTActive)
    return 1;
  if(gAndroidVKLayerActive)
    return 0;
  return -1;
}

extern "C" VK_LAYER_EXPORT VKAPI_ATTR void VKAPI_CALL RDCAndroidSetVKPLTMode(int active)
{
  gAndroidVKPLTActive = active != 0;
}

extern "C" VK_LAYER_EXPORT VKAPI_ATTR VkResult VKAPI_CALL RDCAndroidPLTCreateInstance(
    const VkInstanceCreateInfo *pCreateInfo, const VkAllocationCallbacks *pAllocator,
    VkInstance *pInstance)
{
  return hooked_vkCreateInstance(pCreateInfo, pAllocator, pInstance);
}

extern "C" VK_LAYER_EXPORT VKAPI_ATTR VkResult VKAPI_CALL RDCAndroidPLTCreateDevice(
    VkPhysicalDevice physicalDevice, const VkDeviceCreateInfo *pCreateInfo,
    const VkAllocationCallbacks *pAllocator, VkDevice *pDevice)
{
  return hooked_vkCreateDevice(physicalDevice, pCreateInfo, pAllocator, pDevice);
}

extern "C" VK_LAYER_EXPORT VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL
RDCAndroidLayerGetInstanceProcAddr(VkInstance instance, const char *pName)
{
  return VK_LAYER_RENDERDOC_CaptureGetInstanceProcAddr(instance, pName);
}

extern "C" VK_LAYER_EXPORT VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL
RDCAndroidLayerGetDeviceProcAddr(VkDevice device, const char *pName)
{
  return VK_LAYER_RENDERDOC_CaptureGetDeviceProcAddr(device, pName);
}

extern "C" VK_LAYER_EXPORT VKAPI_ATTR VkInstance VKAPI_CALL
RDCAndroidInstanceRealHandle(VkInstance instance)
{
  return WrappedVkInstance::IsAlloc(instance) ? Unwrap(instance) : instance;
}

extern "C" VK_LAYER_EXPORT VKAPI_ATTR VkDevice VKAPI_CALL RDCAndroidDeviceRealHandle(VkDevice device)
{
  return WrappedVkDevice::IsAlloc(device) ? Unwrap(device) : device;
}

#endif

VK_LAYER_EXPORT VKAPI_ATTR PFN_vkVoidFunction VKAPI_CALL
VK_LAYER_RENDERDOC_Capture_layerGetPhysicalDeviceProcAddr(VkInstance instance, const char *pName)
{
  // GetPhysicalDeviceProcAddr acts like GetInstanceProcAddr but it returns NULL for any functions
  // which are known but aren't physical device functions
  if(!strcmp("vkGetInstanceProcAddr", pName))
    return NULL;
  if(!strcmp("vk_layerGetPhysicalDeviceProcAddr", pName))
    return (PFN_vkVoidFunction)&VK_LAYER_RENDERDOC_Capture_layerGetPhysicalDeviceProcAddr;
  if(!strcmp("vkEnumerateDeviceLayerProperties", pName))
    return (PFN_vkVoidFunction)&VK_LAYER_RENDERDOC_CaptureEnumerateDeviceLayerProperties;
  if(!strcmp("vkEnumerateDeviceExtensionProperties", pName))
    return (PFN_vkVoidFunction)&VK_LAYER_RENDERDOC_CaptureEnumerateDeviceExtensionProperties;
  if(!strcmp("vkEnumerateInstanceExtensionProperties", pName))
    return NULL;
  if(!strcmp("vkGetDeviceProcAddr", pName))
    return NULL;
  if(!strcmp("vkCreateDevice", pName))
    return (PFN_vkVoidFunction)&hooked_vkCreateDevice;
  if(!strcmp("vkDestroyDevice", pName))
    return NULL;

  HookInitVulkanInstance_PhysDev();

#if ENABLED(RDOC_ANDROID)
  {
    PFN_vkVoidFunction passthrough = NULL;
    if(instance != VK_NULL_HANDLE && ForeignInstancePassthrough(instance, pName, &passthrough))
      return passthrough;
  }
#endif

// any remaining functions that are known, we must return NULL for
#undef HookInit
#define HookInit(function)                            \
  if(!strcmp(pName, STRINGIZE(CONCAT(vk, function)))) \
    return NULL;

  // any extensions that are known to be physical device functions, return here
  HookInitVulkanInstanceExts_PhysDev();

  HookInitVulkanInstance();
  HookInitVulkanDevice();

  if(instance == VK_NULL_HANDLE)
    return NULL;

  InstanceDeviceInfo *instDevInfo = NULL;

  if(WrappedVkInstance::IsAlloc(instance))
    instDevInfo = GetRecord(instance)->instDevInfo;
  else
    RDCERR(
        "GetPhysicalDeviceProcAddr passed invalid instance for %s! Possibly broken loader. "
        "Working around by assuming all extensions are enabled - WILL CAUSE SPEC-BROKEN BEHAVIOUR",
        pName);

  DeclExts();

  CheckInstanceExts();
  CheckDeviceExts();

// any remaining functions that are known, we must return NULL for
#undef HookInitExtension
#define HookInitExtension(cond, function)             \
  if(!strcmp(pName, STRINGIZE(CONCAT(vk, function)))) \
    return NULL;

#undef HookInitPromotedExtension
#define HookInitPromotedExtension(cond, function, suffix)                     \
  if(!strcmp(pName, STRINGIZE(CONCAT(vk, function))) ||                       \
             !strcmp(pName, STRINGIZE(CONCAT(vk, CONCAT(function, suffix))))) \
    return NULL;

#undef HookInitExtensionEXTtoKHR
#define HookInitExtensionEXTtoKHR(func) (void)0;

#undef HookInitPromotedExtensionEXTtoKHR
#define HookInitPromotedExtensionEXTtoKHR(func) (void)0;

  HookInitVulkanInstanceExts();
  HookInitVulkanDeviceExts();

  // if we got here we don't recognise the function at all. Shouldn't be possible as we whitelist
  // extensions, but follow the spec and pass along

#if ENABLED(RDOC_ANDROID)
  // don't try to unwrap/query a foreign instance - this is not ours to touch
  if(instance != VK_NULL_HANDLE && !WrappedVkInstance::IsAlloc(instance))
    return NULL;
#endif

  if(GetInstanceDispatchTable(instance)->GetInstanceProcAddr == NULL)
    return NULL;

  PFN_vkGetInstanceProcAddr GPDPA =
      (PFN_vkGetInstanceProcAddr)GetInstanceDispatchTable(instance)->GetInstanceProcAddr(
          Unwrap(instance), "vk_layerGetPhysicalDeviceProcAddr");

  if(GPDPA == NULL)
    return NULL;

  return GPDPA(Unwrap(instance), pName);
}

// layer interface negotation (new interface)
VK_LAYER_EXPORT VKAPI_ATTR VkResult VKAPI_CALL
VK_LAYER_RENDERDOC_CaptureNegotiateLoaderLayerInterfaceVersion(VkNegotiateLayerInterface *pVersionStruct)
{
  if(pVersionStruct->sType != LAYER_NEGOTIATE_INTERFACE_STRUCT)
    return VK_ERROR_INITIALIZATION_FAILED;

#if ENABLED(RDOC_ANDROID)
  // remember the chain's next proc addresses so we can forward foreign handles later (see
  // ForeignInstancePassthrough above)
  if(pVersionStruct->pfnGetInstanceProcAddr && pVersionStruct->pfnGetInstanceProcAddr !=
                                                   VK_LAYER_RENDERDOC_CaptureGetInstanceProcAddr)
    gchainGPA = pVersionStruct->pfnGetInstanceProcAddr;
  if(pVersionStruct->pfnGetDeviceProcAddr &&
     pVersionStruct->pfnGetDeviceProcAddr != VK_LAYER_RENDERDOC_CaptureGetDeviceProcAddr)
    gchainGDPA = pVersionStruct->pfnGetDeviceProcAddr;

  // the loader only negotiates with us when it is activating us as a layer - record that so the
  // PLT hook filters know the loader chain is handling the wrapping (see RDCAndroidVKCaptureMode)
  gAndroidVKLayerActive = true;
#endif

  if(pVersionStruct->loaderLayerInterfaceVersion >= 2)
  {
    pVersionStruct->pfnGetInstanceProcAddr = VK_LAYER_RENDERDOC_CaptureGetInstanceProcAddr;
    pVersionStruct->pfnGetDeviceProcAddr = VK_LAYER_RENDERDOC_CaptureGetDeviceProcAddr;
    pVersionStruct->pfnGetPhysicalDeviceProcAddr =
        VK_LAYER_RENDERDOC_Capture_layerGetPhysicalDeviceProcAddr;
  }

  // we only support the current version. Don't let updating the header silently make us report a
  // higher version without examining what this means
  RDCCOMPILE_ASSERT(CURRENT_LOADER_LAYER_INTERFACE_VERSION == 2,
                    "Loader/layer interface version has been bumped");

  if(pVersionStruct->loaderLayerInterfaceVersion > 2)
    pVersionStruct->loaderLayerInterfaceVersion = 2;

  return VK_SUCCESS;
}
}
