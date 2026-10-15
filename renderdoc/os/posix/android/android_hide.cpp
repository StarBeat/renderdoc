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

// Hide our own library from /proc/self/maps (and /proc/<pid>/maps for any observer).
//
// The technique is the one made famous by Haruue Icymoon and used by Riru:
//   https://github.com/RikkaApps/Riru/blob/master/riru/src/main/cpp/hide/hide.cpp
//
// For every file-backed mapping of our library we backup the contents to anonymous memory,
// munmap the mapping and re-create it as an anonymous mapping at the same address with the
// same protections, then copy the contents back. The pages are byte-identical and everything
// keeps working, but the VMA no longer has our pathname - so maps scanners (anti-cheat,
// tamper checks, ...) can no longer see the library.
//
// We can't run this routine from our own library while we unmap it (the executing page
// would fault), so a small position-independent stub using raw syscalls is copied into an
// anonymous executable buffer and run from there. By the time the stub returns, all of our
// pages have been re-mapped with identical contents, so execution continues seamlessly.
//
// The hide runs from the library constructor (while the linker is still loading us), when
// no other thread can be executing our code. GetLibraryFilename() resolves our path from
// /proc/self/maps just before hiding and caches it, so RenderDoc itself never falls back
// to dladdr.

#include "common/common.h"
#include "api/replay/rdcarray.h"
#include "os/os_specific.h"

#include <inttypes.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <atomic>

#if defined(__aarch64__)

// one mapping to hide. start/end are byte addresses, prot is PROT_* bits.
struct HideEntry
{
  uintptr_t start;
  uintptr_t end;
  uintptr_t prot;
};

// The stub takes (HideEntry *entries in x0, uintptr_t count in x1) and performs the
// backup/unmap/anonymous-remap/restore dance for each entry using raw syscalls only -
// no libc, no PLT, no references back into our library. It only touches caller-saved
// registers (x0-x18) so it can be called like an ordinary function.
//
// aarch64 Linux syscalls used: __NR_munmap=215, __NR_mmap=222, __NR_mprotect=226
extern "C" void rdoc_hide_stub();

asm(
    ".pushsection .text.rdoc_hide_stub, \"ax\", %progbits\n"
    ".global rdoc_hide_stub\n"
    ".type rdoc_hide_stub, %function\n"
    ".p2align 4\n"
    "rdoc_hide_stub:\n"
    "    cbz     x1, .Lrdoc_hide_done\n"
    "    mov     x6, x0\n"                 // x6 = entries pointer
    "    mov     x7, x1\n"                 // x7 = remaining count
    ".Lrdoc_hide_entry:\n"
    "    ldr     x2, [x6]\n"               // x2 = start
    "    ldr     x3, [x6, #8]\n"           // x3 = end
    "    ldr     x4, [x6, #16]\n"          // x4 = prot
    "    sub     x5, x3, x2\n"             // x5 = len
    "    cbz     x5, .Lrdoc_hide_next\n"
    // backup = mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
    "    mov     x0, xzr\n"
    "    mov     x1, x5\n"
    "    mov     x2, #3\n"
    "    mov     x3, #0x22\n"
    "    mov     x4, #-1\n"
    "    mov     x5, xzr\n"
    "    mov     x8, #222\n"
    "    svc     #0\n"
    "    mov     x9, x0\n"                 // x9 = backup
    "    movz    x10, #0xFFFF\n"
    "    movk    x10, #0xFFFF, lsl #16\n"
    "    movk    x10, #0xFFFF, lsl #32\n"
    "    movk    x10, #0xF000, lsl #48\n"  // x10 = -4096
    "    cmp     x9, x10\n"
    "    b.hi    .Lrdoc_hide_next\n"       // backup mmap failed, skip this entry
    // mprotect(start, len, prot | PROT_READ)
    "    ldr     x2, [x6]\n"
    "    ldr     x3, [x6, #8]\n"
    "    ldr     x4, [x6, #16]\n"
    "    sub     x5, x3, x2\n"
    "    mov     x0, x2\n"
    "    mov     x1, x5\n"
    "    orr     x2, x4, #1\n"
    "    mov     x8, #226\n"
    "    svc     #0\n"
    // copy start -> backup
    "    ldr     x2, [x6]\n"
    "    ldr     x3, [x6, #8]\n"
    "    sub     x5, x3, x2\n"
    "    mov     x10, x2\n"                // src
    "    mov     x11, x9\n"                // dst
    ".Lrdoc_hide_copy1_8:\n"
    "    cmp     x5, #8\n"
    "    b.lt    .Lrdoc_hide_copy1_tail\n"
    "    ldr     x12, [x10], #8\n"
    "    str     x12, [x11], #8\n"
    "    sub     x5, x5, #8\n"
    "    b       .Lrdoc_hide_copy1_8\n"
    ".Lrdoc_hide_copy1_tail:\n"
    "    cbz     x5, .Lrdoc_hide_copy1_done\n"
    "    ldrb    w12, [x10], #1\n"
    "    strb    w12, [x11], #1\n"
    "    sub     x5, x5, #1\n"
    "    b       .Lrdoc_hide_copy1_tail\n"
    ".Lrdoc_hide_copy1_done:\n"
    // munmap(start, len)
    "    ldr     x2, [x6]\n"
    "    ldr     x3, [x6, #8]\n"
    "    sub     x5, x3, x2\n"
    "    mov     x0, x2\n"
    "    mov     x1, x5\n"
    "    mov     x8, #215\n"
    "    svc     #0\n"
    // mmap(start, len, prot, MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
    "    ldr     x2, [x6]\n"
    "    ldr     x3, [x6, #8]\n"
    "    ldr     x4, [x6, #16]\n"
    "    sub     x5, x3, x2\n"
    "    mov     x0, x2\n"
    "    mov     x1, x5\n"
    "    mov     x2, x4\n"
    "    mov     x3, #0x32\n"
    "    mov     x4, #-1\n"
    "    mov     x5, xzr\n"
    "    mov     x8, #222\n"
    "    svc     #0\n"
    // mprotect(start, len, prot | PROT_WRITE)
    "    ldr     x2, [x6]\n"
    "    ldr     x3, [x6, #8]\n"
    "    ldr     x4, [x6, #16]\n"
    "    sub     x5, x3, x2\n"
    "    mov     x0, x2\n"
    "    mov     x1, x5\n"
    "    orr     x2, x4, #2\n"
    "    mov     x8, #226\n"
    "    svc     #0\n"
    // copy backup -> start
    "    ldr     x2, [x6]\n"
    "    ldr     x3, [x6, #8]\n"
    "    sub     x5, x3, x2\n"
    "    mov     x10, x9\n"                // src = backup
    "    mov     x11, x2\n"                // dst = start
    ".Lrdoc_hide_copy2_8:\n"
    "    cmp     x5, #8\n"
    "    b.lt    .Lrdoc_hide_copy2_tail\n"
    "    ldr     x12, [x10], #8\n"
    "    str     x12, [x11], #8\n"
    "    sub     x5, x5, #8\n"
    "    b       .Lrdoc_hide_copy2_8\n"
    ".Lrdoc_hide_copy2_tail:\n"
    "    cbz     x5, .Lrdoc_hide_copy2_done\n"
    "    ldrb    w12, [x10], #1\n"
    "    strb    w12, [x11], #1\n"
    "    sub     x5, x5, #1\n"
    "    b       .Lrdoc_hide_copy2_tail\n"
    ".Lrdoc_hide_copy2_done:\n"
    // mprotect(start, len, prot) - restore original protection
    "    ldr     x2, [x6]\n"
    "    ldr     x3, [x6, #8]\n"
    "    ldr     x4, [x6, #16]\n"
    "    sub     x5, x3, x2\n"
    "    mov     x0, x2\n"
    "    mov     x1, x5\n"
    "    mov     x2, x4\n"
    "    mov     x8, #226\n"
    "    svc     #0\n"
    // munmap(backup, len)
    "    ldr     x2, [x6]\n"
    "    ldr     x3, [x6, #8]\n"
    "    sub     x5, x3, x2\n"
    "    mov     x0, x9\n"
    "    mov     x1, x5\n"
    "    mov     x8, #215\n"
    "    svc     #0\n"
    ".Lrdoc_hide_next:\n"
    "    add     x6, x6, #24\n"
    "    subs    x7, x7, #1\n"
    "    b.ne    .Lrdoc_hide_entry\n"
    ".Lrdoc_hide_done:\n"
    "    ret\n"
    ".global rdoc_hide_stub_end\n"
    "rdoc_hide_stub_end:\n"
    ".popsection\n");

extern "C" char rdoc_hide_stub_end[];

#endif    // defined(__aarch64__)

void HideLibraryFromMaps()
{
  static std::atomic<bool> hidden{false};

  if(hidden.exchange(true))
    return;

  // Resolve and cache our own path before hiding - RenderDoc's GetLibraryFilename() uses
  // /proc/self/maps and must not fall back to dladdr after we hide ourselves.
  {
    rdcstr selfLib;
    FileIO::GetLibraryFilename(selfLib);
  }

  // allow opting out with 'setprop debug.rdoc.NO_HIDE 1'. Hiding is on by default.
  char noHide[PROP_VALUE_MAX] = {0};
  __system_property_get("debug.rdoc.NO_HIDE", noHide);
  if(!strncmp(noHide, "1", 1))
  {
    RDCLOG("Library hiding from /proc/self/maps disabled via debug.rdoc.NO_HIDE");
    return;
  }

#if defined(__aarch64__)
  rdcarray<HideEntry> entries;

  FILE *f = fopen("/proc/self/maps", "r");
  if(f)
  {
    char *line = NULL;
    size_t cap = 0;
    while(getline(&line, &cap, f) > 0)
    {
      uintptr_t start = 0, end = 0;
      char perms[5] = {0};
      int pathPos = 0;

      if(sscanf(line, "%" PRIx64 "-%" PRIx64 " %4s %*s %*s %*s %n", (uint64_t *)&start,
                (uint64_t *)&end, perms, &pathPos) < 3)
        continue;

      const char *path = line + pathPos;

      if(strstr(path, RENDERDOC_ANDROID_LIBRARY) && perms[0] == 'r')
      {
        uintptr_t prot = 0;
        if(perms[0] == 'r')
          prot |= PROT_READ;
        if(perms[1] == 'w')
          prot |= PROT_WRITE;
        if(perms[2] == 'x')
          prot |= PROT_EXEC;

        entries.push_back({start, end, prot});
      }
    }

    free(line);
    fclose(f);
  }

  if(entries.empty())
  {
    RDCLOG("No mappings of " RENDERDOC_ANDROID_LIBRARY " found, not hiding anything");
    return;
  }

  RDCLOG("Hiding %zu mapping(s) of " RENDERDOC_ANDROID_LIBRARY " from /proc/self/maps",
         entries.size());

  // copy the stub into an anonymous executable buffer and run it from there, so that
  // unmapping our own text section doesn't kill us mid-hide.
  size_t stubSize = (size_t)((char *)rdoc_hide_stub_end - (char *)rdoc_hide_stub);
  size_t pageSize = (size_t)sysconf(_SC_PAGESIZE);
  size_t bufSize = (stubSize + pageSize - 1) & ~(pageSize - 1);

  void *stub = mmap(NULL, bufSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if(stub == MAP_FAILED)
  {
    RDCWARN("Couldn't allocate stub buffer for library hiding");
    return;
  }

  memcpy(stub, (const void *)rdoc_hide_stub, stubSize);
  __builtin___clear_cache((char *)stub, (char *)stub + stubSize);
  mprotect(stub, bufSize, PROT_READ | PROT_EXEC);

  ((void (*)(HideEntry *, uintptr_t))stub)(entries.data(), (uintptr_t)entries.size());

  RDCLOG("Library hidden from /proc/self/maps");
#else
  RDCLOG("Library hiding only implemented on aarch64");
#endif
}

struct LinkMapDisguiseData
{
  const char *innocentName = NULL;
  char *ourName = NULL;        // points at the string behind dlpi_name
  ElfW(Addr) ourBase = 0;
  const ElfW(Phdr) *ourPhdr = NULL;
  ElfW(Half) ourPhnum = 0;
};

static int LinkMapDisguiseCollect(struct dl_phdr_info *info, size_t size, void *data)
{
  LinkMapDisguiseData *ctx = (LinkMapDisguiseData *)data;

  // remember the first non-empty innocuous soname as the fake identity, and capture our own
  // entry's data.
  if(info->dlpi_name && strstr(info->dlpi_name, RENDERDOC_ANDROID_LIBRARY))
  {
    ctx->ourName = (char *)info->dlpi_name;
    ctx->ourBase = info->dlpi_addr;
    ctx->ourPhdr = info->dlpi_phdr;
    ctx->ourPhnum = info->dlpi_phnum;
  }
  else if(!ctx->innocentName && info->dlpi_name && info->dlpi_name[0])
  {
    ctx->innocentName = info->dlpi_name;
  }

  return 0;
}

static int LinkMapDisguiseVerify(struct dl_phdr_info *info, size_t size, void *data)
{
  if(info->dlpi_name && strstr(info->dlpi_name, RENDERDOC_ANDROID_LIBRARY))
    *(bool *)data = true;

  return 0;
}

// Overwrite the bytes at 'dest' (up to destLen) with 'fake', null-terminated. Used only for
// strings in our own memory (our DT_SONAME in our dynstr), which may be read-only.
static void OverwriteNameString(char *dest, size_t destLen, const char *fake)
{
  size_t fakeLen = strlen(fake);
  if(fakeLen >= destLen)
    return;

  size_t pagesize = (size_t)sysconf(_SC_PAGESIZE);
  uintptr_t pageStart = (uintptr_t)dest & ~(pagesize - 1);
  size_t pageSpan = ((uintptr_t)dest + destLen - pageStart + pagesize - 1) & ~(pagesize - 1);

  if(mprotect((void *)pageStart, pageSpan, PROT_READ | PROT_WRITE) != 0)
    return;

  memset(dest, 0, destLen);
  memcpy(dest, fake, fakeLen);
}

// Disguise our identity in the linker's link_map views by rewriting our DT_SONAME string in
// our own dynstr. bionic's r_debug.r_map (the gdb view) reports l_name from this string, so
// r_map walkers see the fake name. If dl_iterate_phdr reports dlpi_name from the same string
// the disguise covers it too; on bionic versions where dlpi_name is a separate realpath
// string we leave that one alone - it lives inside the linker's protected small-object
// allocator arena and writing it corrupts the linker (observed: SIGSEGV in
// BionicSmallObjectAllocator::alloc on the next dlopen).
//
// We keep our entry itself - unlinking it would stop the unwinder (LLVM libunwind in the
// linker) from finding our .eh_frame and crash any exception that unwinds through our frames.
static void DisguiseLinkMapEntry()
{
  LinkMapDisguiseData data;

  dl_iterate_phdr(LinkMapDisguiseCollect, &data);

  if(!data.ourBase || !data.ourPhdr)
  {
    RDCLOG("Couldn't find our link_map entry to disguise");
    return;
  }

  // the fake name must fit inside our DT_SONAME string.
  const char *fake = data.innocentName;
  if(!fake || strlen(fake) >= strlen(RENDERDOC_ANDROID_LIBRARY))
    fake = "libc.so";

  // overwrite our DT_SONAME string in our own dynstr
  for(ElfW(Half) ph = 0; ph < data.ourPhnum; ph++)
  {
    if(data.ourPhdr[ph].p_type != PT_DYNAMIC)
      continue;

    ElfW(Dyn) *dynamic = (ElfW(Dyn) *)(data.ourBase + data.ourPhdr[ph].p_vaddr);

    const char *strtab = NULL;
    size_t strtabcount = 0;
    size_t sonameOffset = 0;

    while(dynamic->d_tag != DT_NULL)
    {
      if(dynamic->d_tag == DT_STRTAB)
        strtab = (const char *)(data.ourBase + dynamic->d_un.d_ptr);
      else if(dynamic->d_tag == DT_STRSZ)
        strtabcount = dynamic->d_un.d_val;
      else if(dynamic->d_tag == DT_SONAME)
        sonameOffset = dynamic->d_un.d_val;

      dynamic++;
    }

    if(strtab && sonameOffset && sonameOffset < strtabcount)
    {
      // only overwrite the soname string itself - the rest of the string table must stay
      // intact for symbol lookups.
      char *sonameStr = (char *)(strtab + sonameOffset);
      OverwriteNameString(sonameStr, strlen(sonameStr), fake);
    }

    break;
  }

  bool stillVisible = false;
  dl_iterate_phdr(LinkMapDisguiseVerify, &stillVisible);

  if(stillVisible)
    RDCLOG("Disguised our DT_SONAME as '%s' (dl_iterate_phdr still shows our realpath)", fake);
  else
    RDCLOG("Disguised our link_map name as '%s'", fake);
}

// Run the hide during the library constructor - i.e. while the dynamic linker is still
// loading us and no other thread can be executing our code (concurrent dlopens are
// serialised by the linker). Hiding later is racy: the app's render thread may already
// be inside our Vulkan/GLES layer entry points, and temporarily unmapping/mprotect-ing
// our text section would kill it with SIGILL.
__attribute__((constructor)) static void InitLibraryHide()
{
  // The wrapper script sets LD_PRELOAD to get us loaded, and the environment survives into the
  // app's image. Security SDKs (e.g. NetEase ntunisdk) read their own environment and flag a
  // non-empty LD_PRELOAD immediately - we're already loaded by now, so scrub it before any app
  // code (or its anti-tamper modules) gets to run.
  unsetenv("LD_PRELOAD");

  HideLibraryFromMaps();
  DisguiseLinkMapEntry();
}
