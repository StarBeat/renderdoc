/* No-op stand-in for libgfxcore.so inside the remoteserver package.
 * The server never loads this library itself; only the patched libvulkan
 * shim's DT_NEEDED dependency chain reaches it, and that load must not
 * pull the full RenderDoc library (and its startup waits) into the
 * server process.
 */
void __libgfxcore_noop_stub(void) {}
