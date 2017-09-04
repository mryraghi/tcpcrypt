# tcpcrypt
Tcpcrypt, a macOS network kernel extension implementation

### Development notes
* Xcode is using the *-D_FORTIFY_SOURCE=0* compiler flag when building for *Debug* so to avoid the following errors:
  ```
  $ sudo kextload /tmp/Tcpcrypt.kext
  
  ...
  (kernel) kxld[org.tcpcrypt.Kernel]: The following symbols are unresolved for this kext:
  (kernel) kxld[org.tcpcrypt.Kernel]: 	___memcpy_chk
  (kernel) kxld[org.tcpcrypt.Kernel]: 	___memmove_chk
  (kernel) Can't load kext org.tcpcrypt.Kernel - link failed.
  ...
  ```
  My guess is that those symbols are not available when using a development or a debug kernel in the testing machine.
  ```c
  # string.h
  
  ...
  #if defined(__MAC_OS_X_VERSION_MIN_REQUIRED) && __MAC_OS_X_VERSION_MIN_REQUIRED < __MAC_10_13
  /* older deployment target */
  #elif defined(KASAN) || (defined (_FORTIFY_SOURCE) && _FORTIFY_SOURCE == 0)
  /* FORTIFY_SOURCE disabled */
  #else /* _chk macros */
  #if __has_builtin(__builtin___memcpy_chk)
  #define memcpy(dest, src, len) __builtin___memcpy_chk(dest, src, len, __builtin_object_size(dest, 0))
  #endif
  ...
  ```
