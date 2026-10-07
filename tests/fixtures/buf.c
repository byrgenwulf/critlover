/* SYNTHETIC FIXTURE — fake code to exercise critlover's greppers; not a real app, not exploitable. */
/* One memory-copy call below so sink-grep.sh's `native` class has a deterministic hit. */

#include <string.h>

void copy_into(char *dst, const char *src, unsigned long n) {
    memcpy(dst, src, n);   /* native memory sink (native class) */
}
