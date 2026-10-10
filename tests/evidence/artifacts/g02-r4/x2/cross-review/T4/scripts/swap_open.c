/*
 * Deterministic check-then-open (TOCTOU) probe for heimdall-proto on macOS.
 *
 * Loaded with DYLD_INSERT_LIBRARIES into a copy of the binary that was re-signed ad hoc
 * WITHOUT the hardened runtime (the build.sh artifacts carry it and dyld would ignore the
 * variable). It interposes open(2) and openat(2). The first time the program opens exactly
 * the path in HMX_SWAP_PATH, the hook renames HMX_SWAP_FROM over HMX_SWAP_PATH (an atomic
 * replace, e.g. a prepared symlink to a FIFO replaces the symlink to the regular profile)
 * and then performs the real open. Any pre-open check (stat/lstat) has therefore seen the
 * original target, and the open sees the new one: the race window is hit on every run.
 * If HMX_SWAP_LOG is set, "swapped <rename rc>" is appended to it, so the probe can tell a
 * run that reached the open from one that refused the path before opening.
 *
 * Build: cc -dynamiclib -O1 -o swap_open.dylib swap_open.c
 */
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DYLD_INTERPOSE(_replacement, _replacee)                                         \
    __attribute__((used)) static struct {                                               \
        const void *replacement;                                                        \
        const void *replacee;                                                           \
    } _interpose_##_replacee __attribute__((section("__DATA,__interpose"))) = {         \
        (const void *)(unsigned long)&_replacement, (const void *)(unsigned long)&_replacee};

static int swapped = 0;

static void maybe_swap(const char *path) {
    const char *target = getenv("HMX_SWAP_PATH");
    const char *from = getenv("HMX_SWAP_FROM");
    if (swapped || target == NULL || from == NULL || path == NULL || strcmp(path, target) != 0)
        return;
    swapped = 1;
    int saved = errno;
    int rc = rename(from, target);
    const char *log = getenv("HMX_SWAP_LOG");
    if (log != NULL) {
        int fd = open(log, O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (fd >= 0) {
            char buf[64];
            int n = snprintf(buf, sizeof buf, "swapped %d\n", rc);
            if (n > 0) (void)write(fd, buf, (size_t)n);
            close(fd);
        }
    }
    errno = saved;
}

static int hm_open(const char *path, int flags, ...) {
    int mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    maybe_swap(path);
    return open(path, flags, mode);
}

static int hm_openat(int dirfd, const char *path, int flags, ...) {
    int mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    maybe_swap(path);
    return openat(dirfd, path, flags, mode);
}

DYLD_INTERPOSE(hm_open, open)
DYLD_INTERPOSE(hm_openat, openat)
