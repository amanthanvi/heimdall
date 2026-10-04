#include <stdio.h>
__attribute__((constructor)) static void hm_inj(void) { fprintf(stderr, "INJECTED_DYLIB_LOADED\n"); }
