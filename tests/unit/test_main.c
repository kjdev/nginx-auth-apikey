#include "test.h"


int  tests_run = 0;
int  tests_failed = 0;


void
to_hex(const u_char *in, size_t n, char *out)
{
    static const char  hex[] = "0123456789abcdef";
    size_t             i;

    for (i = 0; i < n; i++) {
        out[i * 2] = hex[in[i] >> 4];
        out[i * 2 + 1] = hex[in[i] & 0x0f];
    }
    out[n * 2] = '\0';
}


int
main(void)
{
    run_hash_tests();

    printf("\n%d tests, %d failed\n", tests_run, tests_failed);

    return tests_failed == 0 ? 0 : 1;
}
