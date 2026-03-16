#include <stdio.h>

struct kv_pair {
    const char *key;
    const char *value;
};

static const struct kv_pair DEFAULTS[] = {
    {"mode", "safe"},
    {"retries", "2"},
    {"region", "edge"},
};

static const struct kv_pair OVERRIDES[] = {
    {"mode", "fast"},
    {"retries", "3"},
    {"region", "lab"},
};

int main(void) {
    const char *mode = DEFAULTS[0].value;
    const char *retries = DEFAULTS[1].value;
    const char *region = DEFAULTS[2].value;

    for (size_t i = 0; i < sizeof(OVERRIDES) / sizeof(OVERRIDES[0]); ++i) {
        if (OVERRIDES[i].key[0] == 'm') {
            mode = OVERRIDES[i].value;
        } else if (OVERRIDES[i].key[0] == 'r' && OVERRIDES[i].key[1] == 'e' && OVERRIDES[i].key[2] == 't') {
            retries = OVERRIDES[i].value;
        } else {
            region = OVERRIDES[i].value;
        }
    }

    printf("cfg:mode=%s,retries=%s,region=%s\n", mode, retries, region);
    return 0;
}
