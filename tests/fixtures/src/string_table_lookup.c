#include <stdio.h>

struct color_entry {
    int key;
    const char *name;
};

static const struct color_entry COLORS[] = {
    {1, "cerulean"},
    {2, "amber"},
    {3, "vermilion"},
};

int main(void) {
    const char *selected = "unknown";

    for (size_t i = 0; i < sizeof(COLORS) / sizeof(COLORS[0]); ++i) {
        if (COLORS[i].key == 2) {
            selected = COLORS[i].name;
            break;
        }
    }

    printf("lookup:%s\n", selected);
    return 0;
}
