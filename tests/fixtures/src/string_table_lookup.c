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

int main(int argc, char **argv) {
    (void)argv;
    // Selecting by argc keeps every table entry live under optimisation.
    const int key = argc + 1;
    const char *selected = "unknown";

    for (size_t i = 0; i < sizeof(COLORS) / sizeof(COLORS[0]); ++i) {
        if (COLORS[i].key == key) {
            selected = COLORS[i].name;
            break;
        }
    }

    printf("lookup:%s\n", selected);
    return 0;
}
