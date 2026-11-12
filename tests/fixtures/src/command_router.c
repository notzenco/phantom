#include <stdio.h>

static const char *route_for(int command) {
    switch (command) {
    case 3:
        return "west-gate";
    case 5:
        return "south-hold";
    case 7:
        return "north-east";
    default:
        return "unknown";
    }
}

int main(int argc, char **argv) {
    (void)argv;
    // Routing by argc keeps every case live under optimisation.
    printf("route:%s\n", route_for(8 - argc));
    return 0;
}
