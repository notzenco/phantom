#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--fail") == 0) {
        fprintf(stderr, "status:fail code=17\n");
        return 17;
    }

    printf("status:ok\n");
    return 0;
}
