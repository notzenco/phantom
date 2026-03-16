#include <stdio.h>
#include <stdlib.h>

static const char CSV_DATA[] =
    "3,11,5\n"
    "8,0,0\n"
    "0,0,0\n"
    "0,0,0\n";

int main(void) {
    long sum = 0;
    long max = 0;
    long rows = 0;
    const char *cursor = CSV_DATA;

    while (*cursor != '\0') {
        char *end = NULL;
        long row_sum = 0;

        while (*cursor != '\n' && *cursor != '\0') {
            long value = strtol(cursor, &end, 10);
            row_sum += value;
            if (value > max) {
                max = value;
            }
            cursor = end;
            if (*cursor == ',') {
                ++cursor;
            }
        }

        sum += row_sum;
        ++rows;
        if (*cursor == '\n') {
            ++cursor;
        }
    }

    printf("csv:rows=%ld,sum=%ld,max=%ld\n", rows, sum, max);
    return 0;
}
