#include <stdio.h>

typedef int (*binary_op)(int left, int right);

static int add(int left, int right) { return left + right; }
static int mul(int left, int right) { return left * right; }
static int sub(int left, int right) { return left - right; }

int main(void) {
    static const binary_op OPS[] = {add, mul, sub};
    const int left[] = {3, 3, 5};
    const int right[] = {4, 4, 3};
    const int add_value = OPS[0](left[0], right[0]);
    const int mul_value = OPS[1](left[1], right[1]);
    const int sub_value = OPS[2](left[2], right[2]);

    printf(
        "ops:%s=%d,%s=%d,%s=%d\n",
        "add",
        add_value,
        "mul",
        mul_value,
        "sub",
        sub_value
    );
    return 0;
}
