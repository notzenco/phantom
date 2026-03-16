#include <stdio.h>

enum opcode {
    OP_PUSH = 1,
    OP_ADD = 2,
    OP_MUL = 3,
    OP_HALT = 255,
};

static const unsigned char PROGRAM[] = {
    OP_PUSH, 3,
    OP_PUSH, 4,
    OP_ADD,
    OP_PUSH, 2,
    OP_MUL,
    OP_PUSH, 5,
    OP_ADD,
    OP_HALT,
};

int main(void) {
    int stack[8] = {0};
    int top = -1;
    size_t pc = 0;

    while (pc < sizeof(PROGRAM)) {
        unsigned char op = PROGRAM[pc++];
        switch (op) {
        case OP_PUSH:
            stack[++top] = PROGRAM[pc++];
            break;
        case OP_ADD:
            stack[top - 1] = stack[top - 1] + stack[top];
            --top;
            break;
        case OP_MUL:
            stack[top - 1] = stack[top - 1] * stack[top];
            --top;
            break;
        case OP_HALT:
            pc = sizeof(PROGRAM);
            break;
        default:
            printf("vm:acc=-1\n");
            return 1;
        }
    }

    printf("vm:acc=%d\n", stack[top]);
    return 0;
}
