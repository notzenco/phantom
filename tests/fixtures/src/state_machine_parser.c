#include <stdio.h>

enum state {
    STATE_IDLE,
    STATE_READ,
    STATE_DONE,
};

int main(void) {
    static const char INPUT[] = "IRD";
    enum state states[3];

    for (size_t i = 0; i < sizeof(INPUT) - 1; ++i) {
        switch (INPUT[i]) {
        case 'I':
            states[i] = STATE_IDLE;
            break;
        case 'R':
            states[i] = STATE_READ;
            break;
        default:
            states[i] = STATE_DONE;
            break;
        }
    }

    const char *state0 = states[0] == STATE_IDLE ? "IDLE" : states[0] == STATE_READ ? "READ" : "DONE";
    const char *state1 = states[1] == STATE_IDLE ? "IDLE" : states[1] == STATE_READ ? "READ" : "DONE";
    const char *state2 = states[2] == STATE_IDLE ? "IDLE" : states[2] == STATE_READ ? "READ" : "DONE";

    printf(
        "states:%s,%s,%s\n",
        state0,
        state1,
        state2
    );
    return 0;
}
