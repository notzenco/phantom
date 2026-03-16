#include <stdint.h>
#include <stdio.h>

static const uint8_t PAYLOAD_A[] = {5, 9, 14};
static const uint8_t PAYLOAD_B[] = {28, 3};
static const uint8_t PAYLOAD_C[] = {7};

static uint32_t weighted_sum(const uint8_t *data, size_t len, uint32_t start_index) {
    uint32_t total = 0;

    for (size_t i = 0; i < len; ++i) {
        total += data[i] * (uint32_t)(start_index + i + 1);
    }

    return total;
}

int main(void) {
    uint32_t checksum = 0;

    checksum += weighted_sum(PAYLOAD_A, sizeof(PAYLOAD_A), 0);
    checksum += weighted_sum(PAYLOAD_B, sizeof(PAYLOAD_B), sizeof(PAYLOAD_A));
    checksum += weighted_sum(PAYLOAD_C, sizeof(PAYLOAD_C), sizeof(PAYLOAD_A) + sizeof(PAYLOAD_B));

    printf("checksum:0x%04x\n", checksum);
    return 0;
}
