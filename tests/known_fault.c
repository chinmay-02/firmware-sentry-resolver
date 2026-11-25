#include <stdint.h>
__attribute__((noinline)) int synthetic_known_fault(int value) {
    volatile int local = value + 7;
    return local;
}
int main(void) { return synthetic_known_fault(12); }
