#pragma once
#include <stdatomic.h>
#include <stdint.h>

struct time_shm {
  _Atomic uint64_t value;
};

