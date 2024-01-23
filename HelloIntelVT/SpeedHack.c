#include "SpeedHack.h"

NTSTATUS StartSpeedHack(INT64 Mult)
{
    return DoVmCall('sphk', Mult, 0, 0);
}
