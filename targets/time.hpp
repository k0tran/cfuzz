/// This is class for representing time

#pragma once

#include <cstdlib>

class Time {
public:
    Time();
    Time(uint);

    void set(uint);
    void zero();

    uint get() const;
    float secs() const;
    bool is_zero() const;
private:
    /// t is in ms
    uint t;
};
