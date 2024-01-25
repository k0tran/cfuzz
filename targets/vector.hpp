#pragma once

class Vector2 {
public:
    Vector2(int, int);

    static Vector2 up();
    static Vector2 left();
    static Vector2 down();
    static Vector2 right();
private:
    int x, y;
};
