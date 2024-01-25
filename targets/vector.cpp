#include "vector.hpp"

Vector2::Vector2(int x_coord, int y_coord) : x(x_coord), y(y_coord) {}

Vector2 Vector2::up() { return Vector2(0, 1); }
Vector2 Vector2::left() { return Vector2(-1, 0); }
Vector2 Vector2::down() { return Vector2(0, -1); }
Vector2 Vector2::right() { return Vector2(1, 0); }
