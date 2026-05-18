from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .field import Field


@dataclass(frozen=True)
class Point:
    x: int
    y: int


INF: Optional[Point] = None


class Curve:
    def __init__(self, field: Field, b: int):
        self.F = field
        self.b = b % field.p

    def point(self, x: int, y: int) -> Point:
        x = self.F.check(x, "x")
        y = self.F.check(y, "y")
        P = Point(x, y)
        if not self.is_on_curve(P):
            raise ValueError("point is not on the curve")
        return P

    def is_on_curve(self, P: Point) -> bool:
        return (P.y * P.y - (pow(P.x, 3, self.F.p) + self.b)) % self.F.p == 0

    def neg(self, P: Optional[Point]) -> Optional[Point]:
        if P is INF:
            return INF
        return Point(P.x, (-P.y) % self.F.p)

    def add(self, P: Optional[Point], Q: Optional[Point]) -> Optional[Point]:
        if P is INF:
            return Q
        if Q is INF:
            return P

        p = self.F.p

        if P.x == Q.x and (P.y + Q.y) % p == 0:
            return INF

        if P == Q:
            if P.y == 0:
                return INF
            slope = (3 * P.x * P.x) * self.F.inv(2 * P.y)
        else:
            slope = (Q.y - P.y) * self.F.inv(Q.x - P.x)

        slope %= p
        x3 = (slope * slope - P.x - Q.x) % p
        y3 = (slope * (P.x - x3) - P.y) % p
        return Point(x3, y3)

    def mul(self, n: int, P: Optional[Point]) -> Optional[Point]:
        if n < 0:
            return self.mul(-n, self.neg(P))

        result = INF
        addend = P

        while n:
            if n & 1:
                result = self.add(result, addend)
            addend = self.add(addend, addend)
            n >>= 1

        return result
