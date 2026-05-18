from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Field:
    p: int

    def check(self, x: int, name: str = "value") -> int:
        if not isinstance(x, int) or isinstance(x, bool):
            raise TypeError(f"{name} must be an integer")
        if not (0 <= x < self.p):
            raise ValueError(f"{name} must be in [0, p)")
        return x

    def inv(self, x: int) -> int:
        return pow(x % self.p, -1, self.p)

    def is_square(self, x: int) -> bool:
        x %= self.p
        if x == 0:
            return True
        return pow(x, (self.p - 1) // 2, self.p) == 1

    def sqrt(self, x: int) -> int:
        x %= self.p
        if x == 0:
            return 0
        if not self.is_square(x):
            raise ValueError("not a square")

        if self.p % 4 == 3:
            r = pow(x, (self.p + 1) // 4, self.p)
            if (r * r) % self.p != x:
                raise ValueError("not a square")
            return r

        # Tonelli-Shanks for the p = 1 mod 4 case.
        q = self.p - 1
        s = 0
        while q % 2 == 0:
            s += 1
            q //= 2

        z = 2
        while self.is_square(z):
            z += 1

        m = s
        c = pow(z, q, self.p)
        t = pow(x, q, self.p)
        r = pow(x, (q + 1) // 2, self.p)

        while t != 1:
            i = 1
            t2 = (t * t) % self.p
            while t2 != 1:
                t2 = (t2 * t2) % self.p
                i += 1
                if i == m:
                    raise ValueError("not a square")

            b = pow(c, 1 << (m - i - 1), self.p)
            m = i
            c = (b * b) % self.p
            t = (t * c) % self.p
            r = (r * b) % self.p

        if (r * r) % self.p != x:
            raise ValueError("not a square")
        return r

    def auxiliary_value(self) -> int:
        sqrt_neg_3 = self.sqrt(-3)
        value = ((sqrt_neg_3 - 1) * self.inv(2)) % self.p
        assert value != 1
        assert pow(value, 3, self.p) == 1
        assert (value * value + value + 1) % self.p == 0
        return value
