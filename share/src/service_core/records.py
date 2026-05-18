from __future__ import annotations

from dataclasses import dataclass

from .curve import Curve, Point


@dataclass(frozen=True)
class Metadata:
    r: int
    k: int
    z: int


class RecordFormat:
    def __init__(self, curve: Curve, base: int, step: int, item_limit: int, limb_bound: int):
        self.curve = curve
        self.base = base % curve.F.p
        self.step = step % curve.F.p
        self.item_limit = item_limit
        self.limb_bound = limb_bound

    def encode_x(self, m: int, r: int, k: int) -> int:
        self._check_message_and_metadata(m, r, k)
        return (m * self.base + r * self.step + k) % self.curve.F.p

    def check(self, m: int, P: Point, metadata: Metadata) -> None:
        x = self.encode_x(m, metadata.r, metadata.k)

        if P.x != x:
            raise ValueError("invalid record")

        self.curve.F.check(metadata.z, "z")
        if P.y != (metadata.z * metadata.z) % self.curve.F.p:
            raise ValueError("invalid metadata")

        if not self.curve.is_on_curve(P):
            raise ValueError("invalid point")

    def _check_message_and_metadata(self, m: int, r: int, k: int) -> None:
        for name, value in (("m", m), ("r", r), ("k", k)):
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(f"{name} must be an integer")

        if not (0 <= m < self.item_limit):
            raise ValueError("m out of range")
        if not (0 <= r < self.limb_bound):
            raise ValueError("r out of range")
        if not (0 <= k < self.limb_bound):
            raise ValueError("k out of range")
