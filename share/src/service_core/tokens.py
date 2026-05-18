from __future__ import annotations

import secrets
from dataclasses import dataclass

from .curve import Curve, Point, INF
from .records import Metadata, RecordFormat


@dataclass(frozen=True)
class Token:
    point: Point


class TokenService:
    def __init__(
        self,
        curve: Curve,
        record_format: RecordFormat,
        blocked_item: int,
        secret_key: int | None = None
    ):
        self.curve = curve
        self.record_format = record_format
        self.blocked_item = blocked_item
        self.secret_key = secret_key if secret_key is not None else secrets.randbelow(curve.F.p - 2) + 1

    def sign(self, m: int, P: Point, metadata: Metadata) -> Token:
        if m == self.blocked_item:
            raise ValueError("invalid item")

        self.record_format.check(m, P, metadata)
        sig = self.curve.mul(self.secret_key, P)

        if sig is INF:
            raise ValueError("unexpected point at infinity")

        return Token(sig)

    def verify(self, m: int, P: Point, metadata: Metadata, token: Token) -> bool:
        self.record_format.check(m, P, metadata)
        expected = self.curve.mul(self.secret_key, P)
        return token.point == expected
