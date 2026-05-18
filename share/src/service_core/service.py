from __future__ import annotations

from typing import Any

from .curve import Curve, Point
from .field import Field
from .params import ACCOUNT_ID, ACCOUNT_NAME, B_CURVE, BASE, FLAG, ITEM_LIMIT, LIMB_BOUND, P_FIELD, STEP
from .records import Metadata, RecordFormat
from .tokens import Token, TokenService


class Service:
    def __init__(self):
        self.F = Field(P_FIELD)
        self.curve = Curve(self.F, B_CURVE)
        self.record_format = RecordFormat(self.curve, BASE, STEP, ITEM_LIMIT, LIMB_BOUND)
        self.tokens = TokenService(self.curve, self.record_format, ACCOUNT_ID)

    def handle(self, req: dict[str, Any]) -> dict[str, Any]:
        try:
            if not isinstance(req, dict):
                raise TypeError("request must be a dictionary")

            cmd = req.get("cmd")
            if cmd == "params":
                return self._params()
            if cmd == "sign":
                return self._sign(req)
            if cmd == "verify":
                return self._verify(req)

            raise ValueError("unknown command")
        except (TypeError, ValueError) as exc:
            return {"ok": False, "error": str(exc)}

    def _params(self) -> dict[str, Any]:
        return {
            "ok": True,
            "p": P_FIELD,
            "b": B_CURVE,
            "base": BASE,
            "step": STEP,
            "item_limit": ITEM_LIMIT,
            "limb_bound": LIMB_BOUND,
            "account": ACCOUNT_NAME.decode(),
            "account_id": ACCOUNT_ID,
        }

    def _sign(self, req: dict[str, Any]) -> dict[str, Any]:
        m = self._int(req, "m")
        P = self._point(req, "x", "y")
        metadata = Metadata(r=self._int(req, "r"), k=self._int(req, "k"), z=self._field(req, "z"))

        token = self.tokens.sign(m, P, metadata)
        return {"ok": True, "token": self._point_json(token.point)}

    def _verify(self, req: dict[str, Any]) -> dict[str, Any]:
        P = self._point(req, "x", "y")
        metadata = Metadata(r=self._int(req, "r"), k=self._int(req, "k"), z=self._field(req, "z"))
        sig_point = self._point(req, "sx", "sy")
        token = Token(sig_point)

        if self.tokens.verify(ACCOUNT_ID, P, metadata, token):
            return {"ok": True, "flag": FLAG}

        return {"ok": False, "error": "invalid token"}

    def _point(self, req: dict[str, Any], x_name: str, y_name: str) -> Point:
        return self.curve.point(self._field(req, x_name), self._field(req, y_name))

    def _field(self, req: dict[str, Any], name: str) -> int:
        return self.F.check(self._int(req, name), name)

    @staticmethod
    def _int(req: dict[str, Any], name: str) -> int:
        value = req.get(name)
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError(f"{name} must be an integer")
        return value

    @staticmethod
    def _point_json(P: Point) -> dict[str, int]:
        return {"x": P.x, "y": P.y}
