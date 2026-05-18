from __future__ import annotations
from decimal import Decimal, ROUND_CEILING, ROUND_FLOOR, ROUND_HALF_EVEN, getcontext
from fractions import Fraction
import json
from typing import Iterable

from pwn import context, remote
from sympy.ntheory.residue_ntheory import is_quad_residue, sqrt_mod


HOST = "127.0.0.1"
PORT = 1343

context.log_level = "error"
getcontext().prec = 140


def call(io, cmd: str, payload: dict | None = None) -> dict:
    if payload is None:
        line = cmd
    else:
        line = f"{cmd} {json.dumps(payload, separators=(',', ':'))}"
    io.sendline(line.encode())
    data = io.recvuntil(b"> ", drop=True).strip()
    return json.loads(data.splitlines()[-1].decode())


def round_fraction(x: Fraction) -> int:
    if x >= 0:
        return (2 * x.numerator + x.denominator) // (2 * x.denominator)
    return -((-2 * x.numerator + x.denominator) // (2 * x.denominator))


def lll_reduction(basis: list[list[int]], delta: Fraction = Fraction(99, 100)) -> list[list[int]]:
    basis = [row[:] for row in basis]
    n = len(basis)
    m = len(basis[0])

    def gram_schmidt():
        bstar: list[list[Fraction]] = []
        mu = [[Fraction(0) for _ in range(n)] for __ in range(n)]
        norm: list[Fraction] = []

        for i in range(n):
            v = [Fraction(x) for x in basis[i]]
            for j in range(i):
                if norm[j] != 0:
                    mu[i][j] = sum(Fraction(basis[i][k]) * bstar[j][k] for k in range(m)) / norm[j]
                    for k in range(m):
                        v[k] -= mu[i][j] * bstar[j][k]
            bstar.append(v)
            norm.append(sum(x * x for x in v))

        return mu, norm

    k = 1
    mu, norm = gram_schmidt()
    while k < n:
        for j in range(k - 1, -1, -1):
            q = round_fraction(mu[k][j])
            if q:
                basis[k] = [basis[k][i] - q * basis[j][i] for i in range(m)]
                mu, norm = gram_schmidt()

        if norm[k] >= (delta - mu[k][k - 1] ** 2) * norm[k - 1]:
            k += 1
        else:
            basis[k], basis[k - 1] = basis[k - 1], basis[k]
            mu, norm = gram_schmidt()
            k = max(k - 1, 1)

    return basis


def gso_decimal(basis: list[list[int]]):
    n = len(basis)
    m = len(basis[0])
    bdec = [[Decimal(x) for x in row] for row in basis]
    bstar: list[list[Decimal]] = []
    mu = [[Decimal(0) for _ in range(n)] for __ in range(n)]
    norm: list[Decimal] = []

    for i in range(n):
        v = bdec[i][:]
        for j in range(i):
            if norm[j] != 0:
                mu[i][j] = sum(bdec[i][k] * bstar[j][k] for k in range(m)) / norm[j]
                for k in range(m):
                    v[k] -= mu[i][j] * bstar[j][k]
        bstar.append(v)
        norm.append(sum(x * x for x in v))

    return bstar, mu, norm


def closest_vector(basis: list[list[int]], target: list[int]) -> list[int]:
    n = len(basis)
    m = len(basis[0])
    bstar, mu, norm = gso_decimal(basis)
    tdec = [Decimal(x) for x in target]
    center = [sum(tdec[k] * bstar[i][k] for k in range(m)) / norm[i] for i in range(n)]

    z = [0] * n
    for i in reversed(range(n)):
        c = center[i] - sum(Decimal(z[j]) * mu[j][i] for j in range(i + 1, n))
        z[i] = int(c.to_integral_value(rounding=ROUND_HALF_EVEN))

    def lattice_vector(coeffs: list[int]) -> list[int]:
        return [sum(coeffs[i] * basis[i][k] for i in range(n)) for k in range(m)]

    best_z = z[:]
    best_v = lattice_vector(best_z)
    best_dist = sum((Decimal(best_v[k] - target[k])) ** 2 for k in range(m))
    current = [0] * n

    def dfs(i: int, partial: Decimal) -> None:
        nonlocal best_z, best_v, best_dist
        if i < 0:
            v = lattice_vector(current)
            dist = sum((Decimal(v[k] - target[k])) ** 2 for k in range(m))
            if dist < best_dist:
                best_dist = dist
                best_z = current[:]
                best_v = v
            return

        c = center[i] - sum(Decimal(current[j]) * mu[j][i] for j in range(i + 1, n))
        remain = (best_dist - partial) / norm[i]
        if remain < 0:
            return

        radius = remain.sqrt()
        lo = int((c - radius).to_integral_value(rounding=ROUND_FLOOR))
        hi = int((c + radius).to_integral_value(rounding=ROUND_CEILING))
        values = sorted(range(lo, hi + 1), key=lambda x: abs(Decimal(x) - c))

        for zi in values:
            new_partial = partial + (Decimal(zi) - c) ** 2 * norm[i]
            if new_partial <= best_dist:
                current[i] = zi
                dfs(i - 1, new_partial)

    dfs(n - 1, Decimal(0))
    return best_v


def recover_short_relation(params: dict, omega: int) -> Iterable[tuple[int, int, int, int, int]]:
    p = params["p"]
    base_const = params["base"]
    step = params["step"]
    account_id = params["account_id"]
    item_limit = params["item_limit"]
    limb_bound = params["limb_bound"]

    centers = [item_limit // 2, limb_bound // 2, limb_bound // 2, limb_bound // 2, limb_bound // 2]
    bounds = [item_limit, limb_bound, limb_bound, limb_bound, limb_bound]

    coeffs = [(omega * base_const) % p, (omega * step) % p, omega % p, (-step) % p, (-1) % p]

    constant = (
        omega * (base_const * centers[0] + step * centers[1] + centers[2])
        - (base_const * account_id + step * centers[3] + centers[4])
    ) % p

    q = 1 << 90
    h = 1 << 70
    scales = [max(1, q // (b // 2)) for b in bounds]

    basis = []
    for i, coeff in enumerate(coeffs):
        row = [0] * 6
        row[i] = scales[i]
        row[5] = coeff * h
        basis.append(row)

    basis.append([0, 0, 0, 0, 0, p * h])
    reduced = lll_reduction(basis)
    target = [0, 0, 0, 0, 0, -constant * h]
    closest = closest_vector(reduced, target)
    diff = [closest[i] - target[i] for i in range(6)]

    for candidate in (diff, [-x for x in diff]):
        shifts = []
        ok = True
        for i in range(5):
            if candidate[i] % scales[i] != 0:
                ok = False
                break
            shifts.append(candidate[i] // scales[i])

        if not ok or candidate[5] % h != 0:
            continue
        if any(abs(shifts[i]) > bounds[i] // 2 for i in range(5)):
            continue
        if (constant + sum(coeffs[i] * shifts[i] for i in range(5))) % p != 0:
            continue

        values = tuple(centers[i] + shifts[i] for i in range(5))
        if all(0 <= values[i] < bounds[i] for i in range(5)):
            yield values


def main() -> None:
    io = remote(HOST, PORT)
    io.recvuntil(b"> ")

    try:
        params = call(io, "params")
        assert params["ok"], params

        p = params["p"]
        b = params["b"]
        base_const = params["base"]
        step = params["step"]
        account_id = params["account_id"]

        w = ((sqrt_mod(-3, p) - 1) * pow(2, -1, p)) % p
        for omega in (w, w * w % p):
            for m1, r1, k1, r0, k0 in recover_short_relation(params, omega):
                if m1 == account_id:
                    continue

                x1 = (base_const * m1 + step * r1 + k1) % p
                x0 = (base_const * account_id + step * r0 + k0) % p
                if (omega * x1 - x0) % p != 0:
                    continue

                rhs = (pow(x0, 3, p) + b) % p
                y = sqrt_mod(rhs, p)
                if y is None:
                    continue
                if not is_quad_residue(y, p):
                    y = (-y) % p
                z = sqrt_mod(y, p)
                if z is None:
                    continue

                sign_resp = call(
                    io,
                    "sign",
                    {"m": m1, "x": x1, "y": y, "r": r1, "k": k1, "z": z},
                )
                if not sign_resp.get("ok"):
                    continue

                token = sign_resp["token"]
                sx = (omega * token["x"]) % p
                sy = token["y"]

                verify_resp = call(
                    io,
                    "verify",
                    {"x": x0, "y": y, "r": r0, "k": k0, "z": z, "sx": sx, "sy": sy},
                )
                if verify_resp.get("ok"):
                    print(verify_resp["flag"])
                    return

        print("no relation found")
    finally:
        io.sendline(b"exit")
        io.close()


if __name__ == "__main__":
    main()
