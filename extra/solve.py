from fpylll import CVP, IntegerMatrix, LLL
import json
from pwn import context, remote
from sage.all import GF


HOST = "127.0.0.1"
PORT = 1343

context.log_level = "error"


def call(io, cmd, payload=None):
    if payload is None:
        line = cmd
    else:
        line = cmd + " " + json.dumps(payload, separators=(",", ":"))
    io.sendline(line.encode())
    data = io.recvuntil(b"> ", drop=True).strip()
    return json.loads(data.splitlines()[-1].decode())


def cube_roots(p):
    F = GF(p)
    w = (F(-3).sqrt() - 1) / 2
    return [int(w), int(w**2)]


def make_lattice(params, omega, q_bits, h_bits):
    p = params["p"]
    base = params["base"]
    step = params["step"]
    account_id = params["account_id"]
    item_limit = params["item_limit"]
    limb_bound = params["limb_bound"]

    centers = [
        item_limit // 2,
        limb_bound // 2,
        limb_bound // 2,
        limb_bound // 2,
        limb_bound // 2,
    ]
    bounds = [
        item_limit,
        limb_bound,
        limb_bound,
        limb_bound,
        limb_bound,
    ]

    coeffs = [
        omega * base % p,
        omega * step % p,
        omega % p,
        -step % p,
        -1 % p,
    ]

    const = (
        omega * (base * centers[0] + step * centers[1] + centers[2])
        - (base * account_id + step * centers[3] + centers[4])
    ) % p

    q = 1 << q_bits
    h = 1 << h_bits
    scales = [max(1, q // (b // 2)) for b in bounds]

    rows = []
    for i, c in enumerate(coeffs):
        row = [0] * 6
        row[i] = scales[i]
        row[5] = c * h
        rows.append(row)

    rows.append([0, 0, 0, 0, 0, p * h])

    B = IntegerMatrix.from_matrix(rows)
    LLL.reduction(B)

    target = [0, 0, 0, 0, 0, -const * h]
    return B, target, centers, bounds, scales, coeffs, const, h


def decode(v, target, centers, bounds, scales, coeffs, const, h, p):
    diff = [int(v[i]) - target[i] for i in range(6)]

    for d in (diff, [-x for x in diff]):
        if d[5] % h != 0:
            continue

        shifts = []
        ok = True

        for i in range(5):
            ok = ok and d[i] % scales[i] == 0
            shifts.append(d[i] // scales[i])

        ok = ok and all(abs(shifts[i]) <= bounds[i] // 2 for i in range(5))
        ok = ok and (const + sum(coeffs[i] * shifts[i] for i in range(5))) % p == 0

        vals = tuple(centers[i] + shifts[i] for i in range(5))
        ok = ok and all(0 <= vals[i] < bounds[i] for i in range(5))

        if ok:
            return vals

    return None


def find_relation(params):
    settings = [
        (90, 70),
        (88, 68),
        (92, 72),
    ]

    for omega in cube_roots(params["p"]):
        for q_bits, h_bits in settings:
            data = make_lattice(params, omega, q_bits, h_bits)
            B, target, centers, bounds, scales, coeffs, const, h = data

            v = CVP.closest_vector(B, target)
            rel = decode(v, target, centers, bounds, scales, coeffs, const, h, params["p"])

            if rel is not None:
                return omega, rel

    return None, None


def main():
    io = remote(HOST, PORT)
    io.recvuntil(b"> ")

    params = call(io, "params")
    p = params["p"]
    F = GF(p)

    omega, rel = find_relation(params)
    if rel is None:
        print("not found")
        io.sendline(b"exit")
        io.close()
        return

    b = params["b"]
    base = params["base"]
    step = params["step"]
    account_id = params["account_id"]

    m1, r1, k1, r0, k0 = rel

    x1 = (base * m1 + step * r1 + k1) % p
    x0 = (base * account_id + step * r0 + k0) % p

    rhs = F(x0) ** 3 + b
    if not rhs.is_square():
        print("no witness")
        io.sendline(b"exit")
        io.close()
        return

    y = rhs.sqrt()
    if not y.is_square():
        y = -y
    if not y.is_square():
        print("no witness")
        io.sendline(b"exit")
        io.close()
        return
    y, z = int(y), int(y.sqrt())

    sig = call(io, "sign", {
        "m": m1,
        "x": x1,
        "y": y,
        "r": r1,
        "k": k1,
        "z": z,
    })

    if not sig.get("ok"):
        print(sig)
        io.sendline(b"exit")
        io.close()
        return

    token = sig["token"]

    res = call(io, "verify", {
        "x": x0,
        "y": y,
        "r": r0,
        "k": k0,
        "z": z,
        "sx": omega * token["x"] % p,
        "sy": token["y"],
    })

    print(res)

    io.sendline(b"exit")
    io.close()


main()
