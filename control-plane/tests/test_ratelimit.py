"""Shared (Redis) rate limiter: counting, windows, sharing between replicas, Redis outages."""
from __future__ import annotations

from beyond_cp.security import Limiter, RedisRateLimiter


class FakeRedis:
    """Just enough of redis-py for INCR/EXPIRE pipelines; one instance = one shared server."""

    def __init__(self):
        self.data: dict[str, int] = {}
        self.ttl: dict[str, int] = {}
        self.down = False

    def pipeline(self):
        return FakePipe(self)


class FakePipe:
    def __init__(self, r: FakeRedis):
        self.r, self.ops = r, []

    def incr(self, k):
        self.ops.append(("incr", k))

    def expire(self, k, s):
        self.ops.append(("expire", k, s))

    def execute(self):
        if self.r.down:
            raise ConnectionError("redis down")
        out = []
        for op in self.ops:
            if op[0] == "incr":
                self.r.data[op[1]] = self.r.data.get(op[1], 0) + 1
                out.append(self.r.data[op[1]])
            else:
                self.r.ttl[op[1]] = op[2]
                out.append(True)
        return out


def test_limit_is_shared_between_replicas():
    shared = FakeRedis()
    now = [1000.0]
    a = RedisRateLimiter(shared, clock=lambda: now[0])
    b = RedisRateLimiter(shared, clock=lambda: now[0])
    assert [a.allow("login:1.2.3.4", 3) for _ in range(2)] == [True, True]
    assert b.allow("login:1.2.3.4", 3) is True  # third hit, other replica
    assert a.allow("login:1.2.3.4", 3) is False
    assert b.allow("login:5.6.7.8", 3) is True  # other key unaffected
    assert all(t == 61 for t in shared.ttl.values())


def test_new_window_resets_count():
    shared = FakeRedis()
    now = [1000.0]
    r = RedisRateLimiter(shared, clock=lambda: now[0])
    for _ in range(3):
        r.allow("k", 3)
    assert r.allow("k", 3) is False
    now[0] += 61
    assert r.allow("k", 3) is True


def test_outage_falls_back_to_local_limits():
    shared = FakeRedis()
    shared.down = True
    r = RedisRateLimiter(shared)
    assert [r.allow("k", 2) for _ in range(3)] == [True, True, False]  # still limited, per replica


def test_facade_switches_backend(monkeypatch):
    lim = Limiter()
    assert lim.allow("x", 1) and not lim.allow("x", 1)
    lim.use_memory()
    assert lim.allow("x", 1)
