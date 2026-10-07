from attack_qa.web.limits import Limits, RateLimiter

HOUR = 3600.0


class Clock:
    def __init__(self, now: float = 1_800_000_000.0) -> None:  # 2027-01-15 08:00 UTC
        self.now = now

    def __call__(self) -> float:
        return self.now


def _limiter(clock: Clock, per_ip: int = 3, per_day: int = 100) -> RateLimiter:
    return RateLimiter(Limits(per_ip_per_hour=per_ip, per_day=per_day), clock=clock)


def test_allows_up_to_the_hourly_limit_per_ip_then_refuses():
    clock = Clock()
    limiter = _limiter(clock)
    assert [limiter.check("1.1.1.1").allowed for _ in range(4)] == [True, True, True, False]
    assert limiter.check("2.2.2.2").allowed  # other visitors are unaffected


def test_hourly_window_slides_rather_than_resetting_on_the_hour():
    clock = Clock()
    limiter = _limiter(clock)
    for minute in (0, 20, 40):
        clock.now += 0 if minute == 0 else 20 * 60
        assert limiter.check("1.1.1.1").allowed
    clock.now += 19 * 60  # 59 minutes after the first question
    refused = limiter.check("1.1.1.1")
    assert not refused.allowed and refused.reason == "ip"
    assert 0 < refused.retry_after_s <= 60
    clock.now += 61  # the first question is now more than an hour old
    assert limiter.check("1.1.1.1").allowed


def test_refused_attempts_do_not_extend_the_wait():
    clock = Clock()
    limiter = _limiter(clock, per_ip=1)
    assert limiter.check("1.1.1.1").allowed
    for _ in range(5):
        clock.now += 60
        assert not limiter.check("1.1.1.1").allowed
    clock.now = clock.now - 5 * 60 + HOUR + 1
    assert limiter.check("1.1.1.1").allowed


def test_daily_cap_applies_across_all_visitors_and_resets_at_utc_midnight():
    clock = Clock()
    limiter = _limiter(clock, per_ip=100, per_day=2)
    assert limiter.check("1.1.1.1").allowed
    assert limiter.check("2.2.2.2").allowed
    refused = limiter.check("3.3.3.3")
    assert not refused.allowed and refused.reason == "daily"
    clock.now += 16 * HOUR  # 08:00 UTC + 16h = next day 00:00 UTC
    assert limiter.check("3.3.3.3").allowed


def test_remaining_today_counts_down():
    limiter = _limiter(Clock(), per_ip=100, per_day=5)
    limiter.check("1.1.1.1")
    assert limiter.check("1.1.1.1").remaining_today == 3
