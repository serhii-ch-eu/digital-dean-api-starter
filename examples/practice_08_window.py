"""Working standard-library toy admission example; no HTTP, password or database."""
from math import ceil


def toy_admissions(times, maximum=2, window=10):
    start, used, result = None, 0, []
    for now in times:  # Synthetic sorted times; not a production shared limiter.
        if start is None or now >= start + window:
            start, used = now, 0
        if used < maximum:
            used += 1
            result.append((True, 0))
        else:
            result.append((False, max(1, ceil(start + window - now))))
    return result


if __name__ == "__main__":
    observed = toy_admissions([0, 0, 0, 9.9, 10])
    assert observed == [(True, 0), (True, 0), (False, 10), (False, 1), (True, 0)]
    print("Practical 8 isolated admission example passed")
