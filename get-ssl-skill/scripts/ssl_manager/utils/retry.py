"""Polling/retry utility for waiting on async operations."""

from __future__ import annotations

import time
from typing import Callable, TypeVar

from ssl_manager.utils.logger import log

T = TypeVar("T")


def poll_until(
    fn: Callable[[], T | None],
    *,
    interval: int = 10,
    timeout: int = 300,
    desc: str = "operation",
) -> T:
    """Poll a function until it returns a non-None value.

    Args:
        fn: Callable that returns None (keep waiting) or a value (done).
        interval: Seconds between polls.
        timeout: Max seconds to wait before raising TimeoutError.
        desc: Description for log messages.

    Returns:
        The non-None value returned by fn.

    Raises:
        TimeoutError: If timeout is exceeded.
    """
    elapsed = 0
    while elapsed < timeout:
        result = fn()
        if result is not None:
            return result
        log.info(f"Waiting for {desc}... ({elapsed}s / {timeout}s)")
        time.sleep(interval)
        elapsed += interval

    raise TimeoutError(
        f"Timed out after {timeout}s waiting for {desc}. "
        f"Check the Alibaba Cloud console for manual intervention."
    )
