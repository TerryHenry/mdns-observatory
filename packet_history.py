"""Bounded packet-history helpers used by the analyzer and regression tests."""
from __future__ import annotations

MAX_PACKET_HISTORY = 100_000
TRIM_BATCH_SIZE = 5_000


def append_bounded(packets: list, packet, limit: int = MAX_PACKET_HISTORY,
                   trim_batch: int = TRIM_BATCH_SIZE) -> int:
    """Append a packet and trim history in batches to avoid per-packet slicing.

    Returns the number of observations removed. The list never exceeds ``limit``
    after this function returns. Batch deletion trades a small amount of retained
    history after a trim for dramatically less list-copying on long captures.
    """
    if limit < 1 or trim_batch < 1:
        raise ValueError("limit and trim_batch must be positive")
    packets.append(packet)
    if len(packets) > limit:
        remove_count = min(trim_batch, len(packets))
        del packets[:remove_count]
        return remove_count
    return 0
