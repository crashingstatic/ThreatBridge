"""Running a reader over several evidence files at once, in worker processes."""
import multiprocessing
from collections import deque
from concurrent.futures import ProcessPoolExecutor
from itertools import islice


def in_order(func, items, workers, *args):
    """(item, func(item, *args)) for each item, in the order given.

    With more than one worker and item, the calls run in that many worker processes. Each
    finished result waits until it is used, and no more than `workers` calls run ahead, so
    memory stays bounded. Worker processes are started fresh ("spawn"), so they inherit no
    open files, locks or threads from the server."""
    items = list(items)
    if workers <= 1 or len(items) <= 1:
        for item in items:
            yield item, func(item, *args)
        return
    workers = min(workers, len(items))
    pool = ProcessPoolExecutor(workers, mp_context=multiprocessing.get_context("spawn"))
    try:
        todo = iter(items)
        pending = deque((item, pool.submit(func, item, *args)) for item in islice(todo, workers))
        while pending:
            item, future = pending.popleft()
            result = future.result()
            for nxt in todo:                     # keep the workers busy while this one is used
                pending.append((nxt, pool.submit(func, nxt, *args)))
                break
            yield item, result
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
