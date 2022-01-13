import asyncio
import warnings



def _await(coro):
    """Create a new event loop, run the coroutine, then close the event loop."""
    loop = asyncio.new_event_loop()

    with warnings.catch_warnings(record=True) as warns:
        ret = loop.run_until_complete(coro)
        loop.close()

        if warns:
            raise RuntimeError

        return ret


def awaiter(func):
    def sync_func(*args, **kwargs):
        return _await(func(*args, **kwargs))

    return sync_func
