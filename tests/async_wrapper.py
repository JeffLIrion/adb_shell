import asyncio


def _await(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def awaiter(func):
    def sync_func(*args, **kwargs):
        return _await(func(*args, **kwargs))

    return sync_func
