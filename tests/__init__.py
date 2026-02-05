"""Test configuration."""
import pytest


@pytest.fixture(scope="session")
def event_loop_policy():
    """Set event loop policy for async tests."""
    import asyncio
    return asyncio.DefaultEventLoopPolicy()
