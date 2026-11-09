"""Process-local repair for the reproduced httpcore 1.0.9 proxy TLS leak.

CONNECT can succeed before TLS fails. Upstream then leaves that tunnel ACTIVE
forever, eventually making even unrelated requests fail with PoolTimeout.
See https://github.com/encode/httpcore/discussions/921 .
"""
from functools import wraps

import httpcore
from httpcore._async.http_proxy import AsyncTunnelHTTPConnection
from httpcore._synchronization import AsyncShieldCancellation


def apply_proxy_tls_fix() -> None:
    """Close failed, unestablished tunnels; affect only this Python process.

    This uses private internals verified against httpcore==1.0.9. Keep that
    dependency pinned until the upstream fix is reviewed and this shim removed.
    Healthy connections, TLS verification, and request limits are unchanged.
    """
    if httpcore.__version__ != "1.0.9":
        raise RuntimeError("Proxy TLS cleanup requires reviewed httpcore==1.0.9")
    original = AsyncTunnelHTTPConnection.handle_async_request
    if getattr(original, "_earnings_proxy_tls_cleanup", False):
        return

    @wraps(original)
    async def handle_async_request(self, request):
        try:
            return await original(self, request)
        except BaseException:
            if not self._connected:
                with AsyncShieldCancellation():
                    await self.aclose()
            raise

    handle_async_request._earnings_proxy_tls_cleanup = True
    AsyncTunnelHTTPConnection.handle_async_request = handle_async_request
