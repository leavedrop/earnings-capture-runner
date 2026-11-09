"""Bounded public-document transport; parsing and acceptance stay in the collector."""
from contextlib import asynccontextmanager

import curl_cffi
from curl_cffi.const import CurlInfo, CurlHttpVersion
from curl_cffi.requests import AsyncSession


def browser_session():
    return AsyncSession(max_clients=1, trust_env=False, timeout=(5, 12), retry=0,
                        impersonate="chrome", allow_redirects=False, discard_cookies=True, cache=None,
                        curl_infos=[CurlInfo.NAMELOOKUP_TIME, CurlInfo.CONNECT_TIME, CurlInfo.APPCONNECT_TIME,
                                    CurlInfo.PRETRANSFER_TIME, CurlInfo.STARTTRANSFER_TIME, CurlInfo.TOTAL_TIME,
                                    CurlInfo.NUM_CONNECTS])


@asynccontextmanager
async def browser_response(session, method, url, headers):
    # Eager transfer intentionally: libcurl's native first-response-byte timing
    # remains distinct from this function returning the complete decoded body.
    request_headers = {key: value for key, value in headers.items() if key.lower() == "cache-control"}
    response = await session.request(method, url, headers=request_headers)
    yield response


def browser_timing(response):
    names = {"dns_done": CurlInfo.NAMELOOKUP_TIME, "connect_done": CurlInfo.CONNECT_TIME,
             "tls_done": CurlInfo.APPCONNECT_TIME, "pretransfer_done": CurlInfo.PRETRANSFER_TIME,
             "first_response_byte": CurlInfo.STARTTRANSFER_TIME, "transfer_done": CurlInfo.TOTAL_TIME}
    native = {name: response.infos[info] * 1000 for name, info in names.items()}
    connects = response.infos[CurlInfo.NUM_CONNECTS]
    versions = {CurlHttpVersion.V1_0: "HTTP/1.0", CurlHttpVersion.V1_1: "HTTP/1.1",
                CurlHttpVersion.V2_0: "HTTP/2", CurlHttpVersion.V3: "HTTP/3"}
    return {"transport": "curl_cffi_chrome", "transport_version": curl_cffi.__version__,
            "http_version": versions.get(response.http_version, str(response.http_version)),
            "curl_cumulative_ms": native, "new_tcp_connections": connects, "connection_reused": connects == 0,
            "header_timing_semantics": "headers_ms unavailable; native first_response_byte includes response headers, not full-body return",
            "body_timing_semantics": "body_ms unavailable; eager complete transfer measured by native transfer_done and request_total_ms"}
