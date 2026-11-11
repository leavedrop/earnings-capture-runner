"""Bounded public-document transport; parsing and acceptance stay in the collector."""
from contextlib import asynccontextmanager
import asyncio
import hashlib
import re
import time

import curl_cffi
from curl_cffi.const import CurlInfo, CurlHttpVersion
from curl_cffi.requests import AsyncSession


def browser_session(proxy=None):
    return AsyncSession(max_clients=16, trust_env=False, proxy=proxy, timeout=(5, 12), retry=0,
                        impersonate="chrome", allow_redirects=True, max_redirects=5, discard_cookies=True, cache=None,
                        curl_infos=[CurlInfo.NAMELOOKUP_TIME, CurlInfo.CONNECT_TIME, CurlInfo.APPCONNECT_TIME,
                                    CurlInfo.PRETRANSFER_TIME, CurlInfo.STARTTRANSFER_TIME, CurlInfo.TOTAL_TIME,
                                    CurlInfo.NUM_CONNECTS])


@asynccontextmanager
async def browser_response(session, method, url, headers, request_json=None):
    # Eager transfer intentionally: libcurl's native first-response-byte timing
    # remains distinct from this function returning the complete decoded body.
    request_headers = {key: value for key, value in headers.items() if key.lower() in ("cache-control", "if-none-match", "if-modified-since", "content-type", "origin", "referer")}
    response = await session.request(method, url, headers=request_headers,
                                     **({"json": request_json} if request_json is not None else {}))
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


async def download_kkr_ranges(connections, url, size, wait):
    """Assemble four strictly verified responses; size is trusted issuer metadata.

    The caller owns four independent curl sessions and the shared rate limiter.
    Stream-ready timing is not header arrival; first-body timing is the first
    nonempty chunk consumed by this application. No retry or redirect is made.
    """
    if len(connections) != 4 or len({id(connection) for connection in connections}) != 4:
        raise ValueError("Four independent curl sessions are required")
    etag = None
    versions = {CurlHttpVersion.V1_0: "HTTP/1.0", CurlHttpVersion.V1_1: "HTTP/1.1",
                CurlHttpVersion.V2_0: "HTTP/2", CurlHttpVersion.V3: "HTTP/3"}

    async def part(index):
        nonlocal etag
        first, last = index * size // 4, (index + 1) * size // 4 - 1
        queued = time.perf_counter_ns()
        record = {"part": index, "requested_range": f"bytes={first}-{last}",
                  "expected_bytes": last-first+1, "expected_total_bytes": size,
                  "status": None, "http_version": None, "verified": False,
                  "http_response_complete": False, "stopped_on_headers": False,
                  "error_type": None, "queued_mono_ns": queued,
                  "request_start_mono_ns": None, "stream_response_ready_mono_ns": None,
                  "first_body_chunk_mono_ns": None, "eof_mono_ns": None,
                  "new_tcp_connections": None, "connection_reused": None}
        body = bytearray()
        try:
            await wait()
            record["request_start_mono_ns"] = time.perf_counter_ns()
            async with connections[index].stream("GET", url, allow_redirects=False,
                    headers={"Range": record["requested_range"], "Accept-Encoding": "identity"}) as response:
                # curl_cffi snapshots configured infos when the stream becomes
                # readable. Read that snapshot, not a reset/released curl handle.
                connects = response.infos.get(CurlInfo.NUM_CONNECTS)
                record.update(status=response.status_code, final_url=str(response.url),
                    new_tcp_connections=connects,
                    connection_reused=connects == 0 if connects is not None else None,
                    http_version=versions.get(response.http_version, str(response.http_version)),
                    content_type=response.headers.get("content-type"),
                    content_range=response.headers.get("content-range"),
                    content_length=response.headers.get("content-length"),
                    content_encoding=response.headers.get("content-encoding"),
                    retry_after=response.headers.get("retry-after"),
                    etag=response.headers.get("etag"), stream_response_ready_mono_ns=time.perf_counter_ns())
                if (record["status"] != 206
                        or (record["content_range"] or "").strip().lower() != f"bytes {first}-{last}/{size}"
                        or record["content_length"] != str(last-first+1)
                        or (record["content_encoding"] or "identity").lower() != "identity"
                        or not re.fullmatch(r'"[^"\r\n]*"', record["etag"] or "")
                        or etag is not None and etag != record["etag"]):
                    # Pinned curl_cffi streaming close waits; abort its next write
                    # instead of draining an ignored Range / rejected version.
                    response.quit_now.set()
                    record["stopped_on_headers"] = True
                    raise ValueError("Range headers or strong ETag do not match")
                etag = record["etag"]
                async for chunk in response.aiter_content():
                    if chunk and record["first_body_chunk_mono_ns"] is None:
                        record["first_body_chunk_mono_ns"] = time.perf_counter_ns()
                    body.extend(chunk)
                    if len(body) > record["expected_bytes"]:
                        response.quit_now.set()
                        raise ValueError("Range response exceeded the requested bytes")
                record["eof_mono_ns"] = time.perf_counter_ns()
                if len(body) != record["expected_bytes"]:
                    raise ValueError("Range EOF arrived before all requested bytes")
                record.update(http_response_complete=True, verified=True)
        except Exception as exc:
            record.update(error_type=type(exc).__name__, verified=False)
        ended = time.perf_counter_ns()
        requested = record["request_start_mono_ns"]
        record.update(request_end_mono_ns=ended, bytes=len(body), sha256=hashlib.sha256(body).hexdigest(),
                      queue_ms=((requested or ended)-queued)/1e6,
                      request_total_ms=(ended-requested)/1e6 if requested is not None else None)
        return record, bytes(body)

    pieces = await asyncio.gather(*(part(index) for index in range(4)))
    verified = all(record["verified"] for record, _ in pieces)
    return {"verified": verified, "body": b"".join(body for _, body in pieces) if verified else b"",
            "parts": [record for record, _ in pieces], "etag": etag}
