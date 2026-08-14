#!/usr/bin/env python3
"""Minimal read-only client for wink solver serve --stdio."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import Any, BinaryIO


SCHEMA_VERSION = "winkyou.stdio/v1"
FRAMING_VERSION = "lsp-content-length/v1"
MAX_RESPONSE_BYTES = 1 << 20


def write_message(stream: BinaryIO, message: dict[str, Any]) -> None:
    body = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    stream.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii"))
    stream.write(body)
    stream.flush()


def read_message(stream: BinaryIO) -> dict[str, Any]:
    header = stream.readline()
    if not header:
        raise EOFError("server closed stdout")
    if not header.endswith(b"\r\n"):
        raise RuntimeError("response header does not use CRLF")
    name, separator, value = header[:-2].partition(b":")
    if separator != b":" or name.lower() != b"content-length":
        raise RuntimeError("unexpected response header")
    blank = stream.readline()
    if blank != b"\r\n":
        raise RuntimeError("response header terminator is invalid")
    length = int(value.strip())
    if length <= 0 or length > MAX_RESPONSE_BYTES:
        raise RuntimeError("response Content-Length is outside the v1 bound")
    body = stream.read(length)
    if len(body) != length:
        raise EOFError("server returned a partial response body")
    message = json.loads(body.decode("utf-8"))
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        raise RuntimeError("response is not JSON-RPC 2.0")
    return message


def await_response(stream: BinaryIO, request_id: str) -> dict[str, Any]:
    while True:
        message = read_message(stream)
        if message.get("method") == "winkyou/progress":
            progress = message.get("params", {})
            print(
                f"progress {progress.get('request_id')}: {progress.get('stage')} "
                f"({progress.get('remaining_budget_ms')} ms left)",
                file=sys.stderr,
            )
            continue
        if message.get("id") != request_id:
            raise RuntimeError(f"unexpected response id: {message.get('id')!r}")
        if "error" in message:
            error = message["error"]
            error_class = error.get("data", {}).get("class", "unknown")
            raise RuntimeError(f"request failed: {error_class}: {error.get('message', '')}")
        return message["result"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wink", default="wink", help="path to the wink executable")
    args = parser.parse_args()
    process = subprocess.Popen(
        [args.wink, "solver", "serve", "--stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    try:
        write_message(
            process.stdin,
            {
                "jsonrpc": "2.0",
                "id": "handshake-1",
                "method": "handshake",
                "params": {
                    "schema_version": SCHEMA_VERSION,
                    "framing_version": FRAMING_VERSION,
                },
            },
        )
        handshake = await_response(process.stdout, "handshake-1")
        print(
            json.dumps(
                {
                    "schema_version": handshake["schema_version"],
                    "framing_version": handshake["framing_version"],
                    "governor_scope": handshake["governor"]["scope"],
                    "safety_trip": handshake["safety_trip"],
                },
                indent=2,
            )
        )
        write_message(
            process.stdin,
            {
                "jsonrpc": "2.0",
                "id": "status-1",
                "method": "status",
                "params": {"deadline_ms": 2000},
            },
        )
        print(json.dumps(await_response(process.stdout, "status-1"), indent=2))
        return 0
    finally:
        process.stdin.close()
        try:
            return_code = process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.terminate()
            return_code = process.wait(timeout=3)
        if return_code != 0 and process.stderr is not None:
            detail = process.stderr.read().decode("utf-8", errors="replace").strip()
            if detail:
                print(detail, file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
