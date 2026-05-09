from __future__ import annotations

import asyncio
import contextlib
import json
import os
from pathlib import Path
from typing import Any, Awaitable, Callable


class UdsRpcServer:
    def __init__(self, path: str, handlers: dict[str, Callable[..., Any] | Callable[..., Awaitable[Any]]]) -> None:
        self.path = path
        self.handlers = handlers
        self.server: asyncio.base_events.Server | None = None

    async def start(self) -> None:
        sock = Path(self.path)
        sock.parent.mkdir(parents=True, exist_ok=True)
        if sock.exists():
            sock.unlink()
        self.server = await asyncio.start_unix_server(self._handle_client, path=self.path)

    async def close(self) -> None:
        if self.server is None:
            return
        self.server.close()
        await self.server.wait_closed()
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self.path)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        subscriptions: list[asyncio.Queue] = []
        try:
            while not reader.at_eof():
                raw = await reader.readline()
                if not raw:
                    break
                try:
                    req = json.loads(raw.decode("utf-8"))
                except json.JSONDecodeError as exc:
                    writer.write((json.dumps({"ok": False, "error": f"invalid json: {exc}"}) + "\n").encode("utf-8"))
                    await writer.drain()
                    continue

                op = req.get("op")
                req_id = req.get("id")
                params = req.get("params") or {}
                handler = self.handlers.get(op)
                if handler is None:
                    writer.write((json.dumps({"ok": False, "id": req_id, "error": f"unknown op: {op}"}) + "\n").encode("utf-8"))
                    await writer.drain()
                    continue

                try:
                    result = handler(**params)
                    if asyncio.iscoroutine(result):
                        result = await result
                    if isinstance(result, tuple) and len(result) == 2 and isinstance(result[1], asyncio.Queue):
                        initial, queue = result
                        subscriptions.append(queue)
                        writer.write((json.dumps({"ok": True, "id": req_id, "result": initial, "subscribed": True}) + "\n").encode("utf-8"))
                        await writer.drain()
                        asyncio.create_task(self._pump_subscription(queue, writer))
                    else:
                        writer.write((json.dumps({"ok": True, "id": req_id, "result": result}) + "\n").encode("utf-8"))
                        await writer.drain()
                except Exception as exc:
                    writer.write((json.dumps({"ok": False, "id": req_id, "error": str(exc)}) + "\n").encode("utf-8"))
                    await writer.drain()
        finally:
            for queue in subscriptions:
                with contextlib.suppress(Exception):
                    queue.put_nowait(None)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _pump_subscription(self, queue: asyncio.Queue, writer: asyncio.StreamWriter) -> None:
        while True:
            item = await queue.get()
            if item is None:
                return
            writer.write((item + "\n").encode("utf-8"))
            await writer.drain()
