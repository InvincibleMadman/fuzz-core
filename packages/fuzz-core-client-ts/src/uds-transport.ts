import net from "node:net";
import { randomUUID } from "node:crypto";
import type { RpcRequest, RpcResponse } from "./types";

export type Subscription = {
  close: () => void;
};

export class UdsRpcTransport {
  constructor(private readonly socketPath: string) {}

  call<T = unknown>(op: string, params: Record<string, unknown> = {}): Promise<T> {
    const id = randomUUID();
    const request: RpcRequest = { id, op, params };
    return new Promise<T>((resolve, reject) => {
      const socket = net.createConnection({ path: this.socketPath });
      let buffer = "";
      socket.on("connect", () => {
        socket.write(JSON.stringify(request) + "\n");
      });
      socket.on("data", (chunk: any) => {
        buffer += chunk.toString("utf8");
        let index = buffer.indexOf("\n");
        while (index >= 0) {
          const line = buffer.slice(0, index).trim();
          buffer = buffer.slice(index + 1);
          if (line) {
            const response = JSON.parse(line) as RpcResponse<T>;
            if (response.id !== id) {
              index = buffer.indexOf("\n");
              continue;
            }
            socket.end();
            if (!response.ok) {
              reject(new Error(response.error || `RPC failed: ${op}`));
            } else {
              resolve(response.result as T);
            }
            return;
          }
          index = buffer.indexOf("\n");
        }
      });
      socket.on("error", reject);
    });
  }

  subscribe(op: string, params: Record<string, unknown>, onMessage: (payload: unknown) => void): Subscription {
    const id = randomUUID();
    const request: RpcRequest = { id, op, params };
    const socket = net.createConnection({ path: this.socketPath });
    let buffer = "";
    socket.on("connect", () => {
      socket.write(JSON.stringify(request) + "\n");
    });
    socket.on("data", (chunk: any) => {
      buffer += chunk.toString("utf8");
      let index = buffer.indexOf("\n");
      while (index >= 0) {
        const line = buffer.slice(0, index).trim();
        buffer = buffer.slice(index + 1);
        if (line) {
          const parsed = JSON.parse(line) as RpcResponse<unknown> | Record<string, unknown>;
          if ("ok" in parsed) {
            const response = parsed as RpcResponse<unknown>;
            if (!response.ok) {
              throw new Error(response.error || `Subscription failed: ${op}`);
            }
          } else {
            onMessage(parsed);
          }
        }
        index = buffer.indexOf("\n");
      }
    });
    return { close: () => socket.end() };
  }
}
