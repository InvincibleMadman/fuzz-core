declare module "node:net" {
  type Socket = {
    on(event: string, listener: (...args: any[]) => void): Socket;
    write(data: string): void;
    end(): void;
  };
  export function createConnection(options: { path: string }): Socket;
  const net: { createConnection: typeof createConnection };
  export default net;
}

declare module "node:crypto" {
  export function randomUUID(): string;
}
