import { UdsRpcTransport } from "./uds-transport";
import type { ConfigObject, InstrumentInput, ProtocolAnalyzeInput, RiskAnalyzeInput, RiskPreviewInput, SeedGenerateInput } from "./types";

export class FuzzCoreClient {
  private readonly transport: UdsRpcTransport;

  constructor(socketPath = "/tmp/fuzz-core.sock") {
    this.transport = new UdsRpcTransport(socketPath);
  }

  ping() {
    return this.transport.call<{ ok: boolean }>("system.ping");
  }

  getConfig() {
    return this.transport.call<ConfigObject>("config.get");
  }

  patchConfig(patch: ConfigObject) {
    return this.transport.call<ConfigObject>("config.patch", { patch });
  }

  readonly protocol = {
    analyze: (input: ProtocolAnalyzeInput) => this.transport.call("offline.protocol.analyze", input as Record<string, unknown>),
  };

  readonly seeds = {
    generate: (input: SeedGenerateInput) => this.transport.call("offline.seeds.generate", input as Record<string, unknown>),
  };

  readonly risk = {
    analyze: (input: RiskAnalyzeInput) => this.transport.call("offline.risk.analyze", input as Record<string, unknown>),
    preview: (input: RiskPreviewInput = {}) => this.transport.call("offline.risk.preview", input as Record<string, unknown>),
  };

  readonly instrument = {
    run: (input: InstrumentInput) => this.transport.call("offline.instrument", input as Record<string, unknown>),
  };

  readonly jobs = {
    create: (input: Record<string, unknown>) => this.transport.call("jobs.create", input),
    list: () => this.transport.call("jobs.list"),
    get: (jobId: string) => this.transport.call("jobs.get", { job_id: jobId }),
    stop: (jobId: string) => this.transport.call("jobs.stop", { job_id: jobId }),
    lookupByOutput: (outputPath: string) => this.transport.call("jobs.lookup_by_output", { output_path: outputPath }),
    lookupByPid: (pid: number) => this.transport.call("jobs.lookup_by_pid", { pid }),
    metrics: {
      get: (jobId: string) => this.transport.call("jobs.metrics.get", { job_id: jobId }),
      history: (jobId: string, limit = 200) => this.transport.call("jobs.metrics.history", { job_id: jobId, limit }),
      subscribe: (jobId: string, onMessage: (payload: unknown) => void) => this.transport.subscribe("jobs.metrics.subscribe", { job_id: jobId }, onMessage),
    },
    artifacts: {
      list: (jobId: string) => this.transport.call("jobs.artifacts.list", { job_id: jobId }),
      get: (jobId: string, artifactId: string) => this.transport.call("jobs.artifacts.get", { job_id: jobId, artifact_id: artifactId }),
      replay: (jobId: string, artifactId: string) => this.transport.call("jobs.artifacts.replay", { job_id: jobId, artifact_id: artifactId }),
      analyze: (jobId: string, artifactId: string) => this.transport.call("jobs.artifacts.analyze", { job_id: jobId, artifact_id: artifactId }),
      subscribe: (jobId: string, onMessage: (payload: unknown) => void) => this.transport.subscribe("jobs.artifacts.subscribe", { job_id: jobId }, onMessage),
    },
    events: {
      subscribe: (jobId: string, onMessage: (payload: unknown) => void) => this.transport.subscribe("jobs.events.subscribe", { job_id: jobId }, onMessage),
    },
    logs: {
      tail: (jobId: string, limit = 100) => this.transport.call("jobs.logs.tail", { job_id: jobId, limit }),
    },
  };
}
