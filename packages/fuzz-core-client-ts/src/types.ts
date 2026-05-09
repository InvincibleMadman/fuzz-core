export type RpcRequest = {
  id: string;
  op: string;
  params?: Record<string, unknown>;
};

export type RpcResponse<T = unknown> = {
  ok: boolean;
  id?: string;
  result?: T;
  error?: string;
  subscribed?: boolean;
};

export type ConfigObject = Record<string, unknown>;

export type ProtocolAnalyzeInput = {
  source_path: string;
  output_path?: string;
  protocol_name?: string;
  copy_to_scan_dir?: boolean;
  lang?: string;
  implementation?: string;
  protocol_style?: string;
  profile?: string;
  protocol_variant?: string;
  iterations?: number;
  temperature?: number;
  max_tokens?: number;
  base_url?: string;
  api_key?: string;
  model?: string;
};

export type SeedGenerateInput = {
  spec_path?: string;
  spec_dir?: string;
  output_dir?: string;
  count?: number;
  binary?: boolean;
  issue_doc_dir?: string;
  use_uploaded_vuldocs?: boolean;
};

export type RiskAnalyzeInput = {
  source_path: string;
  output_path?: string;
  copy_to_scan_dir?: boolean;
  iterations?: number;
  temperature_coefficient?: number;
  max_tokens?: number;
};

export type RiskPreviewInput = {
  analysis_path?: string;
};

export type InstrumentInput = {
  source_path?: string;
  analysis_path?: string;
  output_path?: string;
  in_place?: boolean;
};
