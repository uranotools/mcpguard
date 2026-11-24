// ============================================================================
// Normalized Contracts for @uranotools/mcpguard
// ============================================================================

export type TransportKind = 'stdio' | 'http' | 'sse' | 'urano-webhook';
export type AuthMode = 'auto' | 'none' | 'oauth' | 'bearer' | 'api-key' | 'hmac';
export type SecurityPolicy = 'strict' | 'warn' | 'off';
export type SecuritySeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type SecurityVerdict = 'CLEAN' | 'WARN' | 'SUSPICIOUS' | 'MALICIOUS';
export type ProgressMode = 'bar' | 'steps' | 'quiet';

// --- MCP Protocol Types ---

export interface JsonSchemaProperty {
  type?: string | string[];
  title?: string;
  description?: string;
  default?: unknown;
  enum?: unknown[];
  items?: JsonSchemaProperty;
  properties?: Record<string, JsonSchemaProperty>;
  required?: string[];
  'x-section'?: string;
  'x-order'?: number;
  [key: string]: unknown;
}

export interface JsonSchemaObject {
  type?: string;
  title?: string;
  description?: string;
  properties?: Record<string, JsonSchemaProperty>;
  required?: string[];
  [key: string]: unknown;
}

export interface McpToolAnnotations {
  title?: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

export interface McpToolDefinition {
  name: string;
  description?: string;
  inputSchema?: JsonSchemaObject;
  annotations?: McpToolAnnotations;
}

export interface McpResourceDefinition {
  uri: string;
  name: string;
  description?: string;
  mimeType?: string;
}

export interface McpPromptDefinition {
  name: string;
  description?: string;
  arguments?: Array<{
    name: string;
    description?: string;
    required?: boolean;
  }>;
}

export interface McpServerInfo {
  name: string;
  version?: string;
  protocolVersion?: string;
  capabilities?: Record<string, unknown>;
}

export interface McpContentItem {
  type: 'text' | 'image' | 'resource' | string;
  text?: string;
  data?: string;
  mimeType?: string;
  [key: string]: unknown;
}

export interface McpToolCallResult {
  content: McpContentItem[];
  isError?: boolean;
  structuredContent?: unknown;
  [key: string]: unknown;
}

export interface McpProgressEvent {
  progressToken: string | number;
  progress: number;
  total?: number;
  message?: string;
}

export interface McpLogEvent {
  level: string;
  logger?: string;
  data: unknown;
}

// --- Transport Adapter Contract ---

export interface RequestOptions {
  timeoutMs?: number;
  progressToken?: string;
  signal?: AbortSignal;
}

export interface McpTransportAdapter {
  readonly kind: TransportKind;
  readonly target: string;
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  request<T = unknown>(
    method: string,
    params?: Record<string, unknown>,
    opts?: RequestOptions,
  ): Promise<T>;
  notify?(method: string, params?: Record<string, unknown>): Promise<void>;
  onNotification(handler: (method: string, params: Record<string, unknown>) => void): () => void;
}

// --- Form Schema / Wizard Types ---

export type FormFieldType = 'string' | 'number' | 'boolean' | 'enum' | 'array' | 'object';

export interface FormStepField {
  name: string;
  path: string[];
  label: string;
  description?: string;
  type: FormFieldType;
  required: boolean;
  defaultValue?: unknown;
  enumValues?: string[];
  section: string;
  stepIndex: number;
}

export interface FormSection {
  name: string;
  fields: FormStepField[];
}

export interface NormalizedToolForm {
  toolName: string;
  description?: string;
  sections: FormSection[];
  steps: FormStepField[];
}

// --- Stored Configuration & Profiles ---

export interface McpServerConfig {
  name: string;
  adapter: TransportKind;
  target: string; // URL for http/sse/urano-webhook, or command for stdio
  args?: string[];
  env?: Record<string, string>;
  headers?: Record<string, string>;
  auth?: AuthMode;
  secretRef?: string; // Vault key reference (token/apiKey/hmacSecret)
  oauth?: {
    authorizationEndpoint: string;
    tokenEndpoint: string;
    clientId: string;
    scopes?: string[];
    redirectUri?: string;
  };
  installedAt: string;
  lastScannedAt?: string;
  lastVerdict?: SecurityVerdict;
}

export type ProviderDriver = 'openai-compat' | 'anthropic' | 'gemini';

export interface ProviderPreset {
  id: string;
  name: string;
  driver: ProviderDriver;
  baseUrl: string;
  envVar: string;
  defaultModel: string;
  requiresKey: boolean;
  extraHeaders?: Record<string, string>;
  docsUrl?: string;
}

export interface ConfiguredProvider {
  id: string;
  name: string;
  driver: ProviderDriver;
  baseUrl: string;
  model: string;
  secretRef?: string;
  envVar?: string;
  extraHeaders?: Record<string, string>;
  addedAt: string;
}

export interface SavedPreset {
  alias: string;
  mcpName: string;
  toolName: string;
  args: Record<string, unknown>;
  createdAt: string;
}

export interface HistoryEntry {
  id: string;
  timestamp: string;
  mcpName: string;
  toolName: string;
  args: Record<string, unknown>;
  durationMs: number;
  ok: boolean;
  error?: string;
}

export interface McpGuardConfigFile {
  version: number;
  defaultProvider?: string;
  securityPolicy: SecurityPolicy;
  threatFeeds?: string[];
  servers: Record<string, McpServerConfig>;
  providers: Record<string, ConfiguredProvider>;
  presets: Record<string, SavedPreset>;
}

// --- AI Provider Contract ---

export interface AiTextRequest {
  prompt: string;
  systemPrompt?: string;
  model?: string;
  temperature?: number;
  maxTokens?: number;
  signal?: AbortSignal;
}

export interface AiSchemaFillRequest {
  instruction: string;
  toolName: string;
  toolDescription?: string;
  schema: JsonSchemaObject;
  existingValues?: Record<string, unknown>;
  model?: string;
  signal?: AbortSignal;
}

export interface AiProviderAdapter {
  readonly id: string;
  readonly name: string;
  readonly driver: ProviderDriver;
  readonly model: string;
  streamText(req: AiTextRequest, onChunk: (delta: string) => void): Promise<string>;
  fillSchema(req: AiSchemaFillRequest): Promise<Record<string, unknown>>;
  healthCheck(): Promise<{ ok: boolean; latencyMs: number; error?: string }>;
}

// --- Security ("VirusTotal for MCP") Contracts ---

export interface SecurityFinding {
  engine: string;
  ruleId: string;
  severity: SecuritySeverity;
  title: string;
  detail: string;
  target?: string;
  evidence?: string;
  remediation?: string;
}

export interface SecurityEngineResult {
  engineId: string;
  engineName: string;
  status: 'pass' | 'warn' | 'fail' | 'skip';
  summary: string;
  durationMs?: number;
  findings: SecurityFinding[];
  metadata?: Record<string, unknown>;
}

export interface CodeEvidenceItem {
  kind: 'outbound-url' | 'env-var' | 'shell-exec' | 'fs-write' | 'dynamic-eval' | 'network-lib';
  value: string;
  file: string;
  line: number;
}

export interface CodeInspectionSummary {
  inspectedRoot: string;
  filesScanned: number;
  outboundUrls: string[];
  outboundDomains: string[];
  envVars: string[];
  capabilities: string[];
  dependencies: Record<string, string>;
  evidence: CodeEvidenceItem[];
}

export interface ArchitectureSummary {
  target: string;
  mode: 'local-inspected' | 'remote-blackbox';
  transport: TransportKind;
  serverInfo?: McpServerInfo;
  toolCount: number;
  toolsByRisk: Array<{
    name: string;
    risk: 'read' | 'write' | 'destructive' | 'exec' | 'network';
    hash: string;
    annotations?: McpToolAnnotations;
  }>;
  outboundUrls: string[];
  outboundDomains: string[];
  envVars: string[];
  osCapabilities: string[];
  oauthEndpoints?: string[];
  notes: string[];
}

export interface ToolAuditDetail {
  name: string;
  description?: string;
  descriptionChars: number;
  risk: 'read' | 'write' | 'destructive' | 'exec' | 'network';
  hash: string;
  annotations?: McpToolAnnotations;
  params: Array<{
    name: string;
    type: string;
    required: boolean;
    section: string;
    description?: string;
    enumValues?: string[];
  }>;
  findingCount: number;
}

export interface MetaDispatcherSummary {
  detected: boolean;
  dispatcherTools: string[];
  discoveryTools: string[];
  expanded: boolean;
  modules: string[];
  actions: Array<{
    name: string;
    module?: string;
    plugin?: string;
    risk: string;
    description?: string;
  }>;
  expansionError?: string;
}

export interface SecurityReport {
  target: string;
  verdict: SecurityVerdict;
  score: number; // 0 (dangerous) - 100 (clean)
  durationMs?: number;
  enginesRun: number;
  enginesFlagged: number;
  enginesSkipped: number;
  engineResults: SecurityEngineResult[];
  findings: SecurityFinding[];
  toolHashes: Record<string, string>;
  toolsDetail?: ToolAuditDetail[];
  metaDispatcher?: MetaDispatcherSummary;
  architecture?: ArchitectureSummary;
  codeInspection?: CodeInspectionSummary;
  networkTelemetry?: Record<string, unknown>;
  timestamp: string;
}

export interface SecurityScanContext {
  target: string;
  serverName?: string;
  transport: TransportKind;
  serverInfo?: McpServerInfo;
  tools: McpToolDefinition[];
  resources: McpResourceDefinition[];
  prompts: McpPromptDefinition[];
  localPath?: string;
  command?: string;
  args?: string[];
  headers?: Record<string, string>;
  oauthScopes?: string[];
  deep?: boolean;
  probe?: boolean;
  expandMeta?: boolean;
  checkCloaking?: boolean;
  vtApiKey?: string;
  threatFeeds?: string[];
  aiProvider?: AiProviderAdapter;
  connector?: {
    callTool(name: string, args: Record<string, unknown>): Promise<McpToolCallResult>;
  };
  contextStore?: McpGuardContext;
}

export interface SecurityEngine {
  readonly id: string;
  readonly name: string;
  readonly requiresNetwork?: boolean;
  analyze(ctx: SecurityScanContext): Promise<SecurityEngineResult>;
}

// --- Core Extensibility: ContextStore, FlagAdapter, AuditSuite ---

export type FlagPhase = 'pre-connect' | 'post-discover' | 'pre-call' | 'post-call' | 'post-scan';

export interface McpGuardContext {
  readonly runId: string;
  readonly startedAt: string;
  get<T = unknown>(key: string): T | undefined;
  set<T = unknown>(key: string, value: T): void;
  publish<T = unknown>(key: string, value: T, source?: string): void;
  has(key: string): boolean;
  keys(): string[];
  snapshot(): Record<string, unknown>;
  sources(): Record<string, string>;
}

export interface AuditTestResult {
  id: string;
  title: string;
  passed: boolean;
  severity: SecuritySeverity;
  detail: string;
  data?: Record<string, unknown>;
}

export interface AuditTestCase {
  readonly id: string;
  readonly title: string;
  readonly severity?: SecuritySeverity;
  run(ctx: McpGuardContext): Promise<{
    passed: boolean;
    detail: string;
    data?: Record<string, unknown>;
  }>;
}

export interface AuditSuite {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly tests: AuditTestCase[];
}

export interface AuditSuiteReport {
  suiteId: string;
  suiteName: string;
  passed: number;
  failed: number;
  total: number;
  results: AuditTestResult[];
  durationMs: number;
}

export interface FlagAdapter {
  readonly flag: string;
  readonly alias?: string;
  readonly description: string;
  readonly valueType: 'boolean' | 'string' | 'string[]';
  readonly phase: FlagPhase;
  readonly auditSuite?: AuditSuite;
  run(value: unknown, ctx: McpGuardContext): Promise<void>;
}

export interface McpGuardPlugin {
  readonly name: string;
  readonly version?: string;
  flags?: FlagAdapter[];
  auditSuites?: AuditSuite[];
  securityEngines?: SecurityEngine[];
}
