/**
 * TypeScript API contracts matching the AdaptShield backend.
 */

export interface SystemStatus {
  status: string;
  mode: 'simulated' | 'live';
  active_policy: 'immediate' | 'manual' | 'none';
  active_detector: string;
  active_manifest: Record<string, any>;
  data_source: string;
  storm_panic: boolean;
  running_scenario?: {
    run_id: string;
    scenario_name: string;
    speed: number;
    seed: number;
    total_windows: number;
  } | null;
  simulated: boolean;
}

export interface ProcessItem {
  pid: number;
  process_name: string;
  cmdline?: string;
  label: string;
  risk_level: 'NORMAL' | 'ELEVATED' | 'CRITICAL';
  ewma: number;
  probability: number;
  status: 'normal' | 'monitored' | 'frozen' | 'quarantined' | 'killed';
  is_frozen: boolean;
  is_quarantined: boolean;
  files_touched: number;
  files_encrypted: number;
  last_window_idx: number;
  updated_at?: string;
  simulated: boolean;
}

export interface FeatureContribution {
  feature: string;
  value: number;
  importance_weight?: number;
  contribution_score?: number;
  narrative?: string;
  fired?: boolean;
  threshold?: number;
}

export interface AlertExplanation {
  type: string;
  summary: string;
  contributions: FeatureContribution[];
  baseline_risk?: number;
  predicted_risk?: number;
}

export interface AlertItem {
  id: string;
  run_id?: string;
  timestamp: string;
  pid: number;
  process_name: string;
  risk_level: string;
  ewma_score: number;
  model_name: string;
  explanation: AlertExplanation;
  window_data: Record<string, any>;
  status: 'active' | 'released' | 'confirmed';
  action_taken: string;
  simulated: boolean;
}

export interface ScenarioDefinition {
  id: string;
  name: string;
  description: string;
  duration_windows: number;
  processes_count: number;
  family: string;
  expected_outcome: string;
}

export interface ScenarioRunDetail {
  id: string;
  scenario_name: string;
  detector: string;
  policy: string;
  speed: number;
  seed: number;
  status: 'running' | 'completed' | 'stopped' | 'failed';
  started_at: string;
  completed_at?: string | null;
  total_windows: number;
  distinct_pids: number;
  contained_pids: number[];
  time_to_detect_windows?: number | null;
  time_to_detect_seconds?: number | null;
  wall_time_seconds?: number | null;
  files_encrypted: number;
  files_restored: number;
  files_intact: number;
  panic_tripped: boolean;
  summary: Record<string, any>;
  simulated: boolean;
}

export interface WebSocketEvent {
  type: string;
  data: any;
  simulated: boolean;
}

export interface WebSocketBatchMessage {
  type: 'batch';
  count: number;
  events: WebSocketEvent[];
  simulated: boolean;
}
