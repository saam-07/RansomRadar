import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AlertsPage } from '../pages/AlertsPage';
import { SettingsPage } from '../pages/SettingsPage';
import { GuidedDemoModal } from '../components/demo/GuidedDemoModal';
import { api } from '../api/client';

// Mock API client
vi.mock('../api/client', () => ({
  api: {
    getAlerts: vi.fn(),
    getAlertDetail: vi.fn(),
    releaseProcess: vi.fn(),
    confirmProcess: vi.fn(),
    getSettings: vi.fn(),
    updateSettings: vi.fn(),
    resetDemoState: vi.fn(),
    runScenario: vi.fn(),
  },
}));

describe('AlertsPage Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (api.getAlerts as any).mockResolvedValue({
      total: 2,
      alerts: [
        {
          id: 'alert-001',
          pid: 4099,
          process_name: 'locker_fast',
          risk_level: 'CRITICAL',
          ewma_score: 0.94,
          model_name: 'xgboost',
          status: 'active',
          action_taken: 'freeze',
          timestamp: '2026-10-06T15:30:00Z',
          explanation: {
            summary: 'High write entropy and rapid rename operations detected.',
            contributions: {
              t1_mean_entropy: 0.42,
              rename_rate: 0.31,
            },
          },
          window_data: {
            event_count: 140,
            mod_rate: 65.0,
            rename_rate: 30.0,
            t1_mean_entropy: 7.91,
            t1_write_rate: 80.0,
          },
          simulated: true,
        },
        {
          id: 'alert-002',
          pid: 2011,
          process_name: 'rsync_backup',
          risk_level: 'WATCH',
          ewma_score: 0.32,
          model_name: 'xgboost',
          status: 'released',
          action_taken: 'monitor',
          timestamp: '2026-10-06T15:20:00Z',
          explanation: { summary: 'Slight burst in modification rate.' },
          window_data: { event_count: 85, mod_rate: 40.0, rename_rate: 0.1 },
          simulated: true,
        },
      ],
      simulated: true,
    });
    (api.releaseProcess as any).mockResolvedValue({ success: true });
    (api.confirmProcess as any).mockResolvedValue({ success: true });
  });

  it('renders alerts table and displays alert rows', async () => {
    render(<AlertsPage />);

    await waitFor(() => {
      expect(screen.getByText('Alerts & Forensic Investigation')).toBeInTheDocument();
      expect(screen.getByText('locker_fast')).toBeInTheDocument();
      expect(screen.getByText('rsync_backup')).toBeInTheDocument();
      expect(screen.getByText('4099')).toBeInTheDocument();
    });
  });

  it('opens forensic evidence drawer when clicking an alert', async () => {
    render(<AlertsPage />);

    await waitFor(() => {
      expect(screen.getByText('locker_fast')).toBeInTheDocument();
    });

    const evidenceBtns = screen.getAllByRole('button', { name: /Evidence/i });
    fireEvent.click(evidenceBtns[0]);

    await waitFor(() => {
      expect(screen.getByText('Forensic Evidence Drawer')).toBeInTheDocument();
    });

    expect(screen.getByText('Release Process')).toBeInTheDocument();
    expect(screen.getByText('Confirm Threat')).toBeInTheDocument();
  });
});

describe('SettingsPage Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (api.getSettings as any).mockResolvedValue({
      theta0: 0.5,
      window: 2.0,
      ewma_alpha: 0.4,
      watch_threshold: 0.3,
      suspect_threshold: 0.6,
      critical_threshold: 0.85,
      critical_confirm_windows: 2,
      policy: 'immediate',
      auto_resolve_timeout: 10.0,
      panic_storm_threshold: 5,
      allowlist: ['rsync', 'tar', 'postgres', 'mysqld', 'sshd'],
      mode: 'simulated',
      simulated: true,
    });
    (api.updateSettings as any).mockResolvedValue({ success: true });
    (api.resetDemoState as any).mockResolvedValue({ success: true, message: 'Reset done' });
  });

  it('renders settings controls, thresholds, and allowlist', async () => {
    render(<SettingsPage />);

    await waitFor(() => {
      expect(screen.getByText('Engine Settings & Containment Safety Rails')).toBeInTheDocument();
      expect(screen.getByText(/EWMA Alpha/i)).toBeInTheDocument();
      expect(screen.getByText('Response Policy Semantics:')).toBeInTheDocument();
      expect(screen.getByText('rsync')).toBeInTheDocument();
      expect(screen.getByText('postgres')).toBeInTheDocument();
      expect(screen.getByText('Reset Demo State')).toBeInTheDocument();
    });
  });

  it('allows adding an allowlist item', async () => {
    render(<SettingsPage />);

    await waitFor(() => {
      expect(screen.getByPlaceholderText(/Add process name/i)).toBeInTheDocument();
    });

    const input = screen.getByPlaceholderText(/Add process name/i);
    fireEvent.change(input, { target: { value: 'nginx' } });
    fireEvent.click(screen.getByRole('button', { name: /Add/i }));

    expect(screen.getByText('nginx')).toBeInTheDocument();
  });
});

describe('GuidedDemoModal Component', () => {
  it('renders 5-step guided story mode and navigates steps', async () => {
    const handleClose = vi.fn();
    const handleNavigate = vi.fn();

    render(<GuidedDemoModal isOpen={true} onClose={handleClose} onNavigate={handleNavigate} />);

    expect(screen.getByText('AdaptShield 3-Minute Guided Demo')).toBeInTheDocument();
    expect(screen.getByText('Normal Workday: Quiet Baseline')).toBeInTheDocument();
    expect(screen.getByText('Presenter Narration Script:')).toBeInTheDocument();
    expect(screen.getByText('Simulate Normal Workday')).toBeInTheDocument();

    // Click Next Step
    fireEvent.click(screen.getByText('Next Step'));

    expect(screen.getByText('Nightly Backup: High I/O Stress Test')).toBeInTheDocument();
    expect(screen.getByText('Simulate Nightly Backup')).toBeInTheDocument();
  });
});
