import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { Navbar } from '../components/layout/Navbar';
import { KpiCards } from '../components/dashboard/KpiCards';
import { ProcessTable } from '../components/dashboard/ProcessTable';
import { EvidenceDrawer } from '../components/dashboard/EvidenceDrawer';
import { AlertItem, ProcessItem, SystemStatus } from '../types/api';

describe('Navbar Component', () => {
  it('renders brand and persistent SIMULATED DEMO DATA badge', () => {
    const mockStatus: SystemStatus = {
      status: 'running',
      mode: 'simulated',
      active_policy: 'immediate',
      active_detector: 'xgboost',
      active_manifest: {},
      data_source: 'synthetic',
      storm_panic: false,
      simulated: true,
    };

    render(
      <Navbar
        status={mockStatus}
        wsConnected={true}
        onPolicyChange={vi.fn()}
        onResetStorm={vi.fn()}
      />
    );

    expect(screen.getByText('ADAPTSHIELD')).toBeInTheDocument();
    expect(screen.getByTestId('simulated-badge')).toHaveTextContent('SIMULATED DEMO DATA');
    expect(screen.getByText('xgboost')).toBeInTheDocument();
    expect(screen.getByText('Live Stream')).toBeInTheDocument();
  });
});

describe('KpiCards Component', () => {
  it('renders correct metrics for processes, alerts, and contained threats', () => {
    const mockProcesses: ProcessItem[] = [
      {
        pid: 1001,
        process_name: 'rsync',
        label: 'backup',
        risk_level: 'NORMAL',
        ewma: 0.12,
        probability: 0.05,
        status: 'normal',
        is_frozen: false,
        is_quarantined: false,
        files_touched: 45,
        files_encrypted: 0,
        last_window_idx: 3,
        simulated: true,
      },
      {
        pid: 4099,
        process_name: 'locker_fast',
        label: 'ransomware',
        risk_level: 'CRITICAL',
        ewma: 0.95,
        probability: 0.99,
        status: 'frozen',
        is_frozen: true,
        is_quarantined: true,
        files_touched: 120,
        files_encrypted: 55,
        last_window_idx: 4,
        simulated: true,
      },
    ];

    const mockAlerts: AlertItem[] = [
      {
        id: 'alt-1',
        timestamp: new Date().toISOString(),
        pid: 4099,
        process_name: 'locker_fast',
        risk_level: 'CRITICAL',
        ewma_score: 0.95,
        model_name: 'xgboost',
        explanation: {
          type: 'tree',
          summary: 'High Shannon entropy detected',
          contributions: [],
        },
        window_data: {},
        status: 'active',
        action_taken: 'freeze',
        simulated: true,
      },
    ];

    render(
      <KpiCards
        processes={mockProcesses}
        alerts={mockAlerts}
        filesSummary={{ intact: 245, restored: 55, encrypted: 0 }}
      />
    );

    expect(screen.getByText('Monitored Processes')).toBeInTheDocument();
    expect(screen.getByText('2')).toBeInTheDocument(); // 2 processes
    expect(screen.getAllByText('1')).toHaveLength(2); // 1 active alert & 1 contained threat
    expect(screen.getByText('300 / 55')).toBeInTheDocument(); // 300 total protected, 55 restored
  });
});

describe('ProcessTable Component', () => {
  it('renders process rows with EWMA score, risk chips, and triggers action callbacks', () => {
    const mockProcesses: ProcessItem[] = [
      {
        pid: 4099,
        process_name: 'locker_fast',
        label: 'ransomware',
        risk_level: 'CRITICAL',
        ewma: 0.912,
        probability: 0.998,
        status: 'frozen',
        is_frozen: true,
        is_quarantined: true,
        files_touched: 150,
        files_encrypted: 55,
        last_window_idx: 4,
        simulated: true,
      },
    ];

    const onRelease = vi.fn();
    const onConfirm = vi.fn();

    render(
      <ProcessTable
        processes={mockProcesses}
        policy="manual"
        onRelease={onRelease}
        onConfirm={onConfirm}
      />
    );

    expect(screen.getByText('4099')).toBeInTheDocument();
    expect(screen.getByText('locker_fast')).toBeInTheDocument();
    expect(screen.getByText('0.912')).toBeInTheDocument();
    expect(screen.getByText('CRITICAL')).toBeInTheDocument();
    expect(screen.getByText('frozen')).toBeInTheDocument();

    // Click release button
    const releaseBtn = screen.getByText('Release');
    fireEvent.click(releaseBtn);
    expect(onRelease).toHaveBeenCalledWith(4099);

    // Click confirm button
    const confirmBtn = screen.getByText('Confirm');
    fireEvent.click(confirmBtn);
    expect(onConfirm).toHaveBeenCalledWith(4099);
  });
});

describe('EvidenceDrawer Component', () => {
  it('renders forensic alert attribution and feature contributions when open', () => {
    const mockAlert: AlertItem = {
      id: 'alert-abc-123',
      timestamp: new Date().toISOString(),
      pid: 4099,
      process_name: 'locker_fast',
      risk_level: 'CRITICAL',
      ewma_score: 0.92,
      model_name: 'xgboost',
      explanation: {
        type: 'tree_feature_contributions',
        summary: 'Elevated byte entropy (7.92) and rapid file modification rate',
        contributions: [
          {
            feature: 't1_mean_entropy',
            value: 7.92,
            contribution_score: 0.38,
            narrative: 'High byte entropy (7.92) indicates encrypted payload',
          },
        ],
      },
      window_data: { pid: 4099, mod_rate: 65.0 },
      status: 'active',
      action_taken: 'freeze',
      simulated: true,
    };

    const onClose = vi.fn();

    render(
      <EvidenceDrawer
        alert={mockAlert}
        isOpen={true}
        onClose={onClose}
      />
    );

    expect(screen.getByText('Forensic Alert Evidence')).toBeInTheDocument();
    expect(screen.getByText(/Elevated byte entropy/)).toBeInTheDocument();
    expect(screen.getByText('t1_mean_entropy')).toBeInTheDocument();
    expect(screen.getByText('Value: 7.92')).toBeInTheDocument();
  });
});

