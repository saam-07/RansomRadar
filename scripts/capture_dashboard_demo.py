"""
Generates high-resolution dashboard screenshot preview for documentation.
"""

from PIL import Image, ImageDraw
import os

img = Image.new('RGB', (1280, 800), color='#080d1a')
d = ImageDraw.Draw(img)

# Navbar
d.rectangle([(0, 0), (1280, 56)], fill='#0d1527', outline='#1e293b')
d.text((24, 18), 'ADAPTSHIELD', fill='#60a5fa')
d.rectangle([(160, 14), (340, 42)], fill='#292218', outline='#f59e0b')
d.text((172, 20), 'SIMULATED DEMO DATA', fill='#fbbf24')

# Navbar right items
d.rectangle([(800, 14), (910, 42)], fill='#0f172a', outline='#334155')
d.text((810, 20), 'Policy: Immediate', fill='#cbd5e1')
d.rectangle([(920, 14), (1070, 42)], fill='#0f172a', outline='#334155')
d.text((930, 20), 'Detector: xgboost [synth]', fill='#34d399')
d.rectangle([(1080, 14), (1250, 42)], fill='#064e3b', outline='#10b981')
d.text((1095, 20), 'Live Stream Active', fill='#6ee7b7')

# Sidebar
d.rectangle([(0, 56), (220, 800)], fill='#0a0f1d', outline='#1e293b')
d.text((24, 80), 'NAVIGATION', fill='#64748b')
d.rectangle([(12, 105), (208, 140)], fill='#1e3a5f', outline='#3b82f6')
d.text((24, 115), 'Live Dashboard', fill='#93c5fd')
d.text((24, 160), 'Scenario Runner [P7]', fill='#94a3b8')
d.text((24, 200), 'Detector Comparison [P7]', fill='#94a3b8')
d.text((24, 240), 'Datasets Explorer [P8]', fill='#94a3b8')
d.text((24, 280), 'Models & Training [P8]', fill='#94a3b8')
d.text((24, 320), 'Alerts & Forensics [P9]', fill='#94a3b8')
d.text((24, 360), 'System Settings [P9]', fill='#94a3b8')

# KPI Cards
d.rectangle([(240, 75), (470, 160)], fill='#0d1424', outline='#1e293b')
d.text((255, 88), 'MONITORED PROCESSES', fill='#94a3b8')
d.text((255, 110), '2', fill='#ffffff')
d.text((255, 135), '1 operating normally', fill='#64748b')

d.rectangle([(490, 75), (720, 160)], fill='#1a1018', outline='#dc2626')
d.text((505, 88), 'ACTIVE ALERTS', fill='#f87171')
d.text((505, 110), '1', fill='#ffffff')
d.text((505, 135), 'CRITICAL containment trigger', fill='#fca5a5')

d.rectangle([(740, 75), (970, 160)], fill='#1a1510', outline='#d97706')
d.text((755, 88), 'CONTAINED THREATS', fill='#fbbf24')
d.text((755, 110), '1', fill='#ffffff')
d.text((755, 135), 'PID 4099 frozen & rolled back', fill='#fcd34d')

d.rectangle([(990, 75), (1250, 160)], fill='#0d1a15', outline='#059669')
d.text((1005, 88), 'FILES PROTECTED / RESTORED', fill='#34d399')
d.text((1005, 110), '300 / 55', fill='#ffffff')
d.text((1005, 135), '55 restored via overlayfs', fill='#6ee7b7')

# Risk Timeline Chart Box
d.rectangle([(240, 180), (1250, 420)], fill='#0d1424', outline='#1e293b')
d.text((255, 195), 'PROCESS RISK TELEMETRY TIMELINE (EWMA & PROBABILITY)', fill='#cbd5e1')
d.text((950, 195), 'Thresholds: 0.3 Elev | 0.6 Susp | 0.85 Contain', fill='#94a3b8')
# Chart axes and reference lines
d.line([(280, 380), (1220, 380)], fill='#334155', width=1)
d.line([(280, 230), (280, 380)], fill='#334155', width=1)
d.line([(280, 335), (1220, 335)], fill='#ca8a04', width=1)
d.text((290, 338), '0.3 Elevated', fill='#eab308')
d.line([(280, 290), (1220, 290)], fill='#ea580c', width=1)
d.text((290, 293), '0.6 Suspicion', fill='#f97316')
d.line([(280, 252), (1220, 252)], fill='#dc2626', width=1)
d.text((290, 255), '0.85 Critical (Containment Threshold)', fill='#ef4444')
# Draw EWMA curve rising and plateauing
points = [(300, 375), (400, 370), (500, 365), (600, 350), (700, 310), (800, 260), (900, 245), (1000, 245), (1100, 245), (1200, 245)]
d.line(points, fill='#38bdf8', width=3)
d.text((910, 230), 'PID 4099 Freezed & Rolled Back', fill='#f87171')

# Process Table Box
d.rectangle([(240, 440), (880, 770)], fill='#0d1424', outline='#1e293b')
d.text((255, 455), 'MONITORED PROCESS TABLE', fill='#cbd5e1')
d.text((255, 485), 'PID    NAME          RISK EWMA    LEVEL      STATUS     FILES TOUCHED   ACTIONS', fill='#64748b')
d.line([(255, 505), (865, 505)], fill='#1e293b', width=1)
d.text((255, 520), '4099   locker_fast   0.912        CRITICAL   frozen     120 (55 enc)    [Release] [Confirm]', fill='#f87171')
d.text((255, 560), '1042   workload_ben  0.042        NORMAL     normal      15 (0 enc)     Active', fill='#94a3b8')

# Forensic Alert Feed Box
d.rectangle([(900, 440), (1250, 770)], fill='#0d1424', outline='#1e293b')
d.text((915, 455), 'FORENSIC ALERT FEED', fill='#cbd5e1')
d.rectangle([(915, 485), (1235, 600)], fill='#1f121a', outline='#b91c1c')
d.text((925, 495), 'CRITICAL: PID 4099 (locker_fast)', fill='#f87171')
d.text((925, 520), 'High Shannon entropy (7.92) & write ratio (85.0)', fill='#fca5a5')
d.text((925, 545), 'Action: FREEZE & ROLLBACK (55 files restored)', fill='#f87171')
d.text((925, 575), 'Evidence Drawer: Click to view attribution ->', fill='#60a5fa')

os.makedirs('docs/demo', exist_ok=True)
img.save('docs/demo/dashboard_live.png')
print('Saved docs/demo/dashboard_live.png successfully!')
