# Contributing to AdaptShield

Thank you for your interest in contributing to AdaptShield.

## Code of Conduct & Defensive Scope
AdaptShield is an open-source defensive host security project.
- **Defensive Scope Only:** Pull requests must focus strictly on detection, containment, system safety, and recovery. Submissions containing functional evasion techniques, weaponized payloads, or real malware binaries will be rejected.
- **Safe Testing:** Use only simulated workloads (`adaptshield simulate benign` or `adaptshield simulate ransomware`) that target isolated sandbox directories.

---

## Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/saam-07/RansomRadar.git
   cd RansomRadar
   ```

2. **Set up Python Virtual Environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   pip install -e .
   ```

3. **Run Unit Tests:**
   ```bash
   pytest tests/ -v
   ```

4. **Lint and Code Style:**
   ```bash
   ruff check src tests
   ```

---

## Contributing Machine Learning Models
If adding a new classifier:
1. Implement the `Classifier` protocol defined in `src/adaptshield/ml/classifier.py`.
2. Adhere to the canonical 11-feature contract defined in `src/adaptshield/ml/schema.py`.
3. Provide model evaluation metrics on both standard test splits and `traces_hard_test.csv`.
4. Register the model in `models/registry/registry_manifest.json` with appropriate `data_source` tagging (`real` vs `synthetic`).
