# Hybrid Smart Contract Security Analysis (Slither + Mythril)

## Overview

This project is a research-oriented framework for analyzing Ethereum smart contract security using a hybrid approach that combines:

- **Source-level static analysis** (Slither)
- **Bytecode-level symbolic analysis** (Mythril)

The goal is to improve vulnerability detection accuracy by:
- reducing false positives
- detecting low-level issues not visible in Solidity source
- combining results from multiple analysis layers

---

## Features

- Custom **Slither detectors**:
  - Access control issues
  - EIP-712 signature validation flaws
  - Price oracle manipulation
  - Delegatecall misuse (via Mythril integration)

- **Hybrid analysis architecture**:
  - Slither performs fast pre-filtering
  - Mythril is invoked selectively for deeper analysis

- **Mythril integration via microservice**:
  - Isolated execution using subprocess
  - JSON-based communication
  - No dependency conflicts with Slither

- **Automated testing environment**:
  - Batch analysis of test contracts
  - solc version management via `solc-select`

---

## Project Structure

code/
├── slither_my_plugin/ # Custom Slither detectors
│ └── detectors/
├── test_contracts/ # Test datasets
├── mythril_server/ # Mythril microservice (Flask)
│ └── server.py
├── scripts/ # Automation scripts
├── slither_venv/ # Slither environment
├── mythril_venv/ # Mythril environment (optional)
└── README.md

---

## Installation

### 1. Slither environment

```bash
python3 -m venv slither_venv
source slither_venv/bin/activate
pip install slither-analyzer
pip install -e .
```

### 2. Mythril server (recommended via Docker)
```
docker build -t mythril-server .
docker run -p 5000:5000 mythril-server
```


## Usage
Run Slither with custom detectors
```
slither . --detect mythril-delegatecall
```
Mythril server API
```
POST /analyze
{
  "bytecode": "0x..."
}
```
Response:
```
{
  "success": true,
  "issues": [...]
}
```

## Key Concepts
### Hybrid Analysis
1. Slither analyzes source code (AST, CFG, IR)
2. Contracts with risky patterns are selected
3. Runtime bytecode is extracted
4. Mythril performs symbolic execution
5. Results are normalized and returned to Slither

### Research Contributions
- Implementation of custom static analyzers using Slither IR
- Interprocedural taint analysis across functions and storage
- Design of a hybrid analysis framework
- Integration of bytecode-level symbolic execution into source-level tooling
- Reduction of false positives via cross-validation

### Limitations
- Mythril analysis is computationally expensive
- Limited path exploration (depth/time constraints)
- No full source ↔ bytecode mapping (future work)

### License
This project is developed for academic research purposes.