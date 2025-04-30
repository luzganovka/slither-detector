#!/bin/bash
pip install -e .
slither contracts/eip712.vuln.sol --detect incorrect-eip712