#!/bin/bash
pip install -e .
slither test_contracts/for_timing/mythril_delegate_call/delegatecall.vuln.1.sol --detect mythril-delegatecall