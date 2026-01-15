#!/bin/bash
pip install -e .
slither test_contracts/for_timing/my_oracle_manipulations_vuln/oracle.vuln.1.sol --detect price-oracle-manipulation