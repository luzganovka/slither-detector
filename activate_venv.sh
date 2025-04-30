#!/bin/bash
python3 -m venv ./slither_venv
source ./slither_venv/bin/activate
pip install slither-analyzer
slither --version
# python setup.py develop
# deactivate # to exit the venv