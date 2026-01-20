from slither_my_plugin.detectors.EIP712_mistakes_detector import EIP712MistakesDetector
from slither_my_plugin.detectors.access_control_detector import AccessControlDetector
from slither_my_plugin.detectors.price_oracle_manipulation import PriceOracleManipulation
from slither_my_plugin.detectors.mythril_delegatecall_detector import MythrilDelegatecallDetector

def make_plugin():
    plugin_detectors = [EIP712MistakesDetector, AccessControlDetector, PriceOracleManipulation, MythrilDelegatecallDetector]
    plugin_printers = []

    return plugin_detectors, plugin_printers