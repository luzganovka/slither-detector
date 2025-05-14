from slither_my_plugin.detectors.my_detector import IncorrectEIP712Detector
from slither_my_plugin.detectors.access_control_detector import AccessControlInitializationDetector


def make_plugin():
    plugin_detectors = [IncorrectEIP712Detector, AccessControlInitializationDetector]
    plugin_printers = []

    return plugin_detectors, plugin_printers