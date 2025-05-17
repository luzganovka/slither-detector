from slither_my_plugin.detectors.EIP712_mistakes_detector import EIP712MistakesDetector


def make_plugin():
    plugin_detectors = [EIP712MistakesDetector]
    plugin_printers = []

    return plugin_detectors, plugin_printers