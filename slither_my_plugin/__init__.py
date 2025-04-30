from slither_my_plugin.detectors.my_detector import IncorrectEIP712Detector


def make_plugin():
    plugin_detectors = [IncorrectEIP712Detector]
    plugin_printers = []

    return plugin_detectors, plugin_printers