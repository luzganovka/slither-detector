from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations.function import Function
from slither.core.cfg.node import NodeType
from slither.slithir.operations.low_level_call import LowLevelCall
from slither.slithir.operations.send import Send
from slither.core.declarations.solidity_variables import SolidityVariableComposed


class UnsafeLowLevelCallDetector(AbstractDetector):
    """
    Detects low-level calls (call, delegatecall, staticcall, send) where the returned success value is not used.
    """

    ARGUMENT = 'unsafe-lowlevel-call'
    HELP = 'Detect low-level calls without checking the success return value'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = 'https://docs.openzeppelin.com/upgrades-plugins/1.x/writing-upgradeable#delegatecall-and-low-level-calls'

    WIKI_TITLE = 'Unsafe Low-level Call Without Success Check'
    WIKI_DESCRIPTION = 'Detects places where low-level calls (call, send, delegatecall, staticcall) are used but their return value is not checked.'
    WIKI_EXPLOIT_SCENARIO = 'A function uses address.call(...) to send Ether but does not check if the call was successful. Ether might not be delivered, but the contract continues execution.'
    WIKI_RECOMMENDATION = 'Always check the returned boolean from low-level calls using require or if.'

    def _detect(self):
        results = []

        for contract in self.slither.contracts:
            for function in contract.functions:
                for node in function.nodes:
                    # Проходим по всем операциям в узле
                    for ir in node.irs:
                        # 1. Проверяем, является ли это низкоуровневым вызовом
                        if isinstance(ir, (LowLevelCall, Send)):
                            # 2. Проверяем, используется ли результат вызова
                            if not self._is_success_used(ir):
                                info = [
                                    f'Low-level call without success check in function {function.name} at {ir.source_mapping}'
                                ]
                                results.append(self.generate_result(info))

        return results

    def _is_success_used(self, ir):
        """
        Проверка: используется ли результат вызова ir (например, success)?
        """
        if ir.lvalue is None:
            return False

        var_name = ir.lvalue.name

        # Проверяем, используется ли результат в require/assert/if
        for node in ir.function.nodes:
            for ir2 in node.irs:
                if hasattr(ir2, "expression") and ir2.expression:
                    expr_str = str(ir2.expression)
                    if var_name in expr_str and any(kw in expr_str for kw in ["require", "assert", "if", "revert"]):
                        return True
        return False
