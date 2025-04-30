from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
# from slither.core.cfg.node import NodeType

class IncorrectEIP712Detector(AbstractDetector):
    ARGUMENT = "incorrect-eip712"  # Аргумент для вызова (--detect incorrect-eip712)
    HELP = "Detects incorrect EIP-712 signature validation"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "qwertyui"

    WIKI_TITLE = "qwertyui"
    WIKI_DESCRIPTION = "qwertyui"
    WIKI_EXPLOIT_SCENARIO = "qwertyui"
    WIKI_RECOMMENDATION = "qwertyui"

    def _detect(self):
        results = []

        for contract in self.compilation_unit.contracts:
            for function in contract.functions:
                for node in function.nodes:
                    # Ищем вызовы ecrecover
                    if "ecrecover" in str(node.expression):
                        # Проверяем, есть ли DOMAIN_SEPARATOR с chainId
                        if not self._has_proper_domain_separator(contract):
                            issue = {
                                "check": self.ARGUMENT,
                                "description": f"Incorrect EIP-712 validation in {function.name}",
                                "impact": self.IMPACT,
                                "confidence": self.CONFIDENCE,
                                "function": function,
                                "node": node,
                            }
                            results.append(issue)
        return results

    def _has_proper_domain_separator(self, contract):
        # Проверяем, что DOMAIN_SEPARATOR включает chainId и verifyingContract
        for variable in contract.state_variables:
            if "DOMAIN_SEPARATOR" in variable.name:
                if "chainId" in str(variable.expression) and "verifyingContract" in str(variable.expression):
                    return True
        return False