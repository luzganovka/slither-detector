from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Contract, Function

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
            if not self._check_eip712_compliance(contract):
                info = [
                    f"Contract {contract.name} has incorrect EIP-712 validation.\n",
                    "DOMAIN_SEPARATOR should include chainId and verifyingContract.\n",
                ]
                json = self.generate_result(info)
                results.append(json)  # Важно: возвращаем результат через generate_result()

        return results

    def _check_eip712_compliance(self, contract: Contract) -> bool:
        for var in contract.state_variables:
            if "DOMAIN_SEPARATOR" in var.name:
                if "chainId" in str(var.expression) and "verifyingContract" in str(var.expression):
                    return True
        return False