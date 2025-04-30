from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations.contract import Contract
from slither.core.variables.state_variable import StateVariable
from slither.core.expressions.call_expression import CallExpression

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

            # Ищем переменную DOMAIN_SEPARATOR
            domain_separator = self._find_domain_separator(contract)
            if not domain_separator:
                continue

            # Проверяем, что он immutable
            if not domain_separator.is_immutable:
                info = [f"DOMAIN_SEPARATOR in {contract.name} should be immutable.\n"]
                json = self.generate_result(info)
                results.append(json)
                continue


            # if not self._check_eip712_compliance(contract):
            if not self._check_constructor_initialization(contract, domain_separator):
                info = [
                    f"Contract {contract.name} has incorrect EIP-712 validation.\n",
                    "DOMAIN_SEPARATOR should include chainId and verifyingContract.\n",
                ]
                json = self.generate_result(info)
                results.append(json)  # возвращаем результат через generate_result()

        return results


    def _find_domain_separator(self, contract: Contract) -> StateVariable:
        for var in contract.state_variables:
            if "DOMAIN_SEPARATOR" in var.name:
                return var
        return None
    

    def _check_constructor_initialization(self, contract: Contract, var: StateVariable) -> bool:
        for func in contract.constructors:
            for node in func.nodes:
                for write in node.state_variables_written:
                    if write == var:
                        # Проверяем, что в выражении есть chainId и address(this)
                        if "chainId" in str(node.expression) and "address(this)" in str(node.expression):
                            return True
        return False


    # def _check_eip712_compliance(self, contract: Contract) -> bool:
    #     for var in contract.state_variables:
    #         if "DOMAIN_SEPARATOR" in var.name and var.expression != None:
    #             print("\nDEBUG |", var.name, "\nDEBUG |", var.expression, "\n")
    #             if "chainid" in str(var.expression) and "verifyingContract" in str(var.expression):
    #                 return True
    #     return False