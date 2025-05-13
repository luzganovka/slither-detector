from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations.contract import Contract
from slither.core.variables.state_variable import StateVariable
from slither.core.cfg.node import NodeType
from slither.core.expressions import Literal

class IncorrectEIP712Detector(AbstractDetector):
    ARGUMENT = "incorrect-eip712"
    HELP = "Detects incorrect EIP-712 signature validation"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/crytic/slither/wiki/Adding-a-new-detector"
    WIKI_TITLE = "Incorrect EIP-712 Implementation"
    WIKI_DESCRIPTION = "Detects insecure EIP-712 implementations missing critical security checks"
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Vulnerable {
    bytes32 public DOMAIN_SEPARATOR;
    
    constructor() {
        // Missing chainId and verifyingContract
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version)"),
            keccak256("MyApp"),
            keccak256("1.0.0")
        ));
    }
    
    function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external view {
        // Missing \x19\x01 prefix
        bytes32 digest = keccak256(abi.encodePacked(hash));
        address signer = ecrecover(digest, v, r, s);
    }
}
```"""
    WIKI_RECOMMENDATION = "Always include chainId, verifyingContract and \x19\x01 prefix in EIP-712 implementations"

    def _detect(self):
        results = []

        for contract in self.compilation_unit.contracts:

            # Ищем переменную DOMAIN_SEPARATOR
            domain_separator = self._find_domain_separator(contract)
            if not domain_separator:
                continue

            # Check if immutable
            if not domain_separator.is_immutable:
                info = [f"DOMAIN_SEPARATOR in {contract.name} should be immutable.\n"]
                results.append(self.generate_result(info))
                continue

            # Check constructor initialization
            if not self._check_constructor_initialization(contract, domain_separator):
                info = [
                    f"Contract {contract.name} has incorrect EIP-712 DOMAIN_SEPARATOR.\n",
                    "It should include chainId and verifyingContract in constructor.\n"
                ]
                results.append(self.generate_result(info))

            # Check for \x19\x01 prefix usage in ecrecover calls
            if not self._check_eip712_prefix_usage(contract):
                info = [
                    f"Contract {contract.name} has incorrect EIP-712 digest computation.\n",
                    "It should include \\x19\\x01 prefix when hashing.\n"
                ]
                results.append(self.generate_result(info))

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
                        expr_str = str(node.expression)
                        return ("chainId" in expr_str and 
                                "address(this)" in expr_str and
                                "EIP712Domain(" in expr_str)
        return False

    def _check_eip712_prefix_usage(self, contract: Contract) -> bool:
        for func in contract.functions:
            for node in func.nodes:
                if (node.type == NodeType.EXPRESSION and 
                    "ecrecover" in str(node.expression)):
                    
                    # Check if the digest computation includes \x19\x01
                    for ir in node.irs:
                        for read in ir.read:
                            if (isinstance(read, Literal) and 
                                read.value == "0x1901"):
                                return True
                            
                    # Alternative check in string representation
                    if "\\x19\\x01" in str(node.expression):
                        return True
        return False