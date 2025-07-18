from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations.contract import Contract
from slither.core.variables.state_variable import StateVariable
from slither.core.cfg.node import NodeType
from slither.core.expressions import Literal

class EIP712MistakesDetector(AbstractDetector):
    ARGUMENT = "incorrect-eip712"
    HELP = "Detects incorrect EIP-712 signature validation"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = """https://github.com/luzganovka/slither-detector/EIP712_mistakes.md"""
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

    contract: Contract              = None
    domain_separator: StateVariable = None
    results: object                 = []

    """search for the 'DOMAIN_SEPARATOR' variable"""
    def _find_domain_separator(self) -> bool:

        for var in self.contract.state_variables:
            if "domain" in var.name.lower() and "separator" in var.name.lower():
                self.domain_separator: StateVariable = var
                # print(f"⚠️ found domain separator: {self.domain_separator.name}")
                return True
            
        self.domain_separator: StateVariable = None
        return False

    """Check if immutable"""
    def _check_ds_immutability(self) -> bool:

        if not self.domain_separator.is_immutable:
            info = [f"DOMAIN_SEPARATOR in {self.contract.name} should be immutable.\n"]
            self.results.append(self.generate_result(info))
            return False
        
        return True

    """Check constructor initialization"""
    def _check_ds_constructor_initialization(self) -> bool:

        # print(f"⚠️ Searching for init of: {var.name}\n")
        SHOULD_INCLUDE = ["name", "version",  "chainid", "address(this)"]
        not_included = []
        for func in self.contract.constructors:
            for node in func.nodes:
                for write in node.state_variables_written:
                    if write == self.domain_separator:
                        expr_str = str(node.expression)
                        # print(f"⚠️ found domain separator init: {expr_str}")
                        for entity in SHOULD_INCLUDE:
                            if entity not in expr_str:
                                not_included.append(entity)

        if 0 != len(not_included):
            self.results.append(self.generate_result([
                f"Contract {self.contract.name} has incorrect EIP-712 DOMAIN_SEPARATOR.\n",
                "It should include in constructor: ", ", ".join(not_included), "\n"
            ]))
            return False
        
        return True

    """Check for \x19\x01 prefix usage in ecrecover calls"""
    def _check_1901_prefix_usage(self) -> bool:

        for func in self.contract.functions:
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
        
        # \x19\x01 was missed
        self.results.append(self.generate_result([
            f"Contract {self.contract.name} has incorrect EIP-712 digest computation.\n",
            "It should include \\x19\\x01 prefix when hashing.\n"
        ]))
        return False

    """function that is called by slither detector"""
    def _detect(self):

        for self.contract in self.compilation_unit.contracts:

            # search for the 'DOMAIN_SEPARATOR' variable
            if not self._find_domain_separator():
                continue

            # Check if immutable
            self._check_ds_immutability()

            # Check constructor initialization
            self._check_ds_constructor_initialization()

            # Check for \x19\x01 prefix usage in ecrecover calls
            self._check_1901_prefix_usage()

        return self.results


