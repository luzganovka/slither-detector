from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Contract
from slither.core.cfg.node import NodeType
import requests
import warnings

class MythrilDelegatecallDetector(AbstractDetector):
    """
    Delegatecall misuse detection using Mythril (bytecode-level analysis)
    """

    ARGUMENT = "mythril-delegatecall"
    HELP = "Detect unsafe delegatecall patterns using Mythril bytecode analysis"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "TODO"
    WIKI_TITLE = "Delegatecall misuse (bytecode-level)"
    WIKI_DESCRIPTION = (
        "Detects unsafe delegatecall usage at the EVM level using Mythril. "
        "Useful for contracts using assembly, proxies or missing source-level checks."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A proxy contract performs delegatecall to an attacker-controlled address, "
        "allowing arbitrary storage modification and contract takeover."
    )
    WIKI_RECOMMENDATION = (
        "Restrict delegatecall targets, protect upgrade logic with access control, "
        "and avoid delegatecall in fallback functions without validation."
    )

    MYTHRIL_ENDPOINT = "http://localhost:5000/analyze"

  # ---------- source-level prefilter ----------

    def has_delegatecall(self, contract: Contract) -> bool:
        for f in contract.functions:
            for node in f.nodes:
                if node.type == NodeType.EXPRESSION:
                    if "delegatecall" in str(node.expression):
                        return True
        return False


  # ---------- mythril oracle ----------

    def run_mythril_server(self, bytecode: str):
        try:
            resp = requests.post(
                self.MYTHRIL_ENDPOINT,
                json={"bytecode": bytecode},
                timeout=90,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            warnings.warn(f"Error while calling server: {e}")
            # Для PoC: не валим Slither целиком
            return []


   # ---------- issue filtering ----------

    def is_delegatecall_issue(self, issue: dict) -> bool:
        title = issue.get("title", "")
        return "DELEGATECALL" in title.upper()

    # ---------- main detector ----------

    def _detect(self):
        results = []

        for contract in self.slither.contracts:
            # source-level prefilter
            if not self.has_delegatecall(contract):
                print(f"DEBUG | No delegatecall in a contract. Skipping")
                continue

            # extract runtime bytecode
            bytecode = contract.file_scope.bytecode_runtime(
                contract.compilation_unit.crytic_compile_compilation_unit,
                contract.name
            )

            if not bytecode:
                print(f"DEBUG | No bytecode in a contract. Skipping")
                continue

            # call mythril service
            print(f"DEBUG | Calling mythril")
            result = self.run_mythril_server(bytecode)
            if not result.get('success', False):
                warnings.warn(f"Mythril fails with error:{result.get('error', 'no error field')}")
                continue
            issues = result['issues']
            print(f"DEBUG | Got issues from mythril: {issues}")

            if not isinstance(issues, list):
                print(f"DEBUG | Issues is not a list. Skipping")
                continue

            # filter delegatecall-related findings
            for issue in issues:
                if not self.is_delegatecall_issue(issue):
                    continue

                title = issue.get("title", "Delegatecall misuse")
                severity = issue.get("severity", "Unknown")

                results.append(
                    self.generate_result(
                        info=[
                            contract,
                            "\nDelegatecall misuse detected via Mythril (bytecode-level)\n",
                            f"Issue: {title}\n",
                            f"Severity: {severity}\n",
                        ]
                    )
                )

        return results
