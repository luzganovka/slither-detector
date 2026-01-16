from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Contract
from slither.core.cfg.node import NodeType
from mythril.mythril import Mythril
from mythril.analysis.security import retrieve_callback_issues


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



    def has_delegatecall(self, contract: Contract) -> bool:
        for f in contract.functions:
            for node in f.nodes:
                if node.type == NodeType.EXPRESSION:
                    if "delegatecall" in str(node.expression):
                        return True
        return False


    def run_mythril(self, bytecode: str):
        mythril = Mythril(
            strategy="dfs",
            max_depth=22,
            execution_timeout=60
        )

        # Загружаем байткод напрямую (без solc)
        mythril.contracts.append(
            mythril.load_from_bytecode(
                bytecode,
                bin_runtime=True
            )
        )

        # Запуск анализа
        issues = mythril.fire_lasers()

        return issues


    def filter_delegatecall_issues(self, issues):
        findings = []
        for issue in issues:
            if "DELEGATECALL" in issue.title.upper():
                findings.append(issue)
        return findings


    def _detect(self):
        results = []

        for contract in self.slither.contracts:
            if not self.has_delegatecall(contract):
                continue

            bytecode = contract.file_scope.bytecode_runtime(
                contract.compilation_unit.crytic_compile_compilation_unit,
                contract.name
            )

            if not bytecode:
                continue

            issues = self.run_mythril(bytecode)
            delegate_issues = self.filter_delegatecall_issues(issues)

            for issue in delegate_issues:
                results.append(
                    self.generate_result(
                        info=[
                            contract,
                            "\nDelegatecall misuse detected via Mythril\n",
                            issue.title
                        ]
                    )
                )

        return results
