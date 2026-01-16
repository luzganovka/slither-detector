import subprocess
import json
import tempfile
import os

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


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

    # путь к myth бинарнику (из mythril_venv)
    MYTH_BINARY = os.path.expanduser("~/Study/slither_detector_module/code/mythril_venv/bin/myth")

    def _run_mythril(self, bytecode: str):
        """
        Run mythril on bytecode and return parsed JSON output
        """
        with tempfile.NamedTemporaryFile(mode="w+", suffix=".hex", delete=True) as f:
            f.write(bytecode)
            f.flush()

            cmd = [
                self.MYTH_BINARY,
                "analyze",
                "-c", f.name,
                "-o", "json",
                "--execution-timeout", "30",
                "--max-depth", "22"
            ]

            try:
                proc = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=60
                )
            except Exception as e:
                return None, f"Mythril execution failed: {e}"

            if proc.returncode != 0:
                return None, proc.stderr

            try:
                return json.loads(proc.stdout), None
            except json.JSONDecodeError:
                return None, "Failed to parse Mythril JSON output"

    def _detect(self):
        results = []

        for contract in self.slither.contracts:

            # Get the initialization (creation) bytecode
            # This includes the constructor and the runtime bytecode
            bytecode_init = contract.file_scope.bytecode_init(
                contract.compilation_unit.crytic_compile_compilation_unit,
                contract.name
            )
            # print(f"Initialization Bytecode: {bytecode_init}\n")

            # Get the runtime bytecode
            # This is the code deployed to the blockchain after the constructor runs
            bytecode_runtime = contract.file_scope.bytecode_runtime(
                contract.compilation_unit.crytic_compile_compilation_unit,
                contract.name
            )
            # print(f"Runtime Bytecode: {bytecode_runtime}\n")
            if not bytecode_runtime:
                print(f"DEBUG | No bytecode_runtime!")
                continue

            mythril_output, error = self._run_mythril(bytecode_runtime)

            if error:
                info = [
                    f"Mythril error for contract `{contract.name}`",
                    error
                ]
                results.append(self.generate_result(info))
                continue

            issues = mythril_output.get("issues", [])

            for issue in issues:
                title = issue.get("title", "").lower()

                # фильтр именно delegatecall
                # if "delegatecall" not in title:
                #     continue

                info = [
                    f"Mythril finding: {issue.get('title')}",
                    f"Contract: {contract.name}",
                    f"Severity: {issue.get('severity')}",
                    f"Description: {issue.get('description')}",
                ]

                # если Mythril указал адрес инструкции
                if "address" in issue:
                    info.append(f"EVM PC: {issue['address']}")

                results.append(self.generate_result(info))

        return results
