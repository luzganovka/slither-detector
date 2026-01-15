from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import HighLevelCall, InternalCall, Assignment, Return
from slither.core.declarations import Function


TRUSTED_CHAINLINK_METHODS = {
    "latestRoundData",
    "latestAnswer",
    "latestTimestamp",
}

DEX_ORACLE_KEYWORDS = {
    "getReserves",
    "getPrice",
    "price0CumulativeLast",
    "price1CumulativeLast",
    "token0",
    "token1",
}

CRITICAL_FINANCIAL_METHODS = {
    "liquidate",
    "mint",
    "burn",
    "transfer",
    "borrow",
    "redeem",
    "withdraw",
    "repay",
    "trade"
}


class PriceOracleManipulation(AbstractDetector):
    ARGUMENT = "price-oracle-manipulation"
    HELP = "Detect manipulable oracle usage with interprocedural taint tracking"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = """https://github.com/luzganovka/slither-detector/Oracle_manipulation_vulnarability.md"""
    WIKI_TITLE = "Price Oracle Manipulation"
    WIKI_DESCRIPTION = (
        "Smart contracts that consume price data from external oracles "
        "should validate values before using them in critical calculations. "
        "Otherwise attackers may manipulate oracle feeds and steal funds."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A lending protocol queries a price feed and directly computes collateral value. "
        "The attacker manipulates price via flash-loan and drains protocol."
    )
    WIKI_RECOMMENDATION = (
        "Validate oracle prices with require() conditions, sanity checks, "
        "TWAP/median aggregation or multiple oracles."
    )

    # ---------------- fields -------------------------------

    def __init__(self, slither, solc_values, result_reporter):
        super().__init__(slither, solc_values, result_reporter)
        self.results = []
        self.tainted_returns = {}
        self.tainted_returns_changed = True

    # ---------------- oracle identification ----------------

    def _is_chainlink(self, ir):
        if ir.function is None:
            return False
        if ir.function.name in TRUSTED_CHAINLINK_METHODS:
            return True
        if ir.function.contract and "Aggregator" in ir.function.contract.name:
            return True
        return False

    def _is_dex_oracle(self, ir):
        if ir.function is None:
            return False
        for k in DEX_ORACLE_KEYWORDS:
            if k in ir.function.name:
                return True
        return False
    
    def _is_critical_financial_function(self, function):
        for kw in CRITICAL_FINANCIAL_METHODS:
            if kw in function.name.lower():
                return True
        return False

    def _report(self, function_name, oracle_type, tainted):
        if oracle_type == "dex":
            impact = "HIGH (DEX oracle — flash-loan manipulable)"
        elif oracle_type == "custom_external":
            impact = "MEDIUM (custom external oracle)"
        else:
            impact = "LOW (trusted oracle or unclear)"

        info = [
            f"Function: {function_name}\n",
            f"Oracle type: {oracle_type}\n",
            f"Impact: {impact}\n",
            f"Tainted vars: {', '.join(str(v) for v in tainted)}\n",
        ]

        self.results.append(self.generate_result(info))

    # ---------------- per-function taint ----------------

    def _analyze_function_internal(self, function):
        """
        Returns True if function returns tainted value
        """
        
        tainted = set()
        oracle_type = None
        info = None

        # print(f"DEBUG | _analyze_function_internal({function}):")
        for node in function.nodes:
            for ir in node.irs:

                # oracle call → taint result
                if isinstance(ir, HighLevelCall):

                    # internal or high-level call
                    if isinstance(ir, (HighLevelCall, InternalCall)) and isinstance(ir.function, Function):
                    # if isinstance(ir.function, (function.internal_calls, function.external_calls)):
                        callee = ir.function
                        callee_oracle_type = self.tainted_returns.get(callee, None)
                        # print(f"DEBUG | '{function.name}' calls '{callee.name}', that has '{callee_oracle_type}' oracle vuln type")
                        if callee_oracle_type:
                            tainted.add(ir.lvalue)
                            oracle_type = callee_oracle_type

                    # manipulable DEX oracle
                    if self._is_dex_oracle(ir):
                        oracle_type = "dex"
                        if ir.lvalue:
                            tainted.add(ir.lvalue)

                    # any unknown oracle except chainlink
                    if not self._is_chainlink(ir):
                        oracle_type = "custom_external"
                        if ir.lvalue:
                            tainted.add(ir.lvalue)

                # taint propagation by assignment
                if isinstance(ir, Assignment):
                    if ir.rvalue in tainted:
                        tainted.add(ir.lvalue)

                # return statement — Slither IR
                if isinstance(ir, Return) and (self.tainted_returns.get(function, None) == None):
                    # print(f"DEBUG | Found return ir in {function.name}")
                    # print(f"DEBUG | returned valuse are: {[getattr(v, 'name', str(v)) for v in ir.values]}")
                    for v in ir.values:
                        if v in tainted:
                            # print(f"DEBUG | {function.name} returns tained!")
                            self.tainted_returns[function] = oracle_type
                            self.tainted_returns_changed = True

                            self._report(function.full_name, oracle_type, tainted)

        #
        # if tainted value influences critical finance logic
        #
        if tainted and self._is_critical_financial_function(function):

            self._report(function.full_name, oracle_type, tainted)

        # print(f"\treturns_tainted = {self.tainted_returns.get(function, None)},\n\
        #       \tlocal vulns = {info}\n\
        #       \tTainted vars = {[getattr(v, 'name', str(v)) for v in tainted]}\n")
        return

    # ---------------- main detector ----------------

    def _detect(self):

        for contract in self.slither.contracts:
            self.tainted_returns_changed = True

            # step 1: intra-procedural taint
            while (self.tainted_returns_changed == True):
                self.tainted_returns_changed = False
                for f in contract.functions:
                    self._analyze_function_internal(f)


            # step 2: final reporting
            for f in contract.functions:

                # print (f"DEBUG | Function `{f.full_name} tained? --> {self.tainted_returns.get(f)}\n")

                if not self.tainted_returns.get(f, False):
                    continue

                if not any(key in f.name.lower() for key in CRITICAL_FINANCIAL_METHODS):
                    continue

                info = [
                    f"Function `{f.full_name}` depends on manipulable oracle-derived price",
                    "Tainted value returned from another function",
                    "Interprocedural taint propagation detected"
                ]

                self.results.append(self.generate_result(info))

        return self.results
