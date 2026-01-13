from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Function, Contract
from slither.core.expressions import CallExpression, MemberAccess
from slither.slithir.operations import HighLevelCall
from slither.slithir.operations import Assignment
from slither.core.cfg.node import Node

TRUSTED_CHAINLINK_METHODS = {
    "latestRoundData",
    "latestAnswer",
    "latestTimestamp",
}

DEX_ORACLE_KEYWORDS = {
    "getReserves",
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
}


class PriceOracleManipulation(AbstractDetector):
    """
    Detect price oracle manipulation vulnerability
    """

    ARGUMENT = "price-oracle-manipulation"
    HELP = "Detects potentially manipulable price oracles used in critical financial calculations"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "TODO"
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

    #
    # --- helper detectors ---
    #

    def _is_chainlink_oracle_call(self, ir: HighLevelCall) -> bool:
        if ir.function is None:
            return False

        if ir.function.name in TRUSTED_CHAINLINK_METHODS:
            return True

        if ir.function.contract and "AggregatorV3Interface" in ir.function.contract.name:
            return True

        return False

    def _is_dex_oracle_call(self, ir: HighLevelCall) -> bool:
        if ir.function is None:
            return False

        for kw in DEX_ORACLE_KEYWORDS:
            if kw in ir.function.name:
                return True

        return False

    def _is_external_call(self, ir: HighLevelCall, current_contract) -> bool:
        # unknown destination => treat as external
        if ir.function is None:
            return True

        if ir.function.contract is None:
            return True

        return ir.function.contract != current_contract

    def _is_critical_financial_function(self, function):
        for kw in CRITICAL_FINANCIAL_METHODS:
            if kw in function.name.lower():
                return True
        return False

    def _propagate_taint(self, tainted_vars, node):
        for ir in node.irs:
            if isinstance(ir, Assignment):
                if ir.rvalue in tainted_vars:
                    tainted_vars.add(ir.lvalue)

    #
    # --- main detection ---
    #

    def _detect(self):
        results = []

        for contract in self.slither.contracts:
            for function in contract.functions_and_modifiers:

                tainted = set()
                oracle_type = None

                for node in function.nodes:
                    for ir in node.irs:

                        #
                        # external / oracle calls
                        #
                        if isinstance(ir, HighLevelCall):

                            # skip internal calls
                            if not self._is_external_call(ir, contract):
                                continue

                            # trusted oracle
                            if self._is_chainlink_oracle_call(ir):
                                oracle_type = "trusted_chainlink"
                                continue

                            # dex oracle (high risk)
                            if self._is_dex_oracle_call(ir):
                                oracle_type = "dex"
                                tainted.add(ir.lvalue)
                                continue

                            # other external call returning value
                            oracle_type = "custom_external"
                            tainted.add(ir.lvalue)

                    # propagate taint inside function
                    self._propagate_taint(tainted, node)

                #
                # if tainted value influences critical finance logic
                #
                print(f"\n\nDEBUG | Tainted vars: {', '.join(str(v) for v in tainted)}\n\n")
                if tainted and self._is_critical_financial_function(function):

                    if oracle_type == "dex":
                        impact = "HIGH (DEX oracle — flash-loan manipulable)"
                    elif oracle_type == "custom_external":
                        impact = "MEDIUM (custom external oracle)"
                    else:
                        impact = "LOW (trusted oracle or unclear)"

                    info = [
                        f"Function: {function.full_name}\n",
                        f"Oracle type: {oracle_type}\n",
                        f"Impact: {impact}\n",
                        f"Tainted vars: {', '.join(str(v) for v in tainted)}\n",
                    ]

                    results.append(self.generate_result(info))

        return results
