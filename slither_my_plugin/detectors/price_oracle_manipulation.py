from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import HighLevelCall
from slither.core.declarations.function import Function


class PriceOracleManipulationDetector(AbstractDetector):
    """
    Detect use of oracle price values without validation
    """

    ARGUMENT = "price-oracle-manipulation"
    HELP = "Detects use of oracle price feeds without validation"

    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = """TODO"""
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

    def _detect(self):

        results = []

        for contract in self.slither.contracts:
            for function in contract.functions:
                for node in function.nodes:
                    for ir in node.irs:

                        # ловим вызовы внешних функций
                        if isinstance(ir, HighLevelCall):

                            call_str = str(ir)

                            # эвристика для обнаружения оракулов
                            if any(
                                kw in call_str.lower()
                                for kw in ["oracle", "price", "feed", "aggregator"]
                            ):
                                # переменная, куда сохраняется результат вызова
                                if ir.lvalue:
                                    var_name = ir.lvalue.name

                                    # проверяем наличие валидации
                                    if not self._has_validation(function, var_name):
                                        info = [
                                            f"Potential price oracle manipulation in {contract.name}.{function.name}",
                                            f"Value from oracle call `{call_str}` is used without validation",
                                        ]
                                        results.append(self.generate_result(info))

        return results

    def _has_validation(self, function: Function, var_name: str) -> bool:
        """
        Detect require/assert/revert checking oracle value
        """

        for node in function.nodes:

            # проверка в require()
            if node.contains_require_or_assert():

                for ir in node.irs:
                    if var_name in str(ir):
                        return True

        return False
