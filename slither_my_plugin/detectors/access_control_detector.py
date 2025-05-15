from slither.core.declarations import Contract
from slither.core.variables.state_variable import StateVariable

"""Различные эвристики для проверки, что функция - конструктор"""

class CriticalFunctionsSearcher:
    
    def __init__(self) -> None:
        return None

    def _called_at_beginning(self, function) -> bool:
        # Эвристика 1: Функция вызывается только внутри конструктора (если есть вызовы)
        for ref in function.references:
            if ref.node and not ref.node.function.is_constructor:
                return False
        return True

    def _inits_critical_variables(self, function):
        # Функция инициализирует критичные переменные (owner, root и т.д.)
        CRITICAL_VARS = {"owner", "admin", "root", "creator"}
        written_vars = {var.name.lower() for node in function.nodes 
                    for var in node.state_variables_written}
        if not written_vars.intersection(CRITICAL_VARS):
            return False
        return True

    def _has_few_args(self, function):
        _TOO_MANY_ARGS = 5  # У конструкторов обычно мало параметров
        # Игнорируем функции с параметрами, которые не похожи на конструкторы
        if len(function.parameters) > _TOO_MANY_ARGS:
            return False
            
        return True

    def _inits_all_variables(self, contract, function) -> bool:
        
        # Собираем все state-переменные контракта (включая унаследованные)
        if not contract.state_variables:
            return False

        all_state_vars = contract.state_variables + [
            var for parent in contract.inheritance 
            for var in parent.state_variables 
            if var not in contract.state_variables
        ]

        # Собираем все переменные, инициализируемые функцией
        written_vars = set()
        for node in function.nodes:
            written_vars.update(node.state_variables_written)

        # Проверяем, что записаны ВСЕ переменные (или их значимая часть)
        if written_vars.issuperset(all_state_vars):
            return True
        else:
            return False
        
    """Проверяет наличие конкретных слов в названии функции"""
    def _name_pattern(self, function):
        _PATTERNS = ['init', 'constructor']
        for pattern in _PATTERNS:
            if pattern in function.name.lower():
                return True
        return False

    def find_potential_constructors(self, contract: Contract) -> list:
        """
        Находит функции, которые инициализируют все state-переменные.
        Дополнительные проверки снижают количество ложных срабатываний.
        """

        potential_constructors = []

        for function in contract.functions:
            
            # Игнорируем view/pure функции и конструкторы, которые Slither уже нашёл
            if function.is_constructor or function.view or function.pure:
                continue

            # Проверка всех условий
            if      self._has_few_args(function) \
                and self._inits_all_variables(contract, function) \
                and self._called_at_beginning(function) \
                or  self._inits_critical_variables(function) \
                or  self._name_pattern(function) \
                :
                potential_constructors.append(function)

        return potential_constructors




from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

class AccessControlDetector(AbstractDetector):
    ARGUMENT = "access-control"
    HELP = "Detects legacy constructor names, unprotected functions, and logical errors"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "qwertyui"

    WIKI_TITLE = "qwertyui"
    WIKI_DESCRIPTION = "qwertyui"
    WIKI_EXPLOIT_SCENARIO = "qwertyui"
    WIKI_RECOMMENDATION = "qwertyui"

    def _detect(self):
        results = []
        CFS: CriticalFunctionsSearcher = CriticalFunctionsSearcher()

        for contract in self.compilation_unit.contracts:

            potential_constructors = CFS.find_potential_constructors(contract)
            print('POTENTIAL CONSTRUCTORS\n', [f.name for f in potential_constructors], '\n\n')

            # Проверка 1. Проверка незащищённых возможных конструкторов
            for func in potential_constructors:
                if  not any(m for m in func.modifiers):
                    info = f"Unprotected potential constructor: {func.name}"
                    results.append(self.generate_result([info]))
                
            # Проверка 2: Устаревшие имена конструкторов (<0.4.22)
            if contract.compilation_unit.solc_version.startswith("0.4"):
                for func in contract.constructors:
                    if func.name != contract.name:
                        info = [f"⚠️ Legacy constructor naming in {contract.name}. Expected '{contract.name}', got '{func.name}'\n"]
                        results.append(self.generate_result(info))

            # Проверка 3: Функции с 'owner' в названии без модификаторов
            for func in contract.functions:
                if "owner" in func.name.lower() and not func.modifiers:
                    info = [f"⚠️ Unprotected owner-change function: {func.name}\n"]
                    results.append(self.generate_result(info))
                
                # Проверка 4: Опасные операторы сравнения
                for node in func.nodes:
                    if ">=" in str(node.expression) and "balance" in str(node.expression):
                        info = [f"⚠️ Suspicious comparison in {func.name}: {node.expression}\n"]
                        results.append(self.generate_result(info))
        
        return results