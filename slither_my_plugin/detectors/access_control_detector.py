from slither.core.declarations import Contract
from slither.core.variables.state_variable import StateVariable

"""
Различные эвристики для проверки,
что функция изменяет критические переменные или является конструктором
"""
class CriticalFunctionsSearcher:
    
    def __init__(self) -> None:
        return None

    """Эвристика 1: Функция вызывается только внутри конструктора (если есть вызовы)"""
    def _called_at_beginning(self, function) -> bool:
        
        for ref in function.references:
            if ref.node and not ref.node.function.is_constructor:
                return False
        return True

    """Эвристика 2. Функция инициализирует критичные переменные (owner, root и т.д.)"""
    def _inits_critical_variables(self, function):
        
        CRITICAL_VARS = {"owner", "admin", "root", "creator"}
        written_vars = {var.name.lower() for node in function.nodes 
                    for var in node.state_variables_written}
        if not written_vars.intersection(CRITICAL_VARS):
            return False
        return True

    """Эвристика 3. У конструкторов обычно мало параметров"""
    def _has_few_args(self, function):
        _TOO_MANY_ARGS = 5  # Граница, после которой считается, что аргументов слишком много
        
        if len(function.parameters) > _TOO_MANY_ARGS:
            return False
        return True

    """Эвристика 4. Функция инициализирует все переменные"""
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

        # Проверяем, что записаны ВСЕ переменные
        if written_vars.issuperset(all_state_vars):
            return True
        else:
            return False
        
    """Эвристика 5. Проверяет наличие конкретных слов в названии функции"""
    def _name_pattern(self, function):
        _PATTERNS = ['init', 'constructor', 'owner']
        for pattern in _PATTERNS:
            if pattern in function.name.lower():
                return True
        return False

    """
    Основываясь на эвристиках, находит функции, которые
    могут изменять критически важные переменные контракта или являться конструкторами.
    Дополнительные проверки снижают количество ложных срабатываний.
    """
    def find_critical_functions(self, contract: Contract) -> list:

        critical_functions = []

        for function in contract.functions:
            
            # Игнорируем view/pure функции и конструкторы, которые Slither уже нашёл
            if function.is_constructor or function.view or function.pure:
                continue

            # Проверка всех условий
            if      self._has_few_args(function) \
                and self._called_at_beginning(function) \
                and  self._inits_all_variables(contract, function) \
                or  self._inits_critical_variables(function) \
                or  self._name_pattern(function) \
                :
                critical_functions.append(function)

        return critical_functions

    """
    Возвращает список функций, уже определённых slither как конструкторы.
    """
    def find_costructors(self, contract: Contract) -> list:
        return contract.constructors



from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

class AccessControlDetector(AbstractDetector):
    ARGUMENT = "access-control"
    HELP = "Detects non-legacy constructor names and unprotected critical functions"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "todo"

    WIKI_TITLE = "empty"
    WIKI_DESCRIPTION = "empty"
    WIKI_EXPLOIT_SCENARIO = "empty"
    WIKI_RECOMMENDATION = "empty"

    """Проверка незащищённых критических функций"""
    def _unprotected_critical_functions(self, contract: Contract, results: object) -> None:

        critical_functions = self.CFS.find_critical_functions(contract)

        for func in critical_functions:
            if  not any(m for m in func.modifiers):
                info = f"Unprotected critical function: {func.name}\n"
                results.append(self.generate_result([info]))

    """Проверка незащищённых конструкторов"""
    def _unprotected_constructors(self, contract: Contract, results: object) -> None:

        for func in self.CFS.find_costructors(contract):
            if  not any(m for m in func.modifiers):
                info = f"Unprotected constructor: {func.name}\n"
                results.append(self.generate_result([info]))

    """Неправильные имена конструкторов для устаревших версий solc (<0.4.22)"""
    def _outdated_constructor_names(self, contract: Contract, results: object) -> None:

        if contract.compilation_unit.solc_version.startswith("0.4"):
            for func in contract.constructors:
                if func.name != contract.name:
                    info = [f"Legacy constructor naming in {contract.name}. Expected '{contract.name}', got '{func.name}'\n"]
                    results.append(self.generate_result(info))

    def _detect(self):
        results = []
        self.CFS: CriticalFunctionsSearcher = CriticalFunctionsSearcher()

        for contract in self.compilation_unit.contracts:

            # Проверка 1. Проверка незащищённых критических функций
            self._unprotected_critical_functions(contract, results)

            # Проверка 2. Проверка незащищённых конструкторов
            self._unprotected_constructors(contract, results)

            # Проверка 3: Неправильные имена конструкторов для устаревших версий solc (<0.4.22)
            self._outdated_constructor_names(contract, results)
        
        return results