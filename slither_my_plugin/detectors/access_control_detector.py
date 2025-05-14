from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

class AccessControlInitializationDetector(AbstractDetector):
    ARGUMENT = 'access-control-init'
    HELP = 'Detects access control initialization vulnerabilities'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "qwertyui"

    WIKI_TITLE = "qwertyui"
    WIKI_DESCRIPTION = "qwertyui"
    WIKI_EXPLOIT_SCENARIO = "qwertyui"
    WIKI_RECOMMENDATION = "qwertyui"
    
    def _detect(self):
        results = []
        
        for contract in self.compilation_unit.contracts:
            # 1. Проверка старых конструкторов
            if any(f.name == contract.name for f in contract.functions):
                info = f"Potential constructor-naming issue in {contract.name}"
                results.append(self.generate_result([info]))
            
            # 2. Проверка незащищённых init-функций
            for func in contract.functions:
                if 'init' in func.name.lower() and not any(m for m in func.modifiers):
                    info = f"Unprotected initialization function: {func.name}"
                    results.append(self.generate_result([info]))
        
        return results