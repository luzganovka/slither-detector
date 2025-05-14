#!/bin/bash

# --- Конфигурация ---

REQUIRED_SOLC="0.4.23"  # Нужная версия
# REQUIRED_SOLC="0.8.0"  # Нужная версия
# ALL_SOLCS=("0.4.26" "0.5." "0.6." "0.7." "0.8.")
SETUP_PY_PATH="$HOME/Study/slither_detector_module/code"
DETECTORS="incorrect-eip712,reentrancy-eth,unchecked-lowlevel"  # Список детекторов (через запятую)
# CONTRACTS_DIR="$HOME/Study/slither_detector_module/smartbugs-curated" 
CONTRACTS_DIR="$HOME/Study/slither_detector_module/smartbugs-curated"                                     # Путь к директории с контрактами
CONTRACT_NAMES=("arithmetic/overflow_single_tx.sol" "../code/contracts/eip712.vuln.sol")  # Массив контрактов
# CONTRACT_NAMES=("../code/contracts/eip712.vuln.sol")  # Массив контрактов

DELIM="----------------------------------------------------------"

python3 -m venv ./slither_venv
source ./slither_venv/bin/activate
# pip install slither-analyzer
pip install -e $SETUP_PY_PATH


# --- Проверка solc ---
CURRENT_SOLC=$(solc --version | grep -oP "0.\d+.\d+")
if [[ "$CURRENT_SOLC" != "$REQUIRED_SOLC" ]]; then
    echo "⚠️ Требуется solc $REQUIRED_SOLC. Устанавливаем через solc-select..."
    pip install solc-select && solc-select install $REQUIRED_SOLC
    solc-select use $REQUIRED_SOLC
fi

# --- Анализ ---
for contract in "${CONTRACTS[@]}"; do
    slither $CONTRACT_DIR/$contract --detect reentrancy --solc-solcs-bin "$(which solc)"
done

# --- Анализ контрактов ---
echo "🔍 Запуск Slither с детекторами: $DETECTORS"
echo "📂 Директория с контрактами: $CONTRACTS_DIR"
echo "📄 Контракты для анализа: ${CONTRACT_NAMES[@]}"
echo $DELIM

for contract in "${CONTRACT_NAMES[@]}"; do
    contract_path="$CONTRACTS_DIR/$contract"
    if [ ! -f "$contract_path" ]; then
        echo "⚠️ Ошибка: Контракт $contract не найден в $CONTRACTS_DIR. Пропускаем."
        continue
    fi

    echo "📋 Анализ $contract..."
    # slither "$contract_path" --detect "$DETECTORS" --solc-solcs-bin "$(which solc)" #--json - | jq .  # Красивое форматирование JSON через jq
    # slither "$contract_path" --detect "incorrect-eip712" --solc-solcs-bin "$(which solc)" #--json - | jq .  # Красивое форматирование JSON через jq
    slither "$contract_path"                             --solc-solcs-bin "$(which solc)"
    echo $DELIM
done

echo "✅ Анализ завершен."