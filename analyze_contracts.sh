#!/bin/bash

# --- Конфигурация ---
SETUP_PY_PATH="$HOME/Study/slither_detector_module/code"
DETECTORS="incorrect-eip712,reentrancy-eth,unchecked-lowlevel"
CONTRACTS_DIR="$HOME/Study/slither_detector_module/smartbugs-curated"
CONTRACT_NAMES=("arithmetic/overflow_single_tx.sol" "../code/contracts/eip712.vuln.sol")

# Устанавливаем последние версии для каждой major версии (0.4.x, 0.5.x и т.д.)
LAST_VERSIONS=("0.4.26" "0.5.17" "0.6.12" "0.7.6" "0.8.23")

DELIM=$'\n\n----------------------------------------------------------\n\n'

# --- Настройка окружения ---
python3 -m venv ./slither_venv
source ./slither_venv/bin/activate
pip install -e $SETUP_PY_PATH
pip install solc-select


# Установка последних версий solc
echo "Устанавливаем последние версии solc..."
for version in "${LAST_VERSIONS[@]}"; do
    solc-select install "$version"
done


# --- Функция для определения нужной версии solc ---
get_required_solc() {
    local contract_path=$1
    # Ищем строку pragma solidity и извлекаем версию
    local pragma_line=$(grep -m 1 -E "pragma solidity\s*(.*);" "$contract_path")
    
    if [[ "$pragma_line" =~ \^0\.([0-9]+)\.[0-9]+\; ]]; then
        local major_version=${BASH_REMATCH[1]}
        for version in "${LAST_VERSIONS[@]}"; do
            if [[ "$version" =~ 0\.$major_version\.[0-9]+ ]]; then
                echo "$version"
                return
            fi
        done
    elif [[ "$pragma_line" =~ \^0\.([0-9]+)\; ]]; then
        local major_version=${BASH_REMATCH[1]}
        for version in "${LAST_VERSIONS[@]}"; do
            if [[ "$version" =~ 0\.$major_version\.[0-9]+ ]]; then
                echo "$version"
                return
            fi
        done
    fi
    
    # Если не смогли определить, используем самую новую версию
    echo "${LAST_VERSIONS[-1]}"
}


# --- Анализ контрактов ---
echo "🔍 Запуск Slither с детекторами: $DETECTORS"
echo "📂 Директория с контрактами: $CONTRACTS_DIR"
echo "📄 Контракты для анализа: ${CONTRACT_NAMES[@]}"
echo "$DELIM"

for contract in "${CONTRACT_NAMES[@]}"; do
    contract_path="$CONTRACTS_DIR/$contract"
    if [ ! -f "$contract_path" ]; then
        echo "⚠️ Ошибка: Контракт $contract не найден в $CONTRACTS_DIR. Пропускаем."
        continue
    fi

    # Определяем нужную версию solc
    REQUIRED_SOLC=$(get_required_solc "$contract_path")
    echo "🛠️ Для $contract требуется solc $REQUIRED_SOLC"
    solc-select use "$REQUIRED_SOLC"

    echo "📋 Анализ $contract..."
    slither "$contract_path"                       --solc-solcs-bin "$(which solc)"
    # slither "$contract_path" --detect "$DETECTORS" --solc-solcs-bin "$(which solc)"
    echo "$DELIM"
done


echo "✅ Анализ завершен."



    # slither "$contract_path" --detect "$DETECTORS" --solc-solcs-bin "$(which solc)" #--json - | jq .  # Красивое форматирование JSON через jq
    # slither "$contract_path" --detect "incorrect-eip712" --solc-solcs-bin "$(which solc)" #--json - | jq .  # Красивое форматирование JSON через jq
    # slither "$contract_path"                             --solc-solcs-bin "$(which solc)"
