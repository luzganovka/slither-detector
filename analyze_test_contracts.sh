#!/bin/bash

# --- Конфигурация ---
SETUP_PY_PATH="$HOME/Study/slither_detector_module/code"
CONTRACTS_DIR="$HOME/Study/slither_detector_module/code/test_contracts/my_eip_vuln"

# Флаги анализа
USE_ALL_DETECTORS=true       # Проверить всеми доступными детекторами (включая кастомные)

# Детекторы (актуально когда флаг false)
DETECTORS="incorrect-eip712,access-control,reentrancy-eth,unchecked-lowlevel"

# Устанавливаем последние версии для каждой major версии (0.4.x, 0.5.x и т.д.)
LAST_VERSIONS=("0.4.26" "0.5.17" "0.6.12" "0.7.6" "0.8.23")

DELIM=$'\n\n----------------------------------------------------------\n\n'

# --- Настройка окружения ---
python3 -m venv ./slither_venv
source ./slither_venv/bin/activate
pip install -e $SETUP_PY_PATH
pip install solc-select

# --- Функция проверки установки версии ---
is_solc_installed() {
    local version=$1
    # Проверяем через solc-select какие версии уже установлены
    if solc-select versions | grep -q "$version"; then
        return 0
    else
        return 1
    fi
}

# Установка последних версий solc с проверкой
echo "Проверяем и устанавливаем необходимые версии solc..."
for version in "${LAST_VERSIONS[@]}"; do
    if is_solc_installed "$version"; then
        echo "✓ Версия $version уже установлена"
    else
        echo "Устанавливаем версию $version..."
        solc-select install "$version"
    fi
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

# --- Определение детекторов для использования ---
determine_detectors() {
    if [ "$USE_ALL_DETECTORS" = true ]; then
        echo "all"  # Специальное значение для всех детекторов
    else
        echo "$DETECTORS"
    fi
}

DETECTORS_TO_USE=$(determine_detectors)

# --- Анализ контрактов ---
echo "🔍 Конфигурация анализа:"
echo "Использовать все детекторы: $USE_ALL_DETECTORS"
echo "Выбранные детекторы: $DETECTORS_TO_USE"
echo "📂 Директория с контрактами: $CONTRACTS_DIR"
echo "📄 Найдено контрактов: $(find "$CONTRACTS_DIR" -name "*.sol" | wc -l)"
echo "$DELIM"

# Рекурсивный поиск всех .sol файлов
find "$CONTRACTS_DIR" -type f -name "*.sol" | while read -r contract_path; do
    contract=$(basename "$contract_path")
    # Пропускаем пустые файлы
    if [ ! -s "$contract_path" ]; then
        echo "⚠️ Пустой файл: $contract_path. Пропускаем."
        continue
    fi

    # Определяем нужную версию solc
    REQUIRED_SOLC=$(get_required_solc "$contract_path")
    echo "🛠️ Для $contract требуется solc $REQUIRED_SOLC"
    solc-select use "$REQUIRED_SOLC"

    echo "📋 Анализ $contract..."
    
    if [ "$DETECTORS_TO_USE" = "all" ]; then
        slither "$contract_path" --solc-solcs-bin "$(which solc)"
    else
        slither "$contract_path" --detect "$DETECTORS_TO_USE" --solc-solcs-bin "$(which solc)"
    fi
    
    echo "$DELIM"
done

echo "✅ Анализ завершен."