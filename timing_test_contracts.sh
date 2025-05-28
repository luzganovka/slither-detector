#!/bin/bash

# --- Конфигурация ---
SETUP_PY_PATH="$HOME/Study/slither_detector_module/code"
DETECTORS="incorrect-eip712,access-control"
CONTRACTS_DIR="$HOME/Study/slither_detector_module/code/test_contracts/my_eip_vuln"
LOG_FILE="timing/analysis_$(date +%Y%m%d_%H%M%S).log"
TIMINGS_FILE="timing/timings.csv"

# Поддерживаемые версии solc (только стабильные релизы)
LAST_VERSIONS=("0.4.26" "0.5.17" "0.6.12" "0.7.6" "0.8.26")

# --- Функции ---
get_required_solc() {
    local contract_path=$1
    local pragma_line=$(grep -m 1 -E "pragma solidity\s*[\^<=>]*\s*[0-9.]+\s*;" "$contract_path" 2>/dev/null | head -1)
    
    if [[ "$pragma_line" =~ 0\.([0-9]+)\.[0-9]+ ]]; then
        local major_ver=${BASH_REMATCH[1]}
        for ver in "${LAST_VERSIONS[@]}"; do
            if [[ "$ver" =~ 0\.$major_ver\.[0-9]+ ]]; then
                echo "$ver"
                return
            fi
        done
    fi
    
    echo "0.8.26"  # Версия по умолчанию
}

analyze_contract() {
    local contract_path=$1
    local required_solc=$(get_required_solc "$contract_path")
    local result="ERROR"

    echo "=== Analyzing $(basename "$contract_path") with solc $required_solc ===" >> "$LOG_FILE"

    # переключаем версию solc
    solc-select use "$required_solc" >/dev/null 2>&1
    
    # запуск и таймирование slither
    local start_time=$(date +%s.%N)
    slither_output=$(slither "$contract_path" \
        --detect "$DETECTORS" \
        --solc-solcs-bin "$(which solc)" \
        2>&1)
    local end_time=$(date +%s.%N)
    local elapsed=$(echo "$end_time - $start_time" | bc -l)

    # Сохраняем вывод в лог
    echo "$slither_output" >> "$LOG_FILE"

    # Проверяем наличие ключевых слов в выводе
    if [[ "$slither_output" =~ "INFO:Slither:" ]]; then
        result="SUCCESS"
        ((success_count++))
        echo "SUCCESS COUNT: $success_count" >> "$LOG_FILE"
    fi
    
    echo "\"$contract_path\",\"$required_solc\",$elapsed,\"$result\"" >> "$TIMINGS_FILE"
    echo "$contract_path : $result (${elapsed}s)"
}

# --- MAIN ---
# --- Инициализация ---
echo "Contract,Version,Time,Result" > "$TIMINGS_FILE"
total_contracts=0
success_count=0

echo "Начало анализа в $(date)" | tee -a "$LOG_FILE"
total_contracts=$(find "$CONTRACTS_DIR" -name "*.sol" | wc -l)

# -- Цикл по всем контрактам ---
while read -r contract; do
    analyze_contract "$contract"
done < <(find "$CONTRACTS_DIR" -name "*.sol") | tqdm --total "$total_contracts" --desc "Анализ контрактов" >/dev/null

# --- Итоги ---
echo "=== Результаты ==="                                           | tee -a "$LOG_FILE"
echo "Всего контрактов: $total_contracts"                           | tee -a "$LOG_FILE"
# echo "Успешно проанализировано: $success_count"                     | tee -a "$LOG_FILE"
# echo "Процент успеха: $((100 * success_count / total_contracts))%"  | tee -a "$LOG_FILE"
echo "Детали в $LOG_FILE и $TIMINGS_FILE"