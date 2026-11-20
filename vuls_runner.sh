#!/usr/bin/env bash
set -euo pipefail

# ================= НАСТРОЙКИ =================
WORK_DIR="$(cd "$(dirname "${BASH_SOURCE}")" && pwd)"
SSH_KEY="${HOME}/.ssh/id_ecdsa"
SSH_KNOWN_HOSTS="${HOME}/.ssh/known_hosts"
HOSTS_FILE="/etc/hosts"

DB_CONFIG="${WORK_DIR}/db.toml"
SERVERS_CONFIG="${WORK_DIR}/servers.toml"
MERGED_CONFIG="${WORK_DIR}/.merged_config.toml"

# Пути к файлам баз данных
CVE_DB="${WORK_DIR}/cve.sqlite3"
OVAL_DB="${WORK_DIR}/oval.sqlite3"
EXPLOIT_DB="${WORK_DIR}/go-exploitdb.sqlite3"

# Укажите дистрибутив и версии ОС из вашего servers.toml
OS_TARGETS=(
    "ubuntu 24.04"
    # "ubuntu 22.04"
    # "debian 12"
)

# Опции монтирования томов (добавьте ",Z", если на хосте включен SELinux)
VOL_OPTS=""
# =============================================

FORCE_UPDATE=false
PREFERRED_RUNTIME=""
CONTAINER_CMD=""

# Функция вывода справки
show_help() {
    cat <<EOF
Использование: $0 [ОПЦИИ]

Опции:
  -f, --force-update          Принудительно обновить базы уязвимостей, даже если они скачаны сегодня
  -r, --runtime <ENGINE>      Принудительно выбрать контейнерный движок: docker или podman
                              (по умолчанию используется docker, если доступен, иначе podman)
  -h, --help                  Показать эту справку и выйти

Примеры:
  $0                          Автовыбор движка и запуск сканирования
  $0 -r podman                Запуск принудительно через Podman
  $0 --runtime docker -f      Запуск через Docker с принудительным обновлением баз
EOF
}

# Определение и проверка контейнерного движка
resolve_runtime() {
    if [[ -n "${PREFERRED_RUNTIME}" ]]; then
        case "${PREFERRED_RUNTIME}" in
            docker|podman)
                if ! command -v "${PREFERRED_RUNTIME}" >/dev/null 2>&1; then
                    echo "Ошибка: указанный движок '${PREFERRED_RUNTIME}' не найден в системе." >&2
                    exit 1
                fi
                CONTAINER_CMD="${PREFERRED_RUNTIME}"
                ;;
            *)
                echo "Ошибка: неподдерживаемый движок '${PREFERRED_RUNTIME}'. Допустимые значения: docker, podman." >&2
                exit 1
                ;;
        esac
    else
        if command -v docker >/dev/null 2>&1; then
            CONTAINER_CMD="docker"
        elif command -v podman >/dev/null 2>&1; then
            CONTAINER_CMD="podman"
        else
            echo "Ошибка: не найден ни docker, ни podman. Установите один из движков для продолжения." >&2
            exit 1
        fi
    fi
}

# Автоматическое добавление новых хостов из servers.toml в ~/.ssh/known_hosts
sync_known_hosts() {
    if ! command -v ssh-keyscan >/dev/null 2>&1 || ! command -v ssh-keygen >/dev/null 2>&1; then
        echo "Предупреждение: утилиты ssh-keyscan/ssh-keygen не найдены, пропуск автообновления known_hosts."
        return 0
    fi

    mkdir -p "$(dirname "${SSH_KNOWN_HOSTS}")"
    touch "${SSH_KNOWN_HOSTS}"
    chmod 600 "${SSH_KNOWN_HOSTS}"

    local hosts
    hosts=$(grep -E '^[[:space:]]*host[[:space:]]*=' "${SERVERS_CONFIG}" \
        | sed -E 's/^[[:space:]]*host[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/' \

        | sort -u || true)

    local default_port
    default_port=$(grep -E '^[[:space:]]*port[[:space:]]*=' "${SERVERS_CONFIG}" \
        | head -n 1 \

        | sed -E 's/^[[:space:]]*port[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/' || true)
    default_port="${default_port:-22}"

    for h in ${hosts}; do
        [[ "${h}" == "127.0.0.1" || "${h}" == "localhost" ]] && continue

        if ! ssh-keygen -F "${h}" -f "${SSH_KNOWN_HOSTS}" >/dev/null 2>&1; then
            echo "-> Добавление отпечатка SSH для ${h} (порт ${default_port}) в known_hosts..."
            ssh-keyscan -H -p "${default_port}" "${h}" >> "${SSH_KNOWN_HOSTS}" 2>/dev/null || \
                echo "Предупреждение: не удалось получить SSH-ключ для ${h}" >&2
        fi
    done
}

# Разбор аргументов командной строки
while [[ $# -gt 0 ]]; do
    case "$1" in
        -f|--force-update)
            FORCE_UPDATE=true
            shift
            ;;
        -r|--runtime)
            if [[ $# -lt 2 || "$2" == -* ]]; then
                echo "Ошибка: флаг $1 требует аргумент (docker или podman)." >&2
                exit 1
            fi
            PREFERRED_RUNTIME="$2"
            shift 2
            ;;
        --runtime=*)
            PREFERRED_RUNTIME="${1#*=}"
            if [[ -z "${PREFERRED_RUNTIME}" ]]; then
                echo "Ошибка: флаг --runtime= требует значение (docker или podman)." >&2
                exit 1
            fi
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Неизвестный параметр: $1" >&2
            echo "Используйте $0 --help для справки." >&2
            exit 1
            ;;
    esac
done

# Автоматическое удаление временного конфига при выходе
cleanup() {
    rm -f "${MERGED_CONFIG}"
}
trap cleanup EXIT

# Функция проверки: нужно ли обновлять файл БД
needs_update() {
    local db_file="$1"

    if [[ "${FORCE_UPDATE}" == "true" ]]; then
        return 0
    fi

    if [[ ! -s "${db_file}" ]]; then
        return 0
    fi

    local file_date
    local today_date
    file_date=$(date -r "${db_file}" +%Y-%m-%d)
    today_date=$(date +%Y-%m-%d)

    if [[ "${file_date}" != "${today_date}" ]]; then
        return 0
    fi

    return 1
}

resolve_runtime

echo "=== [1/5] Сборка конфигурации и проверка окружения (движок: ${CONTAINER_CMD}) ==="
if [[ ! -f "${DB_CONFIG}" || ! -f "${SERVERS_CONFIG}" ]]; then
    echo "Ошибка: не найдены файлы db.toml или servers.toml в ${WORK_DIR}" >&2
    exit 1
fi

if [[ ! -f "${SSH_KEY}" ]]; then
    echo "Ошибка: SSH-ключ ${SSH_KEY} не найден!" >&2
    exit 1
fi

sync_known_hosts

SSH_VOLUMES=(
    -v "${HOSTS_FILE}:/etc/hosts:ro"
    -v "${SSH_KEY}:/root/.ssh/id_ecdsa:ro${VOL_OPTS}"
    -v "${SSH_KNOWN_HOSTS}:/root/.ssh/known_hosts:ro${VOL_OPTS}"
)

cat "${DB_CONFIG}" > "${MERGED_CONFIG}"
echo "" >> "${MERGED_CONFIG}"
cat "${SERVERS_CONFIG}" >> "${MERGED_CONFIG}"

mkdir -p "${WORK_DIR}/results" "${WORK_DIR}/logs"

echo "=== [2/5] Проверка и обновление баз уязвимостей ==="

# 1. База NVD (CVE)
if needs_update "${CVE_DB}"; then
    echo "-> Загрузка базы NVD (cve.sqlite3)..."
    "${CONTAINER_CMD}" run --rm \
        -v "${WORK_DIR}:/vuls${VOL_OPTS}" \
        docker.io/vuls/go-cve-dictionary fetch --dbpath=/vuls/cve.sqlite3 nvd
else
    echo "-> База NVD уже обновлена сегодня. Пропуск."
fi

# 2. База OVAL
if needs_update "${OVAL_DB}"; then
    for target in "${OS_TARGETS[@]}"; do
        read -r distro version <<< "${target}"
        echo "-> Загрузка базы OVAL для ${distro} ${version}..."
        "${CONTAINER_CMD}" run --rm \
            -v "${WORK_DIR}:/vuls${VOL_OPTS}" \
            docker.io/vuls/goval-dictionary fetch --dbpath=/vuls/oval.sqlite3 "${distro}" "${version}"
    done
else
    echo "-> База OVAL уже обновлена сегодня. Пропуск."
fi

# 3. База ExploitDB
if needs_update "${EXPLOIT_DB}"; then
    echo "-> Загрузка базы Go-ExploitDB..."
    "${CONTAINER_CMD}" run --rm \
        -v "${WORK_DIR}:/vuls${VOL_OPTS}" \
        docker.io/vuls/go-exploitdb fetch --dbpath=/vuls/go-exploitdb.sqlite3 exploitdb
else
    echo "-> База Go-ExploitDB уже обновлена сегодня. Пропуск."
fi

echo "=== [3/5] Проверка конфигурации (configtest) ==="
"${CONTAINER_CMD}" run --rm \
    "${SSH_VOLUMES[@]}" \
    -v "${WORK_DIR}:/vuls${VOL_OPTS}" \
    docker.io/vuls/vuls configtest -config=/vuls/.merged_config.toml

echo "=== [4/5] Запуск сканирования (scan) ==="
"${CONTAINER_CMD}" run --rm \
    "${SSH_VOLUMES[@]}" \
    -v "${WORK_DIR}:/vuls${VOL_OPTS}" \
    docker.io/vuls/vuls scan \
    -config=/vuls/.merged_config.toml \
    -results-dir=/vuls/results \
    -log-dir=/vuls/logs

echo "=== [5/5] Генерация отчета (TXT) ==="
FULL_TXT_REPORT="${WORK_DIR}/results/full_report.txt"

# Сохраняем полный текстовый отчет в файл
"${CONTAINER_CMD}" run --rm \
    -v "${WORK_DIR}:/vuls${VOL_OPTS}" \
    docker.io/vuls/vuls report \
    -config=/vuls/.merged_config.toml \
    -results-dir=/vuls/results \
    -log-dir=/vuls/logs \
    -format-full-text > "${FULL_TXT_REPORT}"

# Выводим в консоль краткую сводку по серверам без списка исправляемых пакетов
echo ""
"${CONTAINER_CMD}" run --rm \
    -v "${WORK_DIR}:/vuls${VOL_OPTS}" \
    docker.io/vuls/vuls report \
    -config=/vuls/.merged_config.toml \
    -results-dir=/vuls/results \
    -log-dir=/vuls/logs \
    -format-one-line-text

echo ""
echo "✅ Сканирование завершено! Полный текстовый отчет сохранен в: ${FULL_TXT_REPORT}"
