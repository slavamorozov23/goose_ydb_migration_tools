#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, Dict, List

# === Конфигурация соединения с YDB ===
YDB_SECURE_ENDPOINT: str = "grpcs://ydb.serverless.yandexcloud.net:2135"

# === Пути проекта ===
PROJECT_ROOT_DIRECTORY: Path = Path(__file__).resolve().parent
DEFAULT_MIGRATIONS_DIRECTORY: Path = PROJECT_ROOT_DIRECTORY
IAM_TOKEN_FILE: Path = PROJECT_ROOT_DIRECTORY / "iam.token"

MASK_SECRETS_IN_LOGS = True  # маскировать token=… в печати команд


# ---------- helpers: системные ----------

def read_iam_token(file_path: Path) -> str:
    if not file_path.exists():
        raise RuntimeError("> Не найден iam.token — сперва запусти create_migration.py")
    tok = file_path.read_text(encoding="utf-8").strip()
    if not tok:
        raise RuntimeError("> Файл iam.token пуст — пересоздай токен: python create_migration.py")
    return tok


def build_dsn(endpoint: str, db_path: str, access_token: str) -> str:
    # Для goose+ydb нужен scripting и корректный биндинг параметров
    return (
        f"{endpoint}{db_path}"
        "?go_query_mode=scripting"
        "&go_fake_tx=scripting"
        "&go_query_bind=declare,numeric"
        f"&token={access_token}"
    )


def mask_secrets_in_text(s: str) -> str:
    return re.sub(r"(token=)[^&'\"]+", r"\1***", s)


def check_goose_installed() -> None:
    path = shutil.which("goose")
    if not path:
        raise RuntimeError(
            "> Не найден 'goose' в PATH. Установи: "
            "go install github.com/pressly/goose/v3/cmd/goose@latest"
        )
    try:
        subprocess.run([path, "-h"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except Exception:
        raise RuntimeError("> 'goose' найден, но не запускается. Проверь установку/PATH.")


@dataclass
class ProcResult:
    code: int
    out: str
    err: str


def run_goose(args: List[str]) -> ProcResult:
    printable = " ".join(shlex.quote(a) for a in args)
    if MASK_SECRETS_IN_LOGS:
        printable = mask_secrets_in_text(printable)
    print(f"\n$ {printable}")
    cp = subprocess.run(args, text=True, capture_output=True)
    out, err = cp.stdout or "", cp.stderr or ""
    if out.strip():
        print(out.rstrip())
    if cp.returncode != 0 and err.strip():
        print(err.rstrip())
    return ProcResult(cp.returncode, out, err)


# ---------- helpers: goose ошибки ----------

PATTERNS: List[Tuple[str, str, bool]] = [
    (r"\bUnauthenticated\b|\bUNAUTHENTICATED\b", "> Нет валидных учётных данных: проверь token в iam.token.", False),
    (r"\bPERMISSION_DENIED\b", "> Недостаточно прав на операцию — проверь роли/доступ.", False),
    (r"\bDEADLINE_EXCEEDED\b", "> Транспортный таймаут — проверь сеть/увеличь таймаут.", False),

    (r"code\s*=\s*400130|\bALREADY_EXISTS\b", "> Объект уже существует — шаг эквивалентен применённому.", True),
    (r"code\s*=\s*400070|\bSCHEME_ERROR\b|\bGENERIC_ERROR\b", "> Ошибка схемы — проверь DDL/названия колонок/типов/путь к таблице.", False),
    (r"code\s*=\s*400140|\bNOT_FOUND\b", "> Объект схемы не найден — проверь database path/имя таблицы.", False),
    (r"code\s*=\s*400120|\bPRECONDITION_FAILED\b", "> Состояние БД не позволяет выполнить операцию.", False),
    (r"code\s*=\s*400090|\bTIMEOUT\b", "> Истёк operation timeout на сервере — возможна частичная обработка.", False),
    (r"code\s*=\s*400050|\bUNAVAILABLE\b", "> Сервис временно недоступен — повтори позже.", False),
    (r"code\s*=\s*400060|\bOVERLOADED\b", "> Кластер перегружен — ретраи с паузами.", False),
    (r"code\s*=\s*400100|\bBAD_SESSION\b|\bSESSION_BUSY\b", "> Сессия занята/битая — пересоздай соединение.", True),
    (r"code\s*=\s*400150|\bSESSION_EXPIRED\b", "> Сессия истекла — пересоздай и повтори.", True),

    (r'Column: ".*?" already exists', "> Колонка уже существует — шаг можно пропустить.", True),
    (r"failed to close DB.*DeadlineExceeded", "> Команда выполнена, но закрытие соединения истекло — игнорируем.", True),
]


def explain_error(stderr: str, stdout: str) -> Tuple[str, bool]:
    s = f"{stdout}\n{stderr}"
    for pat, msg, cont in PATTERNS:
        if re.search(pat, s, flags=re.IGNORECASE | re.DOTALL):
            return msg, cont
    return ("> Неизвестная ошибка goose/YDB — смотри stderr выше.", False)


# ---------- выбор файла миграции (Tk) ----------

def pick_migration_file(start_dir: Path) -> Path:
    try:
        import tkinter as tk
        from tkinter import filedialog
    except Exception as e:
        raise RuntimeError("tkinter не доступен: установи стандартный Tk или используй консольный режим") from e

    root = tk.Tk()
    root.withdraw()  # не показывать пустое окно
    path_str = filedialog.askopenfilename(
        initialdir=str(start_dir),
        title="Выбери файл миграции (.sql)",
        filetypes=[("SQL files", "*.sql"), ("All files", "*.*")],
    )
    root.destroy()
    if not path_str:
        raise SystemExit("> Отменено пользователем.")
    return Path(path_str)


# ---------- парсинг SQL: только абсолютные пути ----------

ABS_PATH_IN_BACKTICKS = re.compile(r"`(/ru-central1/[^`]+)`")

def extract_version_from_filename(file_name: str) -> Optional[int]:
    # НЕ валидируем строго. Берём первую «длинную» последовательность цифр.
    m = re.search(r"(\d{6,})", file_name) or re.search(r"(\d+)", file_name)
    if not m:
        return None
    try:
        return int(m.group(1))
    except ValueError:
        return None


def split_goose_sections(sql_text: str) -> Tuple[str, str]:
    """
    Возвращает (up_text, down_text). Если метки не найдены — up_text = весь файл, down_text = "".
    """
    m = re.search(r"(?s)--\s*\+goose\s+Up(.*?)--\s*\+goose\s+Down", sql_text, flags=re.IGNORECASE)
    if m:
        up_text = m.group(1)
        down_text = sql_text[m.end():]
        return up_text, down_text
    # Нет Down — попробуем только Up
    m2 = re.search(r"(?s)--\s*\+goose\s+Up(.*)", sql_text, flags=re.IGNORECASE)
    if m2:
        return m2.group(1), ""
    # Нет меток — берём всё как Up
    return sql_text, ""


def extract_db_path_from_abs_table(abs_table_path: str) -> Optional[str]:
    """
    Преобразование /ru-central1/<cloud>/<db>/<...> -> /ru-central1/<cloud>/<db>
    """
    if not abs_table_path.startswith("/ru-central1/"):
        return None
    parts = abs_table_path.strip("/").split("/")
    if len(parts) < 3:
        return None
    return "/" + "/".join(parts[:3])


def group_sql_lines_by_dbpath(sql_text: str) -> Dict[str, List[str]]:
    """
    Берём только те строки, где есть абсолютный путь в бэктиках.
    Группируем по database path.
    """
    groups: Dict[str, List[str]] = {}
    for line in sql_text.splitlines():
        m = ABS_PATH_IN_BACKTICKS.search(line)
        if not m:
            continue  # по требованию — игнорируем строки без абсолютного пути
        abs_path = m.group(1)
        db_path = extract_db_path_from_abs_table(abs_path)
        if not db_path:
            continue
        groups.setdefault(db_path, []).append(line.rstrip())
    return groups


def build_subset_migration(up_lines: List[str], down_lines: List[str]) -> str:
    """
    Строим минимальную миграцию для выбранного database path.
    Секции Up/Down оборачиваем в один StatementBegin/End на секцию.
    """
    up_block = "\n".join(up_lines).strip()
    down_block = "\n".join(down_lines).strip()

    # Обязательно оставляем обе секции, даже если одна пустая — goose не против.
    parts = ["-- +goose Up", "-- +goose StatementBegin"]
    if up_block:
        parts.append(up_block)
    parts.append("-- +goose StatementEnd")
    parts.append("")
    parts.append("-- +goose Down")
    parts.append("-- +goose StatementBegin")
    if down_block:
        parts.append(down_block)
    parts.append("-- +goose StatementEnd")
    parts.append("")
    return "\n".join(parts)


# ---------- goose действия ----------

def goose_status(dsn: str, migrations_dir: Path) -> None:
    args = ["goose", "-dir", str(migrations_dir), "ydb", dsn, "status"]
    pr = run_goose(args)
    if pr.code == 0:
        return
    msg, cont = explain_error(pr.err, pr.out)
    print(msg)
    if not cont:
        raise SystemExit(1)


def goose_version(dsn: str, migrations_dir: Path) -> Optional[int]:
    args = ["goose", "-dir", str(migrations_dir), "ydb", dsn, "version"]
    pr = run_goose(args)
    txt = (pr.out or "") + "\n" + (pr.err or "")
    m = re.search(r"version\s+(\d+)", txt, re.IGNORECASE)
    if (pr.code == 0 or "failed to close DB" in txt) and m:
        try:
            return int(m.group(1))
        except ValueError:
            return None
    return None


def goose_up_to(dsn: str, migrations_dir: Path, version: int) -> None:
    args = ["goose", "-dir", str(migrations_dir), "ydb", dsn, "up-to", str(version)]
    pr = run_goose(args)
    if pr.code == 0:
        return
    msg, cont = explain_error(pr.err, pr.out)
    print(msg)
    if not cont:
        raise SystemExit(1)


# ---------- main ----------

def main() -> None:
    print("🔍 Проверяем goose...")
    check_goose_installed()

    print("🔐 Читаем IAM-токен...")
    token = read_iam_token(IAM_TOKEN_FILE)

    print("🗂 Открываем проводник для выбора .sql миграции...")
    chosen_file = pick_migration_file(DEFAULT_MIGRATIONS_DIRECTORY)
    if not chosen_file.exists():
        raise RuntimeError(f"> Файл не найден: {chosen_file}")

    version = extract_version_from_filename(chosen_file.name)
    if version is None:
        print(
            "\n⚠️  Не удалось извлечь номер версии из имени файла.\n"
            "Goose запускает конкретную миграцию по НОМЕРУ версии (из имени файла). "
            "Переименуй файл с числовым префиксом (например, 20251026164222_*.sql)."
        )
        sys.exit(2)

    # читаем SQL
    raw_sql = chosen_file.read_text(encoding="utf-8", errors="ignore")

    # делим на Up/Down
    up_text, down_text = split_goose_sections(raw_sql)

    # группируем только те строки, где есть абсолютный путь
    up_groups = group_sql_lines_by_dbpath(up_text)
    down_groups = group_sql_lines_by_dbpath(down_text)

    if not up_groups:
        print(
            "⚠️  В секции Up не найдено ни одной строки с полным путём `/ru-central1/...`.\n"
            "Обработка по требованию выполняется только для абсолютных путей. Нечего применять."
        )
        sys.exit(0)

    # Список всех database path, которые встречаются (объединяем из Up и Down)
    all_db_paths = list({*up_groups.keys(), *down_groups.keys()})

    print(f"📦 Обнаружены database path в файле миграции: {len(all_db_paths)}")
    for dbp in all_db_paths:
        n_up = len(up_groups.get(dbp, []))
        n_down = len(down_groups.get(dbp, []))
        print(f"   • {dbp} — Up: {n_up} stmt, Down: {n_down} stmt")

    # Для каждого database path — делаем временную "под-миграцию" и применяем только её
    for db_path in all_db_paths:
        print(f"\n=== ▶ Применение под-миграции для базы: {db_path} ===")
        subset_sql = build_subset_migration(
            up_lines=up_groups.get(db_path, []),
            down_lines=down_groups.get(db_path, []),
        )

        # создаём временную директорию и файл с ТЕМ ЖЕ именем (чтобы версия совпала)
        with tempfile.TemporaryDirectory(prefix=f"goose_{version}_") as tmpdir:
            tmpdir_path = Path(tmpdir)
            tmp_file = tmpdir_path / chosen_file.name
            tmp_file.write_text(subset_sql, encoding="utf-8")

            dsn = build_dsn(YDB_SECURE_ENDPOINT, db_path, token)

            print("🔎 Статус до применения:")
            goose_status(dsn, tmpdir_path)

            cur_ver = goose_version(dsn, tmpdir_path)
            if cur_ver is not None:
                print(f"> Текущая версия БД: {cur_ver}")

            if cur_ver is None or cur_ver < version:
                print(f"🚀 Применяем: up-to {version} (dir = {tmpdir_path})")
                goose_up_to(dsn, tmpdir_path, version)
            else:
                print(f"> База уже на версии {cur_ver} ≥ {version} — up-to ничего не сделает.")

            print("🔎 Статус после применения:")
            goose_status(dsn, tmpdir_path)

        print(f"=== ✔ Завершено для: {db_path} ===")

    print("\n✅ Все под-миграции по обнаруженным database path успешно обработаны.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n> Отменено пользователем.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)
