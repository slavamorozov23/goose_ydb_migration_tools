#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

# === Константы по умолчанию ===
YDB_SECURE_ENDPOINT: str = "grpcs://ydb.serverless.yandexcloud.net:2135"
YDB_DATABASE_PATH_DEFAULT: str = "/ru-central1/b1g2bgg0i9r8beucbthc/etnhgtg29jpjakvf0v6d"

PROJECT_ROOT_DIRECTORY: Path = Path(__file__).resolve().parent
IAM_TOKEN_FILE: Path = PROJECT_ROOT_DIRECTORY / "iam.token"

MASK_SECRETS_IN_LOGS = True


# ---------- helpers ----------

def read_iam_token(file_path: Path) -> str:
    if not file_path.exists():
        raise RuntimeError("> Не найден iam.token — сперва запусти create_migration.py")
    tok = file_path.read_text(encoding="utf-8").strip()
    if not tok:
        raise RuntimeError("> Файл iam.token пуст — пересоздай токен: python create_migration.py")
    return tok


def build_dsn(endpoint: str, db_path: str, access_token: str) -> str:
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
        raise RuntimeError("> Не найден 'goose' в PATH. Установи: go install github.com/pressly/goose/v3/cmd/goose@latest")
    try:
        subprocess.run([path, "-h"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except Exception:
        raise RuntimeError("> 'goose' найден, но не запускается. Проверь установку/PATH.")


@dataclass
class ProcResult:
    code: int
    out: str
    err: str


def run_goose(args: list[str]) -> ProcResult:
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


# === типовые ошибки (YDB/goose) ===
PATTERNS: list[tuple[str, str, bool]] = [
    (r"\bUnauthenticated\b|\bUNAUTHENTICATED\b", "> Нет валидных учётных данных: проверь token в iam.token.", False),
    (r"\bPERMISSION_DENIED\b", "> Недостаточно прав на операцию — проверь роли/доступ.", False),
    (r"\bDEADLINE_EXCEEDED\b", "> Транспортный таймаут — проверь сеть/увеличь таймаут.", False),

    (r"code\s*=\s*400130|\bALREADY_EXISTS\b", "> Объект уже существует — часть апгрейда уже была.", True),
    (r"code\s*=\s*400070|\bSCHEME_ERROR\b|\bGENERIC_ERROR\b", "> Ошибка схемы — проверь DDL/названия колонок/типов.", False),
    (r"code\s*=\s*400140|\bNOT_FOUND\b", "> Объект схемы не найден — проверь путь базы/имя таблицы.", False),
    (r"code\s*=\s*400090|\bTIMEOUT\b", "> Истёк operation timeout на сервере — частичное выполнение возможно.", False),
    (r"code\s*=\s*400050|\bUNAVAILABLE\b", "> Сервис временно недоступен — повтори позже.", False),
    (r"code\s*=\s*400060|\bOVERLOADED\b", "> Кластер перегружен — сделай ретраи с паузами.", False),

    (r'Column: ".*?" already exists', "> Колонка уже существует — часть апгрейда уже была.", True),
    (r"failed to close DB.*DeadlineExceeded", "> Команда выполнена, но закрытие соединения истекло — игнорируем.", True),
]


def explain_error(stderr: str, stdout: str) -> tuple[str, bool]:
    s = f"{stdout}\n{stderr}"
    for pat, msg, cont in PATTERNS:
        if re.search(pat, s, flags=re.IGNORECASE | re.DOTALL):
            return msg, cont
    return ("> Неизвестная ошибка goose/YDB — смотри stderr выше.", False)


# ---------- выбор файла (Tk) ----------

def pick_migration_file(start_dir: Path) -> Path:
    try:
        import tkinter as tk
        from tkinter import filedialog
    except Exception as e:
        raise RuntimeError("tkinter не доступен: установи стандартный Tk или используй консольный режим") from e

    root = tk.Tk()
    root.withdraw()
    path_str = filedialog.askopenfilename(
        initialdir=str(start_dir),
        title="Выбери файл миграции для ОТКАТА (.sql)",
        filetypes=[("SQL files", "*.sql"), ("All files", "*.*")],
    )
    root.destroy()
    if not path_str:
        raise SystemExit("> Отменено пользователем.")
    return Path(path_str)


# ---------- утилиты goose ----------

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


def goose_down_to(dsn: str, migrations_dir: Path, target_version: int) -> None:
    args = ["goose", "-dir", str(migrations_dir), "ydb", dsn, "down-to", str(target_version)]
    pr = run_goose(args)
    if pr.code == 0:
        return
    msg, cont = explain_error(pr.err, pr.out)
    print(msg)
    if not cont:
        raise SystemExit(1)


# ---------- разбор файла ----------

def detect_targets_hint(sql_text: str) -> list[str]:
    targets: list[str] = []
    for line in sql_text.splitlines():
        line = line.strip()
        if line.startswith("--  - "):  # из create_migration.py
            targets.append(line[6:].strip())
        else:
            m = re.search(r"`(/ru-central1/[^`]+)`", line)  # ALTER TABLE `/ru-central1/...`
            if m:
                targets.append(m.group(1))
    # уникализируем с сохранением порядка
    seen = set()
    uniq = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq


def extract_db_path_from_abs_table(abs_table_path: str) -> Optional[str]:
    """
    /ru-central1/<cloud>/<db>/<...> -> /ru-central1/<cloud>/<db>
    """
    if not abs_table_path.startswith("/ru-central1/"):
        return None
    parts = abs_table_path.strip("/").split("/")
    if len(parts) < 3:
        return None
    return "/" + "/".join(parts[:3])


def detect_db_path_from_sql(sql_text: str) -> Optional[str]:
    # 1) из комментариев
    for line in sql_text.splitlines():
        line = line.strip()
        if line.startswith("--  - "):
            candidate = line[6:].strip()
            dbp = extract_db_path_from_abs_table(candidate)
            if dbp:
                return dbp
    # 2) из ALTER с бэктиками
    for m in re.finditer(r"`(/ru-central1/[^`]+)`", sql_text):
        dbp = extract_db_path_from_abs_table(m.group(1))
        if dbp:
            return dbp
    # 3) из «сырых» путей
    m = re.search(r"(/ru-central1/[\w\-]+/[\w\-]+)", sql_text)
    if m:
        return m.group(1)
    return None


def extract_version_from_filename(file_name: str) -> Optional[int]:
    """
    НЕ валидируем строго. Берём первую «длинную» последовательность цифр в имени файла как версию.
    """
    m = re.search(r"(\d{6,})", file_name) or re.search(r"(\d+)", file_name)
    if not m:
        return None
    try:
        return int(m.group(1))
    except ValueError:
        return None


# ---------- main ----------

def main() -> None:
    print("🔍 Проверяем goose...")
    check_goose_installed()

    print("🔐 Читаем IAM-токен...")
    token = read_iam_token(IAM_TOKEN_FILE)

    print("🗂 Выбираем .sql для ОТКАТА...")
    chosen = pick_migration_file(PROJECT_ROOT_DIRECTORY)
    if not chosen.exists():
        raise RuntimeError(f"> Файл не найден: {chosen}")

    # читаем SQL для подсказок
    try:
        raw_sql = chosen.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        raw_sql = ""

    targets = detect_targets_hint(raw_sql)
    if targets:
        print(f"📦 Файл содержит абсолютные пути к {len(targets)} таблицам:")
        for t in targets[:12]:
            print(f"   • {t}")
        if len(targets) > 12:
            print(f"   … и ещё {len(targets)-12}")
    else:
        print("📦 Подсказки по таблицам не найдены в комментариях/DDL.")

    # Определим database path из файла, если возможно
    db_path_detected = detect_db_path_from_sql(raw_sql)
    db_path_final = db_path_detected or YDB_DATABASE_PATH_DEFAULT
    if db_path_detected and db_path_detected != YDB_DATABASE_PATH_DEFAULT:
        print(f"🏷  Обнаружен database path в файле миграции: {db_path_detected}")
        print(f"🧭 Используем обнаруженный путь вместо дефолтного ({YDB_DATABASE_PATH_DEFAULT}).")
    else:
        print(f"🧭 Используем database path по умолчанию: {YDB_DATABASE_PATH_DEFAULT}")

    print("🔗 Готовим DSN для YDB...")
    dsn = build_dsn(YDB_SECURE_ENDPOINT, db_path_final, token)

    mig_dir = chosen.parent.resolve()

    print("\n🔎 Статус до отката:")
    goose_status(dsn, mig_dir)

    cur_ver = goose_version(dsn, mig_dir)
    if cur_ver is not None:
        print(f"> Текущая версия БД: {cur_ver}")

    version = extract_version_from_filename(chosen.name)
    if version is None:
        print(
            "\n⚠️  Не удалось извлечь номер версии из имени файла. "
            "Goose делает откат по НОМЕРУ версии (из имени). "
            "Переименуй файл с числовым префиксом (например, 20251026163810_*.sql) или используй последовательные номера."
        )
        sys.exit(2)

    if cur_ver is not None and cur_ver < version:
        print(f"\n> Выбранная миграция {version} ещё не применена (текущая версия {cur_ver}). Откатывать нечего.")
    else:
        target = version - 1
        print(f"\n⏪ Выполняем откат: down-to {target} (снимет выбранную миграцию и все более новые).")
        goose_down_to(dsn, mig_dir, target)

    print("\n🔎 Статус после отката:")
    goose_status(dsn, mig_dir)

    print("\n✅ Откат завершён.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n> Отменено пользователем.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)
