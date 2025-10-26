#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import colorsys
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse, parse_qs

try:
    import colorama
except Exception:
    colorama = None

import tkinter as tk
from tkinter import ttk, messagebox

ROOT = Path(__file__).resolve().parent
MIGRATIONS_DIR = ROOT
IAM_TOKEN_FILE = ROOT / "iam.token"

YC_TIMEOUT = 20
YDB_TIMEOUT = 40

DEBUG_RAW = os.environ.get("YDB_MIGRATIONS_DEBUG", "1").lower() not in {"0", "false", "no"}
def _enable_vt_win() -> bool:
    try:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        h = kernel32.GetStdHandle(-11)
        mode = wintypes.DWORD()
        if not kernel32.GetConsoleMode(h, ctypes.byref(mode)):
            return False
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        new_mode = wintypes.DWORD(mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
        if not kernel32.SetConsoleMode(h, new_mode):
            return False
        return True
    except Exception:
        return False

def _supports_ansi() -> bool:
    v = os.environ.get("YDB_MIGRATIONS_ANSI")
    if v is not None:
        return v.lower() not in {"0", "false", "no"}
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        if colorama is not None:
            try:
                colorama.init(convert=True)
                return True
            except Exception:
                pass
        if _enable_vt_win():
            return True
        return False
    return True
ANSI_OK = _supports_ansi()

# ====== утилиты CLI / логирование ======
@dataclass
class RunResult:
    code: int
    out: str
    err: str

class CmdError(RuntimeError):
    pass

def which(bin_name: str) -> Optional[str]:
    from shutil import which as _which
    return _which(bin_name)

def _log_block(label: str, text: str) -> None:
    if not DEBUG_RAW:
        return
    prefix = "\x1b[90m\x1b[3m" if ANSI_OK else ""
    suffix = "\x1b[0m" if ANSI_OK else ""
    indent = "" if ANSI_OK else "  "
    print()
    print(f"{indent}{prefix}=== {label}_BEGIN ==={suffix}")
    if text:
        t = text.rstrip("\n")
        for ln in t.splitlines():
            print(f"{indent}{prefix}{ln}{suffix}")
    print(f"{indent}{prefix}=== {label}_END ==={suffix}")
    print()

def run(cmd: Sequence[str], timeout: int, *, echo_stdout: bool = False, echo_stderr: bool = True, raw_label: Optional[str] = None) -> RunResult:
    printable = " ".join(shlex.quote(x) for x in cmd)
    print()
    print(f"$ {printable}")
    try:
        cp = subprocess.run(
            cmd,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise CmdError(f"> Таймаут: {printable}") from e
    out, err = cp.stdout or "", cp.stderr or ""
    if raw_label is not None:
        _log_block(raw_label + "_STDOUT", out)
        if err.strip():
            _log_block(raw_label + "_STDERR", err)
    # Если вывод уже показан в RAW-блоке, не дублируем его обычной печатью
    if raw_label is None and echo_stdout and out.strip():
        print(out.rstrip())
    if raw_label is None and cp.returncode != 0 and echo_stderr and err.strip():
        print(err.rstrip())
    return RunResult(cp.returncode, out, err)

# ====== IAM‑токен ======

def ensure_iam_token() -> str:
    if IAM_TOKEN_FILE.exists():
        t = IAM_TOKEN_FILE.read_text(encoding="utf-8").strip()
        if t:
            return t
    if not which("yc"):
        raise CmdError("> Не найден 'yc' в PATH. Установи Yandex Cloud CLI и выполни 'yc init'.")
    print("🔐 Получаем IAM‑токен (yc iam create-token)…")
    rr = run(["yc", "iam", "create-token"], timeout=YC_TIMEOUT, raw_label="RAW_YC_IAM_CREATE_TOKEN")
    if rr.code != 0 or not rr.out.strip():
        raise CmdError("> Не удалось получить IAM‑токен (yc iam create-token).")
    tok = rr.out.strip()
    IAM_TOKEN_FILE.write_text(tok, encoding="utf-8")
    print(f"✅ Токен сохранён: {IAM_TOKEN_FILE}")
    return tok

# ====== YC: список баз ======
@dataclass
class YdbDb:
    id: str
    name: str
    endpoint: str  # grpcs://host:2135
    database: str  # /ru-central1/.../...

def _split_ydb_endpoint(full: str) -> Tuple[str, str]:
    p = urlparse(full.strip())
    endpoint = f"{p.scheme}://{p.netloc}".rstrip("/")
    db = (parse_qs(p.query).get("database") or [""])[0]
    return endpoint, db

def _coerce_db_item(item: Dict[str, Any]) -> Optional[YdbDb]:
    eid = str(item.get("id") or item.get("name") or "").strip()
    name = str(item.get("name") or "").strip() or eid
    full = str(item.get("endpoint") or "").strip()
    if not full:
        return None
    ep, db = _split_ydb_endpoint(full)
    if not db.startswith("/"):
        return None
    return YdbDb(id=eid or name, name=name, endpoint=ep, database=db)

def list_ydb_databases() -> List[YdbDb]:
    if not which("yc"):
        raise CmdError("> Не найден 'yc' в PATH.")
    rr = run(["yc", "ydb", "database", "list", "--format", "json"], timeout=YC_TIMEOUT, raw_label="RAW_YC_YDB_DATABASE_LIST")
    if rr.code != 0 or not rr.out.strip():
        raise CmdError("> Не удалось получить список баз (yc ydb database list).")
    items: List[YdbDb] = []
    try:
        data = json.loads(rr.out)
        for it in data:
            db = _coerce_db_item(it)
            if db:
                items.append(db)
    except Exception as e:
        raise CmdError(f"> Некорректный JSON от yc: {e}")
    if not items:
        raise CmdError("> Список баз пуст.")
    return items

# ====== YDB CLI ======
@dataclass
class Node:
    name: str
    path: str  # абсолютный
    is_dir: bool

class YdbCli:
    def __init__(self, endpoint: str, database: str, token_file: Path):
        self.endpoint = endpoint
        self.database = database
        self.token_file = token_file

    def base(self) -> List[str]:
        return [
            "ydb", "-e", self.endpoint, "-d", self.database,
            "--token-file", str(self.token_file),
        ]

    def whoami(self) -> None:
        run(self.base() + ["discovery", "whoami"], timeout=YDB_TIMEOUT, echo_stdout=True, raw_label="RAW_YDB_WHOAMI")

    def scheme_ls_paths(self) -> List[str]:
        # Самый совместимый способ: один объект в строку (-1) + рекурсивно (‑R)
        rr = run(self.base() + ["scheme", "ls", "-R1"], timeout=YDB_TIMEOUT, raw_label="RAW_YDB_SCHEME_LS_R1")
        if rr.code == 0 and rr.out.strip():
            # Формат похож на ls -R: секции с заголовками "<dir>:" и списком имён ниже
            entries: List[str] = []
            cur_dir = ""
            for ln in rr.out.splitlines():
                s = ln.strip()
                if not s:
                    continue
                # Заголовок раздела "path:"
                if s.endswith(":"):
                    hdr = s[:-1].strip()
                    if hdr in (".", "./"):
                        cur_dir = ""
                    else:
                        if hdr.startswith("./"):
                            hdr = hdr[2:]
                        cur_dir = hdr.strip("/")
                    continue
                # Обычная строка-элемент каталога
                item = s.rstrip("/")
                path = f"{cur_dir}/{item}" if cur_dir else item
                # Отсечём системные пути
                if path == ".sys" or path.startswith(".sys/"):
                    continue
                entries.append(path)
            if entries:
                return entries
        # Фолбэк: подробный формат (‑lR)
        rr2 = run(self.base() + ["scheme", "ls", "-lR"], timeout=YDB_TIMEOUT, raw_label="RAW_YDB_SCHEME_LS_lR")
        if not rr2.out.strip():
            return []
        # Попробуем выцепить пути из вида "<table> path" / "<directory> path"
        paths: List[str] = []
        for line in rr2.out.splitlines():
            m = re.search(r"<(?:table|directory|topic|column_table)>\s+(\S+)", line)
            if m:
                paths.append(m.group(1))
        if paths:
            return paths
        # Разбор табличного вывода (рамки) — берём столбцы Type/Name
        in_box = False
        name_idx: Optional[int] = None
        type_idx: Optional[int] = None
        for line in rr2.out.splitlines():
            s = line.strip()
            if not in_box and s.startswith("┌"):
                in_box = True
                name_idx = None
                type_idx = None
                continue
            if in_box and s.startswith("└"):
                in_box = False
                continue
            if in_box and "│" in line:
                cells = [c.strip() for c in line.split("│")]
                if ("Type" in cells) and ("Name" in cells):
                    try:
                        type_idx = cells.index("Type")
                        name_idx = cells.index("Name")
                    except ValueError:
                        name_idx = None
                        type_idx = None
                    continue
                if name_idx is None:
                    name = cells[-2] if len(cells) >= 2 else ""
                    typ = cells[1] if len(cells) >= 2 else ""
                else:
                    name = cells[name_idx] if name_idx < len(cells) else ""
                    typ = cells[type_idx] if (type_idx is not None and type_idx < len(cells)) else ""
                if not name or name == "Name":
                    continue
                if name.startswith(".sys"):
                    continue
                if str(typ).lower() == "table":
                    paths.append(name)
        return paths

    def describe(self, abs_path: str) -> Optional[Dict[str, Any]]:
        rr = run(self.base() + ["scheme", "describe", abs_path], timeout=YDB_TIMEOUT, raw_label=f"RAW_YDB_DESCRIBE:{abs_path}")
        if rr.code != 0 or not rr.out.strip():
            return None
        cols: List[Dict[str, Any]] = []
        pk: List[str] = []
        header = rr.out.splitlines()[0].strip() if rr.out else ""
        # Разбираем ТОЛЬКО секцию "Columns:" с рамкой
        next_box_is_columns = False
        in_columns_box = False
        name_idx: Optional[int] = None
        type_idx: Optional[int] = None
        key_idx: Optional[int] = None
        columns_raw_lines: List[str] = []
        for line in rr.out.splitlines():
            s = line.strip()
            if s == "Columns:":
                next_box_is_columns = True
                continue
            # Начало любой таблицы
            if s.startswith("┌"):
                in_columns_box = next_box_is_columns
                next_box_is_columns = False
                # Сброс индексов для новой таблицы
                name_idx = type_idx = key_idx = None
                if in_columns_box:
                    columns_raw_lines.append(s)
                continue
            # Конец таблицы
            if s.startswith("└"):
                if in_columns_box:
                    columns_raw_lines.append(s)
                in_columns_box = False
                continue
            if not in_columns_box:
                continue
            # Внутри таблицы "Columns" — парсим строки с разделителем '│' (или '|' на всякий случай)
            if ("│" not in line) and ("|" not in line):
                columns_raw_lines.append(line)
                continue
            sep = "│" if "│" in line else "|"
            cells = [c.strip() for c in line.split(sep)]
            columns_raw_lines.append(line)
            # Заголовок столбцов внутри бокса: найдём индексы Name/Type/Key
            if ("Name" in cells) and ("Type" in cells):
                try:
                    name_idx = cells.index("Name")
                    type_idx = cells.index("Type")
                    # Столбец Key может отсутствовать/быть пустым
                    key_idx = cells.index("Key") if "Key" in cells else None
                except ValueError:
                    name_idx = type_idx = key_idx = None
                continue
            # Данные
            if name_idx is None or type_idx is None:
                continue
            # Для строк-данных края тоже дают пустые элементы — фильтровать по индексам
            nm = cells[name_idx] if name_idx < len(cells) else ""
            tp = cells[type_idx] if type_idx < len(cells) else ""
            if not nm or nm == "Name":
                continue
            not_null = not tp.endswith("?")
            cols.append({"name": nm, "type": tp, "notNull": not_null})
            if key_idx is not None and key_idx < len(cells):
                if str(cells[key_idx]).startswith("K"):
                    pk.append(nm)
        return {"columns": cols, "primaryKey": pk, "_header": header, "_raw": rr.out, "_columns_raw": "\n".join(columns_raw_lines)}

# ====== сигнатура и цвет ======

def schema_signature(desc: Dict[str, Any]) -> str:
    cols = desc.get("columns") or []
    pk = set(desc.get("primaryKey") or [])
    norm = []
    for c in cols:
        name = str(c.get("name"))
        typ = str(c.get("type"))
        not_null = bool(c.get("notNull"))
        norm.append((name in pk, name, typ, not_null))
    norm.sort(key=lambda x: (not x[0], x[1].lower()))
    # Если распарсить не удалось (пусто) — используем сырую секцию Columns
    if not norm:
        raw_box = desc.get("_columns_raw") or desc.get("_raw") or desc.get("_header") or ""
        h = hashlib.md5(str(raw_box).encode("utf-8")).hexdigest()
        return json.dumps({"raw": h}, ensure_ascii=False)
    return json.dumps(norm, ensure_ascii=False)

def color_for_sig(sig: str) -> str:
    import hashlib as _h
    h = int(_h.md5(sig.encode("utf-8")).hexdigest()[:6], 16) / 0xFFFFFF
    r, g, b = colorsys.hsv_to_rgb(h, 0.6, 0.85)
    return "#%02x%02x%02x" % (int(r*255), int(g*255), int(b*255))

# ====== Tkinter UI ======
class SchemaPicker(tk.Tk):
    def __init__(self, dbs: List[YdbDb]):
        super().__init__()
        self.title("Выбор базы YDB")
        self.geometry("960x440")
        self.resizable(True, True)
        self.selected_db: Optional[YdbDb] = None
        self._dbs = dbs

        ttk.Label(self, text="Выбери базу данных (стрелки ↑/↓, Enter)", font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=12, pady=8)
        self.tree = ttk.Treeview(self, columns=("name", "endpoint", "database"), show="headings", selectmode="browse")
        self.tree.heading("name", text="name")
        self.tree.heading("endpoint", text="endpoint")
        self.tree.heading("database", text="database")
        self.tree.column("name", width=240)
        self.tree.column("endpoint", width=360)
        self.tree.column("database", width=360)
        self.tree.pack(fill="both", expand=True, padx=12, pady=(0,8))

        for i, d in enumerate(self._dbs):
            self.tree.insert("", "end", iid=f"db:{i}", values=(d.name or d.id, d.endpoint, d.database), tags=("db",))
        if self._dbs:
            self.tree.selection_set("db:0")

        btns = ttk.Frame(self); btns.pack(fill="x", padx=12, pady=8)
        ttk.Button(btns, text="Продолжить", command=self._ok).pack(side="right", padx=6)
        ttk.Button(btns, text="Отмена", command=self._cancel).pack(side="right")
        self.bind("<Return>", lambda e: self._ok())

    def _ok(self):
        sel = self.tree.selection()
        if not sel:
            return
        idx = int(sel[0].split(":",1)[1])
        self.selected_db = self._dbs[idx]
        self.destroy()

    def _cancel(self):
        self.selected_db = None
        self.destroy()

class TableTree(tk.Tk):
    def __init__(self, ydb: YdbCli, tables: List[str], sig_map: Dict[str, List[str]], item_sig: Dict[str, str]):
        super().__init__()
        self.title("Схема YDB — выбери таблицу (↑/↓, Enter)")
        self.geometry("980x640")
        self.resizable(True, True)

        ttk.Label(self, text="Выбери таблицу. Все таблицы с той же схемой будут помечены ✏️ и цветом.", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=12, pady=8)

        self.tree = ttk.Treeview(self, show="tree")
        self.tree.pack(fill="both", expand=True, padx=12, pady=(0,6))

        self.orig_text: Dict[str, str] = {}
        self.item_sig = item_sig
        self.sig_map = sig_map
        self.selected_table: Optional[str] = None
        self.prev_marked: List[str] = []

        root_db = ydb.database.rstrip("/")
        root_iid = f"dir:{root_db}"
        self.tree.insert("", "end", iid=root_iid, text=root_db, tags=("dir_root",))
        self.orig_text[root_iid] = root_db

        # Построим дерево только из путей таблиц: директории выводим из их родителей
        parent_for_path: Dict[str, str] = {root_db: root_iid}
        def ensure_dir(p_abs: str) -> str:
            if p_abs in parent_for_path:
                return parent_for_path[p_abs]
            parent = p_abs.rsplit("/", 1)[0]
            parent_iid = ensure_dir(parent)
            iid = f"dir:{p_abs}"
            name = p_abs.rsplit("/", 1)[-1]
            self.tree.insert(parent_iid, "end", iid=iid, text=name, tags=("dir",))
            self.orig_text[iid] = name
            parent_for_path[p_abs] = iid
            return iid

        for abs_path in sorted(tables):
            parent_abs = abs_path.rsplit("/", 1)[0]
            parent_iid = ensure_dir(parent_abs)
            iid = f"tbl:{abs_path}"
            name = abs_path.rsplit("/", 1)[-1]
            self.tree.insert(parent_iid, "end", iid=iid, text=name, tags=("tbl",))
            self.orig_text[iid] = name

        # Используем короткие безопасные теги на основе хеша сигнатуры
        self.sig_tag: Dict[str, str] = {}
        for sig in self.sig_map.keys():
            tag = f"sig:{hashlib.md5(sig.encode('utf-8')).hexdigest()[:8]}"
            self.sig_tag[sig] = tag
            self.tree.tag_configure(tag, foreground=color_for_sig(sig))

        self.tree.item(root_iid, open=True)
        for ch in self.tree.get_children(root_iid):
            self.tree.item(ch, open=True)

        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.bind("<Return>", lambda e: self._ok())

        bar = ttk.Frame(self); bar.pack(fill="x", padx=12, pady=6)
        self.info = ttk.Label(bar, text="Выберите таблицу…")
        self.info.pack(side="left")
        ttk.Button(bar, text="Продолжить", command=self._ok).pack(side="right", padx=6)
        ttk.Button(bar, text="Отмена", command=self._cancel).pack(side="right")

        # Автовыбор первой таблицы и фокус на дереве, чтобы работали ↑/↓
        first_tbl = next((i for i in self.tree.get_children(root_iid) if i.startswith("tbl:")), None)
        if first_tbl:
            self.tree.selection_set(first_tbl)
            self.tree.focus(first_tbl)
        self.tree.focus_set()

    def _on_select(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return
        iid = sel[0]
        if not iid.startswith("tbl:"):
            return
        path = iid.split(":", 1)[1]
        self.selected_table = path
        sig = self.item_sig.get(iid)

        for it in self.prev_marked:
            self.tree.item(it, text=self.orig_text[it])
            # Уберём все теги-сигнатуры, оставив прочие
            cur_tags = list(self.tree.item(it, "tags") or ())
            cur_tags = [t for t in cur_tags if not t.startswith("sig:")]
            self.tree.item(it, tags=tuple(cur_tags))
        self.prev_marked.clear()

        if not sig:
            self.info.config(text="Нет сигнатуры для выбранной таблицы")
            return
        group_items = []
        for p in self.sig_map.get(sig, []):
            iid_tbl = f"tbl:{p}"
            if self.tree.exists(iid_tbl):
                group_items.append(iid_tbl)
        for it in group_items:
            self.tree.item(it, text="✏️ " + self.orig_text[it])
            cur_tags = set(self.tree.item(it, "tags") or ())
            cur_tags.add(self.sig_tag.get(sig, "sig"))
            self.tree.item(it, tags=tuple(cur_tags))
        self.prev_marked = group_items
        self.info.config(text=f"Выбрано: {path}  —  затронет {len(group_items)} табл.")

    def _ok(self):
        if not self.selected_table:
            messagebox.showwarning("Выбор таблицы", "Сначала выберите таблицу")
            return
        self.destroy()

    def _cancel(self):
        self.selected_table = None
        self.destroy()

# ====== миграция ======

def ask_templates_console() -> Tuple[str, str, str]:
    # Имя миграции фиксированное, SQL не спрашиваем — используем шаблоны
    name = "migration"
    up_default = "ALTER TABLE {table} ADD COLUMN remote_interface_access_key Utf8;"
    down_default = "ALTER TABLE {table} DROP COLUMN remote_interface_access_key;"
    return name, up_default, down_default

def write_migration_file(name: str, selected_tables: List[str], up_tpl: str, down_tpl: str, dest_dir: Path) -> Path:
    ts = datetime.now().strftime("%Y%m%d%H%M%S")
    # Разрешаем Unicode-имена (включая кириллицу) в файле миграции
    safe = re.sub(r"[^\w.-]+", "_", name, flags=re.UNICODE).strip("._ ")
    if not safe:
        safe = "migration"
    fname = f"{ts}_" + safe + ".sql"
    path = dest_dir / fname
    up_lines = [up_tpl.format(table=f"`{t}`") for t in selected_tables]
    down_lines = [down_tpl.format(table=f"`{t}`") for t in selected_tables]
    content = (
        "-- Автосгенерировано create_migration.py (Tk UI, bulk by schema)\n"
        f"-- Целевые таблицы ({len(selected_tables)}):\n" + "\n".join(f"--  - {t}" for t in selected_tables) + "\n\n" +
        "-- +goose Up\n-- +goose StatementBegin\n" + "\n".join(up_lines) + "\n-- +goose StatementEnd\n\n" +
        "-- +goose Down\n-- +goose StatementBegin\n" + "\n".join(down_lines) + "\n-- +goose StatementEnd\n"
    )
    path.write_text(content, encoding="utf-8")
    return path

# ====== Main ======

def main() -> None:
    ensure_iam_token()

    dbs = list_ydb_databases()
    picker = SchemaPicker(dbs)
    picker.mainloop()
    if not picker.selected_db:
        print("> Отменено пользователем (этап выбора базы)")
        sys.exit(1)
    db = picker.selected_db

    ydb = YdbCli(db.endpoint, db.database, IAM_TOKEN_FILE)
    print("# discovery whoami (проверка авторизации)")
    ydb.whoami()

    print("# scheme ls (список путей)")
    rel_or_abs_paths = ydb.scheme_ls_paths()
    _log_block("RAW_SCHEME_LS_PATHS_PARSED", "\n".join(rel_or_abs_paths))

    # Нормализуем в абсолютные пути и оставим только таблицы (через describe)
    candidates_abs: List[str] = []
    for p in rel_or_abs_paths:
        full = p if p.startswith("/") else (db.database.rstrip("/") + "/" + p)
        candidates_abs.append(full)

    print(f"# describe кандидатов (всего: {len(candidates_abs)})")
    tables_abs: List[str] = []
    desc_cache: Dict[str, Dict[str, Any]] = {}
    for i, abs_path in enumerate(candidates_abs, 1):
        desc = ydb.describe(abs_path)
        if not desc:
            continue
        desc_cache[abs_path] = desc
        header = str(desc.get("_header") or "").lower()
        has_cols = bool(desc.get("columns"))
        if "<table>" in header or has_cols:
            tables_abs.append(abs_path)

    _log_block("RAW_TABLES_DETECTED", "\n".join(tables_abs))

    # Исключаем служебную таблицу goose_db_version
    tables_abs = [p for p in tables_abs if not p.rstrip("/").endswith("/goose_db_version")]

    if not tables_abs:
        raise CmdError("> Не найдено ни одной таблицы. Приложи сюда блоки RAW_ из вывода выше.")

    print("# сигнатуры таблиц")
    sig_map: Dict[str, List[str]] = {}
    item_sig: Dict[str, str] = {}
    for t in tables_abs:
        desc = desc_cache.get(t) or ydb.describe(t) or {}
        sig = schema_signature(desc)
        sig_map.setdefault(sig, []).append(t)
        item_sig[f"tbl:{t}"] = sig

    tree_win = TableTree(ydb, tables_abs, sig_map, item_sig)
    tree_win.mainloop()
    if not tree_win.selected_table:
        print("> Отменено пользователем (этап выбора таблицы)")
        sys.exit(1)

    chosen = tree_win.selected_table
    chosen_sig = item_sig.get(f"tbl:{chosen}")
    affected = sorted(sig_map.get(chosen_sig, [])) if chosen_sig else []

    name, up_tpl, down_tpl = ask_templates_console()
    def _safe_seg(s: str) -> str:
        seg = re.sub(r"[^\w.\- ()]+", "_", s or "", flags=re.UNICODE).strip("._ ")
        return seg or "_"

    db_last = (db.database.strip("/").split("/") or [""])[-1]
    db_dir_name = f"{db_last} ({db.name})"
    base_dir = MIGRATIONS_DIR / "ydb_dbs" / _safe_seg(db_dir_name)

    db_prefix = db.database.rstrip("/") + "/"
    if chosen.startswith("/"):
        rel = chosen[len(db_prefix):] if chosen.startswith(db_prefix) else chosen.strip("/")
    else:
        rel = chosen.strip("/")
    parent = rel.rsplit("/", 1)[0] if "/" in rel else ""
    tbl_name = rel.rsplit("/", 1)[-1]

    dest_dir = base_dir
    if parent:
        for seg in parent.split("/"):
            if seg:
                dest_dir = dest_dir / _safe_seg(seg)
    dest_dir = dest_dir / _safe_seg(tbl_name)
    dest_dir.mkdir(parents=True, exist_ok=True)

    mig = write_migration_file(name, affected, up_tpl, down_tpl, dest_dir)
    print(f"\n✅ Создан файл migration: {mig}")
    print("👉 Примени migrations: python apply_migration.py")


if __name__ == "__main__":
    try:
        main()
    except CmdError as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n> Отменено пользователем.")
        sys.exit(1)
