#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import sys

try:
    import colorama
except Exception:
    colorama = None

def _enable_vt_win() -> bool:
    try:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        h = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
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

def _init_ansi() -> bool:
    if os.name == "nt":
        if colorama is not None:
            try:
                colorama.init(convert=True)
                return True
            except Exception:
                pass
        if _enable_vt_win():
            return True
    return sys.stdout.isatty()

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
UNDER = "\x1b[4m"
ITALIC = "\x1b[3m"

FG = {
    "черный": "\x1b[30m",
    "красный": "\x1b[31m",
    "зеленый": "\x1b[32m",
    "желтый": "\x1b[33m",
    "синий": "\x1b[34m",
    "магента": "\x1b[35m",
    "циан": "\x1b[36m",
    "белый": "\x1b[37m",
    "ярк-красный": "\x1b[91m",
    "ярк-зеленый": "\x1b[92m",
    "ярк-желтый": "\x1b[93m",
    "ярк-синий": "\x1b[94m",
    "ярк-магента": "\x1b[95m",
    "ярк-циан": "\x1b[96m",
    "ярк-белый": "\x1b[97m",
}

BG = {
    "bg красный": "\x1b[41m",
    "bg зеленый": "\x1b[42m",
    "bg желтый": "\x1b[43m",
    "bg синий": "\x1b[44m",
    "bg магента": "\x1b[45m",
    "bg циан": "\x1b[46m",
    "bg белый": "\x1b[47m",
}

def main() -> None:
    _init_ansi()
    print("Пример цветов (текст):")
    for name, code in FG.items():
        print(f"{code}{name}{RESET}")
    print()
    print("Пример атрибутов:")
    print(f"{BOLD}полужирный{RESET}")
    print(f"{UNDER}подчеркнутый{RESET}")
    print(f"{ITALIC}курсив{RESET}")
    print()
    print("Пример фона:")
    for name, code in BG.items():
        print(f"{code}\x1b[30m{name}{RESET}")
    print()
    print("Truecolor градиент:")
    blocks = []
    for r in range(0, 256, 32):
        g = 255 - r
        b = 128
        blocks.append(f"\x1b[38;2;{r};{g};{b}m█")
    print("".join(blocks) + RESET)

if __name__ == "__main__":
    main()
