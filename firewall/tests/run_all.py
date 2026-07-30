"""Прогон всех тестов фаервола. Как в upstream-репе MCP: без pytest, каждый файл —
самостоятельный скрипт в своём процессе, база всегда временная.

    .venv/bin/python tests/run_all.py            # все
    .venv/bin/python tests/run_all.py policy     # только совпадающие по имени
"""
from __future__ import annotations

import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def main() -> int:
    want = sys.argv[1] if len(sys.argv) > 1 else ""
    files = sorted(f for f in os.listdir(HERE)
                   if f.startswith("test_") and f.endswith(".py") and want in f)
    if not files:
        print(f"нет тестов по фильтру {want!r}")
        return 1
    failed = 0
    started = time.time()
    for name in files:
        t0 = time.time()
        proc = subprocess.run([sys.executable, os.path.join(HERE, name)],
                              capture_output=True, text=True)
        ok = proc.returncode == 0
        failed += 0 if ok else 1
        print(f"{name:<24} {'PASS' if ok else 'FAIL'} {time.time() - t0:6.2f}s")
        if not ok:
            print((proc.stdout + proc.stderr).rstrip())
    print(f"\n{len(files) - failed}/{len(files)} прошло за {time.time() - started:.1f}s")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
