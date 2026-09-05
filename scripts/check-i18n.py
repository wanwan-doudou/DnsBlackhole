# -*- coding: utf-8 -*-
"""校验英文字典是否覆盖界面里所有 t() 文案。

字典以中文原文为键（gettext 风格），所以中文不需要字典、也不会漏词；
这个脚本只检查英文侧：有没有漏翻、有没有重复键、有没有字典里留着但代码已删掉的条目。

用法：
    python scripts/check-i18n.py

退出码非 0 表示需要修字典，可直接接进 CI。
"""
import collections
import glob
import io
import os
import re
import sys

BS = chr(92)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DICT_PATH = os.path.join(ROOT, 'src', 'i18n', 'en-US.ts')

# t("...")：字符串体里允许 \" 之类的转义
CALL = re.compile(r'\bt\(\s*"((?:[^"\\]|\\.)*)"')
# 长文案的译文会换行写在下一行，所以冒号后不能强制要求空白字符
KEY = re.compile(r'^\s*"((?:[^"\\]|\\.)*)":')

# 语言名按惯例用其本身的语言书写，不算漏翻
ALLOWED_UNTRANSLATED = {'简体中文'}


def decode(raw):
    """把 TS 源码里的转义还原成实际字符串值。"""
    return (raw.replace(BS + '"', '"')
            .replace(BS + 'n', chr(10))
            .replace(BS + 't', chr(9))
            .replace(BS + 'r', chr(13))
            .replace(BS + BS, BS))


def collect_used():
    used = []
    pattern = os.path.join(ROOT, 'src', '**', '*.ts')
    for path in sorted(glob.glob(pattern, recursive=True)):
        rel = os.path.relpath(path, ROOT).replace(os.sep, '/')
        if rel.endswith('.test.ts') or rel.startswith('src/i18n/'):
            continue
        for m in CALL.finditer(io.open(path, encoding='utf-8').read()):
            text = decode(m.group(1))
            if text not in used:
                used.append(text)
    return used


def collect_dictionary():
    keys = collections.defaultdict(list)
    for lineno, line in enumerate(io.open(DICT_PATH, encoding='utf-8').read().split('\n'), 1):
        m = KEY.match(line)
        if m:
            keys[decode(m.group(1))].append(lineno)
    return keys


def main():
    enc = sys.stdout.encoding or 'utf-8'

    def out(text):
        sys.stdout.write(text.encode(enc, 'replace').decode(enc, 'replace') + '\n')

    used = collect_used()
    keys = collect_dictionary()

    missing = [s for s in used if s not in keys and s not in ALLOWED_UNTRANSLATED]
    stale = [k for k in keys if k not in used]
    dups = {k: v for k, v in keys.items() if len(v) > 1}

    out('界面文案 %d 条，英文字典 %d 条' % (len(used), len(keys)))
    if missing:
        out('缺少英文译文 %d 条：' % len(missing))
        for text in missing:
            out('  - ' + text)
    if stale:
        out('字典里存在但代码已不再使用 %d 条：' % len(stale))
        for text in stale:
            out('  + ' + text)
    if dups:
        out('重复键 %d 个（后者会覆盖前者）：' % len(dups))
        for text, lines in dups.items():
            out('  ! %s -> 行 %s' % (text, lines))

    if missing or stale or dups:
        return 1
    out('检查通过')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
