# -*- coding: utf-8 -*-
"""检查所有可见 select 都接入统一的自绘下拉控件。"""

import io
import os
import re
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_PATH = os.path.join(ROOT, "src", "template.ts")
MAIN_PATH = os.path.join(ROOT, "src", "main.ts")

SELECT = re.compile(r"<select\b(?P<attrs>[^>]*)>", re.IGNORECASE | re.DOTALL)
ID = re.compile(r'\bid="([^"]+)"')
SELECT_BINDING = re.compile(
    r'const\s+(\w+)\s*=\s*query<HTMLSelectElement>\("#([^"]+)"\);'
)
INITIALIZERS = re.compile(
    r"// WebView2[^\n]*\n\[\s*(?P<body>.*?)\s*\]\.forEach\(initializeCustomSelect\);",
    re.DOTALL,
)


def read(path):
    return io.open(path, encoding="utf-8").read()


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    template = read(TEMPLATE_PATH)
    source = read(MAIN_PATH)
    visible_ids = []
    for match in SELECT.finditer(template):
        attrs = match.group("attrs")
        id_match = ID.search(attrs)
        if not id_match or re.search(r'\baria-hidden="true"', attrs, re.IGNORECASE):
            continue
        visible_ids.append(id_match.group(1))

    bindings = {element_id: variable for variable, element_id in SELECT_BINDING.findall(source)}
    initializer_matches = list(INITIALIZERS.finditer(source))
    if len(initializer_matches) != 1:
        print("应当且只能存在一个 initializeCustomSelect 初始化列表")
        return 1
    initialized = {
        name.strip()
        for name in initializer_matches[0].group("body").split(",")
        if re.fullmatch(r"\w+", name.strip())
    }

    failures = []
    for element_id in visible_ids:
        variable = bindings.get(element_id)
        if variable is None:
            failures.append(f"#{element_id} 没有 HTMLSelectElement 绑定")
        elif variable not in initialized:
            failures.append(f"#{element_id}（{variable}）未接入 initializeCustomSelect")

    if failures:
        print("控件一致性检查失败：")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"检查通过：{len(visible_ids)} 个可见 select 均已接入统一控件")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
