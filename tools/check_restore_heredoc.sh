#!/bin/bash
# 检查 tools/postlock.sh 里那段「展开式 heredoc」是否含未转义的命令替换。
#
# 背景（血泪两次）:
#   restore 脚本是用 `cat > "$RESTORE_LOCAL" <<EOF` 生成的 —— 分隔符没有引号,
#   所以 body 里没转义的 `$(...)` / 反引号会被 **host** 在执行 postlock.sh 时
#   就展开掉, 而不是在设备上执行。典型表现: 日志里出现 host 侧的值或空串,
#   更糟的情况是 host 命令被执行（或被解析成语法错误）导致整轮不可解释。
#   设备侧要写命令替换, 必须写成 \$(...) （反引号同理写成 \` ）。
#
#   反过来 `$TMP` / `$APP` / `$STAGE` / `$KASLR_MODE` 这类是**故意**让 host
#   展开的, 本检查不管 —— 只抓命令替换, 因为那才是「意外执行 host 命令」。
#
# 用法: tools/check_restore_heredoc.sh
# 退出码: 0 = 干净; 1 = 发现问题; 2 = 找不到 heredoc
set -u

REPO=$(cd "$(dirname "$0")/.." && pwd)
SRC=${1:-$REPO/tools/postlock.sh}

python3 - "$SRC" <<'PY'
import re
import sys

path = sys.argv[1]
lines = open(path, encoding='utf-8').read().split('\n')

start = end = None
for i, line in enumerate(lines):
    if start is None:
        if re.search(r'<<\s*["\']?EOF["\']?\s*$', line):
            start = i            # body 从下一行开始
    elif line == 'EOF':
        end = i
        break

if start is None or end is None:
    sys.exit('check: %s 里找不到 <<EOF ... EOF 的 restore heredoc' % path)

def unescaped(s, needle):
    """返回 needle 在 s 中「前面反斜杠个数为偶数」的起始位置列表。"""
    out = []
    for m in re.finditer(re.escape(needle), s):
        i = m.start()
        bs = 0
        j = i - 1
        while j >= 0 and s[j] == '\\':
            bs += 1
            j -= 1
        if bs % 2 == 0:
            out.append(i)
    return out

bad = []
for n in range(start + 1, end):
    line = lines[n]
    for needle in ('$(', '`'):
        if unescaped(line, needle):
            bad.append((n + 1, needle, line.strip()[:140]))
            break

if bad:
    print('FAIL: restore heredoc 里有未转义的命令替换 —— host 会先执行它们:')
    for ln, needle, text in bad:
        token = '$(...)' if needle == '$(' else '`...`'
        print('  %5d: %s  %s' % (ln, token, text))
    print('修法: 设备侧写成 \\$(...) / \\`...\\`（heredoc 分隔符没加引号, 是展开式的）')
    sys.exit(1)

print('OK: restore heredoc (%d 行) 无未转义的命令替换' % (end - start - 1))
PY
