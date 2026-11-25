#!/usr/bin/env bash
# 构造自测用 ELF 固件。输出目录由第一个参数指定（保持与不可信数据隔离的目录约定）。
# 全部为 x86-64、带 DWARF 调试信息，并通过 --build-id=0x... 固定 Build ID。
set -euo pipefail

OUT="${1:?usage: build_fixtures.sh OUT_DIR}"
SRC="$(mktemp -d)"
trap 'rm -rf "$SRC"' EXIT
mkdir -p "$OUT"

# 把临时编译目录归一化进 DWARF，保证不同机器/次运行间源码路径字面量稳定，
# 复发观察的“源码文件名”比对才能构造出确定的同/异用例。
SRC_MAP=( -fdebug-prefix-map="$SRC=/src" )

cat > "$SRC/demo.c" <<'EOF'
#include <stdio.h>

int helper_add(int a, int b) {
    int s = a + b;          /* demo line: helper_add */
    return s;
}

void crash_here(int x) {
    int v = helper_add(x, 1);
    printf("v=%d\n", v);    /* demo line: crash_here */
}

int main(int argc, char **argv) {
    crash_here(argc);
    return 0;
}
EOF

cat > "$SRC/other.c" <<'EOF'
int other_func(int n) {
    int r = n * 2;          /* other line */
    return r;
}
EOF

# 复发观察用“修复版”固件，Build ID 与旧版 (aaaa/bbbb) 不同：
# - fixed-recur：同源码同函数 -> 前两帧文件名与函数名四项全同（复发证据）
# - fixed-renamed：函数体相同但源文件改名 -> 源码文件名已知不同（排除）
# - fixed-func：同文件名但函数改名 -> 函数名已知不同（排除）
mkdir -p "$SRC/alt"
cat > "$SRC/alt/demo_renamed.c" <<'EOF'
#include <stdio.h>

int helper_add(int a, int b) {
    int s = a + b;          /* demo line: helper_add */
    return s;
}

void crash_here(int x) {
    int v = helper_add(x, 1);
    printf("v=%d\n", v);    /* demo line: crash_here */
}

int main(int argc, char **argv) {
    crash_here(argc);
    return 0;
}
EOF

# 同名 demo.c、仅函数改名：用于单独验证“函数名已知不同即排除”
mkdir -p "$SRC/funcrename"
cat > "$SRC/funcrename/demo.c" <<'EOF'
#include <stdio.h>

int helper_add_v2(int a, int b) {
    int s = a + b;          /* fixed line: helper */
    return s;
}

void crash_here_v2(int x) {
    int v = helper_add_v2(x, 1);
    printf("v=%d\n", v);    /* fixed line: crash */
}

int main(int argc, char **argv) {
    crash_here_v2(argc);
    return 0;
}
EOF

# 1) 两个“正常”ELF，固定且不同的 Build ID，保留调试信息
gcc -O0 -g -gdwarf-5 -fno-pie -no-pie "${SRC_MAP[@]}" \
    -Wl,--build-id=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    "$SRC/demo.c" -o "$OUT/demo-aaaa.elf"

# 同源码再出一份 DWARF v4，用于覆盖 v4 行表目录索引规则（Build ID 不同）
gcc -O0 -g -gdwarf-4 -fno-pie -no-pie "${SRC_MAP[@]}" \
    -Wl,--build-id=0xadd4aaaaadd4aaaaadd4aaaaadd4aaaaadd4aaaa \
    "$SRC/demo.c" -o "$OUT/demo-dwarf4-aaaa.elf"

gcc -O0 -g -gdwarf-5 -shared -fPIC "${SRC_MAP[@]}" \
    -Wl,--build-id=0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
    "$SRC/other.c" -o "$OUT/other-bbbb.elf"

# 2) 同 Build ID、不同内容：链接 demo.c 但改一个常量
sed 's/a + b/a + b + 1/' "$SRC/demo.c" > "$SRC/demo_conflict.c"
gcc -O0 -g -gdwarf-5 -fno-pie -no-pie "${SRC_MAP[@]}" \
    -Wl,--build-id=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    "$SRC/demo_conflict.c" -o "$OUT/demo-aaaa-CONFLICT.elf"

# 3) 缺 Build ID
gcc -O0 -g -gdwarf-5 -fno-pie -no-pie -Wl,--build-id=none \
    "$SRC/demo.c" -o "$OUT/no-buildid.elf"

# 4) 有 Build ID 但 strip 掉调试信息
gcc -O0 -g -gdwarf-5 -fno-pie -no-pie "${SRC_MAP[@]}" \
    -Wl,--build-id=0xcccccccccccccccccccccccccccccccccccccccc \
    "$SRC/demo.c" -o "$OUT/stripped-cccc.elf"
strip --strip-debug "$OUT/stripped-cccc.elf"

# 5) 非 ELF 文件
printf 'this is definitely not an ELF\n' > "$OUT/not-elf.bin"

# 6) 复发观察“修复版”三份固件
gcc -O0 -g -gdwarf-5 -fno-pie -no-pie "${SRC_MAP[@]}" \
    -Wl,--build-id=0xd1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1 \
    "$SRC/demo.c" -o "$OUT/fixed-recur-d1d1.elf"

gcc -O0 -g -gdwarf-5 -fno-pie -no-pie "${SRC_MAP[@]}" \
    -Wl,--build-id=0xd2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2 \
    "$SRC/alt/demo_renamed.c" -o "$OUT/fixed-renamed-d2d2.elf"

gcc -O0 -g -gdwarf-5 -fno-pie -no-pie "${SRC_MAP[@]}" \
    -Wl,--build-id=0xd3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3 \
    "$SRC/funcrename/demo.c" -o "$OUT/fixed-func-d3d3.elf"

echo "fixtures written to $OUT"
ls -l "$OUT"
