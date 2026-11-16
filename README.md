# AyuTrace — Kernel Syscall Tracer (KPM)

基于 KernelPatch/APatch 的内核系统调用追踪模块。默认 hook 13 个 64 位 syscall + 13 个 arm32 compat syscall 共 **26 个 hook**（v1.3.2 起 compat 默认开启，见配置表），支持 PID 锁定、包名嗅探**两阶段自动锁定**（v1.3.1）、ring buffer 缓冲输出。

## 编译环境准备

### 1. 克隆仓库并初始化 KernelPatch 子模块

```bash
git clone --recursive <本仓库地址>
cd kpm_trace_svc
git submodule update --init --recursive
```

### 2. 下载 ARM64 交叉编译工具链

从 ARM 官网下载 `aarch64-none-elf-` 工具链：
https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads

推荐版本：`arm-gnu-toolchain-13.3.rel1-x86_64-aarch64-none-elf.tar.xz`

```bash
wget https://developer.arm.com/-/media/Files/downloads/gnu/13.3.rel1/binrel/arm-gnu-toolchain-13.3.rel1-x86_64-aarch64-none-elf.tar.xz
tar -xf arm-gnu-toolchain-13.3.rel1-x86_64-aarch64-none-elf.tar.xz
export TARGET_COMPILE=/path/to/arm-gnu-toolchain-13.3.rel1-x86_64-aarch64-none-elf/bin/aarch64-none-elf-
```

### 3. 编译

```bash
make
# 产出: kpm_trace_svc.kpm
```

## APatch 参数命令

| 命令 | 功能 |
|------|------|
| `add 12345` | 锁定 PID 12345，只追踪该进程 |
| `add com.example.app` | 包名嗅探模式，App 启动后自动锁定 |
| `del 12345` | 移除 PID 12345 |
| `del-pkg` | 取消包名嗅探 |
| `clear` | 清空所有目标，恢复追踪全部用户 App |
| `stop` | drain ring buffer → 关闭 hook → 清空目标 |
| `disable` | 关闭所有 hook（不清空目标） |
| `enable` | 重新启用 hook |
| `status` / 空 | 查看当前状态 |
| `dump <hex addr> <hex len>` | 手动 dump 目标进程指定内存区域（挂起到目标下一次 syscall 时执行） |
| `dumpstat` | 查看 dump 状态：已落盘文件数/配额、符号解析、rwx 观察表、去重表 |

## 使用流程

### 1. 加载模块

APatch 管理器 → 内核模块 → 加载 `kpm_trace_svc.kpm`

### 2. 追踪指定 App（推荐：包名嗅探）

```bash
# APatch 参数输入：
add com.example.app
```

**锁定过程（v1.3.1 两阶段）**：任何进程 openat 路径命中包名只会登记为候选；候选进程再出现自证信号（comm 含包名/尾段，或打开自己的私有数据目录 `/data/user/N/<pkg>/`）才转正锁定。日志标记依次为：

```
AyuTrace|>>> SNIFF CANDIDATE tgid=1234 pkg=com.example.app (path: /data/app/.../com.example.app-xxx/base.apk)
AyuTrace|>>> SNIFF LOCKED   tgid=1234 pkg=com.example.app (self data dir: /data/user/0/com.example.app/cache/...)
```

> 背景：Android 桌面 launcher-loader 会替图标加载去读其它 app 的 base.apk。v1.3.0 按"路径含包名即锁"曾把桌面进程锁成目标、真 app 全程被过滤，v1.3.1 起依赖自证信号杜绝误锁。

### 3. 启动日志采集

```bash
adb shell
su
dmesg -w | grep "AyuTrace" > /data/local/tmp/trace.log &
```

### 4. 启动目标 App

点击 App 图标。KPM 在 App 启动时自动锁定其 PID，开始记录所有 syscall。

### 5. 停止采集

```bash
fg          # 拉回前台
Ctrl+C      # 终止 dmesg
```

### 6. 停止追踪（可选）

```bash
# APatch 参数输入：
stop        # flush + disable + clear
```

### 7. 拉取日志

```bash
adb pull /data/local/tmp/trace.log .
```

## 日志格式

```
AyuTrace|<tag> pid:<PID> tid:<TID> comm:<进程名16字节> <参数>...
```

通用前缀字段：

| 字段 | 含义 | 示例 |
|------|------|------|
| `tag` | syscall 名 | `openat`, `mmap`, `kill` |
| `pid` | 进程 ID（TGID） | `12345` |
| `tid` | 线程 ID（TID） | `12346` |
| `comm` | 进程名（截断到 16 字符） | `com.example.app` |

## Hook 清单与日志解读

### 文件操作

| tag | syscall | 日志参数 | 逆向价值 |
|-----|---------|---------|---------|
| `openat` | `openat` | `path:<路径>` | **最核心**。壳解密 so、释放 dex、读配置文件 |
| `readlinkat` | `readlinkat` | `path:<路径>` | fd→路径反查 |

日志示例：
```
openat     pid:12345  tid:12345  comm:com.example.app  path:/data/user/0/com.example.app/files/config.json
readlinkat pid:12345  tid:12345  comm:com.example.app  path:/proc/self/fd/67
```

### 内存映射（壳行为检测）

| tag | syscall | 日志参数 | 逆向价值 |
|-----|---------|---------|---------|
| `mmap` | `mmap` | `addr`, `len`, `prot:rwx`, `flags`, `fd`, `off`, `->映射地址`, `pc` | **so/dex 加载**。fd≥0 → 文件映射；fd=-1 → 匿名映射 |
| `mprotect` | `mprotect` | `addr`, `len`, `prot:rwx`, `pc` | **权限变更**。`rw-`→`r-x` 是代码解密后执行的标准模式 |

prot 字段解读：`r`=读 `w`=写 `x`=执行，`-`=无权限。例如 `r-x`=可读可执行，`rwx`=全权限。

flags 常见值：`0x2`=MAP_PRIVATE, `0x22`=MAP_PRIVATE\|MAP_ANONYMOUS, `0x4022`=MAP_PRIVATE\|MAP_ANONYMOUS\|MAP_NORESERVE

日志示例：
```
mmap      pid:12345  tid:12345  comm:com.example.app  addr:0x0 len:0x8000 prot:r-x flags:0x2 fd:98 off:0 ->0x7b1a2000 pc:0x7b0c3f04
mprotect  pid:12345  tid:12345  comm:com.example.app  addr:0x7b000000 len:0x10000 prot:r-x pc:0x7b0c4120
```

通过 `pc` 定位调用来源：日志中的 `lr=`/`bt` 字段已在事件当下自动符号化；若只有裸地址（进程还活着时），用「调用上下文 → 不杀进程的离线地址定位脚本」一节的可移植 `res` 函数解析。

### 调用上下文

已锁定的目标进程会在日志末尾追加 `pc` 和 `lr`，`lr` 附带符号解析（`lr:0x...=libc.so+0x47e68`，格式 `完整路径+偏移`）。`openat`、`mmap/mmap32`、`mprotect`、`ptrace` 另外追加 `sp`、`fp`。**条件 BT 深扫**（fp 链 + 栈扫描，逐帧解析为 `路径+偏移`，最多 6 帧）触发条件：匿名可执行 `mmap`；转可执行 `mprotect`；`ptrace` 敏感请求（TRACEME/ATTACH/DETACH/POKE*/SETREGS*/SEIZE）；`clone` 含 CLONE_VM 且处于 RWX 窗口；`exit`/`kill`/`tkill`/`tgkill` 处于 RWX 窗口或信号为 5/6/9/11/19 或目标为自身；`execve` 非系统路径；`unshare` 恒触发；`openat` 路径命中敏感特征（/proc/self/、frida/magisk/xposed/riru、.so/.dex/.odex/.vdex）；`readlinkat` 指向 /proc/self 时追加 sp/fp。RWX 窗口：mprotect 转 X 或匿名可执行 mmap 后开启（64 个目标事件内有效），使后续 clone/exit/kill 自动升级深扫。解析失败回退为原始 `0x...`；匿名可执行区显示 `anon+0x...`（偏移相对该匿名映射基址）。

```text
mprotect ... pc:0xe86fae68 lr:0xc2a6d870=/data/app/.../lib/arm/libshell.so+0x2ae68 \
         sp:0xfff7bb70 fp:0xe0420 bt:/apex/.../bionic/libc.so+0x47e68,libshell.so+0x2ae68,anon+0x234
```

`pc` 是 svc 指令的下一条（几乎总在 libc/linker 里）；`lr` 是调用者；`bt` 向上穿过 libc/linker 到达 App 自身代码。

**符号解析机制**：目标事件发生时调用内核导出函数 `find_vma(mm, addr)` 定位所在 VMA，再用 `show_map_vma`（构造假 seq_file 调用，内核自行格式化 maps 行）取得**完整路径与权限**；`偏移 = addr - 该 so 首个映射基址`（沿同路径 VMA 向前回溯）。解析过程不依赖任何内核结构体布局，跨内核版本稳定；`copy_from_kernel_nofault` 兜底保护所有内核读。探测成功打一行 `bt-res ok (show_map_vma): <路径>`；任一符号缺失自动回退纯十六进制输出，不影响其余字段。

候选进程和未锁定进程不执行寄存器扩展、符号解析或栈回溯。ARM64 用 `x29/x30`；ARM32 按执行状态用 `r7/r11` 作 fp、`r14` 作 lr；arm32 无可靠 frame pointer 时 `bt` 主要靠栈扫描补帧。

### 不杀进程的离线地址定位脚本

日志里的 `pc`/`lr`/`bt` 原始十六进制地址，只要 **app 进程还活着**，即可在手机上用 `/proc/<pid>/maps` 离线解析成 `so+偏移`（不需要 KPM 参与，可与日志里的自动解析互相印证）。手机自带的 `sh` 即可运行（不依赖 awk/gawk）：

```bash
# 用法：在 su 下执行。res <十六进制地址> <pid>
res() {
  a=$((${1} & ~1))
  while read range perms off dev inode rest; do
    s=$((0x${range%-*}))
    e=$((0x${range#*-}))
    if [ "$a" -ge "$s" ] && [ "$a" -lt "$e" ]; then
      printf "%s +0x%x  (文件偏移 %s)\n" "$rest" $((a - s + 0x$off)) "$off"
      return 0
    fi
  done < /proc/$2/maps
  echo "$1 未命中任何映射"
  return 1
}

# 示例：解析日志里的几个地址（app 未退出时）
res 0xe4df84c0 7875
res 0xe4dcd3af 7875
res 0x96565870 7875
```

输出形如 `/apex/com.android.runtime/lib/bionic/libc.so +0x463ae`。批量解析一条日志里所有地址：

```bash
grep "mprotect" trace.log | head -1 | grep -oE "0x[0-9a-f]+" | while read a; do res "$a" 7875; done
```

注意：`maps` 第 3 列是该映射在文件内的起始偏移，so 内偏移 = `地址 - 映射起始 + 文件偏移`；脚本已包含此换算。app 退出后 `/proc/<pid>/maps` 消失，所以要在采集期间或采集刚结束时解析；arm32 的 Thumb 位（bit0）脚本已自动清除。

### 进程/线程生命周期

| tag | syscall | 日志参数 | 逆向价值 |
|-----|---------|---------|---------|
| `execve` | `execve` | `path:<程序路径>` | 进程执行新程序 |
| `clone` | `clone` | `new_tid:<新线程ID>` | 线程/进程创建，追踪反调试线程 |
| `exit` | `exit` | `status:<退出码>` | 线程退出，配合 clone 看生命周期 |
| `set_tid_addr` | `set_tid_address` | `ret:<TID>` | 线程就绪标记（pthread_create 底层） |

日志示例：
```
clone         pid:12345  tid:12345  comm:com.example.app  new_tid:12456
exit          pid:12345  tid:12456  comm:com.example.app  status:0
set_tid_addr  pid:12345  tid:12456  comm:com.example.app  ret:12456
```

### 信号与反调试

| tag | syscall | 日志参数 | 逆向价值 |
|-----|---------|---------|---------|
| `kill` | `kill` | `target:<PID> sig:<信号> pc` | 进程间发信号。`sig:9`=强杀，`pid==target`=自杀 |
| `tkill` | `tkill` | `tid:<TID> sig:<信号> pc` | 向线程发信号。`raise()`/`abort()` 底层 |
| `tgkill` | `tgkill` | `tgid:<PID> tid:<TID> sig:<信号> pc` | 最精确信号。`pthread_kill` 底层 |
| `ptrace` | `ptrace` | `req:<操作> target:<PID> addr/data` | **反调试核心**。`TRACEME`=反调试占位 |

信号常见值：`9`=SIGKILL, `6`=SIGABRT, `11`=SIGSEGV, `15`=SIGTERM, `19`=SIGSTOP

ptrace req 常见值：`TRACEME`=声明被追踪(反调试), `ATTACH`=附加调试, `DETACH`=脱离, `PEEKDATA`=读内存

日志示例：
```
kill    pid:12345  tid:12345  comm:com.example.app  target:12345  sig:9  pc:0x7b0c3f04
ptrace  pid:12345  tid:12345  comm:com.example.app  req:TRACEME  target:0  addr:0x0  data:0x0
```

通过 `pc` 定位反调试代码：日志中的 `lr=`/`bt` 已自动符号化；裸地址用「调用上下文 → 不杀进程的离线地址定位脚本」一节的 `res` 函数解析。

### 其他

| tag | syscall | 日志参数 | 逆向价值 |
|-----|---------|---------|---------|
| `unshare` | `unshare` | `flags:<标志>` | 命名空间隔离，少见 |

### 已注释的 hook

| tag | 原因 |
|-----|------|
| `read` | 高频（eventfd/pipe 每秒数千次），噪音远大于信息量。如需启用，编辑 `trace.c` 去掉 `/* */` 并设置 `TRACE_HIGH_FREQ 1` |

## 日志分析实战

### 一行日志怎么读

```
[  90.284] AyuTrace|mprotect pid:8358 tid:8358 comm:demo.app \
  addr:0x97e9e000 len:921600 prot:r-x pc:0xe8171e68 \
  lr:0x96565870=/data/user/0/com.demo.app/.stub/libstub.so+0xd870 \
  sp:0xff8cf180 fp:0xe0420 \
  bt:libstub.so+0xc404,libstub.so+0x3840c,libc.so+0x2df52,...
```

| 字段 | 怎么看 | 分析用途 |
|------|--------|---------|
| `tag`+参数 | 事件类型与数据 | mprotect 的 `prot:r-x` = 解密完要执行了 |
| `pc` | svc 下一条指令，几乎总在 libc/linker | 一般不用管 |
| `lr:0x..=路径+0x..` | **直接调用者**，符号化后即 `so+偏移` | 谁发起的这个 syscall——IDA/Ghidra 里按偏移跳转 |
| `bt:` | **向上多层调用链**（条件触发，见下） | 穿过 libc/linker 直达壳自身代码的完整路径 |
| `anon+0x..` | 匿名可执行区内的帧 | 壳解密落地代码，偏移相对映射基址，可与 `ayudump_*` 对照 |

### 标准分析流程（四步法）

**第一步：确认锁定**——日志开头的 `SNIFF CANDIDATE`/`SNIFF LOCKED` 说明目标进程已就位，之后的 `pid:` 才是真正采集的进程。

**第二步：还原加载链**——用 `openat` 的 `path` 和 `mmap32` 的 `fd` 配对：

```
openat  path:/data/app/.../lib/arm/libstub.so          ← 打开壳 so
mmap32  fd:58 ... ->0x96cfa000                          ← 映射进内存
```

fd 相同即同一文件；`->` 是映射后的基址，后续 mprotect/dump 的地址都可以和它对照。

**第三步：定位解密执行点**——找 `prot:r-x` 的 mprotect 或 `prot:rwx` 的匿名 mmap：

```
mprotect addr:0x97e9e000 len:921600 prot:r-x \
  lr:...libstub.so+0xd870  bt:libstub.so+0xc404,...
>>> DUMPED addr:0x97e9e000 len:921600 ... ayudump_1_..._0x97e9e000_....bin
```

- `lr` 告诉你是壳的哪段代码（`+0xd870`）发起了权限切换；
- `bt` 给出这段代码被谁调用（`+0xc404` 等）；
- `DUMPED` 的 bin 文件就是**解密后的代码本体**，拉出来直接拖进 IDA。

**第四步：定位反调试**——`ptrace`（TRACEME/ATTACH）、`kill` 自杀信号、`exit` 等均带深扫（条件触发），`lr`/`bt` 直达壳的反调试代码。

### bt 的触发条件（为什么有的行没有 bt）

深扫只在**高价值低频率**路径触发，其余事件只有 `lr`（也已符号化）：

| 事件 | 触发 bt 的条件 |
|------|---------------|
| `mprotect` | prot 含 X（转可执行） |
| `mmap/mmap32` | 匿名可执行（prot 含 X 且 fd<0） |
| `ptrace` | TRACEME/ATTACH/DETACH/POKE\*/SETREGS\*/SEIZE |
| `openat` | 路径含 `/proc/self/`、frida/magisk/xposed/riru、`.so/.dex/.odex/.vdex` |
| `execve` | 路径以 `/data/` 开头 |
| `unshare` | 恒触发 |
| `clone` | CLONE_VM 且处于 RWX 窗口 |
| `exit`/`kill` 系 | RWX 窗口内，或致命/调试信号，或目标为自身 |
| 其余（readlinkat 等） | 不深扫，仅 `lr` 符号化 |

**RWX 窗口**：mprotect 转 X 或匿名可执行 mmap 后开启 64 个目标事件，使紧随其后的 clone/exit/kill 自动升级深扫——专抓"解密→起线程→自杀"连招。

### 常见疑问

- **为什么有的 bt 停在系统 so（libc/linker/art）？** 这类 syscall 本来就是系统组件代劳的（如 ART 加载 odex、linker 映射 so），app 帧在更深的 Java/JNI 层，超出 6 帧/4KB 窗口；壳自研代码直接发起的 syscall（解密、权限切换、反调试）bt 必达 app so。
- **`anon+0x..` 是什么？** 匿名可执行区（壳解密落地的代码段），`0x` 前部分是映射基址，与 `DUMPED` 文件名中的地址一致。
- **`bt-res ok (show_map_vma): ...` 是什么？** 解析器首次探测成功的一行日志，显示第一条被解析的 vma 路径；没有这行说明解析降级为裸地址（不影响其他功能）。
- **app 退出后还能解析地址吗？** 日志里的 `lr=`/`bt` 已在事件当下解析完成，随时可查；裸地址（`0x...`）则需进程存活时用上文离线脚本解析。

## 加固壳行为识别

### 壳自解密执行签名
```
# 第一步：匿名分配可读写内存（壳解密 buf）
mmap    addr:0x0 len:0x50000 prot:rw- flags:0x22 fd:-1  ->0x7a000000

# 第二步：解密代码写入 buf（通过 write/read，这里看不到内容）

# 第三步：改成可执行
mprotect addr:0x7a000000 len:0x50000 prot:r-x

# 第四步：跳转执行（后续 CPU 从该地址取指令）
```

看到 `mmap prot:rw- ANON` + `mprotect prot:r-x` 连续出现 → 高度疑似壳自解密（会自动触发内存 dump，见下文「壳内存自动 dump」）。

### 反调试检测签名
```
# App 启动后第一条 ptrace
ptrace  req:TRACEME target:0  ← 壳占住 ptrace 位，阻止你附加调试器

# 检测到异常后自杀
kill    target:<自己的pid> sig:9  ← pid==target，自毁
```

### 加载 native so
```
openat  path:/data/app/.../lib/arm64/libnative.so  ← 打开 so 文件
mmap    fd:98 prot:r-x off:0    ->0x7b1a2000         ← 映射 .text 段（代码）
mmap    fd:98 prot:rw- off:0x8000 ->0x7b1aa000       ← 映射 .data 段（数据）
```

## 壳内存自动 dump（v1.4.0）

包名嗅探模式（`add <pkg>`）下，已锁定目标出现壳解密执行签名时自动把内存落盘。**触发点**：

1. **mprotect 转可执行**（prot 含 X，len ≥ 64KB）——解密写入发生在 mprotect 之前，before 钩子时刻读到的就是解密完成的代码；
2. **匿名 rwx mmap 直跑**——mmap 时登记观察（日志 `RWX WATCH`），区域头部写入非零后才落盘（登记线程 exit 时 + 目标进程每累计 64 个 syscall 各检查一次，8 次窗口仍全零则 `RWX DROP` 放弃）——实测某 32 位壳的写码线程 mmap 后即退出、解密写入由其它线程稍后完成，只按 exit 时点 dump 会拿到全零页；
3. **手动** `dump <addr> <len>`——挂起，目标下一次经过任何钩子时执行。

**文件名与 trace 日志一一对应**：

```
/data/user/0/<pkg>/ayudump_<seq>_pid<PID>_tid<TID>_0x<addr>_0x<len>_pc0x<pc>.bin
```

以日志行
`mprotect pid:10311 tid:10311 comm:... addr:0x9e398000 len:921600 prot:r-x pc:0xed3b4e68`
为例，对应文件名为 `ayudump_2_pid10311_tid10311_0x9e398000_0xe1000_pc0xed3b4e68.bin`。
同时内核日志会打一条同字段格式的 `>>> DUMPED` 行，直接 `grep addr:0x... trace.log` 即可定位。

**取文件**（内核以 app 自身身份写入其私有目录，抓完用 su 拷出）：

```bash
adb shell
su
cp /data/user/0/<pkg>/ayudump_*.bin /data/local/tmp/
adb pull /data/local/tmp/ayudump_*.bin .
```

**读取机制**：dump 触发点均在目标进程自身上下文，优先 `__arch_copy_from_user` 直读；整块读不到时退化到 KPM-MemReader 式跨进程页表遍历（`find_task_by_vpid` + pgd/pud/pmd/pte + physmap 换算，页大小/VA/PA 位数与 mm_struct.pgd 偏移运行期自探测）。任一内核符号缺失自动降级为只记日志不落盘，不影响原有 trace 功能。

## 配置

编辑 `trace.h`：

| 宏 | 默认值 | 说明 |
|----|--------|------|
| `TRACE_HIGH_FREQ` | `1` | `0`=关闭 kill/clone/exit hook |
| `TRACE_COMPAT_HOOKS` | `1`（v1.3.2 起） | arm32 compat hook。目标为 32 位 app（primaryCpuAbi=armeabi-v7a）时必须开启，否则其全部 syscall 走 compat 表、无钩子可挂 |
| `TRACE_BT_MAX` | `6` | bt 回溯最大帧数（建议 4~8） |
| `TRACE_UID_THRESHOLD` | `10000u` | 默认只追踪 UID≥10000 的用户 App |
| `TARGET_PID_MAX` | `16` | 最多同时追踪的进程数 |

编辑 `trace.c` 启用 read hook：去掉 `before_read` 函数的 `/* */` 注释，并在 `trace_install`/`trace_uninstall` 中去掉对应的注释。

## 注意事项

- **KernelPatch 版本必须与内核 kpimg 对齐**：本模块固定 `KernelPatch` 子模块到 `0.13.0`（commit 324b440），与 Pixel 6 内核注入的 kpimg v0.13.0-d00 一致。头文件结构体/ABI 与运行时不匹配的后果不可预期（参见 panda-hide 的 ABS64 教训）。
- **字符串指针数组禁用**：`.rodata` 中 `const char *xx[]` 表会生成 R_AARCH64_ABS64 重定位，kpimg 0.13.0 加载器会损坏表槽 → `%s` 解引用垃圾指针崩溃。ptrace req 名称已改为 switch 返回直接字面量。
- **v1.3 默认关闭追踪**：空目标状态下会对全系统 UID≥10000 进程直写 printk，洪泛冲刷 dmesg/pstore（连带清掉 SukiSU/SUSFS 启动日志）。加载后用 `add <pid/pkg>` 或 `enable` 显式开启。
- **v1.3.1 嗅探两阶段确认**：路径命中仅登记候选（`SNIFF CANDIDATE`），须自证信号（comm 匹配或访问自己的私有数据目录）才转正锁定，原因标注在 `(comm match:)` / `(self data dir:)` / `(already in list)`；候选表满 16 自动挤掉最旧项。此前"路径即锁"会被桌面 launcher-loader 抢锁导致采集颗粒无收。
- **pid/tgid 来源**：直接读取 KP 运行时维护的 task_ext（fork 时按真实值填充），不再扫描 task_struct 偏移自校准 —— 各内核布局不同且存在误判风险。
- **compat（32位）hook**：v1.3.2 起默认开启（此前默认关闭）。历史上曾误用 64 位编号注册 compat hook，实际装到 EABI 编号空间里不相关的 syscall 上；现 13 个编号全部按内核树 `unistd32.h` 逐一核实。注意 compat 的 `mmap` 是 5 参数的 `mmap2`，独立 fargs5 处理器避免 ret 偏移错读。鉴别目标进程位数：`adb shell dumpsys package <pkg> | grep primaryCpuAbi`。
- **多 KPM 共存**：fp_hook 系按"每张 syscall 表槽一条回调链"管理（befores/afters 数组），与 panda-hide 同挂 openat 等可正常共存、依注册顺序链式调用。
- **v1.4.0 自动 dump**：仅在包名嗅探 + 已锁定目标下触发，每会话最多 16 个文件（去重表 16 条 FIFO，rwx 观察表 8 条 FIFO）；`clear`/`stop` 重置全部 dump 状态。落盘走目标 app 自身 cred，写不进 app 目录时只报错不崩溃。rwx 观察区的 exit 检查依赖 exit hook（`TRACE_HIGH_FREQ=0` 时仅剩 syscall 宽限窗口检查）。
- **bt 符号解析**：`lr`/`bt` 的 `so名+偏移` 解析基于 VMA 结构偏移运行期探测 + dentry `d_name` 直读（basename；加载后目标首个事件打出 `bt-res ok: ...` 行）；任一探测失败自动回退十六进制。**全部内核内存读经 `copy_from_kernel_nofault` 拷贝 + 16GB 数值窗口粗筛**，不调用任何 kallsyms 解析出的函数指针做校验，垃圾指针只降级不崩溃。栈扫描补帧可能混入栈上陈旧返回地址，属已知噪声。解析兼容 `__randomize_layout`（mm_struct.mmap 不硬编码），跨内核版本可用。若手机异常关机，重启后 `cat /sys/fs/pstore/console-ramoops*` 查看 panic 现场。
- **task_ext 无故障读取**：pid/tgid 一律经 `copy_from_kernel_nofault`（缺失退 `probe_kernel_read`，再退原始直读）拷贝后校验 magic，task_ext 指针越界/为 NULL 时只跳过该事件（打一次 `task_ext invalid` 行），不会再 panic。实测某 32 位 app 启动期 kill 调用曾因 ext 指针异常触发内核翻译错误关机。
- **已知边界**：ctl 并发操作极端情形下 pid 列表计数非原子（人工操作频率下可忽略）；TLOG 格式化缓冲为单一静态区，多核高频并发下个别行可能交错。

### 旧行为存档（4.9 LKM 版本）

- **内核版本**：早期 `.ko` 版本基于 Linux 4.9.270 开发测试。
- **性能**：默认模式直出 dmesg；add 后走 ring buffer。
- **pc:0x0**：32 位 compat 进程的 PC 可能无法获取，64 位进程正常。
