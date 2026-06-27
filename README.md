# AyuTrace — Kernel Syscall Tracer (KPM)

基于 KernelPatch/APatch 的内核系统调用追踪模块。hook 13 个 syscall（× 64-bit + 32-bit compat = 26 个 hook），支持 PID 锁定、包名嗅探自动锁定、ring buffer 缓冲输出。

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

## 使用流程

### 1. 加载模块

APatch 管理器 → 内核模块 → 加载 `kpm_trace_svc.kpm`

### 2. 追踪指定 App（推荐：包名嗅探）

```bash
# APatch 参数输入：
add com.example.app
```

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

通过 `pc` 定位调用来源（需要进程未退出）：
```bash
grep "\.so" /proc/<pid>/maps | awk -v pc=0x7b0c3f04 \
  'split($1,a,"-"){s=strtonum("0x"a[1]);e=strtonum("0x"a[2]); \
    if(s<=strtonum(pc)&&strtonum(pc)<=e)printf "%s +0x%x\n",$5,strtonum(pc)-s}'
```

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

通过 `pc` 定位反调试代码：
```bash
grep "\.so" /proc/<pid>/maps | awk -v pc=0x7b0c3f04 \
  'split($1,a,"-"){s=strtonum("0x"a[1]);e=strtonum("0x"a[2]); \
    if(s<=strtonum(pc)&&strtonum(pc)<=e)printf "%s +0x%x\n",$5,strtonum(pc)-s}'
```

### 其他

| tag | syscall | 日志参数 | 逆向价值 |
|-----|---------|---------|---------|
| `unshare` | `unshare` | `flags:<标志>` | 命名空间隔离，少见 |

### 已注释的 hook

| tag | 原因 |
|-----|------|
| `read` | 高频（eventfd/pipe 每秒数千次），噪音远大于信息量。如需启用，编辑 `trace.c` 去掉 `/* */` 并设置 `TRACE_HIGH_FREQ 1` |

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

看到 `mmap prot:rw- ANON` + `mprotect prot:r-x` 连续出现 → 高度疑似壳自解密。

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

## 配置

编辑 `trace.h`：

| 宏 | 默认值 | 说明 |
|----|--------|------|
| `TRACE_HIGH_FREQ` | `1` | `0`=关闭 kill/clone/exit hook |
| `TRACE_UID_THRESHOLD` | `10000u` | 默认只追踪 UID≥10000 的用户 App |
| `TARGET_PID_MAX` | `16` | 最多同时追踪的进程数 |

编辑 `trace.c` 启用 read hook：去掉 `before_read` 函数的 `/* */` 注释，并在 `trace_install`/`trace_uninstall` 中去掉对应的注释。

## 注意事项

- **内核版本**：当前模块基于 **Linux 4.9.270** 开发与测试。其他内核版本的 task_struct 偏移量可能不同，但模块采用自校准机制，首次 hook 触发时自动适配 pid/tgid 偏移。comm 通过 KernelPatch 的 `get_task_comm()` 获取，兼容各内核版本。
- **日志丢失**：dmesg 环形缓冲区有限。高频 syscall 下旧日志会被覆盖。锁定单一 PID 可最大程度避免丢失。
- **性能**：默认模式（未 add）直出 dmesg，零额外开销。add 后走 ring buffer，hook 内耗时 < 500ns。
- **pc:0x0**：32 位 compat 进程的 PC 可能无法获取，64 位进程正常。

