#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kputils.h>
#include <syscall.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <taskext.h>
#include <asm/current.h>
#include <uapi/asm-generic/unistd.h>
#include "trace.h"
static int g_pid_ofs  = -1;
static int g_tgid_ofs = -1;
static int g_calibrated = 0;
#define C         ((unsigned long)current)
#define tk_comm() get_task_comm(current)
static inline int tk_pid(void) {
    if (likely(g_calibrated > 0))
        return *(int *)(C + g_pid_ofs);
    return current_ext->pid;
}
static inline int tk_tgid(void) {
    if (likely(g_calibrated > 0))
        return *(int *)(C + g_tgid_ofs);
    return current_ext->pid;
}
static void try_calibrate(void) {
    if (g_calibrated != 0) return;
    int tid = current_ext->pid;
    unsigned long base = C;
    for (int ofs = 0x300; ofs < 0xA00; ofs += 4) {
        if (*(int *)(base + ofs) != tid) continue;
        int prev = *(int *)(base + ofs - 4);
        int next = *(int *)(base + ofs + 4);
        int found_tgid = -1, tgid_ofs = -1;
        if (prev > 0 && prev != tid)      { found_tgid = prev; tgid_ofs = ofs - 4; }
        else if (next > 0 && next != tid) { found_tgid = next; tgid_ofs = ofs + 4; }
        else if (prev == tid)             { found_tgid = prev; tgid_ofs = ofs - 4; }
        else if (next == tid)             { found_tgid = next; tgid_ofs = ofs + 4; }
        else continue;
        if (found_tgid < 1 || found_tgid > 0x7fffffff) continue;
        g_pid_ofs  = ofs;
        g_tgid_ofs = tgid_ofs;
        g_calibrated = 1;
        return;
    }
}
static unsigned long get_svc_pc(void *hook_fargs) {
    if (has_syscall_wrapper) {
        struct pt_regs *regs = (struct pt_regs *)((hook_fargs0_t *)hook_fargs)->args[0];
        if (regs && regs->pc) return regs->pc;
    }
    unsigned long *stack = get_stack(current);
    if (stack) {
        struct pt_regs *regs = (struct pt_regs *)((unsigned long)stack + thread_size) - 1;
        if (regs->pc) return regs->pc;
    }
    return 0;
}
static int target_pids[TARGET_PID_MAX], target_pid_cnt;
static int pending_list[PENDING_MAX], pending_cnt;
static char sniff_pkg[PATH_BUF_SIZE];
static int sniff_locked;
int trace_add_pid(int pid) {
    if (target_pid_cnt < TARGET_PID_MAX) {
        target_pids[target_pid_cnt++] = pid;
        return 0;
    }
    return -1;
}
int trace_add_pkg(const char *pkg) {
    int i;
    for (i = 0; i < PATH_BUF_SIZE - 1 && pkg[i]; i++)
        sniff_pkg[i] = pkg[i];
    sniff_pkg[i] = '\0';
    sniff_locked = 0;
    return 0;
}
int trace_del_pid(int pid) {
    for (int i = 0; i < target_pid_cnt; i++)
        if (target_pids[i] == pid) {
            target_pids[i] = target_pids[--target_pid_cnt];
            return 0;
        }
    return -1;
}
int trace_del_pkg(void) {
    sniff_pkg[0] = '\0';
    sniff_locked = 0;
    return 0;
}
void trace_clear_pid(void) {
    target_pid_cnt = 0;
    pending_cnt = 0;
    sniff_pkg[0] = '\0';
    sniff_locked = 0;
}
static int is_in_target_list(int tgid) {
    for (int i = 0; i < target_pid_cnt; i++)
        if (target_pids[i] == tgid) return 1;
    return 0;
}
static int is_in_pending(int tgid) {
    for (int i = 0; i < pending_cnt; i++)
        if (pending_list[i] == tgid) return 1;
    return 0;
}
static void pending_add(int tgid) {
    if (pending_cnt < PENDING_MAX && !is_in_target_list(tgid) && !is_in_pending(tgid))
        pending_list[pending_cnt++] = tgid;
}
static void pending_confirm(int tgid) {
    for (int i = 0; i < pending_cnt; i++) {
        if (pending_list[i] == tgid) {
            pending_list[i] = pending_list[--pending_cnt];
            break;
        }
    }
    if (!is_in_target_list(tgid))
        trace_add_pid(tgid);
}
static void pending_remove(int tgid) {
    for (int i = 0; i < pending_cnt; i++) {
        if (pending_list[i] == tgid) {
            pending_list[i] = pending_list[--pending_cnt];
            return;
        }
    }
}
static int comm_matches_pkg(const char *comm) {
    if (!sniff_pkg[0]) return 0;
    int pkglen;
    for (pkglen = 0; sniff_pkg[pkglen]; pkglen++);
    for (int i = 0; comm[i]; i++) {
        int j;
        for (j = 0; sniff_pkg[j] && comm[i+j] == sniff_pkg[j]; j++);
        if (sniff_pkg[j] == '\0') return 1;
    }
    return 0;
}
static int path_matches_pkg(const char *path) {
    if (!sniff_pkg[0]) return 0;
    const char *data = path;
    while ((data = strstr(data, "/data/")) != NULL) {
        data += 6;
        if (strncmp(data, "user/", 5) == 0) {
            data += 5;
            while (*data >= '0' && *data <= '9') data++;
            if (*data == '/') data++;
        } else if (strncmp(data, "data/", 5) == 0) {
            data += 5;
        }
        if (strncmp(data, sniff_pkg, strlen(sniff_pkg)) == 0)
            return 1;
    }
    return 0;
}
static void try_sniff_lock(int tgid) {
    if (!sniff_pkg[0] || sniff_locked) return;
    if (is_in_target_list(tgid)) {
        sniff_locked = 1;
        pr_info("AyuTrace|>>> SNIFF LOCKED tgid=%d pkg=%s (already in list)\n", tgid, sniff_pkg);
        return;
    }
    if (comm_matches_pkg(tk_comm())) {
        trace_add_pid(tgid);
        sniff_locked = 1;
        pending_remove(tgid);
        pr_info("AyuTrace|>>> SNIFF LOCKED tgid=%d pkg=%s (comm match: %.16s)\n",
                tgid, sniff_pkg, tk_comm());
        return;
    }
}
static void try_sniff_path(int tgid, const char *path) {
    if (!sniff_pkg[0] || sniff_locked) return;
    if (!path) return;
    if (path_matches_pkg(path)) {
        trace_add_pid(tgid);
        sniff_locked = 1;
        pending_remove(tgid);
        pr_info("AyuTrace|>>> SNIFF LOCKED tgid=%d pkg=%s (path match: %s)\n",
                tgid, sniff_pkg, path);
    }
}
#define FLUSH_INTERVAL 32
#define FLUSH_BATCH    512
static struct log_entry ring[RING_ENTRIES];
static uint32_t ring_head __attribute__((aligned(8)));
static uint32_t ring_tail __attribute__((aligned(8)));
static uint32_t ring_dropped;
static int ring_lock_val;
static inline void ring_lock(void) {
    int tmp = 1;
    asm volatile(
        "1: ldaxr %w0, [%1]\n"
        "   cbnz %w0, 1b\n"
        "   stxr %w0, %w2, [%1]\n"
        "   cbnz %w0, 1b\n"
        : "=&r"(tmp)
        : "r"(&ring_lock_val), "r"(1)
        : "memory"
    );
}
static inline void ring_unlock(void) {
    asm volatile("stlr wzr, [%0]" :: "r"(&ring_lock_val) : "memory");
}
static void ring_push(uint8_t flags, int tgid, const char *msg, int len) {
    if (len <= 0 || len > (int)sizeof(ring[0].data)) return;
    ring_lock();
    uint32_t head = ring_head;
    uint32_t next = (head + 1) % RING_ENTRIES;
    if (next == smp_load_acquire(&ring_tail)) {
        smp_store_release(&ring_tail, (ring_tail + 1) % RING_ENTRIES);
        ring_dropped++;
    }
    ring[head].flags = flags;
    ring[head].tgid  = tgid;
    ring[head].len   = (uint16_t)len;
    for (int i = 0; i < len; i++) ring[head].data[i] = msg[i];
    smp_store_release(&ring_head, next);
    ring_unlock();
}
static void ring_flush(void) {
    uint32_t tail = smp_load_acquire(&ring_tail);
    uint32_t head = smp_load_acquire(&ring_head);
    int flushed = 0;
    while (tail != head) {
        struct log_entry *e = &ring[tail];
        if (e->flags == LOG_FLAG_CONFIRMED) {
            pr_info("AyuTrace|%.*s\n", e->len, e->data);
            flushed++;
        } else if (e->flags == LOG_FLAG_PENDING) {
            if (is_in_target_list(e->tgid)) {
                pr_info("AyuTrace|[P->K] %.*s\n", e->len, e->data);
                flushed++;
            }
        }
        e->flags = LOG_FLAG_EMPTY;
        tail = (tail + 1) % RING_ENTRIES;
        if (++flushed >= FLUSH_BATCH) break;
    }
    smp_store_release(&ring_tail, tail);
    if (ring_dropped > 1000) {
        uint32_t d = ring_dropped;
        ring_dropped = 0;
        pr_info("AyuTrace|>>> DROPPED %u entries (ring full)\n", d);
    }
}
static int flush_counter;
static int hooks_enabled = 1;
void trace_disable(void) { if (hooks_enabled) { hooks_enabled=0; pr_info("AyuTrace|>>> HOOKS DISABLED\n"); } }
void trace_enable(void)  { if (!hooks_enabled){ hooks_enabled=1; pr_info("AyuTrace|>>> HOOKS ENABLED\n"); } }
int  trace_is_enabled(void) { return hooks_enabled; }
const char *trace_status(void) {
    if (sniff_pkg[0])
        return sniff_locked ? "sniff-locked" : "sniff-waiting";
    if (target_pid_cnt > 0)
        return "pid-locked";
    return "all-user-apps";
}
static inline int should_log(uint8_t *out_flags) {
    if (!hooks_enabled) return 0;
    try_calibrate();
    int tgid = tk_tgid();
    if (++flush_counter >= FLUSH_INTERVAL) {
        flush_counter = 0;
        ring_flush();
    }
    try_sniff_lock(tgid);
    if (is_in_target_list(tgid)) {
        *out_flags = LOG_FLAG_CONFIRMED;
        return 1;
    }
    if (is_in_pending(tgid)) {
        *out_flags = LOG_FLAG_PENDING;
        return 1;
    }
    if (sniff_pkg[0] && !sniff_locked)
        return 0;
    if (target_pid_cnt == 0 && !sniff_pkg[0])
        return current_uid() >= TRACE_UID_THRESHOLD;
    return 0;
}
static char _tlog_buf[LOG_ENTRY_SIZE];
static inline int use_ring(void) {
    return target_pid_cnt > 0 || sniff_pkg[0] != '\0';
}
#define TLOG(tag, fmt, ...) do { \
    uint8_t _fl = 0; \
    if (!should_log(&_fl)) break; \
    if (use_ring()) { \
        int _len = xsnprintf(_tlog_buf, sizeof(_tlog_buf), \
                  "%-10s pid:%-6d tid:%-6d comm:%-16.16s " fmt, \
                  tag, tk_tgid(), tk_pid(), tk_comm(), ##__VA_ARGS__); \
        if (_len > 0) ring_push(_fl, tk_tgid(), _tlog_buf, _len); \
    } else { \
        pr_info("AyuTrace|%-10s pid:%-6d tid:%-6d comm:%-16.16s " fmt "\n", \
                tag, tk_tgid(), tk_pid(), tk_comm(), ##__VA_ARGS__); \
    } \
} while(0)
static void before_openat(hook_fargs4_t *args, void *udata) {
    (void)udata; const char __user *fn = (const char __user *)syscall_argn(args, 1);
    if (!fn) return; char p[PATH_BUF_SIZE];
    long len = compat_strncpy_from_user(p, fn, sizeof(p));
    if (len <= 1 || (unsigned long)len >= sizeof(p)) return; p[len-1] = '\0';
    try_sniff_path(tk_tgid(), p);
    TLOG("openat", "path:%.128s", p);
}
static void before_readlinkat(hook_fargs4_t *args, void *udata) {
    (void)udata; const char __user *src = (const char __user *)syscall_argn(args, 1);
    if (!src) return; char ps[PATH_BUF_SIZE];
    long ls = compat_strncpy_from_user(ps, src, sizeof(ps));
    if (ls <= 1 || (unsigned long)ls >= sizeof(ps)) return; ps[ls-1] = '\0';
    TLOG("readlinkat", "path:%.128s", ps);
}
static void before_execve(hook_fargs3_t *args, void *udata) {
    (void)udata; const char __user *fn = (const char __user *)syscall_argn(args, 0);
    if (!fn) return; char p[PATH_BUF_SIZE];
    long len = compat_strncpy_from_user(p, fn, sizeof(p));
    if (len <= 1 || (unsigned long)len >= sizeof(p)) return; p[len-1] = '\0';
    TLOG("execve", "path:%.128s", p);
}
#if TRACE_HIGH_FREQ
/*
/*
static void before_read(hook_fargs3_t *args, void *udata) {
    (void)udata;
    TLOG("read", "fd:%lu req_size:%lu", syscall_argn(args,0), syscall_argn(args,2));
}
*/
static void before_kill(hook_fargs2_t *args, void *udata) {
    (void)udata; TLOG("kill", "target:%ld sig:%ld pc:0x%lx", syscall_argn(args,0), syscall_argn(args,1), get_svc_pc(args));
}
static void before_tkill(hook_fargs2_t *args, void *udata) {
    (void)udata; TLOG("tkill", "tid:%ld sig:%ld pc:0x%lx", syscall_argn(args,0), syscall_argn(args,1), get_svc_pc(args));
}
static void before_tgkill(hook_fargs3_t *args, void *udata) {
    (void)udata; TLOG("tgkill", "tgid:%ld tid:%ld sig:%ld pc:0x%lx", syscall_argn(args,0), syscall_argn(args,1), syscall_argn(args,2), get_svc_pc(args));
}
static void before_exit(hook_fargs1_t *args, void *udata) {
    (void)udata; TLOG("exit", "status:%ld", syscall_argn(args,0));
}
static void after_clone(hook_fargs5_t *args, void *udata) {
    (void)udata;
    long new_tid = (long)args->ret;
    TLOG("clone", "new_tid:%ld", new_tid);
    {
        const char *comm = tk_comm();
        if (comm && (strncmp(comm, "zygote", 6) == 0 || strncmp(comm, "main", 4) == 0)) {
            if (new_tid > 1) pending_add((int)new_tid);
        }
    }
}
#endif
static void after_set_tid_address(hook_fargs1_t *args, void *udata) {
    (void)udata; TLOG("set_tid_addr", "ret:%lld", (long long)args->ret);
}
static void before_unshare(hook_fargs1_t *args, void *udata) {
    (void)udata; TLOG("unshare", "flags:0x%lx", (unsigned long)syscall_argn(args,0));
}
static const char *ptrace_reqs[] = {"TRACEME","PEEKTEXT","PEEKDATA","PEEKUSR","POKETEXT","POKEDATA","POKEUSR","CONT","KILL","SINGLESTEP","?","?","?","?","?","?","ATTACH","DETACH","?","?","?","?","?","?","SYSCALL"};
static void before_ptrace(hook_fargs4_t *args, void *udata) {
    (void)udata; unsigned rq = (unsigned)(unsigned long)syscall_argn(args,0);
    int tg = (int)(long)syscall_argn(args,1);
    unsigned long ad = (unsigned long)syscall_argn(args,2);
    unsigned long dt = (unsigned long)syscall_argn(args,3);
    TLOG("ptrace", "req:%s target:%d addr:0x%lx data:0x%lx",
         (rq<25)?ptrace_reqs[rq]:"?", tg, ad, dt);
}
#define __NR_compat_mmap2    192
#define __NR_compat_mprotect 125
static const char *prot_str(int prot) {
    static char b[4]; char *p = b;
    *p++ = (prot & 1) ? 'r' : '-';
    *p++ = (prot & 2) ? 'w' : '-';
    *p++ = (prot & 4) ? 'x' : '-';
    return b;
}
static void after_mmap(hook_fargs6_t *args, void *udata) {
    (void)udata;
    unsigned long addr  = syscall_argn(args, 0);
    unsigned long len   = syscall_argn(args, 1);
    int prot            = (int)syscall_argn(args, 2);
    int flags           = (int)syscall_argn(args, 3);
    int fd              = (int)syscall_argn(args, 4);
    unsigned long off   = syscall_argn(args, 5);
    long long ret       = (long long)args->ret;
    TLOG("mmap", "addr:0x%lx len:%lu prot:%s flags:0x%x fd:%d off:%lu ->0x%llx pc:0x%lx",
         addr, len, prot_str(prot), flags, fd, off, ret, get_svc_pc(args));
}
static void before_mprotect(hook_fargs3_t *args, void *udata) {
    (void)udata;
    unsigned long addr  = syscall_argn(args, 0);
    unsigned long len   = syscall_argn(args, 1);
    int prot            = (int)syscall_argn(args, 2);
    TLOG("mprotect", "addr:0x%lx len:%lu prot:%s pc:0x%lx", addr, len, prot_str(prot), get_svc_pc(args));
}
static int hk_openat, hk_readlinkat, hk_execve, hk_set_tid, hk_unshare, hk_ptrace;
static int hk_openat_c, hk_readlinkat_c, hk_execve_c, hk_set_tid_c, hk_unshare_c, hk_ptrace_c;
static int hk_mmap, hk_mmap_c, hk_mprotect, hk_mprotect_c;
#if TRACE_HIGH_FREQ
static int  hk_kill, hk_tkill, hk_tgkill, hk_exit, hk_clone;
static int hk_kill_c, hk_tkill_c, hk_tgkill_c, hk_exit_c, hk_clone_c;
#endif
void trace_install(void) {
    hook_err_t e; int cnt = 0;
#define H(nr,n,b,a)   e=fp_hook_syscalln(nr,n,b,a,NULL); if(!e){cnt++;}else pr_err("AyuTrace: "#nr" fail %d\n",e)
#define HC(nr,n,b,a)  e=fp_hook_compat_syscalln(nr,n,b,a,NULL); if(!e){cnt++;}else pr_err("AyuTrace: compat "#nr" fail %d\n",e)
    H (__NR_openat,4,before_openat,NULL);          if(!e) hk_openat    =1;
    HC(__NR_openat,4,before_openat,NULL);          if(!e) hk_openat_c  =1;
    H (__NR_readlinkat,4,before_readlinkat,NULL);  if(!e) hk_readlinkat   =1;
    HC(__NR_readlinkat,4,before_readlinkat,NULL);  if(!e) hk_readlinkat_c =1;
    H (__NR_execve,3,before_execve,NULL);          if(!e) hk_execve    =1;
    HC(__NR_execve,3,before_execve,NULL);          if(!e) hk_execve_c  =1;
    H (__NR_set_tid_address,1,NULL,after_set_tid_address); if(!e) hk_set_tid    =1;
    HC(__NR_set_tid_address,1,NULL,after_set_tid_address); if(!e) hk_set_tid_c  =1;
    H (__NR_unshare,1,before_unshare,NULL);        if(!e) hk_unshare    =1;
    HC(__NR_unshare,1,before_unshare,NULL);        if(!e) hk_unshare_c  =1;
    H (__NR_ptrace,4,before_ptrace,NULL);          if(!e) hk_ptrace     =1;
    HC(__NR_ptrace,4,before_ptrace,NULL);          if(!e) hk_ptrace_c   =1;
    H (222, 6,NULL,after_mmap);              if(!e) hk_mmap       =1;
    HC(__NR_compat_mmap2, 5, NULL, after_mmap);    if(!e) hk_mmap_c     =1;
    H (__NR_mprotect,3,before_mprotect,NULL);      if(!e) hk_mprotect   =1;
    HC(__NR_compat_mprotect, 3, before_mprotect, NULL); if(!e) hk_mprotect_c =1;
#if TRACE_HIGH_FREQ
    H (__NR_kill,   2, before_kill,   NULL);  if(!e) hk_kill     =1;
    HC(__NR_kill,   2, before_kill,   NULL);  if(!e) hk_kill_c   =1;
    H (__NR_tkill,  2, before_tkill,  NULL);  if(!e) hk_tkill    =1;
    HC(__NR_tkill,  2, before_tkill,  NULL);  if(!e) hk_tkill_c  =1;
    H (__NR_tgkill, 3, before_tgkill, NULL);  if(!e) hk_tgkill   =1;
    HC(__NR_tgkill, 3, before_tgkill, NULL);  if(!e) hk_tgkill_c =1;
    H (__NR_exit,   1, before_exit,   NULL);  if(!e) hk_exit     =1;
    HC(__NR_exit,   1, before_exit,   NULL);  if(!e) hk_exit_c   =1;
    H (__NR_clone,  5, NULL, after_clone);    if(!e) hk_clone    =1;
    HC(__NR_clone,  5, NULL, after_clone);    if(!e) hk_clone_c  =1;
#endif
#undef H
#undef HC
    pr_info("AyuTrace installed %d hooks (ringbuf + sniff)\n", cnt);
}
void trace_stop(void) {
    for (int i = 0; i < 8; i++) ring_flush();
    trace_disable();
    trace_clear_pid();
    pr_info("AyuTrace|>>> STOPPED: flushed, disabled, cleared\n");
}
void trace_uninstall(void) {
    ring_flush();
    ring_flush();
#define U(nr,b,a)   fp_unhook_syscalln(nr,b,a)
#define UC(nr,b,a)  fp_unhook_compat_syscalln(nr,b,a)
    if(hk_openat)      U (__NR_openat,      before_openat,      NULL);
    if(hk_openat_c)    UC(__NR_openat,      before_openat,      NULL);
    if(hk_readlinkat)  U (__NR_readlinkat,  before_readlinkat,  NULL);
    if(hk_readlinkat_c)UC(__NR_readlinkat,  before_readlinkat,  NULL);
    if(hk_execve)      U (__NR_execve,      before_execve,      NULL);
    if(hk_execve_c)    UC(__NR_execve,      before_execve,      NULL);
    if(hk_set_tid)     U (__NR_set_tid_address, NULL, after_set_tid_address);
    if(hk_set_tid_c)   UC(__NR_set_tid_address, NULL, after_set_tid_address);
    if(hk_unshare)     U (__NR_unshare,     before_unshare,     NULL);
    if(hk_unshare_c)   UC(__NR_unshare,     before_unshare,     NULL);
    if(hk_ptrace)      U (__NR_ptrace,      before_ptrace,      NULL);
    if(hk_ptrace_c)    UC(__NR_ptrace,      before_ptrace,      NULL);
    if(hk_mmap)        U (222,              NULL,               after_mmap);
    if(hk_mmap_c)      UC(__NR_compat_mmap2,NULL,               after_mmap);
    if(hk_mprotect)    U (__NR_mprotect,    before_mprotect,    NULL);
    if(hk_mprotect_c)  UC(__NR_compat_mprotect, before_mprotect,NULL);
#if TRACE_HIGH_FREQ
    if(hk_kill)        U (__NR_kill,        before_kill,        NULL);
    if(hk_kill_c)      UC(__NR_kill,        before_kill,        NULL);
    if(hk_tkill)       U (__NR_tkill,       before_tkill,       NULL);
    if(hk_tkill_c)     UC(__NR_tkill,       before_tkill,       NULL);
    if(hk_tgkill)      U (__NR_tgkill,      before_tgkill,      NULL);
    if(hk_tgkill_c)    UC(__NR_tgkill,      before_tgkill,      NULL);
    if(hk_exit)        U (__NR_exit,        before_exit,        NULL);
    if(hk_exit_c)      UC(__NR_exit,        before_exit,        NULL);
    if(hk_clone)       U (__NR_clone,       NULL,               after_clone);
    if(hk_clone_c)     UC(__NR_clone,       NULL,               after_clone);
#endif
#undef U
#undef UC
    pr_info("AyuTrace uninstalled\n");
}
