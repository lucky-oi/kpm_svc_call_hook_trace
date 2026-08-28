#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kputils.h>
#include <kallsyms.h>
#include <syscall.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <taskext.h>
#include <asm/current.h>
#include <uapi/asm-generic/unistd.h>
#include "trace.h"








#define tk_comm() get_task_comm(current)
static inline int tk_pid(void) {
    struct task_ext *ext = current_ext;
    return task_ext_valid(ext) ? ext->pid : 0;
}
static inline int tk_tgid(void) {
    struct task_ext *ext = current_ext;
    return task_ext_valid(ext) ? ext->tgid : 0;
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


static unsigned long dumped_addr[DUMP_REGION_MAX];
static unsigned long dumped_len[DUMP_REGION_MAX];
static int dumped_cnt;
static int dump_file_seq;
static int dump_session_cnt;
static int dump_partial_logged;
static int dump_skip_logged;
static int dump_lock_val;
static unsigned long man_dump_addr, man_dump_len;
static int man_dump_pending;


struct dump_pend { int tid; unsigned long addr, len, pc; int retries; };
static struct dump_pend dump_pend_tab[DUMP_PEND_MAX];
static int dump_pend_cnt;
static int dump_grace_ctr;
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
    
    dumped_cnt = 0;
    dump_session_cnt = 0;
    dump_file_seq = 0;
    man_dump_pending = 0;
    dump_pend_cnt = 0;
    dump_grace_ctr = 0;
    dump_partial_logged = 0;
    dump_skip_logged = 0;
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


static int pending_add(int tgid) {
    if (is_in_target_list(tgid) || is_in_pending(tgid))
        return 0;
    if (pending_cnt >= PENDING_MAX) {
        for (int i = 1; i < PENDING_MAX; i++)
            pending_list[i - 1] = pending_list[i];
        pending_cnt--;
    }
    pending_list[pending_cnt++] = tgid;
    return 1;
}
static int str_contains(const char *haystack, const char *needle) {
    int nlen;
    for (nlen = 0; needle[nlen]; nlen++);
    if (!nlen) return 0;
    for (int i = 0; haystack[i]; i++) {
        int j;
        for (j = 0; needle[j] && haystack[i+j] == needle[j]; j++);
        if (needle[j] == '\0') return 1;
    }
    return 0;
}
static int comm_matches_pkg(const char *comm) {
    if (!sniff_pkg[0]) return 0;
    if (str_contains(comm, sniff_pkg)) return 1;
    int pkglen;
    for (pkglen = 0; sniff_pkg[pkglen]; pkglen++);
    int last = pkglen;
    while (last > 0 && sniff_pkg[last-1] != '.') last--;
    if (last < pkglen && pkglen - last <= 16)
        return str_contains(comm, sniff_pkg + last);
    return 0;
}
static int path_matches_pkg(const char *path) {
    if (!sniff_pkg[0] || !path) return 0;
    return str_contains(path, sniff_pkg);
}















static int sp_len(const char *s) { int n = 0; while (s[n]) n++; return n; }
static int str_prefix(const char *s, const char *p) {
    for (int i = 0; p[i]; i++)
        if (s[i] != p[i]) return 0;
    return 1;
}

static int path_in_own_datadir(const char *path) {
    const char *p;
    int pkglen;
    if (!sniff_pkg[0] || !path) return 0;
    if (!str_prefix(path, "/data/")) return 0;
    p = path + 6;
    if      (str_prefix(p, "user_de/")) p += 8;
    else if (str_prefix(p, "user/"))    p += 5;
    else if (str_prefix(p, "data/"))    p += 5;   
    else return 0;
    
    if (p[0] >= '0' && p[0] <= '9') {
        while (p[0] >= '0' && p[0] <= '9') p++;
        if (p[0] != '/') return 0;
        p++;
    }
    if (!str_prefix(p, sniff_pkg)) return 0;
    pkglen = sp_len(sniff_pkg);
    if (p[pkglen] != '/') return 0;               
    return 1;
}

static void sniff_promote(int tgid, const char *via, const char *detail) {
    trace_add_pid(tgid);
    sniff_locked = 1;
    pending_cnt = 0;
    if (detail && detail[0])
        pr_info("AyuTrace|>>> SNIFF LOCKED tgid=%d pkg=%s (%s: %.96s)\n",
                tgid, sniff_pkg, via, detail);
    else
        pr_info("AyuTrace|>>> SNIFF LOCKED tgid=%d pkg=%s (%s)\n",
                tgid, sniff_pkg, via);
}
static void try_sniff_lock(int tgid) {
    if (!sniff_pkg[0] || sniff_locked) return;
    if (is_in_target_list(tgid)) {
        sniff_promote(tgid, "already in list", NULL);
        return;
    }
    
    if (comm_matches_pkg(tk_comm()))
        sniff_promote(tgid, "comm match", tk_comm());
}
static void try_sniff_path(int tgid, const char *path) {
    if (!sniff_pkg[0] || sniff_locked || !path) return;
    if (is_in_target_list(tgid)) return;
    
    if (path_in_own_datadir(path)) {
        if (is_in_pending(tgid))
            sniff_promote(tgid, "self data dir", path);
        return;
    }
    
    if (path_matches_pkg(path)) {
        if (pending_add(tgid))
            pr_info("AyuTrace|>>> SNIFF CANDIDATE tgid=%d pkg=%s (path: %.96s)\n",
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

static inline void spin_raw(int *l) {
    int tmp = 1;
    asm volatile(
        "1: ldaxr %w0, [%1]\n"
        "   cbnz %w0, 1b\n"
        "   stxr %w0, %w2, [%1]\n"
        "   cbnz %w0, 1b\n"
        : "=&r"(tmp)
        : "r"(l), "r"(1)
        : "memory"
    );
}
static inline void spin_rel(int *l) {
    asm volatile("stlr wzr, [%0]" :: "r"(l) : "memory");
}
static inline void ring_lock(void) { spin_raw(&ring_lock_val); }
static inline void ring_unlock(void) { spin_rel(&ring_lock_val); }
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




static int hooks_enabled = 0;
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























struct dump_file;   
typedef long long dk_loff_t;
#define DK_O_WRONLY   1
#define DK_O_CREAT    0100
#define DK_O_TRUNC    01000
#define DK_MAX_ERRNO  4096
static unsigned long (*dk_kernel_write)(struct dump_file *, const void *,
                                        unsigned long, dk_loff_t *);
static struct dump_file *(*dk_filp_open)(const char *, int, unsigned int);
static int (*dk_filp_close)(struct dump_file *, void *);
static unsigned long (*dk_copy_from_user)(void *, const void *, unsigned long);
static char dump_buf[DUMP_CHUNK] __attribute__((aligned(64)));
static int dump_syms_ok;
static int dump_syms_tried;
static inline int dk_is_err(const void *p) {
    return (unsigned long)p >= (unsigned long)-DK_MAX_ERRNO;
}
static void rl_resolve(void);   
static void dump_resolve_syms(void) {
    if (dump_syms_tried) return;
    dump_syms_tried = 1;
    if (!kallsyms_lookup_name) {   
        pr_err("AyuTrace|dump syms missing: kallsyms_lookup_name is NULL\n");
        return;
    }
    dk_kernel_write   = (void *)kallsyms_lookup_name("kernel_write");
    dk_filp_open      = (void *)kallsyms_lookup_name("filp_open");
    dk_filp_close     = (void *)kallsyms_lookup_name("filp_close");
    dk_copy_from_user = (void *)kallsyms_lookup_name("__arch_copy_from_user");
    if (dk_kernel_write && dk_filp_open && dk_filp_close && dk_copy_from_user) {
        dump_syms_ok = 1;
        pr_info("AyuTrace|dump syms ok: kernel_write/filp_open/filp_close/__arch_copy_from_user\n");
    } else {
        pr_err("AyuTrace|dump syms missing: kernel_write=0x%llx filp_open=0x%llx filp_close=0x%llx cfu=0x%llx\n",
               (unsigned long long)(unsigned long)dk_kernel_write,
               (unsigned long long)(unsigned long)dk_filp_open,
               (unsigned long long)(unsigned long)dk_filp_close,
               (unsigned long long)(unsigned long)dk_copy_from_user);
    }
    rl_resolve();   
}








static int rl_tried, rl_ok;
static unsigned long rl_page_shift = 12, rl_va_bits = 48, rl_pa_bits = 48;
static unsigned long rl_memstart, rl_voffset;   
static unsigned long rl_pgd_off = (unsigned long)-1;  
static void *(*rl_find_task)(int);
static void *(*rl_get_mm)(void *);
static void (*rl_put_mm)(void *);
static int (*rl_pfn_valid)(unsigned long);
static int (*rl_valid_phys)(unsigned long, unsigned long);

static void rl_resolve(void) {
    unsigned long tcr, mmfr0, ttbr1, parange;
    unsigned long im_mm, kvo, ms, off;
    unsigned long expected;
    static const unsigned long pa_table[] = { 32, 36, 40, 42, 44, 48, 52 };
    if (rl_tried) return;
    rl_tried = 1;
    if (!kallsyms_lookup_name) return;
    rl_find_task  = (void *)kallsyms_lookup_name("find_task_by_vpid");
    rl_get_mm     = (void *)kallsyms_lookup_name("get_task_mm");
    rl_put_mm     = (void *)kallsyms_lookup_name("mmput");
    rl_pfn_valid  = (void *)kallsyms_lookup_name("pfn_valid");
    rl_valid_phys = (void *)kallsyms_lookup_name("valid_phys_addr_range");
    ms   = (unsigned long)kallsyms_lookup_name("memstart_addr");
    kvo  = (unsigned long)kallsyms_lookup_name("kimage_voffset");
    im_mm = (unsigned long)kallsyms_lookup_name("init_mm");
    if (!rl_find_task || !rl_get_mm || !rl_put_mm || !ms || !kvo || !im_mm) {
        pr_err("AyuTrace|remote-read syms missing: ft=%px mm=%px mmput=%px memstart=%lx kvo=%lx init_mm=%lx\n",
               rl_find_task, rl_get_mm, rl_put_mm, ms, kvo, im_mm);
        return;
    }
    rl_memstart = *(unsigned long *)ms;
    rl_voffset  = *(unsigned long *)kvo;
    asm volatile("mrs %0, tcr_el1" : "=r"(tcr));
    rl_va_bits = 64 - ((tcr >> 16) & 0x1F);
    if (rl_va_bits > 48) rl_va_bits = 48;   
    {
        unsigned long tg1 = (tcr >> 30) & 0x3;
        rl_page_shift = (tg1 == 1) ? 14 : (tg1 == 3) ? 16 : 12;
    }
    asm volatile("mrs %0, id_aa64mmfr0_el1" : "=r"(mmfr0));
    parange = mmfr0 & 0xF;
    rl_pa_bits = (parange > 6) ? 48 : pa_table[parange];
    
    asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));
    expected = rl_voffset + (ttbr1 & (-1UL << rl_page_shift) & 0xFFFFFFFFFFFEULL);
    for (off = 0; off < 176; off += 4)
        if (*(unsigned long *)(im_mm + off) == expected) {
            rl_pgd_off = off;
            break;
        }
    if (rl_pgd_off == (unsigned long)-1) {
        pr_err("AyuTrace|remote-read pgd offset not found in init_mm\n");
        return;
    }
    rl_ok = 1;
    pr_info("AyuTrace|remote-read ok: page=%luK va=%lu pa=%lu pgd_off=%lu\n",
            (1UL << rl_page_shift) / 1024, rl_va_bits, rl_pa_bits, rl_pgd_off);
}

static int rl_read_chunk(int tgid, unsigned long vaddr, void *buf, unsigned long chunk) {
    void *task, *mm;
    unsigned long ps = rl_page_shift, es = ps - 3;
    long levels = (long)((rl_va_bits - 4) / es);
    unsigned long phys = 0, kva;
    if (levels < 1) return 0;
    task = rl_find_task(tgid);
    if (!task) return 0;
    mm = rl_get_mm(task);
    if (!mm) return 0;
    {
        long level = 4 - levels;
        unsigned long tbl = *(unsigned long *)((unsigned long)mm + rl_pgd_off);
        unsigned long pmask = ~(-1UL << (48 - ps)) << ps;
        unsigned long imask = (1U << es) - 1;
        int found = 0;
        while (!found) {
            unsigned long shift = (4 - level) * es + 3;
            unsigned long idx = (vaddr >> shift) & imask;
            unsigned long entry = *(unsigned long *)(tbl + idx * 8);
            unsigned long dt = entry & 3;
            if (dt == 3) {
                tbl = (pmask & entry) + (-1UL << rl_va_bits) - rl_memstart;
                level++;
                if (level >= 3) { found = 1; break; }
            } else if (dt == 1) {
                if (level == 0) {
                    pmask = ~(-1UL << (48 - (ps + 3 * es))) << (ps + 3 * es);
                    tbl = (pmask & entry) + (-1UL << rl_va_bits) - rl_memstart;
                    level++;
                    if (level >= 3) { found = 1; break; }
                    continue;
                }
                found = 1;
                break;
            } else {
                break;
            }
        }
        if (found) {
            unsigned long shift = (4 - level) * es + 3;
            unsigned long idx = (vaddr >> shift) & imask;
            unsigned long entry = *(unsigned long *)(tbl + idx * 8);
            if ((~(unsigned short)entry & 0x401) == 0) {   
                unsigned long pa_frame = 0;
                if (rl_pa_bits == 52)
                    pa_frame = (entry << 36) & 0xF000000000000ULL;
                phys = (pa_frame + (entry & pmask)) & (-1UL << ps);
                phys |= vaddr & ~(-1UL << ps);
            }
        }
    }
    rl_put_mm(mm);
    if (!phys) return 0;
    if (rl_pfn_valid && !rl_pfn_valid(phys >> ps)) return 0;
    if (rl_valid_phys && !rl_valid_phys(phys, chunk)) return 0;
    kva = (phys & (-1UL << ps)) - rl_memstart + (-1UL << rl_va_bits)
        + (phys & ~(-1UL << ps));
    memcpy(buf, (void *)kva, chunk);
    return 1;
}

static unsigned long rl_read_mem(int tgid, unsigned long vaddr, void *buf, unsigned long len) {
    unsigned long done = 0, got = 0;
    while (done < len) {
        unsigned long pgsz = 1UL << rl_page_shift;
        unsigned long pgoff = vaddr & (pgsz - 1);
        unsigned long chunk = pgsz - pgoff;
        if (chunk > len - done) chunk = len - done;
        if (rl_read_chunk(tgid, vaddr, (char *)buf + done, chunk))
            got += chunk;
        else
            memset((char *)buf + done, 0, chunk);
        done += chunk;
        vaddr += chunk;
    }
    return got;
}

static int dump_already(unsigned long addr, unsigned long len) {
    for (int i = 0; i < dumped_cnt; i++)
        if (dumped_addr[i] == addr && dumped_len[i] == len) return 1;
    return 0;
}
static void dump_register(unsigned long addr, unsigned long len) {
    if (dumped_cnt < DUMP_REGION_MAX) {
        dumped_addr[dumped_cnt] = addr;
        dumped_len[dumped_cnt]  = len;
        dumped_cnt++;
        return;
    }
    for (int i = 1; i < DUMP_REGION_MAX; i++) {   
        dumped_addr[i - 1] = dumped_addr[i];
        dumped_len[i - 1]  = dumped_len[i];
    }
    dumped_addr[DUMP_REGION_MAX - 1] = addr;
    dumped_len[DUMP_REGION_MAX - 1]  = len;
}



static void dump_region(int tgid, int tid, unsigned long uaddr, unsigned long len,
                        unsigned long pc, const char *why) {
    char path[256];
    struct dump_file *filp;
    dk_loff_t pos = 0;
    unsigned long done = 0;
    int n, seq;
    if (!dump_syms_ok) return;
    if (!sniff_pkg[0]) return;   
    if (!len || len > DUMP_MAX_LEN || !uaddr) return;   
    spin_raw(&dump_lock_val);
    if (dump_already(uaddr, len)) {   
        spin_rel(&dump_lock_val);
        return;
    }
    if (dump_session_cnt >= DUMP_SESSION_MAX) {
        if (!dump_skip_logged) {
            dump_skip_logged = 1;
            pr_info("AyuTrace|>>> DUMP SKIP 0x%lx (session limit %d files)\n",
                    uaddr, DUMP_SESSION_MAX);
        }
        spin_rel(&dump_lock_val);
        return;
    }
    seq = ++dump_file_seq;
    n = xsnprintf(path, sizeof(path),
                  "/data/user/0/%s/ayudump_%d_pid%d_tid%d_0x%lx_0x%lx_pc0x%lx.bin",
                  sniff_pkg, seq, tgid, tid, uaddr, len, pc);
    if (n <= 0 || n >= (int)sizeof(path)) {
        spin_rel(&dump_lock_val);
        return;
    }
    filp = dk_filp_open(path, DK_O_WRONLY | DK_O_CREAT | DK_O_TRUNC, 0644);
    if (!filp || dk_is_err(filp)) {
        pr_err("AyuTrace|dump filp_open(%s) err=%lld\n",
               path, -(long long)(unsigned long)filp);
        spin_rel(&dump_lock_val);
        return;
    }
    while (done < len) {
        unsigned long chunk = len - done;
        unsigned long nc, w;
        if (chunk > DUMP_CHUNK) chunk = DUMP_CHUNK;
        memset(dump_buf, 0, chunk);
        


        nc = dk_copy_from_user(dump_buf, (const void *)(uaddr + done), chunk);
        if (nc == chunk && rl_ok)
            nc = chunk - rl_read_mem(tgid, uaddr + done, dump_buf, chunk);
        if (nc && !dump_partial_logged) {
            dump_partial_logged = 1;
            pr_info("AyuTrace|dump partial pages in 0x%lx+%lx (%lu bytes not read)\n",
                    uaddr, done, nc);
        }
        w = (unsigned long)dk_kernel_write(filp, dump_buf, chunk, &pos);
        if ((long)w < 0) {
            pr_err("AyuTrace|dump kernel_write err=%ld at off %lu\n", (long)w, done);
            break;
        }
        done += chunk;
    }
    dk_filp_close(filp, NULL);
    dump_register(uaddr, len);
    dump_session_cnt++;
    

    ring_flush();
    
    pr_info("AyuTrace|>>> DUMPED pid:%-6d tid:%-6d comm:%-16.16s addr:0x%lx len:%lu pc:0x%lx (%s, %lu/%lu bytes) -> %s\n",
            tgid, tid, tk_comm(), uaddr, len, pc, why, done, len, path);
    spin_rel(&dump_lock_val);
}
static void maybe_auto_dump(unsigned long addr, unsigned long len, int prot,
                            unsigned long pc) {
    if (!hooks_enabled || !dump_syms_ok) return;
    if (!(prot & 4)) return;   
    if (len < DUMP_MIN_LEN || len > DUMP_MAX_LEN) return;
    if (!sniff_pkg[0]) return;
    if (!is_in_target_list(tk_tgid())) return;
    dump_region(tk_tgid(), tk_pid(), addr, len, pc, "auto: mprotect -> exec");
}







static void dump_pend_add(int tid, unsigned long addr, unsigned long len,
                          unsigned long pc) {
    for (int i = 0; i < dump_pend_cnt; i++)
        if (dump_pend_tab[i].tid == tid && dump_pend_tab[i].addr == addr)
            return;
    if (dump_pend_cnt >= DUMP_PEND_MAX) {   
        for (int i = 1; i < DUMP_PEND_MAX; i++)
            dump_pend_tab[i - 1] = dump_pend_tab[i];
        dump_pend_cnt--;
    }
    dump_pend_tab[dump_pend_cnt].tid     = tid;
    dump_pend_tab[dump_pend_cnt].addr    = addr;
    dump_pend_tab[dump_pend_cnt].len     = len;
    dump_pend_tab[dump_pend_cnt].pc      = pc;
    dump_pend_tab[dump_pend_cnt].retries = 0;
    dump_pend_cnt++;
    
    ring_flush();
    pr_info("AyuTrace|>>> RWX WATCH pid:%d tid:%d addr:0x%lx len:%lu pc:0x%lx (dump when written)\n",
            tk_tgid(), tid, addr, len, pc);
}

static int dump_pend_ready(unsigned long addr) {
    char h[4];
    if (dk_copy_from_user(h, (const void *)addr, 4)) return 0;
    return h[0] || h[1] || h[2] || h[3];
}

static int dump_pend_try(int i) {
    struct dump_pend *p = &dump_pend_tab[i];
    int j;
    if (!dump_pend_ready(p->addr)) return 0;
    dump_region(tk_tgid(), p->tid, p->addr, p->len, p->pc, "auto: anon rwx");
    for (j = i + 1; j < dump_pend_cnt; j++)
        dump_pend_tab[j - 1] = dump_pend_tab[j];
    dump_pend_cnt--;
    return 1;
}
static void dump_pend_flush_tid(int tid) {
    int i;
    if (!hooks_enabled) return;   
    for (i = 0; i < dump_pend_cnt; ) {
        if (dump_pend_tab[i].tid == tid && dump_pend_try(i))
            continue;   
        i++;
    }
}
static void dump_pend_flush_grace(void) {
    int i;
    if (!hooks_enabled) return;
    for (i = 0; i < dump_pend_cnt; ) {
        if (dump_pend_try(i))
            continue;
        if (++dump_pend_tab[i].retries >= DUMP_PEND_RETRIES) {
            pr_info("AyuTrace|>>> RWX DROP tid:%d addr:0x%lx len:%lu (still zero after %d windows)\n",
                    dump_pend_tab[i].tid, dump_pend_tab[i].addr,
                    dump_pend_tab[i].len, DUMP_PEND_RETRIES);
            for (int j = i + 1; j < dump_pend_cnt; j++)
                dump_pend_tab[j - 1] = dump_pend_tab[j];
            dump_pend_cnt--;
            continue;
        }
        i++;
    }
}
static void maybe_pend_rwx(unsigned long addr, unsigned long len, int prot, int fd,
                           unsigned long pc) {
    if (!hooks_enabled || !dump_syms_ok) return;
    if (!(prot & 4) || fd >= 0) return;   
    if (len < DUMP_MIN_LEN || len > DUMP_MAX_LEN) return;
    if (!sniff_pkg[0]) return;
    if (!is_in_target_list(tk_tgid())) return;
    dump_pend_add(tk_pid(), addr, len, pc);
}


void trace_dump_manual(unsigned long addr, unsigned long len) {
    man_dump_addr = addr;
    man_dump_len  = len;
    man_dump_pending = 1;
    pr_info("AyuTrace|>>> DUMP REQ 0x%lx len 0x%lx queued (runs on target's next syscall)\n",
            addr, len);
}
void trace_exec_manual_dump(void) {
    unsigned long a = man_dump_addr;
    unsigned long l = man_dump_len;
    man_dump_pending = 0;
    if (!l || l > DUMP_MAX_LEN) return;
    if (!sniff_pkg[0]) {
        pr_err("AyuTrace|manual dump needs sniff mode (add <pkg>): file must go to app dir\n");
        return;
    }
    dump_region(tk_tgid(), tk_pid(), a, l, 0, "manual ctl");
}
void trace_dump_stat(char *out, int outlen) {
    int n, i;
    if (!out || outlen <= 0) return;
    n = xsnprintf(out, outlen, "files:%d/%d syms:%s remote-read:%s rwx-watch:%d manual:%s",
                  dump_session_cnt, DUMP_SESSION_MAX,
                  dump_syms_ok ? "ok" : "missing",
                  rl_ok ? "ok" : "off",
                  dump_pend_cnt,
                  man_dump_pending ? "yes" : "no");
    if (n < 0) return;
    for (i = 0; i < dumped_cnt && n < outlen - 2; i++) {
        int k = xsnprintf(out + n, outlen - n, " |0x%lx:%lx",
                          dumped_addr[i], dumped_len[i]);
        if (k <= 0) break;
        n += k;
    }
}
static inline int should_log(uint8_t *out_flags) {
    if (!hooks_enabled || !task_ext_valid(current_ext)) return 0;
    int tgid = tk_tgid();
    if (++flush_counter >= FLUSH_INTERVAL) {
        flush_counter = 0;
        ring_flush();
    }
    try_sniff_lock(tgid);
    if (is_in_target_list(tgid)) {
        *out_flags = LOG_FLAG_CONFIRMED;
        if (man_dump_pending)
            trace_exec_manual_dump();   
        if (dump_pend_cnt && ++dump_grace_ctr >= DUMP_PEND_GRACE) {
            dump_grace_ctr = 0;         
            dump_pend_flush_grace();
        }
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
    
    if (len <= 1 || (unsigned long)len >= sizeof(p)) return;
    try_sniff_path(tk_tgid(), p);
    TLOG("openat", "path:%.128s", p);
}
static void before_readlinkat(hook_fargs4_t *args, void *udata) {
    (void)udata; const char __user *src = (const char __user *)syscall_argn(args, 1);
    if (!src) return; char ps[PATH_BUF_SIZE];
    long ls = compat_strncpy_from_user(ps, src, sizeof(ps));
    if (ls <= 1 || (unsigned long)ls >= sizeof(ps)) return;
    TLOG("readlinkat", "path:%.128s", ps);
}
static void before_execve(hook_fargs3_t *args, void *udata) {
    (void)udata; const char __user *fn = (const char __user *)syscall_argn(args, 0);
    if (!fn) return; char p[PATH_BUF_SIZE];
    long len = compat_strncpy_from_user(p, fn, sizeof(p));
    if (len <= 1 || (unsigned long)len >= sizeof(p)) return;
    TLOG("execve", "path:%.128s", p);
}
#if TRACE_HIGH_FREQ






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
    
    dump_pend_flush_tid(tk_pid());
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




static const char *__attribute__((optimize("O0"))) ptrace_req_name(unsigned rq) {
    if (rq == 0)  return "TRACEME";
    if (rq == 1)  return "PEEKTEXT";
    if (rq == 2)  return "PEEKDATA";
    if (rq == 3)  return "PEEKUSR";
    if (rq == 4)  return "POKETEXT";
    if (rq == 5)  return "POKEDATA";
    if (rq == 6)  return "POKEUSR";
    if (rq == 7)  return "CONT";
    if (rq == 8)  return "KILL";
    if (rq == 9)  return "SINGLESTEP";
    if (rq == 16) return "ATTACH";
    if (rq == 17) return "DETACH";
    if (rq == 24) return "SYSCALL";
    return "?";
}
static void before_ptrace(hook_fargs4_t *args, void *udata) {
    (void)udata; unsigned rq = (unsigned)(unsigned long)syscall_argn(args,0);
    int tg = (int)(long)syscall_argn(args,1);
    unsigned long ad = (unsigned long)syscall_argn(args,2);
    unsigned long dt = (unsigned long)syscall_argn(args,3);
    TLOG("ptrace", "req:%s target:%d addr:0x%lx data:0x%lx",
         ptrace_req_name(rq), tg, ad, dt);
}






#define __NR_compat_exit              1
#define __NR_compat_execve           11
#define __NR_compat_ptrace           26
#define __NR_compat_kill             37
#define __NR_compat_clone           120
#define __NR_compat_mprotect        125
#define __NR_compat_mmap2           192
#define __NR_compat_tkill           238
#define __NR_compat_set_tid_address 256
#define __NR_compat_tgkill          268
#define __NR_compat_openat          322
#define __NR_compat_readlinkat      332
#define __NR_compat_unshare         337

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
    
    maybe_pend_rwx((unsigned long)ret, len, prot, fd, get_svc_pc(args));
}
static void before_mprotect(hook_fargs3_t *args, void *udata) {
    (void)udata;
    unsigned long addr  = syscall_argn(args, 0);
    unsigned long len   = syscall_argn(args, 1);
    int prot            = (int)syscall_argn(args, 2);
    unsigned long pc    = get_svc_pc(args);
    TLOG("mprotect", "addr:0x%lx len:%lu prot:%s pc:0x%lx", addr, len, prot_str(prot), pc);
    
    maybe_auto_dump(addr, len, prot, pc);
}

#if TRACE_COMPAT_HOOKS


static void after_mmap_c(hook_fargs5_t *args, void *udata) {
    (void)udata;
    unsigned long addr = syscall_argn(args, 0);
    unsigned long len  = syscall_argn(args, 1);
    int prot           = (int)syscall_argn(args, 2);
    int flags          = (int)syscall_argn(args, 3);
    int fd             = (int)syscall_argn(args, 4);
    long long ret      = (long long)args->ret;
    TLOG("mmap32", "addr:0x%lx len:%lu prot:%s flags:0x%x fd:%d ->0x%llx pc:0x%lx",
         addr, len, prot_str(prot), flags, fd, ret, get_svc_pc(args));
    
    maybe_pend_rwx((unsigned long)ret, len, prot, fd, get_svc_pc(args));
}
#endif
static int hk_openat, hk_readlinkat, hk_execve, hk_set_tid, hk_unshare, hk_ptrace;
static int hk_mmap, hk_mprotect;
#if TRACE_COMPAT_HOOKS
static int hk_openat_c, hk_readlinkat_c, hk_execve_c, hk_set_tid_c, hk_unshare_c, hk_ptrace_c;
static int hk_mmap_c, hk_mprotect_c;
#endif
#if TRACE_HIGH_FREQ
static int  hk_kill, hk_tkill, hk_tgkill, hk_exit, hk_clone;
#if TRACE_COMPAT_HOOKS
static int hk_kill_c, hk_tkill_c, hk_tgkill_c, hk_exit_c, hk_clone_c;
#endif
#endif
void trace_install(void) {
    hook_err_t e; int cnt = 0;
#define H(nr,n,b,a)   e=fp_hook_syscalln(nr,n,b,a,NULL); if(!e){cnt++;}else pr_err("AyuTrace: "#nr" fail %d\n",e)
#if TRACE_COMPAT_HOOKS
#define HC(nr,n,b,a)  e=fp_hook_compat_syscalln(nr,n,b,a,NULL); if(!e){cnt++;}else pr_err("AyuTrace: compat "#nr" fail %d\n",e)
#else
#define HC(nr,n,b,a)  do {} while (0)
#endif
    H (__NR_openat,4,before_openat,NULL);          if(!e) hk_openat    =1;
#if TRACE_COMPAT_HOOKS
    HC(__NR_compat_openat,4,before_openat,NULL);   if(!e) hk_openat_c  =1;
#endif
    H (__NR_readlinkat,4,before_readlinkat,NULL);  if(!e) hk_readlinkat   =1;
#if TRACE_COMPAT_HOOKS
    HC(__NR_compat_readlinkat,4,before_readlinkat,NULL); if(!e) hk_readlinkat_c =1;
#endif
    H (__NR_execve,3,before_execve,NULL);          if(!e) hk_execve    =1;
#if TRACE_COMPAT_HOOKS
    HC(__NR_compat_execve,3,before_execve,NULL);   if(!e) hk_execve_c  =1;
#endif
    H (__NR_set_tid_address,1,NULL,after_set_tid_address); if(!e) hk_set_tid    =1;
#if TRACE_COMPAT_HOOKS
    HC(__NR_compat_set_tid_address,1,NULL,after_set_tid_address); if(!e) hk_set_tid_c  =1;
#endif
    H (__NR_unshare,1,before_unshare,NULL);        if(!e) hk_unshare    =1;
#if TRACE_COMPAT_HOOKS
    HC(__NR_compat_unshare,1,before_unshare,NULL); if(!e) hk_unshare_c  =1;
#endif
    H (__NR_ptrace,4,before_ptrace,NULL);          if(!e) hk_ptrace     =1;
#if TRACE_COMPAT_HOOKS
    HC(__NR_compat_ptrace,4,before_ptrace,NULL);   if(!e) hk_ptrace_c   =1;
#endif
    H (222, 6,NULL,after_mmap);              if(!e) hk_mmap       =1;
#if TRACE_COMPAT_HOOKS
    HC(__NR_compat_mmap2, 5, NULL, after_mmap_c);  if(!e) hk_mmap_c     =1;
#endif
    H (__NR_mprotect,3,before_mprotect,NULL);      if(!e) hk_mprotect   =1;
#if TRACE_COMPAT_HOOKS
    HC(__NR_compat_mprotect, 3, before_mprotect, NULL); if(!e) hk_mprotect_c =1;
#endif
#if TRACE_HIGH_FREQ
    H (__NR_kill,   2, before_kill,   NULL);  if(!e) hk_kill     =1;
    H (__NR_tkill,  2, before_tkill,  NULL);  if(!e) hk_tkill    =1;
    H (__NR_tgkill, 3, before_tgkill, NULL);  if(!e) hk_tgkill   =1;
    H (__NR_exit,   1, before_exit,   NULL);  if(!e) hk_exit     =1;
    H (__NR_clone,  5, NULL, after_clone);    if(!e) hk_clone    =1;
#if TRACE_COMPAT_HOOKS
    HC(__NR_compat_kill,   2, before_kill,   NULL);  if(!e) hk_kill_c   =1;
    HC(__NR_compat_tkill,  2, before_tkill,  NULL);  if(!e) hk_tkill_c  =1;
    HC(__NR_compat_tgkill, 3, before_tgkill, NULL);  if(!e) hk_tgkill_c =1;
    HC(__NR_compat_exit,   1, before_exit,   NULL);  if(!e) hk_exit_c   =1;
    HC(__NR_compat_clone,  5, NULL, after_clone);    if(!e) hk_clone_c  =1;
#endif
#endif
#undef H
#undef HC
    dump_resolve_syms();
#if TRACE_COMPAT_HOOKS
    pr_info("AyuTrace installed %d hooks (ringbuf + sniff, compat on)\n", cnt);
#else
    pr_info("AyuTrace installed %d hooks (ringbuf + sniff)\n", cnt);
#endif
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
#if TRACE_COMPAT_HOOKS
#define UC(nr,b,a)  fp_unhook_compat_syscalln(nr,b,a)
#else
#define UC(nr,b,a)  do {} while (0)
#endif
    if(hk_openat)      U (__NR_openat,      before_openat,      NULL);
    if(hk_readlinkat)  U (__NR_readlinkat,  before_readlinkat,  NULL);
    if(hk_execve)      U (__NR_execve,      before_execve,      NULL);
    if(hk_set_tid)     U (__NR_set_tid_address, NULL, after_set_tid_address);
    if(hk_unshare)     U (__NR_unshare,     before_unshare,     NULL);
    if(hk_ptrace)      U (__NR_ptrace,      before_ptrace,      NULL);
    if(hk_mmap)        U (222,              NULL,               after_mmap);
    if(hk_mprotect)    U (__NR_mprotect,    before_mprotect,    NULL);
#if TRACE_COMPAT_HOOKS
    if(hk_openat_c)    UC(__NR_compat_openat,      before_openat,      NULL);
    if(hk_readlinkat_c)UC(__NR_compat_readlinkat,  before_readlinkat,  NULL);
    if(hk_execve_c)    UC(__NR_compat_execve,      before_execve,      NULL);
    if(hk_set_tid_c)   UC(__NR_compat_set_tid_address, NULL, after_set_tid_address);
    if(hk_unshare_c)   UC(__NR_compat_unshare,     before_unshare,     NULL);
    if(hk_ptrace_c)    UC(__NR_compat_ptrace,      before_ptrace,      NULL);
    if(hk_mmap_c)      UC(__NR_compat_mmap2,       NULL,               after_mmap_c);
    if(hk_mprotect_c)  UC(__NR_compat_mprotect,    before_mprotect,    NULL);
#endif
#if TRACE_HIGH_FREQ
    if(hk_kill)        U (__NR_kill,        before_kill,        NULL);
    if(hk_tkill)       U (__NR_tkill,       before_tkill,       NULL);
    if(hk_tgkill)      U (__NR_tgkill,      before_tgkill,      NULL);
    if(hk_exit)        U (__NR_exit,        before_exit,        NULL);
    if(hk_clone)       U (__NR_clone,       NULL,               after_clone);
#if TRACE_COMPAT_HOOKS
    if(hk_kill_c)      UC(__NR_compat_kill,   before_kill,   NULL);
    if(hk_tkill_c)     UC(__NR_compat_tkill,  before_tkill,  NULL);
    if(hk_tgkill_c)    UC(__NR_compat_tgkill, before_tgkill, NULL);
    if(hk_exit_c)      UC(__NR_compat_exit,   before_exit,   NULL);
    if(hk_clone_c)     UC(__NR_compat_clone,  NULL,          after_clone);
#endif
#endif
#undef U
#undef UC
    pr_info("AyuTrace uninstalled\n");
}
