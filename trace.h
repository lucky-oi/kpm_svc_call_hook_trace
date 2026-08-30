#ifndef __TRACE_H__
#define __TRACE_H__
#include <ktypes.h>
extern int kfunc_def(snprintf)(char *buf, size_t size, const char *fmt, ...);
#define xsnprintf kfunc(snprintf)
#define TRACE_UID_THRESHOLD   10000u
#define PATH_BUF_SIZE         128
#define PTRACE_ANTI_DEBUG     0
#define TRACE_HIGH_FREQ       1
#define TARGET_PID_MAX        16
#define PENDING_MAX           16
#define RING_ENTRIES          1024
#define LOG_ENTRY_SIZE        768













#define DUMP_MIN_LEN          (64 * 1024)      
#define DUMP_MAX_LEN          (8 * 1024 * 1024) 
#define DUMP_CHUNK            (64 * 1024)      
#define DUMP_REGION_MAX       16               
#define DUMP_SESSION_MAX      16               
#define DUMP_PEND_MAX         8                
#define DUMP_PEND_GRACE       64
#define DUMP_PEND_RETRIES     8
#define TRACE_BT_MAX          6








#ifndef TRACE_COMPAT_HOOKS
#define TRACE_COMPAT_HOOKS 1
#endif
#define LOG_FLAG_EMPTY     0
#define LOG_FLAG_PENDING   1   
#define LOG_FLAG_CONFIRMED 2   
struct log_entry {
    uint8_t  flags;
    int32_t  tgid;
    uint16_t len;               
    char     data[LOG_ENTRY_SIZE - 8];
};
void trace_install(void);
void trace_uninstall(void);
int  trace_add_pid(int pid);
int  trace_add_pkg(const char *pkg);
int  trace_del_pid(int pid);
int  trace_del_pkg(void);
void trace_clear_pid(void);
void trace_stop(void);   
void trace_disable(void);
void trace_enable(void);
int  trace_is_enabled(void);
const char *trace_status(void);
void trace_dump_manual(unsigned long addr, unsigned long len);
void trace_dump_stat(char *out, int outlen);
#endif
