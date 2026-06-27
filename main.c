#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/printk.h>
#include <linux/string.h>
#include "trace.h"
KPM_NAME("kpm_trace_svc");
KPM_VERSION("1.2.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Ayu");
KPM_DESCRIPTION("SVC Call Hook — pid/pkg sniff + ring buffer");
static long trace_init(const char *args, const char *event,
                       void *__user reserved)
{
    (void)reserved;
    pr_info("AyuTrace init: event=%s\n", event ? event : "null");
    trace_install();
    return 0;
}
static long trace_exit(void *__user reserved)
{
    (void)reserved;
    trace_uninstall();
    return 0;
}
static int my_atoi(const char *s)
{
    int n = 0;
    while (*s >= '0' && *s <= '9') n = n * 10 + (*s++ - '0');
    return n;
}
static int is_all_digits(const char *s)
{
    if (!s || !*s) return 0;
    for (; *s; s++)
        if (*s < '0' || *s > '9') return 0;
    return 1;
}
static long trace_control0(const char *args, char *__user out_msg,
                           int outlen)
{
    char resp[256];
    int pid;
    if (!args || !args[0] || strcmp(args, "status") == 0) {
        const char *st = trace_status();
        int len = xsnprintf(resp, sizeof(resp),
            "status: %s | add <pid/pkg> del <pid> del-pkg clear\n", st);
        compat_copy_to_user(out_msg, resp, len + 1);
        return 0;
    }
    if (strcmp(args, "stop") == 0) {
        trace_stop();
        compat_copy_to_user(out_msg, "flushed + disabled + cleared\n", 29);
        return 0;
    }
    if (strcmp(args, "xiangcb") == 0 || strcmp(args, "disable") == 0) {
        trace_disable();
        compat_copy_to_user(out_msg, "all hooks disabled\n", 19);
        return 0;
    }
    if (strcmp(args, "enable") == 0) {
        trace_enable();
        compat_copy_to_user(out_msg, "hooks enabled\n", 14);
        return 0;
    }
    if (strncmp(args, "add ", 4) == 0) {
        const char *arg = args + 4;
        while (*arg == ' ') arg++;
        if (is_all_digits(arg)) {
            trace_enable();
            pid = my_atoi(arg);
            if (trace_add_pid(pid) == 0) {
                int len = xsnprintf(resp, sizeof(resp), "pid %d added\n", pid);
                compat_copy_to_user(out_msg, resp, len + 1);
            } else {
                compat_copy_to_user(out_msg, "pid list full (max 16)\n", 22);
            }
        } else {
            trace_enable();
            trace_add_pkg(arg);
            int len = xsnprintf(resp, sizeof(resp),
                "sniffing pkg: %s (waiting for app start)\n", arg);
            compat_copy_to_user(out_msg, resp, len + 1);
        }
        return 0;
    }
    if (strncmp(args, "del ", 4) == 0) {
        pid = my_atoi(args + 4);
        if (trace_del_pid(pid) == 0) {
            int len = xsnprintf(resp, sizeof(resp), "pid %d removed\n", pid);
            compat_copy_to_user(out_msg, resp, len + 1);
        } else {
            compat_copy_to_user(out_msg, "pid not found\n", 14);
        }
        return 0;
    }
    if (strcmp(args, "del-pkg") == 0) {
        trace_del_pkg();
        compat_copy_to_user(out_msg, "package sniffing cancelled\n", 27);
        return 0;
    }
    if (strcmp(args, "clear") == 0) {
        trace_enable();
        trace_clear_pid();
        compat_copy_to_user(out_msg, "cleared — tracing all user apps\n", 33);
        return 0;
    }
    compat_copy_to_user(out_msg, "unknown cmd: try add/del/clear/status\n", 40);
    return 0;
}
KPM_INIT(trace_init);
KPM_CTL0(trace_control0);
KPM_EXIT(trace_exit);
