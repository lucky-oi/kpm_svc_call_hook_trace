#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/printk.h>
#include <linux/string.h>
#include "trace.h"
KPM_NAME("kpm_trace_svc");
KPM_VERSION("1.5.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Ayu");
KPM_DESCRIPTION("SVC Call Hook — pid/pkg sniff + ring buffer + shell-decrypt auto dump");
static long trace_init(const char *args, const char *event,
                       void *__user reserved)
{
    (void)reserved;
    pr_info("AyuTrace init: event=%s\n", event ? event : "null");
    trace_install();
    
    pr_info("AyuTrace: tracing DISABLED by default - use 'add <pid|pkg>' or 'enable'\n");
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

static unsigned long hex_to_ul(const char *s)
{
    unsigned long v = 0;
    if (!s) return 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    for (; *s; s++) {
        int c = *s;
        if (c >= '0' && c <= '9')      v = v * 16 + (c - '0');
        else if (c >= 'a' && c <= 'f') v = v * 16 + (c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v = v * 16 + (c - 'A' + 10);
        else break;
    }
    return v;
}



static void ctl_reply(char *__user out_msg, int outlen, const char *msg)
{
    char buf[96];
    int n;
    if (!out_msg || !msg) return;
    n = xsnprintf(buf, sizeof(buf), "%s", msg);
    if (n < 0) return;
    if (n > outlen - 1) n = outlen - 1;
    if (n < 0) return;
    compat_copy_to_user(out_msg, buf, n + 1);
}
static long trace_control0(const char *args, char *__user out_msg,
                           int outlen)
{
    char resp[256];
    int pid;
    if (!args || !args[0] || strcmp(args, "status") == 0) {
        const char *st = trace_status();
        int len = xsnprintf(resp, sizeof(resp),
            "status: %s | add <pid/pkg> del <pid> del-pkg clear dump <addr> <len> dumpstat\n", st);
        compat_copy_to_user(out_msg, resp, len + 1);
        return 0;
    }
    if (strcmp(args, "stop") == 0) {
        trace_stop();
        ctl_reply(out_msg, outlen, "flushed + disabled + cleared\n");
        return 0;
    }
    if (strcmp(args, "xiangcb") == 0 || strcmp(args, "disable") == 0) {
        trace_disable();
        ctl_reply(out_msg, outlen, "all hooks disabled\n");
        return 0;
    }
    if (strcmp(args, "enable") == 0) {
        trace_enable();
        ctl_reply(out_msg, outlen, "hooks enabled\n");
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
                ctl_reply(out_msg, outlen, "pid list full (max 16)\n");
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
            ctl_reply(out_msg, outlen, "pid not found\n");
        }
        return 0;
    }
    if (strcmp(args, "del-pkg") == 0) {
        trace_del_pkg();
        ctl_reply(out_msg, outlen, "package sniffing cancelled\n");
        return 0;
    }
    if (strcmp(args, "clear") == 0) {
        trace_enable();
        trace_clear_pid();
        ctl_reply(out_msg, outlen, "cleared — tracing all user apps\n");
        return 0;
    }
    if (strncmp(args, "dump ", 5) == 0) {
        const char *p = args + 5;
        unsigned long da, dl;
        while (*p == ' ') p++;
        da = hex_to_ul(p);
        while (*p && *p != ' ') p++;
        while (*p == ' ') p++;
        dl = hex_to_ul(p);
        if (!da || !dl || dl > DUMP_MAX_LEN) {
            ctl_reply(out_msg, outlen,
                "usage: dump <hex addr> <hex len> (len <= 0x800000)\n");
            return 0;
        }
        trace_dump_manual(da, dl);
        ctl_reply(out_msg, outlen, "dump queued — file appears in app dir\n");
        return 0;
    }
    if (strcmp(args, "dumpstat") == 0) {
        char r[256];
        trace_dump_stat(r, sizeof(r));
        ctl_reply(out_msg, outlen, r);
        return 0;
    }
    ctl_reply(out_msg, outlen,
        "unknown cmd: try add/del/clear/dump <addr> <len>/dumpstat\n");
    return 0;
}
KPM_INIT(trace_init);
KPM_CTL0(trace_control0);
KPM_EXIT(trace_exit);
