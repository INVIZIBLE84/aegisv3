# observer/system_observer.py
# Two eBPF hooks:
#   1. sys_enter_execve  - catches every process execution (existing)
#   2. sys_enter_openat  - catches every file open (new - kills LOLBin problem)

try:
    from bcc import BPF
except ImportError:
    from bpfcc import BPF

import threading
import datetime

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE  64
#define PATHSIZE 128

struct exec_data_t {
    u32  pid;
    char comm[16];
    char arg0[ARGSIZE];
    char arg1[ARGSIZE];
    char arg2[ARGSIZE];
    char arg3[ARGSIZE];
    char arg4[ARGSIZE];
};

struct open_data_t {
    u32  pid;
    char comm[16];
    char filename[PATHSIZE];
};

BPF_PERF_OUTPUT(exec_events);
BPF_PERF_OUTPUT(open_events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct exec_data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    const char **argv = (const char **)(args->argv);
    const char *argp  = NULL;

    bpf_probe_read(&argp, sizeof(argp), (void *)&argv[0]);
    if (argp) bpf_probe_read_str(&data.arg0, ARGSIZE, (void *)argp);
    bpf_probe_read(&argp, sizeof(argp), (void *)&argv[1]);
    if (argp) bpf_probe_read_str(&data.arg1, ARGSIZE, (void *)argp);
    bpf_probe_read(&argp, sizeof(argp), (void *)&argv[2]);
    if (argp) bpf_probe_read_str(&data.arg2, ARGSIZE, (void *)argp);
    bpf_probe_read(&argp, sizeof(argp), (void *)&argv[3]);
    if (argp) bpf_probe_read_str(&data.arg3, ARGSIZE, (void *)argp);
    bpf_probe_read(&argp, sizeof(argp), (void *)&argv[4]);
    if (argp) bpf_probe_read_str(&data.arg4, ARGSIZE, (void *)argp);

    exec_events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct open_data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, PATHSIZE, (void *)args->filename);
    open_events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

print("[Observer] Compiling eBPF hooks (execve + openat)...")

b = BPF(text=bpf_text)

exec_buffer = []
open_buffer = []

def on_exec_event(cpu, data, size):
    event = b["exec_events"].event(data)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        base_cmd = event.comm.decode("utf-8", "replace").strip()
    except Exception:
        base_cmd = "unknown"
    parts = []
    for field in [event.arg0, event.arg1, event.arg2, event.arg3, event.arg4]:
        try:
            s = field.decode("utf-8", "replace").strip()
            if s:
                parts.append(s)
        except Exception:
            continue
    full_cmd = " ".join(parts) or base_cmd
    exec_buffer.append({
        "timestamp":     timestamp,
        "pid":           event.pid,
        "process_name":  base_cmd,
        "full_cmd":      full_cmd,
        "user":          "root",
        "path":          base_cmd,
        "kernel_thread": False,
        "event_type":    "EXEC",
    })

def on_open_event(cpu, data, size):
    event = b["open_events"].event(data)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        proc = event.comm.decode("utf-8", "replace").strip()
    except Exception:
        proc = "unknown"
    try:
        filename = event.filename.decode("utf-8", "replace").strip()
    except Exception:
        filename = "unknown"

    if not filename:
        return
    if filename.startswith("/proc/"):
        return
    if filename.startswith("/sys/"):
        return
    if filename.startswith("/dev/"):
        return

    open_buffer.append({
        "timestamp":    timestamp,
        "pid":          event.pid,
        "process_name": proc,
        "filename":     filename,
        "event_type":   "OPEN",
    })

b["exec_events"].open_perf_buffer(on_exec_event)
b["open_events"].open_perf_buffer(on_open_event)

def _poll_loop():
    while True:
        try:
            b.perf_buffer_poll()
        except Exception:
            break

_thread = threading.Thread(target=_poll_loop, daemon=True)
_thread.start()

def collect_process_info():
    global exec_buffer
    batch = list(exec_buffer)
    exec_buffer.clear()
    return batch

def collect_file_events():
    global open_buffer
    batch = list(open_buffer)
    open_buffer.clear()
    return batch
