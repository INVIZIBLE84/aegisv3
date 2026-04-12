# observer/system_observer.py
# Three eBPF hooks:
#   1. sys_enter_execve  - every process execution
#   2. sys_enter_openat  - every file open (FIM)
#   3. sched_process_fork - every fork/clone (parent-child lineage)

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

/* ── exec event: process execution ── */
struct exec_data_t {
    u32  pid;
    u32  ppid;
    char comm[16];
    char arg0[ARGSIZE];
    char arg1[ARGSIZE];
    char arg2[ARGSIZE];
    char arg3[ARGSIZE];
    char arg4[ARGSIZE];
};

/* ── open event: file access ── */
struct open_data_t {
    u32  pid;
    char comm[16];
    char filename[PATHSIZE];
};

/* ── fork event: parent-child relationship ── */
struct fork_data_t {
    u32  parent_pid;
    u32  child_pid;
    char parent_comm[16];
};

BPF_PERF_OUTPUT(exec_events);
BPF_PERF_OUTPUT(open_events);
BPF_PERF_OUTPUT(fork_events);

/* ── Hook 1: execve ── */
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct exec_data_t data = {};

    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid  = pid_tgid >> 32;

    /* Get parent PID from the task struct */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;

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

/* ── Hook 2: openat ── */
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct open_data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, PATHSIZE, (void *)args->filename);
    open_events.perf_submit(args, &data, sizeof(data));
    return 0;
}

/* ── Hook 3: fork/clone — capture parent-child relationship ── */
TRACEPOINT_PROBE(sched, sched_process_fork) {
    struct fork_data_t data = {};
    data.parent_pid = args->parent_pid;
    data.child_pid  = args->child_pid;
    /* Read parent comm from current task — child not yet named at fork time */
    bpf_get_current_comm(&data.parent_comm, sizeof(data.parent_comm));
    fork_events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

print("[Observer] Compiling eBPF hooks (execve + openat + fork)...")

b = BPF(text=bpf_text)

exec_buffer = []
open_buffer = []
fork_buffer = []

# ── execve handler ────────────────────────────────────────────────────────────
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
        "ppid":          event.ppid,
        "process_name":  base_cmd,
        "full_cmd":      full_cmd,
        "user":          "root",
        "path":          base_cmd,
        "kernel_thread": False,
        "event_type":    "EXEC",
    })

# ── openat handler ────────────────────────────────────────────────────────────
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
    if filename.startswith("/proc/") or filename.startswith("/sys/") or filename.startswith("/dev/"):
        return
    open_buffer.append({
        "timestamp":    timestamp,
        "pid":          event.pid,
        "process_name": proc,
        "filename":     filename,
        "event_type":   "OPEN",
    })

# ── fork handler ──────────────────────────────────────────────────────────────
def on_fork_event(cpu, data, size):
    event = b["fork_events"].event(data)
    try:
        parent_comm = event.parent_comm.decode("utf-8", "replace").strip()
    except Exception:
        return
    fork_buffer.append({
        "parent_pid":  event.parent_pid,
        "parent_comm": parent_comm,
        "child_pid":   event.child_pid,
        "child_comm":  "",   # filled in later via exec event ppid lookup
        "event_type":  "FORK",
    })

b["exec_events"].open_perf_buffer(on_exec_event)
b["open_events"].open_perf_buffer(on_open_event)
b["fork_events"].open_perf_buffer(on_fork_event)

def _poll_loop():
    while True:
        try:
            b.perf_buffer_poll()
        except Exception:
            break

_thread = threading.Thread(target=_poll_loop, daemon=True)
_thread.start()

# ── Public API ────────────────────────────────────────────────────────────────

def collect_process_info():
    """Execution events — for signal_translator pipeline."""
    global exec_buffer
    batch = list(exec_buffer)
    exec_buffer.clear()
    return batch

def collect_file_events():
    """File open events — for fim_engine pipeline."""
    global open_buffer
    batch = list(open_buffer)
    open_buffer.clear()
    return batch

def collect_fork_events():
    """Fork/spawn events — for lineage_engine pipeline."""
    global fork_buffer
    batch = list(fork_buffer)
    fork_buffer.clear()
    return batch
