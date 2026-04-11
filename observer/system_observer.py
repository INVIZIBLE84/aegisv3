# observer/system_observer.py
# BCC import handles both Ubuntu 20.04 (bcc) and 22.04 (bpfcc)
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

#define ARGSIZE 64

struct data_t {
    u32 pid;
    char comm[16];
    char arg0[ARGSIZE];
    char arg1[ARGSIZE];
    char arg2[ARGSIZE];
    char arg3[ARGSIZE];
    char arg4[ARGSIZE];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    const char **argv = (const char **)(args->argv);
    const char *argp = NULL;

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

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

print("[Observer] Compiling eBPF hooks...")

b = BPF(text=bpf_text)
event_buffer = []

def process_event(cpu, data, size):
    event = b["events"].event(data)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        base_cmd = event.comm.decode('utf-8', 'replace')
    except:
        base_cmd = "unknown"
    parts = []
    for arg_field in [event.arg0, event.arg1, event.arg2, event.arg3, event.arg4]:
        try:
            s = arg_field.decode('utf-8', 'replace').strip()
            if s:
                parts.append(s)
        except:
            continue
    full_cmd = " ".join(parts) or base_cmd
    event_buffer.append({
        "timestamp": timestamp,
        "pid": event.pid,
        "process_name": base_cmd,
        "full_cmd": full_cmd,
        "user": "root",
        "path": base_cmd,
        "kernel_thread": False
    })

b["events"].open_perf_buffer(process_event)

def listen_to_kernel():
    while True:
        try:
            b.perf_buffer_poll()
        except Exception:
            break

listener_thread = threading.Thread(target=listen_to_kernel, daemon=True)
listener_thread.start()

def collect_process_info():
    global event_buffer
    current = list(event_buffer)
    event_buffer.clear()
    return current
