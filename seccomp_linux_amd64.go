package main

import "golang.org/x/sys/unix"

const auditArch = unix.AUDIT_ARCH_X86_64

// deniedTable maps the names of seccomp/denied.txt to amd64's numbers.
var deniedTable = map[string]uint32{
	"ptrace": unix.SYS_PTRACE, "process_vm_readv": unix.SYS_PROCESS_VM_READV, "process_vm_writev": unix.SYS_PROCESS_VM_WRITEV,
	"kcmp": unix.SYS_KCMP, "init_module": unix.SYS_INIT_MODULE, "finit_module": unix.SYS_FINIT_MODULE,
	"delete_module": unix.SYS_DELETE_MODULE, "kexec_load": unix.SYS_KEXEC_LOAD, "kexec_file_load": unix.SYS_KEXEC_FILE_LOAD,
	"reboot": unix.SYS_REBOOT, "bpf": unix.SYS_BPF, "perf_event_open": unix.SYS_PERF_EVENT_OPEN,
	"userfaultfd": unix.SYS_USERFAULTFD, "keyctl": unix.SYS_KEYCTL, "add_key": unix.SYS_ADD_KEY,
	"request_key": unix.SYS_REQUEST_KEY, "mount": unix.SYS_MOUNT, "umount2": unix.SYS_UMOUNT2,
	"pivot_root": unix.SYS_PIVOT_ROOT, "fsopen": unix.SYS_FSOPEN, "fsconfig": unix.SYS_FSCONFIG,
	"fsmount": unix.SYS_FSMOUNT, "fspick": unix.SYS_FSPICK, "move_mount": unix.SYS_MOVE_MOUNT,
	"open_tree": unix.SYS_OPEN_TREE, "mount_setattr": unix.SYS_MOUNT_SETATTR, "unshare": unix.SYS_UNSHARE,
	"setns": unix.SYS_SETNS, "swapon": unix.SYS_SWAPON, "swapoff": unix.SYS_SWAPOFF, "acct": unix.SYS_ACCT,
	"quotactl": unix.SYS_QUOTACTL, "vhangup": unix.SYS_VHANGUP, "settimeofday": unix.SYS_SETTIMEOFDAY,
	"clock_settime": unix.SYS_CLOCK_SETTIME, "clock_adjtime": unix.SYS_CLOCK_ADJTIME, "adjtimex": unix.SYS_ADJTIMEX,
	"open_by_handle_at": unix.SYS_OPEN_BY_HANDLE_AT, "name_to_handle_at": unix.SYS_NAME_TO_HANDLE_AT,
	"lookup_dcookie": unix.SYS_LOOKUP_DCOOKIE,
}
