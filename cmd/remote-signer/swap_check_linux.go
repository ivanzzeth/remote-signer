//go:build linux

package main

import (
	"log/slog"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// checkSwapEnabled warns if the process can use swap.
//
// Why this matters:
//
//	Private keys (ECDSA, Ed25519) are held in process memory at runtime.
//	If the OS swaps these memory pages to disk, the key material is written
//	to persistent storage in plaintext. An attacker with disk access (stolen
//	server, cloud snapshot, forensic image) can recover the keys even after
//	the process exits. Disabling swap ensures keys never leave RAM.
//
// Bare-metal / VM:
//
//	Run `swapoff -a` or use encrypted swap (dm-crypt).
//
// Docker:
//
//	Set --memory-swap equal to --memory so the container gets zero swap quota,
//	even if the host has swap enabled:
//	  docker run --memory=512m --memory-swap=512m --memory-swappiness=0 ...
//	Or in docker-compose:
//	  mem_swappiness: 0
//	  memswap_limit: 512m   # must equal memory limit
func checkSwapEnabled(log *slog.Logger) {
	// 1. Container check: cgroup v2 memory.swap.max (preferred)
	//    "0" means no swap allowed; "max" means unlimited.
	if data, err := os.ReadFile("/sys/fs/cgroup/memory.swap.max"); err == nil {
		val := strings.TrimSpace(string(data))
		if val != "0" {
			if val == "max" {
				log.Warn("SECURITY: container has unlimited swap — private keys may be swapped to disk. "+
					"Set --memory-swap equal to --memory (e.g. --memory=512m --memory-swap=512m) to disable swap.",
					"memory.swap.max", val,
				)
			} else if n, err := strconv.ParseInt(val, 10, 64); err == nil && n > 0 {
				log.Warn("SECURITY: container has swap quota — private keys may be swapped to disk. "+
					"Set --memory-swap equal to --memory (e.g. --memory=512m --memory-swap=512m) to disable swap.",
					"memory.swap.max_bytes", n,
				)
			}
		}
		return // cgroup check is authoritative, skip host /proc/swaps
	}

	// 2. Container check: cgroup v1 memory.memsw.limit_in_bytes vs memory.limit_in_bytes
	if memswData, err := os.ReadFile("/sys/fs/cgroup/memory/memory.memsw.limit_in_bytes"); err == nil {
		if memData, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
			memsw := strings.TrimSpace(string(memswData))
			mem := strings.TrimSpace(string(memData))
			memswVal, err1 := strconv.ParseInt(memsw, 10, 64)
			memVal, err2 := strconv.ParseInt(mem, 10, 64)
			if err1 == nil && err2 == nil && memswVal > memVal {
				log.Warn("SECURITY: container has swap quota — private keys may be swapped to disk. "+
					"Set --memory-swap equal to --memory (e.g. --memory=512m --memory-swap=512m) to disable swap.",
					"swap_bytes", memswVal-memVal,
				)
			}
			return
		}
	}

	// 3. Host-level check: /proc/swaps
	data, err := os.ReadFile("/proc/swaps")
	if err != nil {
		return // cannot read (e.g. restricted /proc), skip silently
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	// First line is the header; any additional lines indicate active swap devices
	if len(lines) > 1 {
		log.Warn("SECURITY: swap is enabled — private keys in memory may be swapped to disk. "+
			"Run 'swapoff -a' or use encrypted swap (dm-crypt).",
			"swap_devices", len(lines)-1,
		)
	}
}

// hardenProcessMemory applies OS-level protections to keep private keys safe in memory.
//
// 1. PR_SET_DUMPABLE=0:
//   - Disables core dumps — if the process crashes, private keys are NOT written
//     to a core dump file on disk.
//   - Blocks /proc/<pid>/mem access from non-root processes — prevents other
//     processes (even with the same UID) from reading this process's memory.
//   - This is the single most effective in-process defense against memory scraping.
//
// 2. mlockall(MCL_CURRENT|MCL_FUTURE):
//   - Locks all current and future memory pages into RAM, preventing the kernel
//     from ever paging them out — even if swap is somehow enabled.
//   - Acts as defense-in-depth on top of swap disabling (cgroup/swapoff).
//   - Requires CAP_IPC_LOCK capability. In Docker:
//       cap_add:
//         - IPC_LOCK
func hardenProcessMemory(log *slog.Logger) {
	// 1. Disable core dumps and /proc/<pid>/mem access
	//    prctl(PR_SET_DUMPABLE, 0)
	const prSetDumpable = 4
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0); errno != 0 {
		log.Warn("SECURITY: failed to set PR_SET_DUMPABLE=0 — core dumps may expose private keys",
			"error", errno.Error(),
		)
	} else {
		log.Info("Memory protection: core dumps disabled (PR_SET_DUMPABLE=0)")
	}

	// 2. Lock all memory pages (current + future) to prevent any paging to disk
	//    mlockall(MCL_CURRENT|MCL_FUTURE)
	//    Requires CAP_IPC_LOCK; add to docker-compose.yml:
	//      cap_add:
	//        - IPC_LOCK
	const (
		mclCurrent = 1
		mclFuture  = 2
	)
	if _, _, errno := syscall.RawSyscall(syscall.SYS_MLOCKALL, uintptr(mclCurrent|mclFuture), 0, 0); errno != 0 {
		log.Warn("SECURITY: mlockall() failed — memory pages may be swapped to disk. "+
			"Grant CAP_IPC_LOCK to the container (cap_add: [IPC_LOCK] in docker-compose.yml).",
			"error", errno.Error(),
		)
	} else {
		log.Info("Memory protection: all pages locked in RAM (mlockall)")
	}

}
