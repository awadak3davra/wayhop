//go:build linux

package ramdir

import "syscall"

const (
	tmpfsMagic = 0x01021994
	ramfsMagic = 0x858458f6
)

func isRAMFSImpl(dir string) (bool, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return false, err
	}
	// Type is int32 on 32-bit MIPS/ARM and int64 elsewhere; compare as uint32 (the magic fits).
	t := uint32(st.Type)
	return t == tmpfsMagic || t == ramfsMagic, nil
}
