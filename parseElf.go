package objx86elf

import (
	"debug/elf"
	"fmt"

	pstruct "github.com/pangine/pangineDSM-utils/program-struct"
)

// ParseObj use go built in container parser to parse an elf object
func (objectelf ObjectElf) ParseObj(file string) (bi pstruct.BinaryInfo) {
	b, err := elf.Open(file)
	if err != nil {
		panic("file open error")
	}
	defer b.Close()
	s := b.Sections
	nsct := len(s)
	if nsct == 0 {
		fmt.Printf("file %v is empty", file)
	} else {
		maxbyteslen := 0
		for _, is := range s {
			byteslen := int(is.Offset)
			b, err := is.Data()
			if err != nil {
				continue
			} else {
				byteslen += len(b)
			}
			if byteslen > maxbyteslen {
				maxbyteslen = byteslen
			}
		}
		bi.Sections.Data = make([]uint8, maxbyteslen)
		offset := 0
		maxReach := 0
		for i, is := range s {
			bi.Sections.Name = append(bi.Sections.Name, is.Name)
			bi.Sections.Offset = append(bi.Sections.Offset, int(is.Offset))
			if i > 0 {
				noffset := int(is.Offset)
				if maxReach > offset {
					offset = maxReach
				}
				for j := offset; j < noffset; j++ {
					// Fill differences with NOP (0x90)
					bi.Sections.Data[j] = 0x90
				}
				offset = noffset
			}
			var noffset int
			data, err := is.Data()
			if err != nil {
				noffset = offset
			} else {
				noffset = offset + len(data)
			}

			if noffset > maxReach {
				maxReach = noffset
			}
			for j := offset; j < noffset; j++ {
				bi.Sections.Data[j] = data[j-offset]
			}
			offset = noffset
		}
	}
	// Read the program headers for load
	for _, e := range b.Progs {
		if e.Type == 1 {
			bi.ProgramHeaders = append(
				bi.ProgramHeaders,
				pstruct.ProgramHeader{
					PAddr: int(e.Off),
					VAddr: int(e.Vaddr),
				},
			)
		}
	}
	return
}
