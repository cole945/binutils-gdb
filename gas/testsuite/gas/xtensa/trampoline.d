#as:
#objdump: -d
#name: trampolines relaxation

.*: +file format .*xtensa.*
#...
.*0:.*j.0x1194c
.*3:.*j.0x1194f
.*6:.*j.0x11952
.*9:.*j.0x1d4e4
#...
.*11949:.*j.0x11955
.*1194c:.*j.0x24a0e
.*1194f:.*j.0x24a0e
.*11952:.*j.0x24a11
#...
.*1d4e1:.*j.0x1d4e7
.*1d4e4:.*j.0x33462
#...
.*24a0e:.*j.0x24a0e
.*24a11:.*j.0x24a11
#...
.*3345f:.*ret
.*33462:.*j.0x49407
#...
.*49407:.*j.0x49407