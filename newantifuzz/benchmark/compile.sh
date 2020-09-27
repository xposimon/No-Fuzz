funcnum=1000
taskname=strip
python3 /home/xposimon/Desktop/AFEliminator/newantifuzz/codeins.py /home/xposimon/Desktop/AFEliminator/newantifuzz/${taskname}.c $funcnum

#current-strip
mv ./output.c /home/xposimon/Desktop/binutils-2.34/binutils/output.c
cd /home/xposimon/Desktop/binutils-2.34/binutils

gcc -DHAVE_CONFIG_H -I.  -I. -I. -I../bfd -I./../bfd -I./../include -DLOCALEDIR="\"/usr/local/share/locale\"" -Dbin_dummy_emulation=bin_vanilla_emulation  -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wshadow -Wstack-usage=262144 -I./../zlib -g -O2 -MT objcopy.o -MD -MP -MF $depbase.Tpo -c -o objcopy.o output.c &&\
/bin/bash ./libtool  --tag=CC   --mode=link gcc -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wshadow -Wstack-usage=262144 -I./../zlib -g -O2   -o strip_myat objcopy.o is-strip.o rename.o rddbg.o debug.o stabs.o rdcoff.o wrstabs.o bucomm.o version.o filemode.o ../bfd/libbfd.la ../libiberty/libiberty.a  -ldl

mv /home/xposimon/Desktop/binutils-2.34/binutils/${taskname}_myat /home/xposimon/Desktop/AFEliminator/newantifuzz/benchmark/${taskname}/${taskname}_${funcnum}_funcchain

exit 

#size
gcc -DHAVE_CONFIG_H -I.  -I. -I. -I../bfd -I./../bfd -I./../include -DLOCALEDIR="\"/usr/local/share/locale\"" -Dbin_dummy_emulation=bin_vanilla_emulation  -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wshadow -Wstack-usage=262144 -I./../zlib -g -O2 -MT size.o -MD -MP -MF $depbase.Tpo -c -o size.o output.c &&\
/bin/bash ./libtool  --tag=CC   --mode=link gcc -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wshadow -Wstack-usage=262144 -I./../zlib -g -O2   -o size_myat size.o bucomm.o version.o filemode.o ../bfd/libbfd.la ../libiberty/libiberty.a  -ldl

#addr2line
gcc -DHAVE_CONFIG_H -I.  -I. -I. -I../bfd -I./../bfd -I./../include -DLOCALEDIR="\"/usr/local/share/locale\"" -Dbin_dummy_emulation=bin_vanilla_emulation  -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wshadow -Wstack-usage=262144 -I./../zlib -g -O2 -MT addr2line.o -MD -MP -MF $depbase.Tpo -c -o addr2line.o output.c &&\
/bin/bash ./libtool  --tag=CC   --mode=link gcc -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wshadow -Wstack-usage=262144 -I./../zlib -g -O2   -o addr2line_myat addr2line.o bucomm.o version.o filemode.o ../bfd/libbfd.la ../libiberty/libiberty.a  -ldl 

#ar
gcc -DHAVE_CONFIG_H -I.  -I. -I. -I../bfd -I./../bfd -I./../include -DLOCALEDIR="\"/usr/local/share/locale\"" -Dbin_dummy_emulation=bin_vanilla_emulation  -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wshadow -Wstack-usage=262144 -I./../zlib -g -O2 -MT ar.o -MD -MP -MF $depbase.Tpo -c -o ar.o output.c &&\
/bin/bash ./libtool  --tag=CC   --mode=link gcc -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wshadow -Wstack-usage=262144 -I./../zlib -g -O2   -o ar_myat arparse.o arlex.o ar.o not-ranlib.o arsup.o rename.o binemul.o emul_vanilla.o bucomm.o version.o filemode.o ../bfd/libbfd.la ../libiberty/libiberty.a -lfl  -ldl


# strings
gcc -DHAVE_CONFIG_H -I.  -I. -I. -I../bfd -I./../bfd -I./../include -DLOCALEDIR="\"/usr/local/share/locale\"" -Dbin_dummy_emulation=bin_vanilla_emulation  -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wshadow -Wstack-usage=262144 -I./../zlib -g -O2 -MT strings.o -MD -MP -MF $depbase.Tpo -c -o strings.o output.c &&\
/bin/bash ./libtool  --tag=CC   --mode=link gcc -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wshadow -Wstack-usage=262144 -I./../zlib -g -O2   -o strings_myat strings.o bucomm.o version.o filemode.o ../bfd/libbfd.la ../libiberty/libiberty.a  -ldl

#nm
gcc -DHAVE_CONFIG_H -I.  -I. -I. -I../bfd -I./../bfd -I./../include -DLOCALEDIR="\"/usr/local/share/locale\"" -Dbin_dummy_emulation=bin_vanilla_emulation  -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wshadow -Wstack-usage=262144 -I./../zlib -g -O2 -MT nm.o -MD -MP -MF $depbase.Tpo -c -o nm.o output.c &&\
/bin/bash ./libtool  --tag=CC   --mode=link gcc -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wshadow -Wstack-usage=262144 -I./../zlib -g -O2   -o nm-new_myat nm.o bucomm.o version.o filemode.o ../bfd/libbfd.la ../libiberty/libiberty.a  -ldl

# objcopy
gcc -DHAVE_CONFIG_H -I.  -I. -I. -I../bfd -I./../bfd -I./../include -DLOCALEDIR="\"/usr/local/share/locale\"" -Dbin_dummy_emulation=bin_vanilla_emulation  -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wshadow -Wstack-usage=262144 -I./../zlib -g -O2 -MT objcopy.o -MD -MP -MF $depbase.Tpo -c -o objcopy.o output.c &&\
/bin/bash ./libtool  --tag=CC   --mode=link gcc -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wshadow -Wstack-usage=262144 -I./../zlib -g -O2   -o objcopy_myat objcopy.o not-strip.o rename.o rddbg.o debug.o stabs.o rdcoff.o wrstabs.o bucomm.o version.o filemode.o ../bfd/libbfd.la ../libiberty/libiberty.a  -ldl

