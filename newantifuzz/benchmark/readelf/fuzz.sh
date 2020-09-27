nohup afl-fuzz -Q -i ./input -o ./ori_output2 -M readelf_fuzz0 -- ./readelf -a @@ >/dev/null 2>&1 &
nohup afl-fuzz -Q -i ./input -o ./ori_output2 -S readelf_fuzz1 -- ./readelf -a @@ >/dev/null 2>&1 &
nohup afl-fuzz -Q -i ./input -o ./ori_output2 -S readelf_fuzz2 -- ./readelf -a @@ >/dev/null 2>&1 &
nohup afl-fuzz -Q -i ./input -o ./ori_output2 -S readelf_fuzz3 -- ./readelf -a @@ >/dev/null 2>&1 &
nohup afl-fuzz -Q -i ./input -o ./ori_output2 -S readelf_fuzz4 -- ./readelf -a @@ >/dev/null 2>&1 &
nohup afl-fuzz -Q -i ./input -o ./ori_output2 -S readelf_fuzz5 -- ./readelf -a @@ >/dev/null 2>&1 &
nohup afl-fuzz -Q -i ./input -o ./ori_output2 -S readelf_fuzz6 -- ./readelf -a @@ >/dev/null 2>&1 &

# 100 funchains
nohup afl-fuzz -Q -i ./input -o ./func_output2 -M readelf_funchain_fuzz8 -- ./readelf_100_funchain -a @@ >/dev/null 2>&1 &
nohup afl-fuzz -Q -i ./input -o ./func_output2 -S readelf_funchain_fuzz9 -- ./readelf_100_funchain -a @@ >/dev/null 2>&1 &
nohup afl-fuzz -Q -i ./input -o ./func_output2 -S readelf_funchain_fuzz10 -- ./readelf_100_funchain -a @@ >/dev/null 2>&1 &
nohup afl-fuzz -Q -i ./input -o ./func_output2 -S readelf_funchain_fuzz11 -- ./readelf_100_funchain -a @@ >/dev/null 2>&1 &
nohup afl-fuzz -Q -i ./input -o ./func_output2 -S readelf_funchain_fuzz12 -- ./readelf_100_funchain -a @@ >/dev/null 2>&1 &
nohup afl-fuzz -Q -i ./input -o ./func_output2 -S readelf_funchain_fuzz13 -- ./readelf_100_funchain -a @@ >/dev/null 2>&1 &
nohup afl-fuzz -Q -i ./input -o ./func_output2 -S readelf_funchain_fuzz14 -- ./readelf_100_funchain -a @@ >/dev/null 2>&1 &


# 500 funchains
nohup afl-fuzz -Q -i ./input -o ./func_output2 -t 5000 -M readelf_funchain_fuzz8 -- ./readelf_500_funchain -a @@ >/dev/null 2>&1 &
nohup afl-fuzz -Q -i ./input -o ./func_output2 -t 5000 -S readelf_funchain_fuzz9 -- ./readelf_500_funchain -a @@ >/dev/null 2>&1 &
nohup afl-fuzz -Q -i ./input -o ./func_output2 -t 5000 -S readelf_funchain_fuzz10 -- ./readelf_500_funchain -a @@ >/dev/null 2>&1 &
nohup afl-fuzz -Q -i ./input -o ./func_output2 -t 5000 -S readelf_funchain_fuzz11 -- ./readelf_500_funchain -a @@ >/dev/null 2>&1 &
nohup afl-fuzz -Q -i ./input -o ./func_output2 -t 5000 -S readelf_funchain_fuzz12 -- ./readelf_500_funchain -a @@ >/dev/null 2>&1 &
nohup afl-fuzz -Q -i ./input -o ./func_output2 -t 5000 -S readelf_funchain_fuzz13 -- ./readelf_500_funchain -a @@ >/dev/null 2>&1 &
nohup afl-fuzz -Q -i ./input -o ./func_output2 -t 5000 -S readelf_funchain_fuzz14 -- ./readelf_500_funchain -a @@ >/dev/null 2>&1 &
