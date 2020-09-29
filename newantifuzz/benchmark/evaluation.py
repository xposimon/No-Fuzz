import time, os, subprocess

last_time = 12 * 3600 #seconds
parallel_num = 2
execute_one_round = 7

bin_format = '{binname}_{num}_{attype}'
cmd_format = 'nohup afl-fuzz -Q -i ./{bin_name}/input -o ./{bin_name}/{outputdir} {delay} -%s {taskname}_fuzz%d -- ./{bin_name}/{taskname} {run_cmd} >/dev/null 2>&1 &'

run_cmds = {'readelf':' -a @@', 'objdump':' -d @@', 'nm':' @@', 'objcopy':' -S @@'}
tasks = {'readelf':[('0','ori', '')] + [(str(i*100), 'funcchain', '') if i < 2 else (str(i*100), 'funcchain', '-t 5000') for i in range(1, 6)] + [('10000', 'atbr', '-t 5000'), ("1000", "2funcchain", '-t 5000'), ("1000", "funcchain", "-t 5000")], 
'objdump':[('0', 'ori', ''), ('100', '0funcchain', ''), ('500', '0funcchain', ' -t 5000'), ('1000', '2funcchain', ' -t 5000')],
'nm':[('0', 'ori', ''), ('100', 'funcchain', ''), ('500', 'funcchain', ' -t 5000'), ('1000', 'funcchain', ' -t 5000')],
'objcopy':[('0', 'ori', ''), ('100', 'funcchain', ''), ('500', 'funcchain', ' -t 5000'), ('1000', 'funcchain', ' -t 5000')]
}

commands = []
parallel_commands = []

for binname in tasks.keys():
    commands = [cmd_format.format(bin_name=binname, outputdir = bin_format.format(binname=binname, num=funcnum, attype=aptype)+'_output', taskname = bin_format.format(binname=binname,num=funcnum, attype=aptype), delay=t, run_cmd=run_cmds[binname]) for funcnum, aptype, t in tasks[binname]]

    # AFL parallel
    for i in range(len(commands)):
        parallel_commands += [commands[i]%(host_type, id) for host_type, id in [('M',0)] + [('S', j) for j in range(1, parallel_num)] ]

cnt = 0
while cnt*parallel_num*execute_one_round < len(parallel_commands):
    cmd = parallel_commands[cnt*parallel_num*execute_one_round:(cnt+1)*parallel_num*execute_one_round]
    correct_check_num = len(cmd)
    cmd = '\n'.join(cmd)
    time.sleep(2)
    print("[*] %d-%d:"%(cnt*parallel_num*execute_one_round, (cnt+1)*parallel_num*execute_one_round))
    print(cmd)
    os.system(cmd+"\n")
    time.sleep(5)
    ps = subprocess.check_output(["ps", "-aux"])
    process = subprocess.Popen(["grep", "afl-fuzz"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    #print(process, ps)
    data, err = process.communicate(ps)
    check_num = len(data.decode().split("\n"))
    if check_num != correct_check_num + 1:
        os.system("pkill afl-fuzz")
        print(check_num, correct_check_num+1)
        time.sleep(10)
        print("[-] Restart!")
        continue
    print(check_num, correct_check_num + 1)

    start = time.time()
    cnt += 1
    while True:
        now = time.time()
        if now - start > last_time:
            print("[*] End")
            os.system("pkill afl-fuzz")
            time.sleep(2)
            break
        else:
            time.sleep(5)


