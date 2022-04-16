import os, r2pipe, time, stat
import subprocess
from shutil import copyfile
from config import *
from algorithms import *

class DelayRemover:

    def __init__(self, binary_path, trace_info_file, seed_dir, argv, functionality_test):
        self.file_dir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
        self.binary_path = os.path.join(self.file_dir, binary_path)
        self.seed_dir = seed_dir
        self.argv = argv
        self.blks_info = {}

        with open(trace_info_file) as f:
            trace_info = f.read()
        trace_info = trace_info.split("\n")

        for info_line in trace_info:
            if len(info_line) == 0:
                continue

            blk_addr, info_line = info_line.split(" : ")
            blk_addr = int(blk_addr)
            avg_blk_time, info_line = info_line.split(" * ")
            blk_hit, pre_blk_addr = info_line.split(" <- ")
            blk_hit = int(blk_hit)
            pre_blk_addr = int(pre_blk_addr)

            self.blks_info[blk_addr] = (avg_blk_time, blk_hit, pre_blk_addr)

        #print(len(self.blks_info))
        keys = list(self.blks_info.keys())
        for blk_addr in keys:
            # Remove external calls
            if blk_addr > 0x7f0000000000:
                del self.blks_info[blk_addr]

        print(len(self.blks_info))


    def splitFunc(self):
        r2 = r2pipe.open(self.binary_path, flags=['-d'])
        for blk_addr in self.blks_info.keys():
            r2.cmd("db "+hex(blk_addr))

        seeds = []
        for root, dirs, files in os.walk(self.seed_dir, topdown=False):
            for name in files:
                seeds.append(os.path.join(root, name))

        # for seed in seeds:
        self.argv = self.argv.replace('@@', seeds[0])
        r2.cmd('ood ' + self.argv)
        r2.cmd('dc')

        self.funcDict = {}
        cnt = 0
        while True:
            rip = r2.cmd("dr rip")
            cur_addr = int(rip, 16)

            if cur_addr not in self.blks_info.keys():
                break


            dis = r2.cmd("pd 2")
            # In case at the beginning of a function, rbp should be changed
            if (("push rbp" in dis or "push ebp" in dis) and ("mov rbp" in dis or 'mov ebp' in dis)):
                r2.cmd("ds 2")

            # pair = (addr, start/end, hash)
            feature = r2.cmd("dr rbp").strip()
            print(feature)
            if feature not in self.funcDict:
                self.funcDict[feature] = []

            self.funcDict[feature].append(cur_addr)
            print(cnt)
            cnt += 1
            r2.cmd('db -' + hex(cur_addr))
            r2.cmd('dc')

        r2.process.terminate()

        print(self.funcDict)
        with open("./func.dict", "w") as f:
            f.write(str(self.funcDict))

        return self.funcDict

    def calPerFuncTime(self):
        with open("./func.dict", "r") as f:
            content = f.read()

        self.funcDict = eval(content)
        #print(self.funcDict)

        self.funcTime = []
        for func_ebp in self.funcDict.keys():
            exec_time = 0
            for addr in self.funcDict[func_ebp]:
                avg_blk_time, blk_hit, _ = self.blks_info[addr]
                avg_blk_time = int(avg_blk_time)
                blk_hit = int(blk_hit)
                exec_time += avg_blk_time*blk_hit
            self.funcTime.append((func_ebp, exec_time))

        self.funcTime = sorted(self.funcTime, key=lambda x: x[1], reverse=True)
        #print(self.funcTime)
        return self.funcTime

    def modifyHighDelayFunc(self):

        seeds = []
        for root, dirs, files in os.walk(self.seed_dir, topdown=False):
            for name in files:
                seeds.append(os.path.join(root, name))

        # for seed in seeds:
        self.argv = self.argv.replace('@@', seeds[0])
        print(self.argv.split(' '))
        print("Original run:")
        start = time.time()
        original_res = subprocess.check_output([self.binary_path]+ self.argv.split(' '))
        end = time.time()

        #print(original_res)
        print(end-start)

        r2 = r2pipe.open(self.binary_path, flags=['-w'])
        tmp_file = self.binary_path + "_tmp"
        if os.path.exists(tmp_file):
            os.remove(tmp_file)

        # Only remove the highest 5 functions
        for func in self.funcTime[:5]:
            addrs = self.funcDict[func[0]]
            print(func[0], list(map(hex, addrs))[:5])
            cnt = 0
            for addr in addrs:
                if cnt > 10:
                    break
                dis = r2.cmd("pd 2 @ %s"%(hex(addr)))
                # print(dis)
                if (("push rbp" in dis or "push ebp" in dis) and ("mov rbp" in dis or 'mov ebp' in dis)):
                    if not os.path.exists(tmp_file):
                        copyfile(self.binary_path, tmp_file)

                    r2_tmp = r2pipe.open(tmp_file, flags=['-w'])
                    r2_tmp.cmd("wa ret @ %s"%(hex(addr)))
                    dis = r2.cmd("pd 2 @ %s" % (hex(addr)))
                    # print(dis)
                    r2_tmp.process.terminate()
                    st = os.stat(tmp_file)
                    os.chmod(tmp_file, st.st_mode | stat.S_IEXEC )
                    time.sleep(0.5)
                    start = time.time()
                    try:
                        modified_res = subprocess.check_output([tmp_file] + self.argv.split(' '))
                    except subprocess.CalledProcessError as e:
                        modified_res = 'Error!'
                    end = time.time()

                    print("Modify run", end-start)
                    if (original_res != modified_res):
                        print(modified_res)
                        os.remove(tmp_file)
                        continue

                    cnt += 1
                    r2.cmd("wa ret @ %s"%(hex(addr)))
                    dis = r2.cmd("pd 2 @ %s" % (hex(addr)))
                    # print(dis)
                    time.sleep(0.5)
                    # One break in one func enough


if __name__ == '__main__':
    copyfile('./readelf_all_copy', './readelf_all_elibranch')
    start = time.time()
    dr = DelayRemover('./readelf_all_elibranch', './out_remove', './seeds/', '-a @@')
    # dr.splitFunc()
    dr.calPerFuncTime()
    dr.modifyHighDelayFunc()
    end = time.time()
    print('total time:', end-start)