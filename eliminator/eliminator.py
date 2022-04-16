import os, r2pipe, re
from shutil import copyfile
from config import *
from algorithms import *

class Eliminator:

    def __init__(self, binary_path, trace_info_file, seed_dir, argv):

        self.file_dir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
        self.binary_path = os.path.join(self.file_dir, binary_path)
        self.seed_dir = seed_dir
        self.argv = argv
        #self.trace_info = trace_info_file
        self.blks_info = {}
        self.blk_hit_fre = {}
        self.next_list = {}
        self.visited = set()

        self.roots = []
        self.leaves = []

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
            if blk_hit <= BLK_HIT_THRESHOLD:
                continue

            if blk_hit not in self.blk_hit_fre:
                self.blk_hit_fre[blk_hit] = 1
            else:
                self.blk_hit_fre[blk_hit] += 1

    def SplitPath(self, blks):
        '''
        Divide the ordered blocks into different chains
        '''
        
        for i, blk in enumerate(blks):
            _, __, pre_blk_addr = self.blks_info[blk]
            self.next_list[pre_blk_addr] = blk 

        paths = []
        for blk in self.next_list.keys():
            self.BFS(blk)

        for root in self.roots:
            cur = root
            tmp_path = []
            depth = 0

            while cur in self.next_list:
                tmp_path.append(cur)
                cur = self.next_list[cur]
            
            paths.append(tmp_path)

        return paths

    def BFS(self, start):
        queue = [start]

        while len(queue) > 0:
            cur = queue.pop(0)

            if cur not in self.roots and cur not in self.visited:
                self.roots.append(cur)

            if cur not in self.visited:
                self.visited.add(cur)
            
            if cur not in self.next_list:
                self.leaves.append(cur)
                return

            child = self.next_list[cur]

            if child in self.roots:
                self.roots.remove(child)

            if child not in self.visited:
                self.visited.add(child)
                queue.append(child)
            else:
                continue

    def IdentFakePath(self):
        potential_fake_paths = {}
        for blk_addr, blk_info in self.blks_info.items():
            _, blk_hit, __ = blk_info
            if blk_hit in self.blk_hit_fre and \
                    self.blk_hit_fre[blk_hit] > SAME_HIT_BLKNUM_THRESHOLD:
                if blk_hit not in potential_fake_paths:
                    potential_fake_paths[blk_hit] = []
                potential_fake_paths[blk_hit].append(blk_addr)

        self.longengh_fake_paths = []

        for blk_hit in potential_fake_paths.keys():
            blks = sorted(potential_fake_paths[blk_hit])
            paths = self.SplitPath(blks)
            for path in paths:
                if len(path) > PATH_CUT_INTERVAL:
                    print(list(map(hex, path[:5])), list(map(hex, path[-5:])))
                    self.longengh_fake_paths.append(path)

        return self.longengh_fake_paths

    def checkStack(self, startAddrs, endAddrs):
        r2_check = r2pipe.open(self.binary_path, flags=['dbg://../readelf_all'])
        seeds = []
        for root, dirs, files in os.walk(self.seed_dir, topdown=False):
            for name in files:
                seeds.append(os.path.join(root, name))
        for addr in startAddrs+endAddrs:
            r2_check.cmd("db "+hex(addr))

        jmp_dict = {}
        for seed in seeds:
            argv = self.argv.replace('@@', seed)

            r2_check.cmd('ood '+ argv)
            r2_check.cmd('dc')

            while True:
                rip = r2_check.cmd("dr rip")
                cur_addr = int(rip, 16)
                pair = [cur_addr]
                if cur_addr in startAddrs:
                    pair.append('start')
                elif cur_addr in endAddrs:
                    pair.append('end')
                else:
                    break
                # pair = (addr, start/end, hash)
                pair.append(r2_check.cmd("ph sha1 64 @ rsp"))
                addr, se, hash = pair
                if hash not in jmp_dict:
                    jmp_dict[hash] = {'start':[], 'end':[]}

                jmp_dict[hash][se].append(addr)
                r2_check.cmd('db -'+hex(addr))
                r2_check.cmd('dc')

        r2_check.process.terminate()

        return jmp_dict


    def StatelessJmp(self):
        # Assume there is no state change in those fake paths
        binary_name = os.path.split(self.binary_path)[-1]
        copy_filename =  os.path.join(self.file_dir, binary_name+"_elibranch")
        copyfile(self.binary_path, copy_filename)

        r2 = r2pipe.open(copy_filename, flags=['-w'])
        for fake_path in self.longengh_fake_paths:
            startAddrs = fake_path[PATH_REMOVE_START_POS:PATH_REMOVE_START_POS+ADDR_CHECK_NUM]
            endAddrs = fake_path[-PATH_REMOVE_END_POS-ADDR_CHECK_NUM:]

            jmp_dict = self.checkStack(startAddrs, endAddrs)
            print(jmp_dict)
            for hash in jmp_dict.keys():
                se_list = jmp_dict[hash]
                if len(se_list['start']) > 0 and len(se_list['end']) > 0:
                    for start in se_list['start']:
                        print(r2.cmd('pd 1 @ '+hex(start)))
                        r2.cmd('wa jmp %s @ %s'%(hex(se_list['end'][-1]), hex(start)))


if __name__ == "__main__":
    eli = Eliminator("../readelf_all", "./out_final", './seeds/', '-h @@')
    eli.IdentFakePath()
    eli.StatelessJmp()