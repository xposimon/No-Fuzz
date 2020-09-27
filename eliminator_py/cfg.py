import os
import angr
import time
import r2pipe
import subprocess32
from visual import Visual
from utils import replace_input_placeholder, logprint

# Path configure
# sys.path.append('.')

class CFG(object):

    def __init__(self, program_path, work_dir, generated_program_dir, seed_dir, target_opts,
                 extra_opts = [], input_placeholder = "@@", traverse_path_limit = 2000,
                 dangerous_func = None, input_func= None, program_queue_limit = 10, ):

        self.work_dir = work_dir
        self.target_opts = target_opts
        self.extra_opts = extra_opts
        self.seed_dir = seed_dir
        self.input_placeholder = input_placeholder
        self.program_path = program_path
        pro_dir = os.path.split(self.program_path)[0]
        self.generated_program_dir = os.path.join(pro_dir, generated_program_dir)
        #print(self.generated_program_dir)
        if not os.path.exists(self.generated_program_dir):
            os.makedirs(self.generated_program_dir)

        self.program_queue_limit = program_queue_limit
        self.project = angr.Project(program_path, auto_load_libs = False)
        cfg = self.project.analyses.CFGFast()
        self.nodes = cfg.graph.nodes()
        self.edges = cfg.graph.edges()

        time.sleep(1)

        self.addr_to_node = {}
        for cfgnode in self.nodes:
            print(cfgnode, hex(cfgnode.addr))
            self.addr_to_node[cfgnode.addr] = cfgnode

        self.adj_list = {}
        self.pre_blk = 0
        self.per_blk_exec = {}

        p = subprocess32.Popen('which rarun2', shell=True, stdout=subprocess32.PIPE)
        rarun2_path = p.communicate()[0]
        self.rarun2_path = rarun2_path.decode().strip()

    def graph_construction(self):
        # Construct the adjacency_list of the nodes, and path selection will be conducted on the tree
        # For convenience, be consistent with depth_map, that use address to index

        self.adj_list = {}

        for from_node, to_node in self.edges:

            if from_node.addr not in self.act_blks:
                continue

            if from_node.addr in self.adj_list:
                self.adj_list[from_node.addr].append(to_node.addr)
            else:
                self.adj_list[from_node.addr] = [to_node.addr]
            if to_node.addr not in self.adj_list:
                self.adj_list[to_node.addr] = []

        for node_addr in self.act_blks:
            if node_addr not in self.adj_list:
                self.adj_list[node_addr] = []

    def retrieve_act_blocks(self):
        self.act_blks = []

        for r, d, f in os.walk(self.seed_dir):
            for file in f:
                seed_file = os.path.join(r, file)
                print(seed_file)
                if self.target_opts is not None and self.input_placeholder in self.target_opts:
                    # Command line parameters
                    r2 = r2pipe.open(self.program_path, flags=['-d'])
                    input_target_opts = replace_input_placeholder(self.target_opts, seed_file,
                                                                  input_placeholder=self.input_placeholder)
                    args_cmd = ' '.join(input_target_opts)
                    # print("args:", args_cmd)
                    r2.cmd("ood " + args_cmd)
                elif "-f" in self.extra_opts:
                    pass
                else:
                    profile_rr2 = "#!%s\nprogram=%s\nstdin=%s\n"
                    self.profile_path = os.path.join(r, 'profile.rr2')
                    with open(self.profile_path, 'w') as f:
                        f.write(profile_rr2 % (self.rarun2_path, self.program_path, seed_file))

                    r2 = r2pipe.open(self.program_path, flags=['-d', '-e', 'dbg.profile=%s' % (self.profile_path)])

                r2.cmd("db-*")
                for addr in self.addr_to_node.keys():
                    if addr not in self.act_blks:
                        r2.cmd("db " + hex(addr))

            r2.cmd("dc")

            while True:

                ip = r2.cmd("dr eip")
                if len(ip) == 0:
                    ip = r2.cmd("dr rip")
                while True:
                    try:
                        blk_addr = int(ip, 16)
                        break
                    except:
                        # In case to fast
                        ip = r2.cmd("dr eip")
                        if len(ip) == 0:
                            ip = r2.cmd("dr rip")
                        time.sleep(0.5)

                dis = r2.cmd("pd 1@" + ip)
                if "invalid" in dis:
                    break
                if blk_addr not in self.act_blks:
                    self.act_blks.append(blk_addr)

                r2.cmd("dc")

            r2.process.terminate()

        return self.act_blks

    def construct_dyn_cfg(self):
        # Static cfg construction
        self.graph_construction()
        #vis = Visual(self.adj_list)
        #vis.draw_cfg()

        for r, d, f in os.walk(self.seed_dir):
            for file in f:
                seed_file = os.path.join(r, file)
                print(seed_file)
                if self.target_opts is not None and self.input_placeholder in self.target_opts:
                    # Command line parameters
                    r2 = r2pipe.open(self.program_path, flags=['-d'])
                    input_target_opts = replace_input_placeholder(self.target_opts, seed_file,
                                                                  input_placeholder=self.input_placeholder)
                    args_cmd = ' '.join(input_target_opts)
                    # print("args:", args_cmd)
                    r2.cmd("ood " + args_cmd)
                elif "-f" in self.extra_opts:
                    pass
                else:
                    profile_rr2 = "#!%s\nprogram=%s\nstdin=%s\n"
                    self.profile_path = os.path.join(r, 'profile.rr2')
                    with open(self.profile_path, 'w') as f:
                        f.write(profile_rr2 % (self.rarun2_path, self.program_path, seed_file))

                    r2 = r2pipe.open(self.program_path, flags=['-d', '-e', 'dbg.profile=%s' % (self.profile_path)])

                r2.cmd("db-*")
                for addr in self.act_blks:
                    r2.cmd("db " + hex(addr))

                self.pre_blk = 0
                self.per_blk_exec = {}
                start = time.clock()

                r2.cmd("dc")
                while True:
                    ip = r2.cmd("dr eip")
                    if len(ip) == 0:
                        ip = r2.cmd("dr rip")
                    while True:
                        try:
                            blk_addr = int(ip, 16)
                            break
                        except:
                            # In case too fast
                            ip = r2.cmd("dr eip")
                            if len(ip) == 0:
                                ip = r2.cmd("dr rip")
                            time.sleep(0.5)

                    dis = r2.cmd("pd 1@" + ip)
                    if "invalid" in dis:
                        break

                    end = time.clock()
                    if blk_addr not in self.per_blk_exec:
                        self.per_blk_exec[blk_addr] = []
                    self.per_blk_exec[blk_addr].append(end-start)
                    start = time.clock()
                    r2.cmd("dc")
                r2.process.terminate()

        for k in self.per_blk_exec.keys():
            self.per_blk_exec[k] = sum(self.per_blk_exec[k])/len(self.per_blk_exec[k])

        print(self.per_blk_exec)



if __name__ == "__main__":
   pass



