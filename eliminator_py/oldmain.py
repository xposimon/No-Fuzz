import os
import time
import random
import shutil
from cfg import CFG
from utils import replace_input_placeholder


class ATEliminator(object):

    def __init__(self, target_binary, seed_dir="./output/slowseed", work_dir="workdir",generated_program_path = "generated_programs", dependency =None, target_opts=[],
                 round_time = 30,extra_opts = None, input_placeholder='@@', seed_files = None, qemu=True):
       
        if not os.path.isfile(target_binary):
            raise RuntimeError("Not valid binary file")

        self.target_opts = target_opts
        self.extra_opts = extra_opts if extra_opts is not None else []
        self.input_placeholder = input_placeholder

        self.abs_binary = os.path.abspath(target_binary)
        self.binary_dir, self.binary_name = os.path.split(self.abs_binary)
        self.work_dir = os.path.join(self.binary_dir, work_dir)
        self.seed_dir = os.path.join(self.binary_dir, seed_dir)
        self.target_binary = self.abs_binary
        print(self.abs_binary, self.binary_dir, self.target_binary)
        self.generated_program_dir = generated_program_path
        self.dependency = dependency

        if not os.path.exists(self.work_dir):
            os.makedirs(self.work_dir)
        if not os.path.exists(self.generated_program_dir):
            os.makedirs(self.generated_program_dir)

        if self.dependency is not None:
            for dep in self.dependency:
                depname = os.path.split(dep)[-1]
                if os.path.isdir(dep):
                    shutil.copytree(dep, os.path.join(self.generated_program_dir, depname))
                elif os.path.isfile(dep):
                    shutil.copy(dep, os.path.join(self.generated_program_dir, depname))

        self.cfg = CFG(self.target_binary, self.work_dir, self.generated_program_dir, self.seed_dir, target_opts = self.target_opts, input_placeholder = self.input_placeholder)
        
    def behaviour_trace(self):
        self.cfg.retrieve_act_blocks()
        self.cfg.construct_dyn_cfg()

if __name__ == "__main__":
    at = ATEliminator("../readelf_afl", work_dir="./workdir/", target_opts=[])
    at.behaviour_trace()

