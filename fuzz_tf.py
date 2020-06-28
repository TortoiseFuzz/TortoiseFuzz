import os
import sys
import json
import time

afl_type_list = ["bb", "func", "loop"]

class FuzzConfig():
    def __init__(self, dic_json, package):
        self.dic_json = dic_json
        self.package  = package
        self.aflarg   = dic_json[0][package][0]
        self.progarg  = dic_json[0][package][1]
        self.to_path  = dic_json[1]["tofuzz_path"][0]

def init_tmux(package):
    curdir = os.path.abspath(os.path.dirname(__file__))
    os.system("tmux send-keys -t tofuzz 'cd %s' ENTER;" % (curdir))
    time.sleep(0.3)
    os.system("tmux send-keys -t tofuzz 'tmux new-window -n %s-tf' ENTER;" % (package))
    time.sleep(0.3)
    os.system("tmux send-keys -t tofuzz 'tmux split-window -v' ENTER;")
    time.sleep(0.3)
    os.system("tmux send-keys -t tofuzz 'tmux split-window -h' ENTER;")
    time.sleep(0.3)
    os.system("tmux send-keys -t tofuzz 'tmux select-pane -U' ENTER;")
    time.sleep(0.3)
    os.system("tmux send-keys -t tofuzz 'tmux split-window -h' ENTER;")
    time.sleep(0.3)
    os.system("tmux send-keys -t tofuzz 'tmux select-pane -t 0' ENTER;")
    time.sleep(0.3)

def _fuzz(fconfig, index):
    aflarg  = fconfig.aflarg
    progarg = fconfig.progarg
    to_path = fconfig.to_path
    afl_type = afl_type_list[index]

    for i in range(1,11): # [1, 10]
        if(not os.path.exists("%s/out_%s%d" % (package, afl_type, i))):
            break

    afl_path = "%s/%s_metric/afl-fuzz" % (to_path, afl_type)
    _cmd  = "%s/bin_%s/bin/%s" % (package, afl_type, progarg)
    afl_out = "%s/out_%s%d" % (package, afl_type, i)
    afl_args= "%s -s -i %s/in -o %s %s" % (afl_path, package, afl_out, aflarg)
    cmd = "timeout -s 1 504000 %s -- %s" % (afl_args, _cmd)

    print(cmd)
    if(package == "gpac"):
        os.system("tmux send-keys -t tofuzz 'export LD_LIBRARY_PATH=./gpac/bin_%s/lib' ENTER;" % (afl_type))
    os.system("tmux send-keys -t tofuzz 'tmux select-pane -t %d && %s' ENTER;" % (index+1, cmd))
    time.sleep(0.3)
    # os.system("tmux send-keys -t tofuzz '%s' ENTER;" % cmd)
    if(index == 4):
        exit(-1)

def fuzz_main(dic_json, package):
    fconfig = FuzzConfig(dic_json, package)
    init_tmux(package)
    for i in range(0, len(afl_type_list)): # [0, 2]
        _fuzz(fconfig, i)

if (__name__ == "__main__"):
    f = open(sys.argv[1], "r")
    package  = sys.argv[2]
    dic_json = json.loads(f.read())
    
    fuzz_main(dic_json, package)