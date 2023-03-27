#!/usr/bin/env python3

import os
import subprocess as sp
import os.path as path
import shutil
import sys

def call(cmd):
    sp.check_call(cmd, shell=True)

script_dir = os.path.dirname(os.path.realpath(__file__))

disable_env_var = "HWFUZZ_NO_DFSAN"

os.environ[disable_env_var] = "1"
call("make -C ..")
del os.environ[disable_env_var]

os.environ["PATH"] = path.join(script_dir, "..") + ":" + os.environ["PATH"]

call("afl-clang-fast++ -fsanitize-ignorelist=ignore_list -fsanitize=dataflow -o target_taint test.cpp")

os.environ[disable_env_var] = "1"
call("afl-clang-fast++ -fsanitize-ignorelist=ignore_list -fsanitize=dataflow -o target_no_taint test.cpp")

os.environ["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
os.environ["AFL_BENCH_UNTIL_CRASH"] = "1"

os.makedirs("fuzz/in", exist_ok=True)
with open("fuzz/in/start", "w") as f:
    f.write('abcdef')

shutil.rmtree("fuzz/out_taint", ignore_errors=True)
os.makedirs("fuzz/out_taint")

shutil.rmtree("fuzz/out_no_taint", ignore_errors=True)
os.makedirs("fuzz/out_no_taint")

print("#########################################")
print("Running with taint")
print("#########################################")
os.system("afl-fuzz -i fuzz/in -o fuzz/out_taint -- ./target_taint @@")

print("#########################################")
print("Running without taint")
print("#########################################")
os.system("afl-fuzz -i fuzz/in -o fuzz/out_no_taint -- ./target_no_taint @@")
