from my_debugger import *
from my_debugger_defines import *
import utils
import smtplib
import random
import sys
import struct
import threading
import os
import shutil
import time
import getopt


class file_fuzzer:
    def __init__(self, exe_path, ext, notify):
        self.exe_path = exe_path
        self.ext = ext
        self.notify_crash = notify
        self.orig_file = None
        self.mutated_file = None
        self.iteration = 0
        self.crash = None
        self.send_notify = False
        self.pid = None
        self.in_accessv_handler = False
        self.dbg = None
        self.running = False
        self.ready = False
        self.test_cases = ['%s%n%s%n%s%n', '\xff', '\x00', 'A']

        # optional
        self.smtpserver = 'mail.nostarch.com'
        self.recipients = []
        self.sender = 'jms@bughunter.ca'

    def file_picker(self):
        """
        随机选择文件
        """
        file_list = os.listdir("examples/")
        list_length = len(file_list)
        file = file_list[random.randint(0, list_length - 1)]
        shutil.copy("examples\\%s" % file, "test.%s" % self.ext)
        return file

    def fuzz(self):
        while True:
            if not self.running:
                self.test_file = self.file_picker()  # 随机选择文件
                self.mutate_file()

                pydbg_thread = threading.Thread(target=self.star_debugger)
                pydbg_thread.setDaemon(0)
                pydbg_thread.start()
                while self.pid == None:
                    time.sleep(1)
                monitor_thread = threading.Thread(target=self.monitor_debugger)
                monitor_thread.setDaemon(0)
                monitor_thread.start()

                self.iteration += 1
            else:
                time.sleep(1)

    def star_debugger(self):
        print("[*] Starting debugger for iteration: %d" % self.iteration)
        self.running = True
        # self.dbg = pydbg()
        self.dbg = debugger()
        self.dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, self.check_accessv)
        pid = self.dbg.load(self.exe_path, "test.%s" % self.ext)
        self.pid = self.dbg.pid
        self.dbg.run()

    def check_accessv(self, dbg):
        if dbg.dbg.u.Exception.dwFirstChance:
            return DBG_CONTINUE
        print("[*] Woot! Handling an access violation!")
        self.in_accessv_handler = True
        crash_bin = utils.crash_binning.crash_binning()
        crash_bin.record_crash(dbg)
        self.crash = crash_bin.crash_synopsis()
        crash_fd = open("crashes\\crash-%d" % self.iteration, "w")
        crash_fd.write(self.crash)
        shutil.copy("test.%s" % self.ext, "crashes\\%d.%s" %
                    (self.iteration, self.ext))
        shutil.copy("examples\\%s" % self.test_file,
                    "crashes\\%d_orig.%s" % (self.iteration, self.ext))
        self.dbg.terminate_process()
        self.in_accessv_handler = False
        self.running = False
        return DBG_EXCEPTION_NOT_HANDLED

    def monitor_debugger(self):
        counter = 0
        print("[*] Monitor thread for pid: %d waiting." % self.pid)
        while counter < 3:
            time.sleep(1)
            print(counter)
            counter += 1

        if self.in_accessv_handler != True:
            time.sleep(1)
            self.dbg.terminate_process()
            self.pid = None
            self.running = False
        else:
            print("[*] The access violation handler is doing its business. Waiting.")
            while self.running:
                time.sleep(1)

    def notify(self):
        crash_message = "From: %s\r\n\r\nTo: \r\n\r\nIteration: %d\n\nOuput:\n\n %s" % (
            self.sender, self.iteration, self.crash)
        session = smtplib.SMTP(self.smtpserver)
        session.sendmail(self.sender, self.recipients, crash_message)
        session.quit()
        return

    def mutate_file(self):
        fd = open("test.%s" % self.ext, "rb")
        stream = fd.read()
        fd.close()
        test_case = self.test_cases[random.randint(0, len(self.test_cases) - 1)]
        stream_length = len(stream)
        rand_offset = random.randint(0, stream_length - 1)
        rand_len = random.randint(1, 1000)
        test_case = test_case * rand_len
        fuzz_file = stream[0:rand_offset]
        fuzz_file += str(test_case)
        fuzz_file += stream[rand_offset:]
        fd = open("test.%s" % self.ext, "wb")
        fd.write(fuzz_file)
        fd.close()
        return

def print_usage():
    print("[*]")
    print("[*] python file_fuzzer.py -e <Executable Path> -x <File Extension>")
    print("[*]")
    sys.exit(0)

if __name__ == '__main__':
    print("[*] Generic File Fuzzer.")
    try:
        opts, argo = getopt.getopt(sys.argv[1:], "e:x:n")
    except getopt.GetoptError:
        print_usage()

    exe_path = None
    ext = None
    notify = False

    for o,a in opts:
        print(o,a)
        if o == '-e':
            exe_path = a
        elif o == '-x':
            ext = a
        elif o == '-n':
            notify = True
    
    if exe_path is not None and ext is not None:
        fuzzer = file_fuzzer(exe_path, ext, notify)
        fuzzer.fuzz()
    else:
        print_usage()