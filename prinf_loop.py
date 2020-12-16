from ctypes import *
import time

msvcrt = cdll.msvcrt
counter = 0

while True:
    msvcrt.printf(b"Loop iteration %d!\n" % counter)
    time.sleep(2)
    counter += 1