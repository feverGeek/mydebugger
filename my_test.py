import my_debugger

debugger = my_debugger.debugger()

pid = input("Enter the PID of the process to attach to:")
debugger.attach(int(pid))

# 获取wprintf的地址
printf_address = debugger.func_resolve("C:\\Windows\\System32\\msvcrt.dll", b"printf")
print("[*] Address of printf: 0x%08x" % printf_address)

# 下断点
debugger.bp_set_sw(printf_address)

debugger.run()
