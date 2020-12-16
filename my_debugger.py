from ctypes import *
from my_debugger_defines import *

kernel32 = windll.kernel32


class debugger():
    def __init__(self):
        self.h_process = None
        self.pid = None
        self.debugger_active = False
        self.h_thread = None
        self.context = None
        self.exception = None
        self.exception_address = None
        self.software_breakpoints = {}
        self.hardware_breakpoints = {}
        self.memory_breakpoints = {}
        self.first_breakpoints = True
        system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(system_info))
        self.page_size = system_info.dwPageSize
        self.guarded_pages = []

    def load(self, path_to_exe):
        # dwCreation flag determines how to create the process
        # set creation_flags = CREATE_NEW_CONSOLE if you want
        # to see the calculator GUI
        creation_flags = DEBUG_PROCESS
        # instantiate the structs
        startupinfo = STARTUPINFO()
        process_information = PROCESS_INFORMATION()
        # The following two options allow the started process
        # to be shown as a separate window. This also illustrates
        # how different settings in the STARTUPINFO struct can affect
        # the debuggee.
        startupinfo.dwFlags = 0x1
        startupinfo.wShowWindow = 0x0
        # We then initialize the cb variable in the STARTUPINFO struct
        # which is just the size of the struct itself
        startupinfo.cb = sizeof(startupinfo)

        if kernel32.CreateProcessW(path_to_exe, None, None, None, None, creation_flags, None, None, byref(startupinfo), byref(process_information)):
            print("[*] We have successfully launched the process!")
            print("[*] PID: %d" % process_information.dwProcessId)
            self.h_process = self.open_process(process_information.dwProcessId)
        else:
            print("[*] Error: 0x%08x." % kernel32.GetLastError())

    def open_process(self, pid):
        """
        打开指定pid的进程
        """
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        return h_process

    def attach(self, pid):
        """
        附加进程
        """
        self.h_process = self.open_process(pid)

        if kernel32.DebugActiveProcess(pid):
            self.debugger_active = True
            self.pid = int(pid)
            # self.run()
        else:
            print("[*] Unable to attach to the process.")

    def run(self):
        # Now we have to poll the debuggee for debugging events
        while self.debugger_active == True:
            self.get_debug_event()

    def get_debug_event(self):
        """
        获取调试事件
        """
        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE

        # 捕获 debug event
        if kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):
            # 获取 context
            self.h_thread = self.open_thread(debug_event.dwThreadId)
            self.context = self.get_thread_context(debug_event.dwThreadId)
            print("Event Code: %d Thread ID: %d" %
                  (debug_event.dwDebugEventCode, debug_event.dwThreadId))
                  
            # 处理异常
            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                # 获取 event code
                self.exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress

                # 检测到访问异常
                if self.exception == EXCEPTION_ACCESS_VIOLATION:
                    print("Access Violation Detected.")
                    
                # 检测到 breakpoint (软件断点)
                elif self.exception == EXCEPTION_BREAKPOINT:
                    continue_status = self.exception_handler_breakpoint()

                # 检测到保护页异常
                elif self.exception == EXCEPTION_GUARD_PAGE:
                    print("Guard Page Access Detected.")

                # 检测到单步运行 (硬件断点)
                elif self.exception == EXCEPTION_SINGLE_STEP:
                    self.exception_handler_single_step()
                    print("Single Stepping.")

            # 继续运行 thread
            kernel32.ContinueDebugEvent(
                debug_event.dwProcessId, debug_event.dwThreadId, continue_status)

    def exception_handler_breakpoint(self):
        """
        断点异常处理
        """
        print("[*] Inside the breakpoint handler.")
        print("Exception Address: 0x%08x" % self.exception_address)
        print(kernel32.GetLastError())
        if not self.exception_address in self.hardware_breakpoints.keys():
            if self.first_breakpoints == True:
                self.first_breakpoints = False
                print("[*] Hit the first breakpoint.")
        else:
            print("[*] Hit user defined breakpoint.")
        return DBG_CONTINUE

    def exception_handler_single_step(self):
        if self.context.Dr6 &0x01 and 0 in self.hardware_breakpoints.keys():
            slot = 0
        elif self.context.Dr6 &0x02 and 1 in self.hardware_breakpoints.keys():
            slot = 1
        elif self.context.Dr6 &0x04 and 2 in self.hardware_breakpoints.keys():
            slot = 2
        elif self.context.Dr6 &0x08 and 3 in self.hardware_breakpoints.keys():
            slot = 3
        else:
            continue_status = DBG_EXCEPTION_NOT_HANDLED
            return continue_status
        if self.bp_del_hw(slot):
            continue_status = DBG_CONTINUE
            print("[*] Hardware breakpoint removed.")
            return continue_status

    def read_process_memory(self, address, length):
        """
        读取目标进程的内存
        """
        data = b""
        read_buf = create_string_buffer(length)
        count = c_ulong(0)
        if not kernel32.ReadProcessMemory(self.h_process, address, read_buf, length, byref(count)):
            print("read_process_memory fail.")
            return False
        else:
            data += read_buf.raw
            return data

    def write_process_memory(self, address, data):
        """
        写入目标进程的内存
        """
        count = c_ulong(0)
        length = len(data)
        c_data = c_char_p((data[count.value:]))
        if not kernel32.WriteProcessMemory(self.h_process, address, c_data, length, byref(count)):
            print("write_process_memory fail.")
            return False
        else:
            return True

    def bp_set_sw(self, address):
        """
        设置软件断点
        """
        if not address in self.software_breakpoints.keys():
            try:
                # store the original byte
                original_byte = self.read_process_memory(str(address), 2)
                print("read_process_memory %s" % original_byte)

                # write the INT3 opcode
                ret = self.write_process_memory(str(address), b"\xCC")
                if ret:
                    print("Write success.")
                    print("New memory %s" % self.read_process_memory(str(address),2))
                else:
                    print(kernel32.GetLastError())
                    print("Write fail.")
                # register the breakpoint in our internal list
                self.software_breakpoints[address] = (str(address), original_byte)
            except:
                print("bp_set fail.")
                print(kernel32.GetLastError()) # 返回异常代码值
                return False
        return True

    def bp_set_hw(self, address, length, condition):
        """
        设置硬件断点
        """
        # 检查硬件断点的长度是否有效
        if length not in (1, 2, 4):
            return False
        else:
            length -= 1
        # 检查硬件断点的触发条件是否有效
        if condition not in (HW_ACCESS, HW_EXECUTE, HW_WRITE):
            # 这里的condition其实就是调试寄存器DR7的标志位，
            # HW_ACCESS = 0x00000003, HW_EXECUTE = 0x00000000, HW_WRITE = 0x00000001
            return False
        # 检查是否存在空置的调试寄存器
        if not 0 in self.hardware_breakpoints.keys():  
            available = 0
        elif not 1 in self.hardware_breakpoints.keys():
            available =1
        elif not 2 in self.hardware_breakpoints.keys():
            available = 2
        elif not 3 in self.hardware_breakpoints.keys():
            available = 3
        else:
            return  False
        # 在每个线程环境下设置调试寄存器
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id=thread_id)
            context.Dr7 |= 1 << (available * 2)  # 设置DR7中相应的标志位，来激活断点
            # 在空置的寄存器下写入断点地址
            if available == 0:
                context.Dr0 = address
            elif available == 1:
                context.Dr1 = address
            elif available == 2:
                context.Dr2 = address
            elif available == 3:
                context.Dr3 = address
            # 设置硬件断点触发条件
            context.Dr7 |= condition << ((available * 4) + 16)
            # 设置硬件断点长度
            context.Dr7 |= length << ((available * 4) + 18)
            # 提交改动后线程上下文环境信息
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread, byref(context))
        # 更新内部硬件断点列表
        self.hardware_breakpoints[available] = (str(address), length, condition)
        return  True

    def bp_del_hw(self, slot):
        """
        删除硬件断点
        """
        # 移除所有线程的硬件断点
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id=thread_id)
            # 重新设置DR7调试标志位
            context.Dr7 &= ~(1 << (slot * 2))
            # 清零断点地址
            if slot == 0:
                context.Dr0 = 0x00000000
            elif slot == 1:
                context.Dr1 = 0x00000000
            elif slot == 2:
                context.Dr2 = 0x00000000
            elif slot == 3:
                context.Dr3 = 0x00000000
            else:
                return False
            # 清空断点触发条件标志位
            context.Dr7 &= ~(3 << ((slot * 4) + 16))
            # 清空断点长度标志位
            context.Dr7 &= ~(3 << ((slot * 4) + 18))
            # 提交移除断点后的线程上下文环境信息
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread, byref(context))
        # 从内部断点列表中移除硬件断点
        del self.hardware_breakpoints[slot]
        return True

    def bp_set_mem(self, address, size):
        mbi = MEMORY_BASIC_INFORMATION()
        # 判断是否能获取一个完整的MEMORY_BASIC_INFORMATION结构体，否则返回false
        if kernel32.VirtualQueryEx(self.h_process, address, byref(mbi), sizeof(mbi)) < sizeof(mbi):
            return False
        current_page = mbi.BaseAddress
        # 对整个内存断点区域所覆盖的所有内存页进行设置访问权限
        while current_page <= address + size:
            # 将这个内存页记录在列表中，以便于将这些保护页与操作系统或debuge进程自设的保护页区别开来
            self.guarded_pages.append(current_page)
            old_protection = c_ulong(0)
            if not kernel32.VirtualProtectEx(self.h_process, current_page, size,
                                             mbi.Protect | PAGE_GUARD, byref(old_protection)):
                return False
            # 以系统所设置的内存页大小作为增长单位，递增内存断点区域
            current_page += self.page_size
        # 将该内存断点记录进全局列表中
        self.memory_breakpoints[address] = (address, size, mbi)
        return True

    def func_resolve(self, dll, function):
        """
        提取函数地址
        """
        # Retrieves the handle of dynamic-link library
        handle = kernel32.GetModuleHandleW(dll)
        # Retrieves the address of an exported function or variable from the specified dynamic-link library (DLL).
        address = kernel32.GetProcAddress(handle, function)
        print(kernel32.GetLastError())
        kernel32.CloseHandle(handle)
        return address

    def enumerate_threads(self):
        """
        枚举线程
        """
        thread_entry = THREADENTRY32()
        thread_list = []
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)
        if snapshot is not None:
            # 调用Thread32First之前要先初始化dwSize
            thread_entry.dwSize = sizeof(thread_entry)
            success = kernel32.Thread32First(snapshot, byref(thread_entry))
            while success:
                if thread_entry.th32OwnerProcessID == self.pid:
                    thread_list.append(thread_entry.th32ThreadID)
                success = kernel32.Thread32Next(snapshot, byref(thread_entry))

            kernel32.CloseHandle(snapshot)
            return thread_list
        else:
            print("enumerate_threads fail.")
            return False

    def open_thread(self, thread_id):
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)
        if h_thread is not None:
            return h_thread
        else:
            print("[*] Could not obtain a valid thread handle.")
            return False

    def get_thread_context(self, thread_id):
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS  # context i386
        # Obtain a handle to the thread
        h_thread = self.open_thread(thread_id)
        if kernel32.GetThreadContext(h_thread, byref(context)):
            kernel32.CloseHandle(h_thread)
            return context
        else:
            print("get_thread_context fail.")
            return False

    def detach(self):
        if kernel32.DebugActiveProcessStop(self.pid):
            print("[*] Finished debugging. Exiting...")
            return True
        else:
            print("detach fail.")
            return False
