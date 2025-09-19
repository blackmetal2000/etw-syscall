## ETW

This tool comes to patch [ETW](https://learn.microsoft.com/pt-br/windows-hardware/drivers/devtest/event-tracing-for-windows--etw-) writing a RET instruction (`0xC3`) in `NtTraceEvent` address. Otherwise, this project only uses NT APIs functions with Direct Syscalls.

> ###### `NtOpenProcess`: get process handle <br> `NtQueryInformationProcess`: get NTDLL address <br> `LdrGetProcedureAddress`: get target function address <br> `NtProtectVirtualMemory`: change protection memory <br> `NtAllocateVirtualMemory`: allocate memory <br> `NtWriteVirtualMemory`: write memory <br> `NtReadVirtualMemory`: read memory


#### Before

![alt text](https://i.imgur.com/GbYnY4k.png)

#### After

![alt text](https://i.imgur.com/2ezpAfd.png)

#### What to expect?

```txt
PS C:\Windows\Temp> .\etw.exe 9136
[^] Process PEB ADDRESS: 713765781504
[^] Process NTDLL ADDRESS: 7FFF69770000
[^] Process NtTraceEvent ADDRESS: 7FFF6980E090, OFFSET: 9E090
[^] Changed PAGE_EXECUTE_READ to PAGE_EXECUTE_READWRITE!
[^] Enjoy!
PS C:\Windows\Temp>
```

![alt text](https://i.imgur.com/ANppvFo.png)
