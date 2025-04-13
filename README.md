# RMTRD

### A driver for detecting and intercepting malicious threads creation in target process

## Features

**Detection**
 - detecting malicious thread created from user mode that calling CreateRemoteThread with start address pointed to LoadLibraryA(W) in kernel32.dll or kernelbase.dll
 - detecting malicious thread created from kernel mode that calling ZwCreateThreadEx with start address starts pointed to a wild address which allocated from ZwAllocateVirtualMemory
 - detecting malicious thread created from both user mode or kernel mode that its start address points to an instruction tramplion

**Interception**
 - intercepting malicious thread creation by making it exit gracefully
 - intercepting malicious thread creation by making it exit forcely

> [!NOTE]
> the driver project only demonstrates how to detecting and interceping malicious thread creation in process notepad.exe, user can add more complicated strategy rules to filter the process that needs to be protected  
> some code of this project is referenced from BlackBone and porting to rust  
you can find it here: [BlackBone](https://github.com/DarthTon/Blackbone) 

## How to Verify
### using process-hacker
- complie and start this driver
- prepare a DLL that can be used for injection and do something attracting attention such as pop up a message box in the DLL
- using process-hacker to inject that DLL into notepad.exe and to see if the message box is popped up

### using another kernel driver for injection
- prepare your own driver for injection, typically by creating a remote thread in kernel mode in process creation callbacks
- prepare a DLL for injection
- compile and start this driver
- start notepad.exe and to see if the message box is popped up

## Requirements

- wdk-sys 0.3.0 or higher
- WDK 10.0.22621.2428 or higher
- Windows SDK 10.0.22621.2428 or higher

> [!IMPORTANT]
> This project depends on wdk-sys 0.3.0 or higher  
> please follow the installation instructions in [windows-driver-rs](https://github.com/microsoft/windows-drivers-rs) before compiling

## License
rmtrd is licensed under the MIT License. Dependencies are under their respective licenses.