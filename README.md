# RMTRD

EN | [中文](./README_zh_CN.md)

A kernel mode solution for detecting and preventing the creation of malicious
threads in a target process on Windows.

## Features

- Detects malicious threads created in user mode that call `CreateRemoteThread`
  with a start address pointing to `LoadLibraryA(W)` in `kernel32.dll` or
  `kernelbase.dll`.
- Detects malicious threads created in kernel mode that call `ZwCreateThreadEx`
  with a start address pointing to a wild address allocated by
  `ZwAllocateVirtualMemory`.
- Detects malicious threads created from either user mode or kernel mode with a
  start address pointing to an instruction jump point.
- Intercepts malicious thread creation by making it exit gracefully or
  forcefully.

## Requirements

- WDK 10.0.22621.2428 or higher
- Windows SDK 10.0.22621.2428 or higher.
- wdk-sys 0.3.0 or higher (installation instructions in [windows-drivers-rs])

## Demonstrations

<div align="center">

![](./assets/images/d1.gif)\
*Injection prevention against userland remote thread*

</div>

<div align="center">

![](./assets/images/d2.gif)\
*Injection prevention against kernel mode remote thread*

</div>

> [!NOTE]\
> This project demonstrates the detection and interception of malicious threads
> using `notepad.exe`. Users can implement more complex strategy rules to
> filter the processes that need protection.
>
> Some code in this project is adapted from [BlackBone] and has been ported to
> Rust.

## Testing and Validation

### Method 1: Using Process Hacker

1. Compile and start this driver.
1. Prepare a DLL for injection that performs an attention-grabbing action, such
   as displaying a message box.
1. Use [Process Hacker] to inject the DLL into `notepad.exe` and check if the
   message box appears.

### Method 2: Using Another Kernel Driver for Injection

1. Prepare your own driver for injection, typically by creating a remote thread
   in kernel mode during process creation callbacks.
1. Prepare a DLL for injection.
1. Compile and start this driver.
1. Launch `notepad.exe` and verify if the message box appears.

## License

rmtrd is licensed under the MIT License. Dependencies are under their
respective licenses.

[blackbone]: https://github.com/DarthTon/Blackbone
[process hacker]: https://github.com/winsiderss/systeminformer
[windows-drivers-rs]: https://github.com/microsoft/windows-drivers-rs
