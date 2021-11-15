#![no_main]
#![no_std]
#![feature(asm)]

use core::panic::PanicInfo;
use core::ptr;

pub enum Syscall {
    NtTerminateProcess = 0x2c,
}

fn exit(handle: *const (), status: u32) {
    unsafe {
        asm!("mov r10, rcx",
             "syscall",
             in("eax") (Syscall::NtTerminateProcess as u32),
             in("edx") status,
             in("ecx") handle);
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern fn _start() {
    exit(ptr::null_mut(), 123);
}
