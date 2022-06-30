pub mod error;


use std::{ffi::c_void, ptr, slice};

use dioxus::{prelude::*, desktop::tao::dpi::LogicalSize};
use error::{InjectorError, FileSelectorError};
use windows::{
    core::GUID,
    Win32::{
        Security::SECURITY_ATTRIBUTES,
        System::{
            Com::{
                CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_ALL,
                COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
            },
            Diagnostics::Debug::{WriteProcessMemory, SymEnumProcesses},
            LibraryLoader::{GetModuleHandleA, GetProcAddress},
            Memory::{VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, PAGE_READWRITE},
            Threading::{CreateRemoteThread, OpenProcess, WaitForSingleObject, PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
            WindowsProgramming::INFINITE,
        },
        UI::Shell::{IFileDialog, SIGDN_FILESYSPATH},
    },
};

fn main() {
    dioxus::desktop::launch_cfg(app, |c| c.with_window(|w| {
        w
        .with_title("DLL Injector")
        .with_resizable(false)
        .with_inner_size(LogicalSize::new(320.0, 320.0))
    }));
}

fn app(cx: Scope) -> Element {
    let pid = use_state(&cx, || 0u32);
    let path = use_state(&cx, || String::new());
    let debug_value = use_state(&cx, || String::new());
    cx.render(rsx! {
        style { [include_str!("./assets/main.css")] }
        div {
                id: "maindiv",
            ul{
                id: "listparent",
                
                li {
                    class: "listchild",
                    input {
                        placeholder: "PID number",
                        r#type: "number",
                        onchange:move |event|{
                            pid.set(event.value.parse().unwrap());
                        }
                    }
                }

                li {
                    class: "listchild",
                    button {
                        id: "selectdllbutton",
                        onclick: move |_|{
                            unsafe{
                                match show_file_dialog(){
                                    Ok(path_text) => {path.set(path_text.clone()); debug_value.set(path_text);},
                                    Err(e) => {debug_value.set(e.to_string());}
                                }
                            }
                        },

                        "Select DLL"
                    }
                }

                li {
                    class: "listchild",
                    button {
                        id: "injectdllbutton",
                        onclick: move |_|{
                            unsafe{
                                println!("{pid:?} | {path:?}",);
                                match  start_inject(path, *pid.get()){
                                    Ok(_) => {debug_value.set(String::from("Injected!"));},
                                    Err(e) => {debug_value.set(e.to_string());}
                                }
                            }
                        
                        },

                        "Inject!"
                    }
                }

                li {
                    class: "listchild",
                    h1{ 
                        id: "debug",
                        "{debug_value}"
                    }
                }
            }
    }
    })
}

unsafe fn show_all_process(){
        

    let hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ, false, 0);
}


unsafe fn show_file_dialog() -> Result<String, FileSelectorError> {
        if CoInitializeEx(ptr::null(), COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE,).is_err(){return Err(FileSelectorError::COINITIALIZE);}
        let guid = &GUID::from_values(
            0xDC1C5A9C,
            0xE88A,
            0x4DDE,
            [0xA5, 0xA1, 0x60, 0xF8, 0x2A, 0x20, 0xAE, 0xF7],
        ) as *const _ as *const GUID;
        let hr: IFileDialog = match CoCreateInstance(guid, None, CLSCTX_ALL){
            Ok(fldialog) => fldialog,
            Err(_) => return Err(FileSelectorError::COCREATEINSTANCE),
        };
        if hr.Show(None).is_err() {return Err(FileSelectorError::SHOWFILEDIALOG);}
        let hr = match hr.GetResult(){
            Ok(result) => result,
            Err(_) => return Err(FileSelectorError::GETFILEPATH),
        };
        let hr = match hr.GetDisplayName(SIGDN_FILESYSPATH){
            Ok(path) => path,
            Err(_) => return Err(FileSelectorError::GETFILEPATH),
        };
        let hr = match String::from_utf16_lossy(slice::from_raw_parts(hr.0, 257 as usize)).split_once("\0"){
            Some(path) => path.0.to_string(),
            None => return Err(FileSelectorError::GETFILEPATH),
        };
        CoUninitialize();
        Ok(hr)
}

unsafe fn start_inject(dll_path: &str, pid: u32) -> Result<(), InjectorError> {
    let h_process = match OpenProcess(PROCESS_ALL_ACCESS, false, pid) {
        Ok(h_process) => h_process,
        Err(_) => return Err(InjectorError::PID),
    };

    let proccess_dll_path = VirtualAllocEx(
        h_process,
        0 as *const c_void,
        dll_path.len(),
        MEM_COMMIT,
        PAGE_READWRITE,
    );

    WriteProcessMemory(
        h_process,
        proccess_dll_path,
        dll_path as *const _ as *const c_void,
        dll_path.len(),
        0 as *mut usize,
    );

    let module_handle_a = match GetModuleHandleA("Kernel32.dll") {
        Ok(module_handle_a) => module_handle_a,
        Err(_) => return Err(InjectorError::MODULEHANDLE),
    };

    let kernel_proc = match GetProcAddress(module_handle_a, "LoadLibraryA") {
        Some(kernel_proc) => kernel_proc,
        None => return Err(InjectorError::PROCADRESS),
    };
    let h_load_thread = match CreateRemoteThread(
        h_process,
        0 as *const SECURITY_ATTRIBUTES,
        0,
        Some(*(&kernel_proc as *const _ as *const extern "system" fn(*mut c_void) -> u32)),
        proccess_dll_path,
        0,
        0 as *mut u32,
    ) {
        Ok(module_handle_a) => module_handle_a,
        Err(_) => return Err(InjectorError::REMOTETHREAD),
    };

    WaitForSingleObject(h_load_thread, INFINITE);

    VirtualFreeEx(h_process, proccess_dll_path, dll_path.len(), MEM_RELEASE);

    println!("Dll injected at {proccess_dll_path:?}");

    Ok(())
}