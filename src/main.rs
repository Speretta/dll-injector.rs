pub mod error;

use std::{ffi::{c_void, CString}, mem, ptr, slice};

use dioxus::{desktop::tao::dpi::LogicalSize, prelude::*};
use error::{FileSelectorError, InjectorError};
use windows::{
    core::{GUID, PCSTR},
    Win32::{
        Foundation::{CloseHandle, HINSTANCE},
        System::{
            Com::{
                CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_ALL,
                COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
            },
            Diagnostics::Debug::WriteProcessMemory,
            LibraryLoader::{GetModuleHandleA, GetProcAddress},
            Memory::{VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, PAGE_READWRITE, MEM_RESERVE},
            ProcessStatus::{K32EnumProcessModules, K32EnumProcesses, K32GetModuleBaseNameA},
            Threading::{
                CreateRemoteThread, OpenProcess, WaitForSingleObject, PROCESS_ALL_ACCESS,
                PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
            },
            WindowsProgramming::INFINITE,
        },
        UI::Shell::{IFileDialog, SIGDN_FILESYSPATH},
    },
};

fn main() {
    dioxus::desktop::launch_cfg(app, |c| {
        c.with_window(|w| {
            w.with_title("DLL Injector")
                .with_resizable(false)
                .with_inner_size(LogicalSize::new(320.0, 350.0))
        })
    });
}

fn app(cx: Scope) -> Element {
    let pid = use_state(&cx, || 0u32);
    let path = use_state(&cx, || String::new());
    let debug_value = use_state(&cx, || String::new());
    let search_value = use_state(&cx, || String::new());


    cx.render(rsx! {
        style { [include_str!("./assets/main.css")] }
        div {
                id: "maindiv",
            
            

            ul{
                id: "listparent",

                li{
                    class: "listchild",
                    label{
                        id: "search_label",

                        "Process Name"
                    }
                }

                li{
                    class: "listchild",
                    
                    input{
                        oninput: move |e| search_value.set(e.value.clone()),
                        
                    }
                }

                div{
                    id: "processlistdiv",
                        ul{
                        id: "processlist",
                            
                        unsafe{
                            show_all_process().unwrap()
                            .into_iter()
                            .filter(|(_, proc_name)|{
                                proc_name.to_ascii_uppercase().contains(search_value.to_ascii_uppercase().as_str()) || search_value.is_empty()
                            })
                            .map(|(proc_pid, proc_name)|{
                                rsx! {
                                    li{
                                        class: "processlistchild",
                
                                        onclick: move |_|{
                                            pid.set(proc_pid);
                                            debug_value.set(format!("Selected PID: {proc_pid}"))
                                        },
                
                                        "{proc_name} | {proc_pid}"
                
                                    }
                                }
                            })
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
                        p{ 
                            id: "debug",
                            "{debug_value}"
                        }
                
                    
                }
            }
    }
    })
}

unsafe fn show_all_process() -> Option<Vec<(u32, String)>> {
    let mut a_processes = [0u32; 1024];
    let mut cb_needed = 0u32;
    if !K32EnumProcesses(
        &mut a_processes as *mut _ as *mut u32,
        mem::size_of_val(&a_processes) as u32,
        &mut cb_needed,
    )
    .as_bool()
    {
        return None;
    }
    let mut vec = a_processes
        .iter()
        .filter_map(|proc| {
            if *proc != 0 {
                let h_process =
                    OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, *proc);
                if let Ok(h_process) = h_process {
                    let mut h_mod = HINSTANCE(0);
                    let mut cb_needed = 0u32;
                    if K32EnumProcessModules(
                        h_process,
                        &mut h_mod,
                        mem::size_of_val(&h_mod) as u32,
                        &mut cb_needed,
                    )
                    .as_bool()
                    {
                        let mut proc_name_chars = [0; 260];
                        K32GetModuleBaseNameA(h_process, h_mod, &mut proc_name_chars);
                        CloseHandle(h_process);
                        let mut length = 260;

                        //Maybe split can be used in here
                        'trim_end: for i in 0..259 {
                            if proc_name_chars[259 - i] == 0 && length > 0 {
                                length -= 1;
                            } else {
                                break 'trim_end;
                            }
                        }
                        return Some((
                            *proc,
                            String::from_utf8_lossy(&proc_name_chars[0..length]).to_string(),
                        ));
                    }
                    CloseHandle(h_process);
                }

                None
            } else {
                None
            }
        })
        .collect::<Vec<(u32, String)>>();
    vec.sort_by(|(a, _), (b, _)| a.cmp(b));
    Some(vec)
}

unsafe fn show_file_dialog() -> Result<String, FileSelectorError> {
    if CoInitializeEx(
        ptr::null(),
        COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE,
    )
    .is_err()
    {
        return Err(FileSelectorError::COINITIALIZE);
    }
    let guid = &GUID::from_values(
        0xDC1C5A9C,
        0xE88A,
        0x4DDE,
        [0xA5, 0xA1, 0x60, 0xF8, 0x2A, 0x20, 0xAE, 0xF7],
    ) as *const _ as *const GUID;
    let hr: IFileDialog = match CoCreateInstance(guid, None, CLSCTX_ALL) {
        Ok(fldialog) => fldialog,
        Err(_) => return Err(FileSelectorError::COCREATEINSTANCE),
    };
    if hr.Show(None).is_err() {
        return Err(FileSelectorError::SHOWFILEDIALOG);
    }
    let hr = match hr.GetResult() {
        Ok(result) => result,
        Err(_) => return Err(FileSelectorError::GETFILEPATH),
    };
    let hr = match hr.GetDisplayName(SIGDN_FILESYSPATH) {
        Ok(path) => path,
        Err(_) => return Err(FileSelectorError::GETFILEPATH),
    };
    let hr = match String::from_utf16_lossy(slice::from_raw_parts(hr.0, 260))
        .split_once("\0")
    {
        Some(path) => path.0.to_string(),
        None => return Err(FileSelectorError::GETFILEPATH),
    };
    CoUninitialize();
    Ok(hr)
}

unsafe fn start_inject(dll_path: &str, pid: u32) -> Result<(), InjectorError> {

    
    let dll_path_len = dll_path.as_bytes().len();
    
    println!("{dll_path_len}");


    let h_process = match OpenProcess(PROCESS_ALL_ACCESS, false, pid) {
        Ok(h_process) => h_process,
        Err(_) => return Err(InjectorError::PID),
    };

    let proccess_dll_path = VirtualAllocEx(
        h_process,
        ptr::null(),
        dll_path_len,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
    );

    WriteProcessMemory(
        h_process,
        proccess_dll_path,
        dll_path as *const _ as *const c_void,
        dll_path_len,
        ptr::null_mut(),
    );

    let kernel32_cstring = match CString::new("Kernel32.dll"){
        Ok(kernel32_cstring) => kernel32_cstring,
        Err(_) => return Err(InjectorError::MODULEHANDLE),
    };

    let module_handle_a = match GetModuleHandleA(PCSTR(kernel32_cstring.as_ptr() as *const u8)) {
        Ok(module_handle_a) => module_handle_a,
        Err(_) => return Err(InjectorError::MODULEHANDLE),
    };

    let loadlibrary_cstring = match CString::new("LoadLibraryA"){
        Ok(loadlibrary_cstring) => loadlibrary_cstring,
        Err(_) => return Err(InjectorError::PROCADRESS),
    };

    let kernel_proc = match GetProcAddress(module_handle_a, PCSTR(loadlibrary_cstring.as_ptr() as *const u8)) {
        Some(kernel_proc) => kernel_proc,
        None => return Err(InjectorError::PROCADRESS),
    };
    let h_load_thread = match CreateRemoteThread(
        h_process,
        ptr::null(),
        0,
        Some(*(&kernel_proc as *const _ as *const extern "system" fn(*mut c_void) -> u32)),
        proccess_dll_path,
        0,
        ptr::null_mut(),
    ) {
        Ok(module_handle_a) => module_handle_a,
        Err(_) => return Err(InjectorError::REMOTETHREAD),
    };

    WaitForSingleObject(h_load_thread, INFINITE);

    VirtualFreeEx(h_process, proccess_dll_path, dll_path_len, MEM_RELEASE);

    CloseHandle(h_process);

    println!("Dll injected at {proccess_dll_path:?}");

    Ok(())
}
