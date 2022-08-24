use std::fmt;

pub enum FileSelectorError {
    COINITIALIZE,
    COCREATEINSTANCE,
    SHOWFILEDIALOG,
    GETFILEPATH,
}

impl fmt::Display for FileSelectorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                FileSelectorError::COINITIALIZE => "COINITIALIZE error",
                FileSelectorError::COCREATEINSTANCE => "COCREATEINSTANCE error",
                FileSelectorError::SHOWFILEDIALOG => "SHOWFILEDIALOG error",
                FileSelectorError::GETFILEPATH => "GETFILEPATH error",
            }
        )
    }
}

impl fmt::Debug for FileSelectorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                FileSelectorError::COINITIALIZE => "COINITIALIZE error",
                FileSelectorError::COCREATEINSTANCE => "COCREATEINSTANCE error",
                FileSelectorError::SHOWFILEDIALOG => "SHOWFILEDIALOG error",
                FileSelectorError::GETFILEPATH => "GETFILEPATH error",
            }
        )
    }
}

pub enum InjectorError {
    DLLPATH,
    PID,
    MODULEHANDLE,
    PROCADRESS,
    REMOTETHREAD,
}

impl fmt::Display for InjectorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                InjectorError::DLLPATH => "DLL Path error",
                InjectorError::PID => "PID error",
                InjectorError::MODULEHANDLE => "MODULE_HANDLE error",
                InjectorError::PROCADRESS => "PROCADRESS error",
                InjectorError::REMOTETHREAD => "REMOTE_THREAD error",
            }
        )
    }
}

impl fmt::Debug for InjectorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                InjectorError::DLLPATH => "DLL Path error",
                InjectorError::PID => "PID error",
                InjectorError::MODULEHANDLE => "MODULE_HANDLE error",
                InjectorError::PROCADRESS => "PROCADRESS error",
                InjectorError::REMOTETHREAD => "REMOTE_THREAD error",
            }
        )
    }
}
