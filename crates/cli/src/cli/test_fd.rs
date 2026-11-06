use std::os::fd::AsRawFd;

extern "C" {
    fn alarm(seconds: u32) -> u32;
    fn close(fd: i32) -> i32;
    fn dup(fd: i32) -> i32;
    fn dup2(oldfd: i32, newfd: i32) -> i32;
    fn pipe(pipefd: *mut i32) -> i32;
}

/// Restores a duplicated file descriptor when dropped.
pub struct SavedFd {
    target: i32,
    saved: i32,
    extra: Option<i32>,
}

impl SavedFd {
    pub fn redirect_to(target: i32, source: &impl AsRawFd) -> Self {
        let saved = unsafe { dup(target) };
        assert!(saved >= 0, "dup");
        assert!(unsafe { dup2(source.as_raw_fd(), target) } >= 0, "dup2");
        Self {
            target,
            saved,
            extra: None,
        }
    }

    /// Makes stdout a pipe so `console::Term::stdout()` is not a tty.
    pub fn stdout_to_pipe() -> Self {
        let mut ends = [0; 2];
        assert_eq!(0, unsafe { pipe(ends.as_mut_ptr()) }, "pipe");
        let mut saved = Self::redirect_to(1, &RawFd(ends[1]));
        unsafe { close(ends[1]) };
        saved.extra = Some(ends[0]);
        saved
    }
}

impl Drop for SavedFd {
    fn drop(&mut self) {
        unsafe {
            dup2(self.saved, self.target);
            close(self.saved);
            if let Some(extra) = self.extra {
                close(extra);
            }
        }
    }
}

/// `AsRawFd` for an already-open descriptor number.
struct RawFd(i32);

impl AsRawFd for RawFd {
    fn as_raw_fd(&self) -> i32 {
        self.0
    }
}

/// Fires `SIGALRM` if a coverage test blocks on the editor prompt.
pub struct Alarm;

impl Alarm {
    pub fn seconds(seconds: u32) -> Self {
        unsafe { alarm(seconds) };
        Self
    }
}

impl Drop for Alarm {
    fn drop(&mut self) {
        unsafe { alarm(0) };
    }
}

extern "C" {
    fn cfmakeraw(termios: *mut u8);
    fn openpty(amaster: *mut i32, aslave: *mut i32, name: *mut i8, termp: *mut u8, winp: *mut u8) -> i32;
    fn tcgetattr(fd: i32, termios: *mut u8) -> i32;
    fn tcsetattr(fd: i32, actions: i32, termios: *const u8) -> i32;
}

pub fn close_raw(fd: i32) {
    unsafe { close(fd) };
}

/// A pty whose slave can stand in for stdin and stdout.
pub struct Pty {
    master: std::cell::Cell<i32>,
    slave: i32,
}

impl Pty {
    pub fn open() -> Self {
        let mut master = 0;
        let mut slave = 0;
        assert_eq!(
            0,
            unsafe {
                openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            "openpty"
        );
        Self {
            master: std::cell::Cell::new(master),
            slave,
        }
    }

    pub fn make_raw(&self) {
        let mut termios = [0u8; 256];
        assert_eq!(0, unsafe { tcgetattr(self.slave, termios.as_mut_ptr()) }, "tcgetattr");
        unsafe { cfmakeraw(termios.as_mut_ptr()) };
        assert_eq!(0, unsafe { tcsetattr(self.slave, 0, termios.as_ptr()) }, "tcsetattr");
    }

    pub fn write_master(&self, bytes: &[u8]) {
        use std::io::Write;
        use std::os::fd::FromRawFd;

        let mut file = unsafe { std::fs::File::from_raw_fd(self.master.get()) };
        file.write_all(bytes).expect("write master");
        std::mem::forget(file);
    }

    /// Hands the master fd to the caller. Drop no longer closes it.
    pub fn take_master(&self) -> i32 {
        self.master.replace(-1)
    }

    pub fn attach_stdio(&self) -> (SavedFd, SavedFd) {
        let slave = RawFd(self.slave);
        let stdin = SavedFd::redirect_to(0, &slave);
        let stdout = SavedFd::redirect_to(1, &slave);
        (stdin, stdout)
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        unsafe {
            let master = self.master.get();
            if master >= 0 {
                close(master);
            }
            close(self.slave);
        }
    }
}
