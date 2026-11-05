# Scheduler shortcuts

On Windows, enable **Global shortcuts: Ctrl+Shift+0 to 9** in the Scheduler tab. The shortcuts toggle pause for the first ten active tasks: `Ctrl+Shift+0` controls the first task, `Ctrl+Shift+1` the second, and so on. Shortcuts target their current positions, so removing a task changes the mapping of later tasks.

The shortcuts can be used while another application is focused. If another application already owns a combination, that combination remains unavailable and is identified in the scheduler; available shortcuts can still be used. Disable the checkbox to release them. They are also released when G-Earth Rust exits, and are disabled when it starts.

Global shortcut registration is currently implemented for Windows. Linux and macOS are not yet supported. Automated tests cover partial registration, cleanup and a synthetic Windows hotkey message on an isolated runner. A physical keyboard and a minimized window have not yet been tested interactively.
