# G-Python console

Open Extensions > G-Python live console. Select the Python executable (a full path is accepted), then use **Check Python dependencies**. The interpreter path and console title are saved with the desktop settings. The dependency probe runs on a worker with a 15-second limit, reports missing distributions and checks that G-Python and QtConsole can actually import.

This launcher requires Python 3.11 or later, G-Python 0.1.6 or later, QtConsole, PyQt5, jupyter-console, jupyter-client and ipykernel. Install these in the selected interpreter's environment, for example:

```sh
python -m pip install g-python==0.1.6 qtconsole PyQt5 jupyter-console ipykernel
```

**Open G-Python QtConsole** starts a local Jupyter kernel and connects the existing G-Python API to the Rust extension host. The console exposes `ext`, `HPacket`, `HMessage`, `Direction`, `hparsers`, `hunityparsers`, `htools`, `hunitytools`, `sleep` and the original send/intercept/event/start/stop/console/flags helpers. A running game connection is needed for game packet injection. Up to four consoles can be managed at once.

Launch credentials are transferred over the launcher's stdin, rather than process arguments or a temporary bootstrap file. Initialization is excluded from Jupyter history. The extension token is file-bound, single-use and expires after 60 seconds. Error reports redact the token and have a bounded size. The selected interpreter also starts QtConsole directly, without looking up another environment's jupyter executable.

Closing QtConsole shuts down the owned kernel. **Stop Python consoles** and application shutdown request cleanup on a worker, allow up to three seconds for graceful shutdown, then terminate the owned launcher group/job. Windows uses a kill-on-close Job Object; Linux uses a process group plus Jupyter's parent-process monitor for its independent kernel session. The kernel shutdown fixture checks the actual kernel PID on both systems.

## Validation and limits

Run [41364164969](https://github.com/Tear1338/G-Earth-Rust/actions/runs/41364164969) passes the real published G-Python fixtures on Windows and Linux. It checks authenticated startup, named injection toward the server, injection toward the client, named interception and modification in both directions, blocking and kernel shutdown. The PyPI 0.1.6 wheel is pinned to SHA-256 `baf5a0a6769c71d8cb88c3979b8d5a8802080fa7dbe747070df8e52420bd48d6`. The upstream Git main snapshot at `55681fd81d03595a0d37f168454247ee72a97409` was rejected as an oracle after its circular imports failed under Python 3.12.

The QtConsole smoke test starts the real Qt process in offscreen mode and checks that it remains running after startup. The other checks use actual Jupyter kernels and the published G-Python API. Interactive QtConsole rendering, real hotel scripting, every parser and the full original Python settings workflow remain untested. Packages are installed through the explicit terminal command above; there is no automatic package installation in the desktop application. Python scripts and Java extensions intentionally keep their external runtimes; the G-Earth host and desktop are implemented in Rust.
