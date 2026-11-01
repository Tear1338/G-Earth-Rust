"""QtConsole lifecycle bridge. The application transfers credentials over stdin."""
import json
import sys

if len(sys.argv) > 1 and sys.argv[1] == "probe":
    import importlib
    from importlib.metadata import PackageNotFoundError, version
    packages = {}
    for name in ("g-python", "qtconsole", "PyQt5", "jupyter-console", "jupyter-client", "ipykernel"):
        try:
            packages[name] = version(name)
        except PackageNotFoundError:
            packages[name] = None
    issues = []
    if packages["g-python"] is not None:
        try:
            importlib.import_module("g_python.gextension")
        except Exception as error:
            issues.append("g-python cannot be imported: " + str(error)[:500])
    if packages["qtconsole"] is not None and packages["PyQt5"] is not None:
        try:
            importlib.import_module("qtconsole.qtconsoleapp")
        except Exception as error:
            issues.append("qtconsole cannot be imported: " + str(error)[:500])
    print(json.dumps({"python": list(sys.version_info[:3]), "packages": packages, "issues": issues}))
    raise SystemExit(0)

import subprocess
import threading
import time
from jupyter_client import KernelManager

config = json.loads(sys.stdin.readline())
stop = threading.Event()


def watch_input():
    # EOF means the Rust owner has gone away.
    for line in sys.stdin:
        if line.strip() == "stop":
            break
    stop.set()


threading.Thread(target=watch_input, daemon=True).start()
manager = KernelManager(kernel_name="python3")
client = None
window = None


def execute(code):
    request = client.execute(code, store_history=False)
    deadline = time.monotonic() + 30
    while True:
        if stop.is_set() or time.monotonic() >= deadline:
            raise RuntimeError("Python execution stopped or timed out")
        from queue import Empty
        try:
            response = client.get_shell_msg(timeout=0.1)
        except Empty:
            continue
        if response.get("parent_header", {}).get("msg_id") == request:
            content = response.get("content", {})
            if content.get("status") != "ok":
                raise RuntimeError(content.get("ename", "kernel error") + ": " + content.get("evalue", ""))
            return


try:
    manager.start_kernel(executable=sys.executable)
    client = manager.client()
    client.start_channels()
    client.wait_for_ready(timeout=20)
    if not stop.is_set():
        execute(config["init"])
        print("GEARTH_PYTHON_READY", flush=True)
        if config.get("headless"):
            execute(config["fixture"])
        else:
            command = [sys.executable, "-c", "from qtconsole.qtconsoleapp import main; main()", "--ConsoleWidget.include_other_output=True",
                       "--ConsoleWidget.gui_completion=droplist", "--KernelManager.autorestart=False",
                       "--JupyterConsoleApp.confirm_exit=False", "--existing", manager.connection_file]
            options = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
            if sys.platform == "win32":
                options["creationflags"] = subprocess.CREATE_NO_WINDOW
            window = subprocess.Popen(command, **options)
            startup_deadline = time.monotonic() + 2
            while time.monotonic() < startup_deadline and window.poll() is None and not stop.wait(0.05):
                pass
            if window.poll() is None and not stop.is_set():
                print("GEARTH_QT_RUNNING", flush=True)
            while not stop.wait(0.1) and window.poll() is None:
                pass
            if window.poll() not in (None, 0):
                raise RuntimeError("QtConsole exited with status " + str(window.returncode))
except Exception as error:
    message = str(error).replace(config.get("cookie", ""), "[token]")
    print("GEARTH_PYTHON_ERROR " + message[:2000], flush=True)
    raise SystemExit(1)
finally:
    if window is not None and window.poll() is None:
        window.terminate()
        try:
            window.wait(timeout=3)
        except subprocess.TimeoutExpired:
            window.kill()
    if client is not None:
        try:
            execute("ext.stop()")
        except Exception:
            pass
        client.stop_channels()
    if manager.has_kernel:
        manager.shutdown_kernel(now=True)
