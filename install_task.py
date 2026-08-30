"""
install_task.py

Registers RAM-Guard's monitor and watchdog as Windows Scheduled Tasks, so
both survive user logoff/reboot and automatically restart if either process
is killed or crashes. Addresses the otherwise-trivial "just kill the
python.exe" way to disable a plain script-based monitor with no
supervision at all.

Two tasks are created:
  RAMGuard-Monitor   runs `python main.py` at user logon, auto-restarting
                     on failure (RestartCount / RestartInterval).
  RAMGuard-Watchdog  runs `python watchdog.py --once` every 5 minutes,
                     independently of whether the monitor task is alive --
                     a watchdog that could be killed alongside what it's
                     watching isn't a watchdog (see watchdog.py).

This is Task Scheduler registration, not a true Windows Service (no
SYSTEM-account background service is created) -- deliberately: desktop
popup notifications need to run in the interactive user session, which a
SYSTEM-level service cannot do without significant extra complexity
(session-0 isolation). A logon-triggered scheduled task runs in the user's
own session and can show popups normally.

Usage:
    python install_task.py              # register both tasks
    python install_task.py --uninstall  # remove both tasks
    python install_task.py --status     # show current registration status
"""

import argparse
import platform
import subprocess
import sys
from pathlib import Path

TASK_MONITOR = "RAMGuard-Monitor"
TASK_WATCHDOG = "RAMGuard-Watchdog"

REPO_DIR = Path(__file__).resolve().parent
PYTHON_EXE = sys.executable


def _run_ps(script: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True,
    )


def install():
    monitor_ps = f"""
$action = New-ScheduledTaskAction -Execute '{PYTHON_EXE}' -Argument 'main.py' -WorkingDirectory '{REPO_DIR}'
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName '{TASK_MONITOR}' -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
"""
    watchdog_ps = f"""
$action = New-ScheduledTaskAction -Execute '{PYTHON_EXE}' -Argument 'watchdog.py --once' -WorkingDirectory '{REPO_DIR}'
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650)
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName '{TASK_WATCHDOG}' -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
"""
    for name, ps in [(TASK_MONITOR, monitor_ps), (TASK_WATCHDOG, watchdog_ps)]:
        result = _run_ps(ps)
        if result.returncode != 0:
            print(f"FAILED to register {name}:")
            print((result.stderr or result.stdout).strip())
        else:
            print(f"Registered scheduled task: {name}")


def uninstall():
    for name in [TASK_MONITOR, TASK_WATCHDOG]:
        _run_ps(f"Unregister-ScheduledTask -TaskName '{name}' -Confirm:$false -ErrorAction SilentlyContinue")
        print(f"Removed scheduled task (if present): {name}")


def status():
    result = _run_ps(
        "Get-ScheduledTask | Where-Object {$_.TaskName -like 'RAMGuard-*'} | "
        "Select-Object TaskName, State | Format-Table -AutoSize | Out-String"
    )
    output = result.stdout.strip()
    print(output if output else "No RAMGuard-* scheduled tasks currently registered.")


def main():
    if platform.system() != "Windows":
        print("install_task.py only supports Windows Task Scheduler.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Register/remove RAM-Guard as Windows Scheduled Tasks")
    parser.add_argument("--uninstall", action="store_true")
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args()

    if args.uninstall:
        uninstall()
    elif args.status:
        status()
    else:
        install()


if __name__ == "__main__":
    main()
