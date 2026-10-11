"""Bound the trusted parser process. Never execute/import a target repository."""
import json
import os
from pathlib import Path
import subprocess
import sys


def windows_job(process, memory):
    import ctypes
    from ctypes import wintypes as w
    size = ctypes.c_size_t
    class Basic(ctypes.Structure):
        _fields_ = [('ProcessTime', ctypes.c_longlong), ('JobTime', ctypes.c_longlong),
                    ('Flags', w.DWORD), ('MinWorkingSet', size), ('MaxWorkingSet', size),
                    ('ActiveProcesses', w.DWORD), ('Affinity', size), ('Priority', w.DWORD), ('Scheduling', w.DWORD)]
    class IO(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in ('ReadOps','WriteOps','OtherOps','ReadBytes','WriteBytes','OtherBytes')]
    class Extended(ctypes.Structure):
        _fields_ = [('Basic',Basic), ('IO',IO), ('ProcessMemory',size), ('JobMemory',size), ('PeakProcess',size), ('PeakJob',size)]
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, w.LPCWSTR]; kernel.CreateJobObjectW.restype = w.HANDLE
    kernel.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
    kernel.SetInformationJobObject.restype = w.BOOL
    kernel.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]; kernel.AssignProcessToJobObject.restype = w.BOOL
    kernel.CloseHandle.argtypes = [w.HANDLE]; kernel.CloseHandle.restype = w.BOOL
    handle = kernel.CreateJobObjectW(None, None)
    if not handle: raise OSError('Cannot create parser job')
    config = Extended(); config.Basic.Flags = 0x100 | 0x2000; config.ProcessMemory = memory
    if not kernel.SetInformationJobObject(handle, 9, ctypes.byref(config), ctypes.sizeof(config)) or not kernel.AssignProcessToJobObject(handle, w.HANDLE(int(process._handle))):
        kernel.CloseHandle(handle); raise OSError('Cannot limit parser memory')
    return lambda: kernel.CloseHandle(handle)


def isolated_python(text, name, limitations, mode='STANDARD', max_nodes=50000,
                    max_memory_bytes=128_000_000, max_call_depth=4, seconds=30, max_findings=10000, execution=None):
    if execution is not None: execution['completed'] = False
    if max_memory_bytes < 32_000_000 or seconds <= 0:
        limitations.append('Presupuesto de memoria/tiempo insuficiente para parser: ' + name); return []
    payload = json.dumps(dict(text=text, name=name, mode=mode, max_nodes=max_nodes,
        max_memory_bytes=max_memory_bytes, max_call_depth=max_call_depth, seconds=seconds,
        max_findings=max_findings)).encode('utf-8')
    worker = Path(__file__).with_name('worker.py')
    process = None; close_job = None
    try:
        process = subprocess.Popen([sys.executable, '-I', '-B', str(worker), str(max_memory_bytes)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=worker.parent, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        if os.name == 'nt': close_job = windows_job(process, max_memory_bytes)
        stdout, _ = process.communicate(payload, timeout=seconds)
        if process.returncode != 0 or len(stdout) > 20_000_000: raise RuntimeError('Parser failure')
        result = json.loads(stdout)
        limitations.extend(result['limitations'])
        if execution is not None: execution['completed'] = result.get('completed', False)
        return result['findings']
    except subprocess.TimeoutExpired:
        limitations.append('Límite de tiempo del parser alcanzado: ' + name)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError):
        limitations.append('Parser aislado no disponible o límite de memoria excedido: ' + name)
    finally:
        if process and process.poll() is None: process.kill()
        if process: process.communicate()
        if close_job: close_job()
    return []
