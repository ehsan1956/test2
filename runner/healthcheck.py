import sys
import platform
import socket
import os
from io import StringIO
from runner.banner import VERSION

def do_health_check(options, flag_set):
    cfg_file_path = "config.cfg"  # from flag_set, ferret dummy
    test = StringIO()
    test.write(f"Version: {VERSION}\n")
    test.write(f"Operative System: {sys.platform}\n")
    test.write(f"Architecture: {platform.machine()}\n")
    test.write(f"Go Version: {sys.version}\n")
    test.write(f"Compiler: {platform.python_compiler()}\n")

    test_result = "Ok" if os.access(cfg_file_path, os.R_OK) else "Ko"
    test.write(f'Config file "{cfg_file_path}" Read => {test_result}\n')

    test_result = "Ok" if os.access(cfg_file_path, os.W_OK) else "Ko"
    test.write(f'Config file "{cfg_file_path}" Write => {test_result}\n')

    test_result = "Ok"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("scanme.sh", 80))
        s.close()
    except Exception as e:
        test_result = f"Ko ({e})"
    test.write(f"IPv4 connectivity to scanme.sh:80 => {test_result}\n")

    test_result = "Ok"
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.connect(("scanme.sh", 80))
        s.close()
    except Exception as e:
        test_result = f"Ko ({e})"
    test.write(f"IPv6 connectivity to scanme.sh:80 => {test_result}\n")

    test_result = "Ok"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("scanme.sh", 53))
        s.close()
    except Exception as e:
        test_result = f"Ko ({e})"
    test.write(f"UDP connectivity to scanme.sh:53 => {test_result}\n")

    return test.getvalue()