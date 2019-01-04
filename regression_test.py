#!/usr/bin/env python

"""
A script to lint and test ProxyFS jason RPC client library code.
"""

from __future__ import print_function, unicode_literals
from threading import Timer

import os
import argparse
import functools
import logging
import platform
import contextlib
import subprocess
import shutil
import sys
import tempfile
import time


COLORS = {"bright red": '1;31', "bright green": '1;32'}

@contextlib.contextmanager
def return_to_wd():
    curdir = os.getcwd()
    try:
        yield
    finally:
        os.chdir(curdir)


@contextlib.contextmanager
def self_cleaning_tempdir(*args, **kwargs):
    our_tempdir = tempfile.mkdtemp(*args, **kwargs)
    try:
        yield our_tempdir
    finally:
        shutil.rmtree(our_tempdir, ignore_errors=True)


def proxyfs_binary_path(binary):
    try:
        gopath = os.environ["GOPATH"]
    except KeyError:
        color_print("$GOPATH must be set", 'bright red')
        os.exit(1)
    return os.path.join(gopath, "bin", binary)


def color_print(content, color=None):
    print("\x1b[{color}m{content}\x1b[0m".format(content=content,
                                                 color=COLORS[color]))


def proxyfs_package_path(package):
    try:
        gopath = os.environ["GOPATH"]
    except KeyError:
        color_print("$GOPATH must be set", 'bright red')
        os.exit(1)
    return os.path.join(gopath, "src/github.com/swiftstack/ProxyFS", package)


def color_print(content, color=None):
    print("\x1b[{color}m{content}\x1b[0m".format(content=content,
                                                 color=COLORS[color]))


def report(task, success=False):
    printer = color_print if sys.stdout.isatty() else \
        lambda *a, **kw: print(*a)
    if success:
        printer("{} {}".format(task, "succeeded!"), color="bright green")
    else:
        printer("{} {}".format(task, "failed!"), color="bright red")


def build_jrpcclient(options):
    failures = 0
    full_lib_path = os.path.dirname(os.path.abspath(__file__))
    print("Building Proxyfs RPC client library")
    make_success = not(bool(subprocess.call((['make', 'clean']))))
    failures += not make_success
    make_success = not(bool(subprocess.call((['make', 'all']))))
    failures += not make_success
    if not options.no_install:
        if 'Ubuntu' == platform.linux_distribution()[0]:
            install_cmd = ['make', 'install']
            if not options.deb_builder:
                install_cmd.insert(0, 'sudo')
                install_cmd.insert(1, '-E')
            make_success = not(bool(subprocess.call(install_cmd)))
            failures += not make_success
        if 'CentOS Linux' == platform.linux_distribution()[0]:
            install_cmd = ['make', 'installcentos']
            if not options.deb_builder:
                install_cmd.insert(0, 'sudo')
                install_cmd.insert(1, '-E')
            make_success = not(bool(subprocess.call(install_cmd)))
            failures += not make_success
    report("build_jrpcclient()", not failures)
    return failures


def wait_for_child(address, port, path="", interval=0.5, max_iterations=60,
                   process=None):
    """
    Wait until service at http://<address>:<port>/<path> is up.
    If process is provided, we will check the process has not returned before
    every request.
    We will return True if the service successfully comes up, False otherwise.

    :param address: string
    :param port: int
    :param path: string
    :param interval: float
    :param max_iterations: int
    :param process: subprocess
    :return: bool
    """
    # We're importing requests here to allow build process to work without
    # requests.
    import requests

    current_iteration = 0
    is_child_up = False
    while not is_child_up and current_iteration < max_iterations:
        time.sleep(interval)
        if process and process.poll():
            # Early exit if a process is provided and it returns a return code
            return False
        try:
            r = requests.get('http://{}:{}/{}'.format(address, port, path),
                             timeout=3)
            if r.status_code == 200:
                is_child_up = True
        except Exception:
            pass
        current_iteration += 1
    if not is_child_up:
        print("Service at http://{}:{}/{} is not up after {} "
              "iteration(s), with a {} seconds interval.".format(
            address, port, path, max_iterations, interval))
        try:
            print("Last status code was {}.".format(
                address, port, path, max_iterations, interval, r.status_code))
        except Exception:
            pass
    return is_child_up


def test_jrpcclient():
    private_ip_addr = "127.0.0.1"
    # arbitrary
    ramswift_port = 4592
    # 12347 instead of 12345 so that test can run if proxyfsd is already
    # running
    jsonrpc_port = 12347
    # 32347 instead of 32345 so that test can run if proxyfsd is already
    # running
    jsonrpc_fastport = 32347
    # 15347 instead of 15346 so that test can run if proxyfsd is already
    # running
    http_port = 15347

    color_printer = color_print if sys.stdout.isatty() else \
        lambda *a, **kw: print(*a)

    with self_cleaning_tempdir() as our_tempdir, open(os.devnull) as dev_null:
        ramswift = subprocess.Popen(
            [proxyfs_binary_path("ramswift"),
             "saioramswift0.conf",
             "Peer:Peer0.PrivateIPAddr={}".format(private_ip_addr),
             "SwiftClient.NoAuthTCPPort={}".format(ramswift_port)],
            cwd=proxyfs_package_path("ramswift")
        )

        print("Waiting for ramswift to be up...")
        if not wait_for_child(private_ip_addr, ramswift_port, "info",
                              process=ramswift):
            if ramswift.returncode:
                color_printer("Before starting test, nonzero exit status "
                              "returned from ramswift: "
                              "{}".format(ramswift.returncode),
                              color="bright red")
            else:
                color_printer("ramswift failed to start in a reasonable "
                              "amount of time", color="bright red")
            report("jrpcclient tests", False)

            # Clean up
            ramswift.terminate()

            # Print out ramswift's stdout since it exited unexpectedly
            if ramswift.stdout:
                print(ramswift.stdout.read())

            # If ramswift didn't return with a return code (simply not
            # returning OK status codes), we'll return 1 here.
            return ramswift.returncode or 1

        try:
            subprocess.check_call(
                [proxyfs_binary_path("mkproxyfs"),
                 "-N",
                 "CommonVolume",
                 "saioproxyfsd0.conf",
                 "SwiftClient.RetryLimit=1",
                 "Cluster.PrivateClusterUDPPort=18123",
                 "Logging.LogFilePath={}/{}".format(our_tempdir,
                                                    "proxyfsd_jrpcclient.log"),
                 "Peer:Peer0.PrivateIPAddr={}".format(private_ip_addr),
                 "SwiftClient.NoAuthTCPPort={}".format(ramswift_port),
                 "JSONRPCServer.TCPPort={}".format(jsonrpc_port),
                 "JSONRPCServer.FastTCPPort={}".format(jsonrpc_fastport),
                 "HTTPServer.TCPPort={}".format(http_port)],
                cwd=proxyfs_package_path("proxyfsd")
            )
        except subprocess.CalledProcessError as e:
            color_printer("mkproxyfs failed with returncode {}".format(
                e.returncode), color="bright red")
            ramswift.terminate()
            return e.returncode

        proxyfsd = subprocess.Popen(
            [proxyfs_binary_path("proxyfsd"),
             "saioproxyfsd0.conf",
             "SwiftClient.RetryLimit=1",
             "Cluster.PrivateClusterUDPPort=18123",
             "Logging.LogFilePath={}/{}".format(our_tempdir,
                                                "proxyfsd_jrpcclient.log"),
             "Peer:Peer0.PrivateIPAddr={}".format(private_ip_addr),
             "SwiftClient.NoAuthTCPPort={}".format(ramswift_port),
             "JSONRPCServer.TCPPort={}".format(jsonrpc_port),
             "JSONRPCServer.FastTCPPort={}".format(jsonrpc_fastport),
             "HTTPServer.TCPPort={}".format(http_port)],
            stdout=dev_null, stderr=dev_null,
            cwd=proxyfs_package_path("proxyfsd")
        )

        # Wait a moment for proxyfsd to get set "Up()" or until it returns with
        # a return code.
        print("Waiting for ProxyFS to be up...")
        if not wait_for_child(private_ip_addr, http_port, "version",
                              process=proxyfsd):
            if proxyfsd.returncode:
                color_printer("Before starting test, nonzero exit status "
                              "returned from proxyfsd daemon: "
                              "{}".format(proxyfsd.returncode),
                              color="bright red")
            else:
                color_printer("proxyfsd daemon failed to start in a "
                              "reasonable amount of time", color="bright red")
            report("jrpcclient tests", False)

            # Print out proxyfsd's stdout since it exited unexpectedly
            proxyfsd_logfile = "{}/{}".format(our_tempdir,
                                              "proxyfsd_jrpcclient.log")
            logfile = open(proxyfsd_logfile, 'r')
            print(logfile.read())
            logfile.close()

            # Clean up
            ramswift.terminate()
            # If proxyfsd didn't return with a return code (simply not
            # returning OK status codes), we'll return 1 here.
            return proxyfsd.returncode or 1

        rpc_config_string = "{}:{}/{}".format(private_ip_addr,
                                              jsonrpc_port,
                                              jsonrpc_fastport)

        jrpcclient_tests = subprocess.Popen(
            [os.path.join(".", "test"),
             "-r", rpc_config_string],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            cwd=os.getcwd()
        )

        # Put a time limit on the tests, in case they hang
        def kill_proc(p):
            color_printer("jrpcclient tests timed out!", color="bright red")
            p.kill()

        timeout_sec = 200
        timer = Timer(timeout_sec, kill_proc, [jrpcclient_tests])

        try:
            timer.start()

            if not options.verbose_jrpcclient:
                # This line gets all jrpcclient stdout at once, waits till
                # it's over
                jrpcclient_test_stdout, _ = jrpcclient_tests.communicate()

                # Emit test stdout only if there was a failure
                if jrpcclient_tests.returncode:
                    print(jrpcclient_test_stdout)

            else:
                # I'm not confident in this code yet; deadlock may be possible.

                # Get all jrpcclient stdout line by line.
                # Doesn't continue until the test is done.
                # (if thread is still running, it won't return)
                while True:
                    line = jrpcclient_tests.stdout.readline()
                    print(line, end="")
                    if (line == '' and jrpcclient_tests.poll() != None):
                        break
        finally:
            timer.cancel()

        proxyfsd.terminate()
        time.sleep(0.5)  # wait a moment for proxyfsd to get set "Down()"
        ramswift.terminate()

    report("jrpcclient tests", not jrpcclient_tests.returncode)

    return jrpcclient_tests.returncode


def main(options):
    failures = ""
    #color_print(go_version[:-1], "bright green")

    if not options.quiet:
        logging.basicConfig(format="%(message)s", level=logging.INFO)


    if options.just_test_libs:
        failures = test_jrpcclient()
    else:
        failures = build_jrpcclient(options)
        if not options.just_build_libs and not options.deb_builder:
            failures += test_jrpcclient()

    return failures

if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description=__doc__)
    arg_parser.add_argument('--cover', '-cover',
                            action='store_const', const='-cover',
                            help="include coverage statistics in test output")
    libs_group = arg_parser.add_mutually_exclusive_group()
    libs_group.add_argument('--just-build-libs', action='store_true',
                            help="only build C libraries")
    libs_group.add_argument('--just-test-libs', action='store_true',
                            help="only test C libraries")
    arg_parser.add_argument('--verbose-jrpcclient', action='store_true',
                            help="EXPERIMENTAL, DO NOT USE! "
                                 "emit jrpcclient test stdout even if no "
                                 "failures")
    arg_parser.add_argument('--no-install', action='store_true',
                            help="When building C libraries, do not attempt "
                                 "to install resulting objects")
    arg_parser.add_argument('--deb-builder', action='store_true',
                            help="Modify commands to run inside "
                                 "swift-deb-builder")
    arg_parser.add_argument('--quiet', '-q', action='store_true',
                            help="suppress printing of what commands are being"
                                 " run")
    options = arg_parser.parse_args()

    exit(main(options))
