

# Copyright (C) 2015 by Yuri Victorovich. All rights reserved.
# This code is licensed under BSD license.

## This is the module that recomputes IP and UDP packet checksums

import os, pwd, grp, sys
import signal

def drop_privileges(uid_name, gid_name, files):
    # get the uid/gid from the name
    new_uid = pwd.getpwnam(uid_name).pw_uid
    new_gid = grp.getgrnam(gid_name).gr_gid
    # set log file permissions so we can still write it
    for f in files:
        os.chown(f, new_uid, new_gid)
        os.chmod(f, 0o664)
    # remove group privileges
    os.setgroups([])
    # set uid/gid
    os.setgid(new_gid)
    os.setuid(new_uid)
    # set the conservative umask
    os.umask(0o077)

def drop_privileges(files):
    drop_privileges('nobody', 'nogroup', files)

def do_daemonize(pid_file):
    pid = os.fork()
    if (pid > 0):
        sys.exit(0); # exit first parent
    os.chdir("/")
    os.setsid()
    os.umask(0)

    pid = os.fork()
    if pid > 0:
        if pid_file is not None:
            write_pid_file2(pid_file, pid)
        sys.exit(0); # exit from second parent

def write_pid_file2(f, pid):
    p = str(pid)
    f = open(f, 'w')
    f.write(p)
    f.close()

def write_pid_file(f):
    write_pid_file2(f, os.getpid())

def exit_gracefully(signum, frame, original_sigint, log):
    log('exiting on signal %d' %signum)
    sys.exit(1)

def handle_signals(log):
    original_sigint = signal.getsignal(signal.SIGINT)
    bound_exit_gracefully = lambda signum, frame: exit_gracefully(signum, frame, original_sigint, log)
    signal.signal(signal.SIGINT, bound_exit_gracefully)
    signal.signal(signal.SIGTERM, bound_exit_gracefully)
    signal.signal(signal.SIGINT, bound_exit_gracefully)
    signal.signal(signal.SIGALRM, bound_exit_gracefully)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)

