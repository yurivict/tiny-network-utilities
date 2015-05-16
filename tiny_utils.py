

# Copyright (C) 2015 by Yuri Victorovich. All rights reserved.
# This code is licensed under BSD license.

## This module contains various common routibes of tiny-network-utilities package

import os, pwd, grp, sys
import errno
import signal
import atexit
import datetime

def tm_log():
    return datetime.datetime.now().strftime('[%Y-%m-%d %H:%M:%S %Z]')

def drop_privileges3(uid_name, gid_name, files):
    # get the uid/gid from the name
    new_uid = pwd.getpwnam(uid_name).pw_uid
    new_gid = grp.getgrnam(gid_name).gr_gid
    # set log file permissions so we can still write it
    for f in files:
        if f is not None:
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
    drop_privileges3('nobody', 'nogroup', files)

def do_daemonize(pid_file):
    pid = os.fork()
    if (pid > 0):
        sys.exit(0); # exit first parent
    os.chdir("/")
    os.setsid()
    os.umask(0)

    pid_init = os.getpid()
    pid = os.fork()
    if pid > 0:
        # initial process
        if pid_file is not None:
            write_pid_file2(pid_file, pid)
        sys.exit(0); # exit from second parent
    # wait for the initial process to finish so that pid file is written
    try:
        os.waitpid(pid_init, 0)
    except OSError as err:
        # ECHILD means that initial process has ended
        if err.errno != errno.ECHILD:
            raise
    # pig_file has to be deleted
    atexit.register(os.remove, pid_file)

def write_pid_file2(fname, pid):
    p = str(pid)
    f = open(fname, 'w')
    f.write(p)
    f.close()
    # it should always be the matching atexit.register(os.remove)

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

# common argument processing to avoid code repeat
def process_common_args(arg_daemonize, arg_pid_file, arg_unprivileged, arg_unprivileged_ug, log_file):
    # daemonize and write pid file
    if arg_daemonize:
        do_daemonize(arg_pid_file)
    elif arg_pid_file is not None:
        write_pid_file(arg_pid_file)
        atexit.register(os.remove, arg_pid_file)

    # lose privileges if requested
    if arg_unprivileged:
        if arg_unprivileged_ug is None:
            drop_privileges([log_file,arg_pid_file])
        else:
            drop_privileges3(arg_unprivileged_ug[0], arg_unprivileged_ug[1], [log_file,arg_pid_file])

