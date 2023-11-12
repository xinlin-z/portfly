#!/usr/bin/env python3
"""
Local/Remote Port Forwarding in Python.

Features:
1, Non-Blocking Socket.
2, Event IO.
3, TCP/UDP Tunnel.
4, Multi-Connection.

Author:   xinlin-z
Github:   https://github.com/xinlin-z/portfly
Blog:     https://cs.pynote.net
License:  MIT
"""
import os
import socket
from socket import IPPROTO_TCP, TCP_NODELAY
import selectors
import logging as log
import argparse
import random
import multiprocessing as mp
import threading
import time
from typing import Iterator, Generator
from dataclasses import dataclass
from base64 import b64encode, b64decode
from functools import partial
import hashlib


# seed
random.seed()
# type alias
sk_t = socket.socket


def cx(bmsg: bytes, b64: bool=False) -> bytes:
    """ when b64 is False, there's only one extra byte """
    a = random.randint(0,255)
    t = random.randint(65,90)
    b = bytes((a,)) + bytes(c^a for c in bmsg)
    return b64encode(b)+bytes((t,)) if b64 else b


def dx(bmsg: bytes, b64: bool=False) -> bytes:
    bmsg = b64decode(bmsg[:-1]) if b64 else bmsg
    a = bmsg[0]
    return bytes(c^a for c in bmsg[1:])


cxb = partial(cx, b64=True)
dxb = partial(dx, b64=True)


SK_IO_CHUNK_LEN = 4096
UDP_RECV_LEN    = 1472  # 1500-20-8
UDP_SEND_LEN    = 1444
MAX_STREAM_ID   = 0xFFFFFFFF
HB_BASE_INTV    = 20
BOL = 'little'  # byte order little
BOB = 'big'     # byte order big
START_IDX       = 0x0406A000


"""
Message Format:

* 4 bytes, total length, little endian
* 4 bytes, stream id, big endian
* 1 byte, type:
    0x01, Heart Beat (zero payload)
    0x02, Normal Data
    0x03, New Connection (zero payload)
    0x04, Connection Down (zero payload)
* variable length payload >=0
"""
MSG_HB = b'\x01'
MSG_ND = b'\x02'
MSG_NC = b'\x03'
MSG_CD = b'\x04'


def nrclose_socket(sk: sk_t) -> None:
    """ non-raise close socket """
    try:
        sk.shutdown(socket.SHUT_RDWR)
        sk.close()
    except OSError:
        return


class trafix():
    """ traffic exchanging class """

    @dataclass
    class sk_buf:
        sk: sk_t
        buf: bytes = b''

    # plt_sendto, send_sk_gen_udp, recv_sk_gen_udp are three
    # interfaces used by UDP tunnel.

    def pkt_sendto(self, pt, cont, idx, recv_max_idx=0):
        # First 2 bytes is total length, last 8 bytes is packet index.
        if pt == 'A':    # ack
            pkt = int.to_bytes(50+16-7,2,BOL) \
                        + b'A' \
                        + bytes(random.randint(0,255) for _ in range(32)) \
                        + int.to_bytes(recv_max_idx,4,BOL) \
                        + int.to_bytes(idx,4,BOL)
            pkt += hashlib.md5(pkt).digest()
        elif pt == 'D':  # data
            self.uidx += 1
            pkt = int.to_bytes(len(cont)+14+16-7,2,BOL) \
                        + b'D' \
                        + cont \
                        + int.to_bytes(self.uidx,4,BOL)
            pkt += hashlib.md5(pkt).digest()
        elif pt == 'R':  # raw, when resend
            pkt = cont

        # udp session, no taddr yet. The initial heartbeat.
        if not self.taddr:
            if pt == 'D':
                self.noack[self.uidx] = pkt
            return 1

        plen = len(pkt)

        # Send!
        # even for resend, every time the xor byte is different.
        slen = self.sk.sendto(cx(pkt) if self.x else pkt, self.taddr)

        if slen == plen+(1 if self.x else 0):
            #if pt == 'A':
            #    log.debug('[%d] %s %d %d -->', self.port, pt, idx, plen)
            if pt == 'D':
                log.debug('[%d] %s %d %d -->', self.port, pt, self.uidx, plen)
                self.noack[self.uidx] = pkt
            if pt == 'R':
                idx = int.from_bytes(pkt[-4-16:-16], BOL)
                log.debug('[%d] %s %d %d -->', self.port, pt, idx, plen)
            return 1
        else:
            log.error('[%d] sendto return less! %s plen=%d slen=%d',
                                            self.port, pt, plen, slen)
            return 0

    def send_sk_gen_udp(self, sk):
        data = b''
        resend_time = time.time()
        while True:
            # yield includes none ack udp packets
            noack_size = 0
            for rd in self.noack.values():
                noack_size += len(rd)
            bmsg, sid = yield len(data)+noack_size

            if bmsg is not None:
                data += (len(bmsg)+8).to_bytes(4,BOL) \
                                + sid.to_bytes(4,BOB) \
                                + bmsg
            try:
                # resend data in noack
                if time.time()-resend_time > 0.5:
                    for rd in self.noack.values():
                        if self.pkt_sendto('R',rd,-1) == 0:
                            break
                    resend_time = time.time()
                # normal send
                while len(data):
                    if self.pkt_sendto('D',data[:UDP_SEND_LEN],-1) == 0:
                        break
                    data = data[UDP_SEND_LEN:]
            except BlockingIOError:
                continue

    def recv_sk_gen_udp(self, sk: sk_t):
        recv_max_idx = START_IDX
        data = b''
        while True:
            try:
                # recv
                rd, taddr = sk.recvfrom(UDP_RECV_LEN)
                if self.x:
                    rd = dx(rd)
                # init target addr
                if not self.taddr:
                    self.taddr = taddr
                    log.warning('init udp taddr %s', str(taddr))
                # check taddr
                elif taddr != self.taddr:
                    log.error('different udp taddr!')
                    continue
                # deal packet
                plen = len(rd)
                if plen>2 and int.from_bytes(rd[:2],BOL)==plen:
                    # check md5
                    rd, md5 = rd[:-16], rd[-16:]
                    if hashlib.md5(rd).digest() != md5:
                        log.error('recv illegal packet, md5 wrong!')
                        continue
                    # check type
                    t = rd[2:3]
                    if t not in (b'A',b'D'):
                        log.error('recv illegal packet, type wrong!')
                        continue
                    # get idx
                    recv_idx = int.from_bytes(rd[-4:], BOL)
                    # if ack
                    if t == b'A':
                        rmidx = int.from_bytes(rd[-8:-4], BOL)
                        log.debug('[%d] A %d %d <--',self.port,recv_idx,rmidx)
                        self.noack.pop(recv_idx, None)
                        for k in tuple(self.noack.keys()):
                            if k <= rmidx:
                                self.noack.pop(k, None)
                    # if data
                    else:  # t == b'D':
                        log.debug('[%d] D %d %d <--', self.port,recv_idx,plen)
                        if (recv_idx > recv_max_idx
                                and recv_idx not in self.fdata):
                            # save data
                            self.fdata[recv_idx] = rd[3:-4]
                            # concatenate
                            while (nid:=recv_max_idx+1) in self.fdata:
                                data += self.fdata[nid]
                                self.fdata.pop(nid)
                                recv_max_idx = nid
                            # yield msg
                            while(datalen:=len(data)) > 4:
                                msglen = int.from_bytes(data[:4], BOL)
                                if datalen >= msglen:
                                    sid = int.from_bytes(data[4:8], BOB)
                                    msg = data[8:msglen]
                                    yield sid, msg[:1], msg[1:]
                                    data = data[msglen:]
                                else:
                                    break
                        self.pkt_sendto('A', None, recv_idx, recv_max_idx)
            except BlockingIOError:
                yield None, b'\x00', b''

    # send_sk_gen an recv_sk_gen are used for tcp tunnel.

    def send_sk_gen(self, sk: sk_t) \
                    -> Generator[int, tuple[bytes|None,int], None]:
        """ socket nonblocking send generator """
        data = b''
        while True:
            bmsg, sid = yield len(data)
            if bmsg is not None:
                if self.x: bmsg = cx(bmsg)
                data += (len(bmsg)+8).to_bytes(4,BOL) \
                                + sid.to_bytes(4,BOB) \
                                + bmsg
            try:
                while len(data):
                    if (i:=sk.send(data[:SK_IO_CHUNK_LEN])) == -1:
                        raise ConnectionError('send_sk_gen send -1')
                    data = data[i:]
            except BlockingIOError:
                continue

    def recv_sk_gen(self, sk: sk_t) \
                    -> Iterator[tuple[int|None,bytes,bytes]]:
        """ socket nonblocking recv generator,
            yield sid,type,msg """
        data = b''
        while True:
            try:
                d = sk.recv(SK_IO_CHUNK_LEN)
                if len(d) == 0:
                    raise ConnectionError('recv_sk_gen recv 0')
                data += d
                while (dlen:=len(data)) > 4:
                    mlen = int.from_bytes(data[:4], BOL)
                    if dlen >= mlen:
                        sid = int.from_bytes(data[4:8], BOB)
                        msg = dx(data[8:mlen]) if self.x else data[8:mlen]
                        yield sid, msg[:1], msg[1:]
                        data = data[mlen:]
                    else:
                        break
            except BlockingIOError:
                yield None, b'\x00', b''

    def recv_sk_gen_conn(self, sk: sk_t) -> Iterator[bytes]:
        """ socket nonblocking recv generator, one shot """
        while True:
            try:
                data = sk.recv(SK_IO_CHUNK_LEN)
                if len(data) == 0:
                    raise ConnectionError('recv_sk_gen_conn recv 0')
                yield data
            except BlockingIOError:
                return

    def send_sk_gen_conn(self, sid: int) -> int:
        skb = self.sdict[sid]
        data = skb.buf
        try:
            while len(data):
                if (i:=skb.sk.send(data[:SK_IO_CHUNK_LEN])) == -1:
                    raise ConnectionError('send_sk_gen_conn send -1')
                data = self.sdict[sid].buf = data[i:]
        except BlockingIOError:
            pass
        return len(data)

    def flush(self) -> int:
        """ flush all sending socket, return left bytes number """
        tunnel_left = self.gen_send.send((None,0))
        sk_left = 0
        for sid in list(self.sdict.keys()):
            try:
                sk_left += self.send_sk_gen_conn(sid)
            except OSError as e:
                log.info('[%d] sid %d down while flush',self.port,sid,str(e))
                tunnel_left = self.gen_send.send((MSG_CD,sid))
                self.clean(sid)
        return tunnel_left + sk_left

    def __init__(self, config: dict) -> None:
        self.session_type = config['session_type']
        self.role = config['role']
        if self.session_type == 'udp':
            self.uidx = START_IDX
            self.noack = {}
            self.fdata = {}
            self.sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sk.setblocking(False)
            if config['is_server']:
                self.sk.bind(('',config['tunnel_udp_port']))
                self.taddr = None
            else:
                self.taddr = (config['tunnel_udp_ip'],config['tunnel_udp_port'])
            self.gen_recv = self.recv_sk_gen_udp(self.sk)
            self.gen_send = self.send_sk_gen_udp(self.sk)
        elif self.session_type == 'tcp':
            self.sk = config['tunnel_tcp_sk']
            self.sk.setblocking(False)
            self.gen_recv = self.recv_sk_gen(self.sk)
            self.gen_send = self.send_sk_gen(self.sk)
        next(self.gen_send)

        # selector
        self.sel = selectors.DefaultSelector()
        self.sel.register(self.sk, selectors.EVENT_READ)

        # retrive argv and set accordingly
        self.port = int(config['listen_port'])
        self.x = config['tunnel_x']
        if self.role == 's':
            self.pserv = config['listen_sk']
            self.sid = 1          # sid, stream id
            self.sel.register(self.pserv, selectors.EVENT_READ)
        else:
            self.target = (config['target_ip'], config['target_port'])

        self.sdict: dict[int, trafix.sk_buf] = {}
        self.kdict: dict[sk_t,int] = {}    # socket --> sid
        self.reg: int = 0
        self.unreg: int = 0

        # heartbeat params and send one,
        # to make udp server know its client
        self.heartbeat_time = time.time()
        self.heartbeat_max = 0
        self.gen_send.send((MSG_HB,0))

        # event loop
        try:
            self.loop()
        except Exception as e:
            log.error('[%d] exception: %s', self.port, str(e))
            log.exception(e)
            for skb in self.sdict.values():
                nrclose_socket(skb.sk)
        # the end
        nrclose_socket(self.sk)
        self.sel.unregister(self.sk)
        if self.role == 's':
            nrclose_socket(self.pserv)
        log.warning('[%d] closed', self.port)

    def try_send_heartbeat(self) -> None:
        if self.heartbeat_max > 8:
            raise ConnectionError('heartbeat max is reached')
        now = time.time()
        if now - self.heartbeat_time > HB_BASE_INTV:
            self.gen_send.send((MSG_HB,0))
            log.info('[%d] send heartbeat', self.port)
            self.heartbeat_time = now + random.randint(0,39)
            self.heartbeat_max += 1

    def update_sid(self) -> None:
        # sid 0 is used for heartbeat,
        # sid should be incremented sequentially to avoid conflict.
        while True:
            self.sid = self.sid+1 if self.sid!=MAX_STREAM_ID else 1
            if self.sid not in self.sdict.keys():
                break

    def clean(self, sid: int) -> None:
        """ delete sid from sdict,
            delete sk from kdict,
            close socket,
            unregister sk from selector. """
        assert len(self.sdict) == len(self.kdict)
        _skb = self.sdict.pop(sid)
        sk = _skb.sk
        if sk:
            self.kdict.pop(sk, None)
            nrclose_socket(sk)
            self.sel.unregister(sk)
            self.unreg += 1
            log.debug('[%d] unreg %d', self.port, self.unreg)

    def event_pass(self, events) -> None:  # type: ignore
        p = self.port
        for fd,_ in events:
            # new connections in server role
            if self.role=='s' and fd.fileobj==self.pserv:
                s, addr = self.pserv.accept()
                self.gen_send.send((MSG_NC,self.sid))
                log.info('[%d] accept %s, sid %d', p, str(addr), self.sid)
                s.setsockopt(IPPROTO_TCP, TCP_NODELAY, True)
                s.setblocking(False)             # set nonblocking
                self.sel.register(s, selectors.EVENT_READ)
                self.reg += 1
                log.debug('[%d] reg %d', self.port, self.reg)
                self.sdict[self.sid] = trafix.sk_buf(s)
                self.kdict[s] = self.sid
                self.update_sid()
            # recv from tunnel
            elif fd.fileobj == self.sk:
                while True:
                    sid, t, bmsg = next(self.gen_recv)
                    log.debug('[%d] recv from tunnel, type: %s', p, t)
                    if sid is not None:
                        # new connection in client role
                        if t == MSG_NC:
                            try:
                                s = socket.create_connection(self.target,
                                                             timeout=2)
                                log.info('[%d] connect target %s ok, sid %d',
                                         p, str(self.target), sid)
                                s.setsockopt(IPPROTO_TCP, TCP_NODELAY, True)
                                s.setblocking(False)
                                self.sel.register(s, selectors.EVENT_READ)
                                self.reg += 1
                                log.debug('[%d] reg %d', p, self.reg)
                                self.sdict[sid] = trafix.sk_buf(s)
                                self.kdict[s] = sid
                            except OSError as e:
                                log.error('[%d] connect %s failed: %s',
                                          p, str(self.target), str(e))
                                self.gen_send.send((MSG_CD,sid))
                        # connection down
                        elif t == MSG_CD:
                            if sid in self.sdict.keys():
                                log.info('[%d] close sid %d by peer', p, sid)
                                self.clean(sid)
                        # heartbeat
                        elif t == MSG_HB:
                            log.info('[%d] recv heartbeat', p)
                            self.heartbeat_max = 0
                        # data
                        else:
                            assert t == MSG_ND
                            try:
                                if sid in self.sdict.keys():
                                    self.sdict[sid].buf += bmsg
                                    self.send_sk_gen_conn(sid)
                            except OSError:
                                log.info('[%d] sid %d is closed while send',
                                         p, sid)
                                self.gen_send.send((MSG_CD,sid))
                                self.clean(sid)
                    else:
                        break
            # recv from connections
            else:
                try:
                    sid = self.kdict[fd.fileobj]
                except KeyError:
                    continue
                gen_data = self.recv_sk_gen_conn(fd.fileobj)
                while True:
                    try:
                        data = next(gen_data)
                    except OSError as e:
                        log.info('[%d] sid %d donw when recv, %s',p,sid,str(e))
                        self.gen_send.send((MSG_CD,sid))
                        self.clean(sid)
                        break
                    except StopIteration:
                        break
                    self.gen_send.send((MSG_ND+data,sid))  # send data

    def loop(self) -> None:
        while True:
            bytes_left = self.flush()
            if bytes_left != 0:
                # log.debug('[%d] flushed, bytes left %d', self.port, bytes_left)
                events = self.sel.select(0)  # just a polling
            else:
                events = self.sel.select(HB_BASE_INTV)
            # if no socket ready to be read,
            if len(events) == 0:
                # log.debug('[%d] no events', self.port)
                # it might be a chance to send heartbeat.
                self.try_send_heartbeat()
                # it's better to wait a while before next flush.
                if bytes_left != 0:
                    time.sleep(0.1)
                continue
            self.event_pass(events)


# tunnel init msg
magic_bmsg = b'ask for REopening a PORT'
magic_breply = b'Done'


def zombie_reaper():
    while True:
        try:
            pid, stat = os.wait()
            log.warning('reap zombie pid %d status %s' % (pid,stat))
        except ChildProcessError:
            time.sleep(60)


def server_main(saddr: tuple[str,int]) -> None:
    threading.Thread(target=zombie_reaper, args=(), daemon=True).start()
    log.warning('init zombie reaper thread')
    serv = socket.create_server(saddr)
    log.warning('init server listen at %s', str(saddr))

    config = {}
    config['is_server'] = True

    while True:
        sk, faddr = serv.accept()
        log.warning('accept connection from %s', str(faddr))
        sk.settimeout(3)
        sk.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
        rf = sk.makefile('rb')
        try:
            if dxb(rf.readline().strip()) == magic_bmsg:
                # recv
                forward_mode = dxb(rf.readline().strip())
                log.warning('forwarding mode %s', forward_mode)
                transprot = dxb(rf.readline().strip())
                log.warning('transport protocol %s', transprot)
                udpport = int(dxb(rf.readline().strip()))
                log.warning('udp port %d', udpport)
                if forward_mode == b'R':
                    listen_port = int(dxb(rf.readline().strip()))
                    pserv = socket.create_server(('', listen_port))
                    log.warning('create server at port %d', listen_port)
                else:  # forward_mode == b'L':
                    target_ip = dxb(rf.readline().strip())
                    target_port = int(dxb(rf.readline().strip()))
                    log.warning('target addr %s:%s', target_ip, target_port)
                x = eval((dxb(rf.readline().strip())).decode())
                log.warning('encryption %d', x)
                # reply
                sk.sendall(cxb(magic_breply) + b'\n')
                # process parameters
                config['tunnel_x'] = x
                if forward_mode == b'R':
                    config['role'] = 's'
                    config['listen_sk'] = pserv
                    config['listen_port'] = listen_port
                else:  # if forward_mode == b'L':
                    config['role'] = 'c'
                    config['listen_port'] = -1
                    config['target_ip'] = target_ip
                    config['target_port'] = target_port
                if transprot == b'tcp':
                    config['session_type'] = 'tcp'
                    config['tunnel_tcp_sk'] = sk
                else:  # if transprot == b'udp':
                    config['session_type'] = 'udp'
                    config['tunnel_udp_port'] = udpport
                    nrclose_socket(sk)
                # launching process
                mp.Process(target=trafix, args=(config,), daemon=True).start()
                log.warning('process launched...')
            else:
                raise ValueError('magic bmsg error')
        except Exception as e:
            log.error('exception %s', str(faddr))
            log.exception(e)
            nrclose_socket(sk)


def client_main(forward_mode: bytes,
                transprot: bytes,
                udpport: int,
                mapping: str,
                saddr: tuple[str,int],
                x: bool) -> None:
    listen_port, target_ip, target_port = mapping.split(':')
    listen_port = int(listen_port)
    target_port = int(target_port)

    config = {}
    config['is_server'] = False
    config['listen_port'] = listen_port
    config['target_ip'] = target_ip
    config['target_port'] = target_port
    config['tunnel_x'] = x

    while True:
        try:
            # if local port forwarding
            if forward_mode == b'L':
                pserv = socket.create_server(('', listen_port))
                log.warning('port %d is ready here', listen_port)
            # connect server, send parameters
            sk = socket.create_connection(saddr)
            sk.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
            sk.sendall(cxb(magic_bmsg) + b'\n')
            sk.sendall(cxb(forward_mode) + b'\n')
            sk.sendall(cxb(transprot) + b'\n')
            sk.sendall(cxb(str(udpport).encode()) + b'\n')
            if forward_mode == b'R':
                sk.sendall(cxb(str(listen_port).encode()) + b'\n')
            else:
                sk.sendall(cxb(target_ip.encode()) + b'\n')
                sk.sendall(cxb(str(target_port).encode()) + b'\n')
            sk.sendall(cxb(str(int(x)).encode()) + b'\n')
            # read the only reply
            rf = sk.makefile('rb')
            if dxb(rf.readline().strip()) == magic_breply:
                if forward_mode == b'R':
                  log.warning('connect server %s ok, port %d is ready there',
                                                    str(saddr), listen_port)
                else:
                  log.warning('connect server %s ok', str(saddr))
            else:
                raise ValueError('magic_breply is not match')
            # thread parameters
            if forward_mode == b'R':
                config['role'] = 'c'
                config['listen_port'] = -1
                config['target_ip'] = target_ip
                config['target_port'] = target_port
            else:  # if mode == b'L':
                config['role'] = 's'
                config['listen_sk'] = pserv
                config['listen_port'] = listen_port
            if transprot == b'tcp':
                config['session_type'] = 'tcp'
                config['tunnel_tcp_sk'] = sk
            else:  # transprot == b'udp':
                config['session_type'] = 'udp'
                config['tunnel_udp_ip'] = saddr[0]
                config['tunnel_udp_port'] = udpport
                nrclose_socket(sk)
            # start thread and join
            th = threading.Thread(target=trafix, args=(config,), daemon=True)
            th.start()
            th.join()
        except Exception as e:
            log.exception(e)
        finally:
            nrclose_socket(sk)
            if forward_mode == b'L':
                nrclose_socket(pserv)
            time.sleep(8)


_VER = 'portfly V0.30 by xinlin-z '\
       ' (https://github.com/xinlin-z/portfly)'


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-V', '--version', action='version', version=_VER)
    parser.add_argument('--log', choices=('INFO','DEBUG'), default='WARNING')
    parser.add_argument('-x', action='store_true',
                        help='apply simple encryption to traffic')
    end_type = parser.add_mutually_exclusive_group(required=True)
    end_type.add_argument('-s', '--server', action='store_true')
    end_type.add_argument('-c', '--client', action='store_true')
    parser.add_argument('-L', action='store_true',
                        help='local port forwarding')
    parser.add_argument('-u', '--udp', type=int,
                        help='udp tunnel')
    parser.add_argument('settings')
    args = parser.parse_args()

    log.basicConfig(format='%(asctime)s: %(levelname)s: %(message)s',
                    level=eval('log.'+args.log))

    # python portfly.py -s server_listen_ip:port
    if args.server:
        if args.x or args.L or args.udp:
            log.warning('-x, -L and -u are ignored in server side')
        ip, port = args.settings.split(':')
        server_main((ip.strip(),int(port)))
    # python portfly.py -c [-x] [-L] [-u port] mapping_port:target_ip:port+server_ip:port
    else:
        mapping, saddr = args.settings.strip().split('+')
        server_ip, server_port = saddr.strip().split(':')
        forward_mode = b'L' if args.L else b'R'
        transprot = b'udp' if args.udp else b'tcp'
        udpport = int(args.udp) if args.udp else 0
        client_main(forward_mode,
                    transprot,
                    udpport,
                    mapping.strip(),
                    (server_ip,int(server_port)),
                    args.x)


