#!/usr/bin/env python

import os
import sys
from pathlib import Path


def get_executable_askpass():
    return str(Path(sys.argv[0]).absolute().parent / 'sshh-askpass')


def main():
    if os.environ.get('PASSPHRASE'):
        # behave as ssh-askpass when ssh-add require passphrase
        print(os.environ['PASSPHRASE'])


if __name__ == '__main__':
    main()
