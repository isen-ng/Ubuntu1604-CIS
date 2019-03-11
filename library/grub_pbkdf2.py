#!/usr/bin/env python

from __future__ import print_function
import argparse
from hashlib import pbkdf2_hmac
from os import urandom
from sys import stdin, stderr, exit as sysexit
from binascii import hexlify
from ansible.module_utils.basic import *

def grub_mkpasswd_pbkdf2(passphrase, iterCount=100000, saltLength=64):
    algo = 'sha512'

    try:
        binSalt = urandom(saltLength)
        hexSalt = hexlify(binSalt)
        passHash = hexlify(pbkdf2_hmac(algo, passphrase, binSalt, iterCount))
    except:
        print("Unexpected error generating hash!\n", file=stderr)
        raise

    return "grub.pbkdf2.{}.{}.{}.{}".format(algo, iterCount, hexSalt, passHash)


def main():
    module = AnsibleModule(
        argument_spec = dict(
            password = dict(no_log=True, required=True, type='str'),
            )
        )

    password = module.params['password']
    passwordHash = grub_mkpasswd_pbkdf2(password)
    module.exit_json(changed=False, passhash=passwordHash)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print()
        sysexit()