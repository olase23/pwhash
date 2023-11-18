#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
@author: Olaf Schmerse
@contact: olase23@yahoo.de
@copyright: © 2023 by Olaf Schmerse
@summary: script for creating password hashes

This software is licensed to you under the GNU General Public License,
version 2 (GPLv2). There is NO WARRANTY for this software, express or
implied, including the implied warranties of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. You should have received a copy of GPLv2
along with this software; if not, see
http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
"""

import argparse
import ctypes
import string
import os
import sys
from random import SystemRandom
import crypt

DEFAULT_ALGORITM = 'sha512'

PW_ALGORITHMS = {
    'sha512': ('$6$', 16),
    'sha256': ('$5$', 8),
    'md5': ('$1$', 8),
    'des': ('', 2),
    'bcrypt': ('$2b$', 22),
}

class CryptDataStruct(ctypes.Structure):

    CRYPT_OUTPUT_SIZE = 384
    CRYPT_MAX_PASSPHRASE_SIZE = 512
    CRYPT_DATA_RESERVED_SIZE = 767
    CRYPT_DATA_INTERNAL_SIZE = 30720

    _fields_ = [
        ("output", ctypes.c_char * CRYPT_OUTPUT_SIZE),
        ("setting", ctypes.c_char * CRYPT_OUTPUT_SIZE),
        ("input", ctypes.c_char * CRYPT_MAX_PASSPHRASE_SIZE),
        ("reserved", ctypes.c_char * CRYPT_DATA_RESERVED_SIZE),
        ("initialized", ctypes.c_char),
        ("internal", ctypes.c_char * CRYPT_DATA_INTERNAL_SIZE),
    ]

_saltchars = string.ascii_letters + string.digits + './'
_sr = SystemRandom()
verbose = 0

def parse_args():
    """Parse the command line arguments and return them"""
    parser = argparse.ArgumentParser()
    parser.add_argument('--text',
                        required=True,
                        help='input text')
    parser.add_argument('--salt', '-s',
                        dest='salt',
                        required=False,
                        help='using salt')
    parser.add_argument('--verbose', '-v',
                        dest='verbose',
                        action='store_true',
                        help='verbose mode')
    parser.add_argument('--des', '-d',
                        dest='des',
                        action='store_true',
                        help='use standard Unix password algorithm')
    parser.add_argument('--md5', '-1',
                        dest='md5',
                        action='store_true',
                        help='use MD5 password algorithm')
    parser.add_argument('--sha-256', '-5',
                        dest='sha256',
                        action='store_true',
                        help='use SHA256-based password algorithm')
    parser.add_argument('--sha-512',
                        '-6',
                        dest='sha512',
                        action='store_true',
                        help='use SHA512-based password algorithm')
    parser.add_argument('--bcrypt', '-b',
                        dest='bcrypt',
                        action='store_true',
                        help='use bcrypt password algorithm')
    args = parser.parse_args()

    return args

def mksalt(prefix, length=16, rounds=None):
    """ Gnereate salt for pwhashes. """

    if not isinstance(length, int):
        raise TypeError(f'{length.__class__.__name__} object cannot be '
                        f'interpreted as an integer')

    if rounds is not None and not isinstance(rounds, int):
        raise TypeError(f'{rounds.__class__.__name__} object cannot be '
                        f'interpreted as an integer')
    s = f'{prefix}'
    # handle salt generation for bcrypt
    if prefix == '$2b$':
        if rounds is None:
            log_rounds = 12
        else:
            log_rounds = int.bit_length(rounds - 1)
            if rounds != 1 << log_rounds:
                raise ValueError('rounds must be a power of 2')
            if not 4 <= log_rounds <= 31:
                raise ValueError('rounds out of the range 2**4 to 2**31')
        s += f'{log_rounds:02d}$'
    # handle salt generation based on SHA-256 or SHA-512
    elif prefix in ('$5$', '$6$'):
        if rounds is not None:
            if not 1000 <= rounds <= 999999999:
                raise ValueError('rounds out of the range 1000 to 999_999_999')
            s += f'rounds={rounds}$'

    s += ''.join(_sr.choice(_saltchars) for char in range(length))
    return s

def _crypt(word, salt=None):
    try:
        libcrypt = ctypes.CDLL("libcrypt.so.1", use_errno=True)
    except OSError as e:
        print("Error, could not create pw hash: ", e)
        return None

    if hasattr(libcrypt, "crypt_r"):
        crypt_r = libcrypt.crypt_r
        crypt_r.argtypes = (
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.POINTER(CryptDataStruct))
        crypt_r.restype = ctypes.c_char_p
    else:
        print("Error, could not create pw hash. Function crypt_r() not found.")
        return None

    crypt_data = CryptDataStruct()

    if isinstance(word, str):
        word = word.encode('utf-8')

    if salt is None:
        return None

    if isinstance(salt, str):
        salt = salt.encode('utf-8')

    result = crypt_r(word, salt, ctypes.byref(crypt_data))
    errno_value = ctypes.get_errno()
    ctypes.memset(ctypes.byref(crypt_data), 0, ctypes.sizeof(crypt_data))
    del crypt_data

    if errno_value != 0:
        print("Error, could not create pw hash. Function crypt_r() returned an error: ")
        print(os.strerror(ctypes.get_errno()))
        return

    return result.decode('utf-8') if result else None

def crypt(word, salt, alg):
    result = _crypt(word, salt)
    if verbose > 0:
        print("algorithm ", alg, "salt: ", salt)
        print("hashed password: ", result)
    else:
        print(result)


def abort(msg):
    print(msg)
    sys.exit(1)

def main():
    """
    Simple script to get a hashed password from text.
    """
    verbose = 0

    if sys.platform == "darwin" or sys.platform == "windows":
        abort(f"Error, OS {sys.platform} is not supported.")

    args = parse_args()

    if args.verbose is not False:
        verbose = 1

    input_text = args.text.strip()
    if isinstance(input_text, str):
        input_text = input_text.encode('utf-8')

    algorithm = DEFAULT_ALGORITM
    crypt_jobs = {}
    if args.salt is not None:
        salt = args.salt.strip()
        found = False
        if verbose > 0:
            print("using salt: ", salt)
        for method in PW_ALGORITHMS:
            prefix = PW_ALGORITHMS[method][0]
            if prefix != '' and salt.startswith(prefix):
                found = True
                algorithm = method
        if found is False:
            algorithm = 'des'
        if verbose > 0:
            print("Given salt uses method: ", algorithm)
        crypt_jobs[algorithm] = salt

        noargs = []
        for arg, value in vars(args).items():
            for algo in PW_ALGORITHMS:
                if arg == algo and arg != algorithm and value is True:
                    noargs.append(arg)
        if len(noargs) > 0 and verbose > 0:
            print("skipping algorithm(s) ", noargs)


    elif args.salt is None:
        for arg, value in vars(args).items():
            for method in PW_ALGORITHMS:
                if arg == method and value is True:
                    prefix = PW_ALGORITHMS[method][0]
                    length = PW_ALGORITHMS[method][1]
                    newsalt = mksalt(prefix, length)
                    crypt_jobs[method] = newsalt

        if len(crypt_jobs) == 0:
            prefix = PW_ALGORITHMS[DEFAULT_ALGORITM][0]
            length = PW_ALGORITHMS[DEFAULT_ALGORITM][1]
            newsalt = mksalt(prefix, length)
            crypt_jobs[DEFAULT_ALGORITM] = newsalt

    for method, salt_str in crypt_jobs.items():
        crypt(input_text, salt_str, method)
        if verbose > 0:
            print("-----------------------------------------------")

if __name__ == '__main__':
    main()
