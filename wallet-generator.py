import codecs
import csv
import os
import time

import ecdsa
from Crypto.Hash import keccak


def gen():
    private_key_bytes = os.urandom(32)
    key = ecdsa.SigningKey.from_string(private_key_bytes,
                                       curve=ecdsa.SECP256k1).verifying_key
    key_bytes = key.to_string()
    private_key = codecs.encode(private_key_bytes, 'hex')
    public_key = codecs.encode(key_bytes, 'hex')

    public_key_bytes = codecs.decode(public_key, 'hex')

    h = keccak.new(digest_bits=256)
    h.update(public_key_bytes)
    keccak_digest = h.hexdigest()

    address = '0x' + keccak_digest[-40:]
    return address, public_key, private_key


def main():
    file_name = "{}.csv".format(int(time.time()))
    with open(file_name, 'w', newline='') as csvfile:
        w = csv.writer(csvfile, delimiter=',',
                       quotechar='|', quoting=csv.QUOTE_MINIMAL)
        w.writerow(["Address", "Public key", "Private key"])
        for _ in range(10):
            address, public_key, private_key = gen()
            w.writerow([address, public_key.decode(), private_key.decode()])


if __name__ == '__main__':
    main()
