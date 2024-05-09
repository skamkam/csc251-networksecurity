#!/usr/bin/env python

## Name: Sarah Kam
## Resources:

import os

class OTP:
    def encrypt(self, key: bytes, msg: str):
        """
        :param key: bytes
        :param msg: str
        :return: hexadecimal-str
        """
        msgbin = msg.encode('ascii')
                        # encode msg str into sequence of ASCII bytes
        msglen = len(msgbin)
        cipherints = []
        ciphertext = "" # create a destination for encrypted string
                        # msgbin & key are both type byte
        for i in range(msglen):
            cipherints.append(msgbin[i] ^ key[i])
                        # msgbin[i] and key[i] are type int
                        # ^ (xor) works btwn 2 ints, returns an int
                        # then store xor'd int in list of ints
        cipherbytes = bytes(cipherints)
                        # turn list of ints into a single byte type obj
        ciphertext = cipherbytes.hex()
                        # use .hex() to turn byte obj into a hex string
                        # return a hexadecimal string in ciphertext
        return ciphertext



    def decrypt(self, key: bytes, ciphertext: hex):
        """
        :param key: bytes
        :param ciphertext: hex-str
        :return: str
        """
        ciphbin = bytes.fromhex(ciphertext)
                        # convert ciphertext hex str into bytes
        msglen = len(ciphbin)
        msg = ""

        for i in range(msglen):
            xor = ciphbin[i] ^ key[i]
                        # xor ciphbin bytes with bytes from key
            msg += chr(xor)
                        # convert xor'd byte to character and append to msg
        return msg



    def key_generator(self, length: int):
        """
        :param length: int
        :return: bytes
        """
        key = os.urandom(length)
                        # generates a random key the length of the message
        return key


def main():
    otp = OTP()

    # generate random key
    print("keys:")
    print("-" * 5)
    keys = [otp.key_generator(len(msg)) for msg in messages]
    [print(key) for key in keys]
    print('-' * 80)

    # encrypt:
    print("ciphertexts:")
    print("-" * 11)
    ciphertexts = [otp.encrypt(key, msg) for key, msg in zip(keys, messages)]
    [print(ctext) for ctext in ciphertexts]
    print('-' * 80)

    # decrypt
    print("plaintexts:")
    print("-" * 10)
    plaintexts = [otp.decrypt(key, c) for key, c in zip(keys, ciphertexts)]
    [print(ptext) for ptext in plaintexts]
    print('-' * 80)


if __name__ == "__main__":
    messages = ["I taste a liquor never brewed",
                "From Tankards scooped in Pearl",
                "Not all the Frankfort Berries",
                "Yield such an Alcohol!",
                "Inebriate of air am I",
                "And Debauchee of Dew",
                "Reeling thro endless summer days",
                "From inns of molten Blue",
                "When 'Landlords' turn the drunken Bee",
                "Out of the Foxglove's door",
                "When Butterflies renounce their 'drams'",
                "I shall but drink the more!",
                "Till Seraphs swing their snowy Hats",
                "And Saints to windows run",
                "To see the little Tippler",
                "Leaning against the Sun!"]

    main()
