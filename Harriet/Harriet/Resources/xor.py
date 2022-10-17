#!/usr/bin/env python3

import sys

KEY = "pink9284floyd"


class XorCipher:
    __slots__ = ("key", "_key_length", "_fname", "_ciphertext", "_plaintext")

    def __init__(self, filename: str, xor_key: str) -> None:
        self.key = str(xor_key)
        self._key_length = len(self.key)
        self._fname = filename
        self._ciphertext = ""
        self._plaintext = b""

    def _xor_crypt(self) -> None:
        i = 0
        for char in self._plaintext:
            self._ciphertext += chr(char ^ ord(self.key[i % self._key_length]))
            i += 1

    def _print_ciphertext(self) -> None:
        xor_array = ("{ 0x" +
                     ", 0x".join(hex(ord(x))[2:]
                                 for x in self._ciphertext) + " };")
        print(xor_array)

    def run(self) -> None:
        try:
            with open(self._fname, "rb") as fp:
                self._plaintext = fp.read()
        except Exception as e:
            print(f"[-] Error with specified file({self._fname}): {e}",
                  file=sys.stderr)
            sys.exit(1)
        else:
            self._xor_crypt()
            self._print_ciphertext()
            return


def main():
    # xor key should be similar to the one in the C++ file(fud-uuid-shc.cpp). Please
    # endeavour to change it!!
    # Also the "file" opened by default is the file you supply at the command line

    # NOTE: You can port this class( XorCipher ) to your own scripts neatly.
    try:
        xor_crypt = XorCipher(filename=sys.argv[1], xor_key=KEY)
    except IndexError:
        print("[-] File argument needed! \n\t%s <file_to_xor_encrypt>" %
              sys.argv[0],
              file=sys.stderr)
        sys.exit(1)
    else:
        xor_crypt.run()


if __name__ == "__main__":
    main()
