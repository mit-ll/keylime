import secrets

from keylime.models.base.types.binary import Binary


# TODO: Add documentation
class Nonce(Binary):
    @staticmethod
    def generate(num_of_bits, enforce_entropy=True):
        if num_of_bits % 8 != 0:
            raise ValueError("Nonce.generate() must receive a value which is a multiple of 8")

        if enforce_entropy is True and num_of_bits < 128:
            raise ValueError("a nonce produced by Nonce.generate() should have a length of 128 bits or greater")

        return secrets.token_bytes(int(num_of_bits / 8))
