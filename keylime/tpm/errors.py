class TpmError(Exception):
    pass

class SignatureError(TpmError):
    pass

class PackedDataMismatch(SignatureError):
    pass

class QualifyingDataMismatch(PackedDataMismatch):
    pass

class ObjectNameMismatch(PackedDataMismatch):
    pass

class HashAlgorithmMismatch(SignatureError):
    pass

class SignatureAlgorithmMismatch(SignatureError):
    pass

class IncorrectSignature(SignatureError):
    pass
