from cryptography.hazmat.primitives.keywrap import aes_key_unwrap_with_padding, aes_key_unwrap
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
backend = default_backend()

km_mgs = "\x12\x20\x29\x01\x00\x00\x00\x00\x02\x00\x02\x00\x00\x00\x04\x04" \
"\x3a\x78\x19\x23\x7b\xc1\x8f\xe9\xcd\xe1\x09\x52\x83\xea\x5d\xf8" \
"\xed\x09\x74\x3d\x2e\x51\xe9\x7e\xc2\x96\x5d\x9d\x52\xd9\xce\xa8" \
"\x7c\xa6\x6f\x11\xe1\x8d\x3a\x73"

km_mgs_hex = "12202901000000000200020000000404" \
"3a7819237bc18fe9cde1095283ea5df8" \
"ed09743d2e51e97ec2965d9d52d9cea8" \
"7ca66f11e18d3a73"

# TODO: Use bitstream (https://pypi.org/project/bitstream/)
def parse_km_msg(msg):
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |S|  V  |   PT  |              Sign             |   Resv1   | KK|
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                              KEKI                             |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |     Cipher    |      Auth     |       SE      |     Resv2     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |             Resv3             |      SLen     |      KLen     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                              Salt                             |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                                                               |
    # +                          Wrapped Key                          +
    # |                                                               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    #print(type(msg))
    b  = bytes.fromhex(msg)
    S  = (b[0] >> 7) & 0x01 # 1 bit
    V  = (b[0] >> 4) & 0x07 # 3 bits
    PT = (b[0] >> 0) & 0x0F # 4 bits
    Sign = b[1] << 8 | b[2]
    Resv1 = (b[3] >> 2) & 0x3F # 6 bits
    KK = (b[3]) & 0x03 # 2 bits

    KEKI = (b[4] << (8 * 3)) + (b[5] << (8 * 2)) + (b[6] << (8 * 1)) + b[7]

    SE = b[10]

    SLen = b[15]
    KLen = b[15]

    Salt = 0
    for i in range(SLen * 4):
        Salt = (Salt << 8) | b[16 + i]

    ICV = 0
    ICV_offset = 16 + SLen * 4
    for i in range(8):
        ICV = (ICV << 8) | b[ICV_offset + i]

    SEK_wrapped = 0
    SEK_offset = ICV_offset + 8
    for i in range(KLen * 4):
        SEK_wrapped = (SEK_wrapped << 8) | b[SEK_offset + i]

    print(f"S:  {S}")
    print(f"V:  {V}")
    print(f"PT: {PT}")
    print(f"Sign: 0x{Sign:x} (expected: 0x2029)")
    print(f"Resv1: {Resv1}")
    print(f"KK: {KK}")
    print(f"KEKI: {KEKI}")
    print(f"SE: {SE}")
    print(f"SLen: {SLen}")
    print(f"KLen: {KLen}")

    print(f"Salt: 0x{Salt:x}")
    bSalt = Salt.to_bytes(SLen * 4, byteorder='big')
    bSaltLSB64 = bSalt[SLen * 4 - 64 // 8: SLen * 4]
    print(f"LSB(64, Salt): 0x{bSaltLSB64.hex()}")
    print(f"ICV: 0x{ICV:x}")
    print(f"SEK (wrapped): 0x{SEK_wrapped:x}")

    # SHA-1 is a deprecated hash algorithm that has practical known collision attacks.
    # You are strongly discouraged from using it. Existing applications should strongly consider moving away.
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA1(),
        length = 4 * KLen,
        salt = bSaltLSB64,
        iterations = 2048,
        backend = backend
    )

    KEK = kdf.derive(b"passphrase")
    print(f"KEK: 0x{KEK.hex()}")

    bSEK_wrapped = SEK_wrapped.to_bytes(KLen * 4, byteorder='big')
    print(f"SEK_wrapped: 0x{bSEK_wrapped.hex()}")

    #print(b[0] & 0x80)
    SEK = aes_key_unwrap_with_padding(KEK, SEK_wrapped.to_bytes(KLen * 4, byteorder='big'), backend=backend)
    #print(f"SEK: 0x{SEK:x}")

#cryptography.hazmat.primitives.keywrap.aes_key_unwrap

#print(km_mgs)
parse_km_msg(km_mgs_hex)