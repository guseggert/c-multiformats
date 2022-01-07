import ctypes
from ctypes import byref, POINTER, c_uint8, c_size_t, c_uint, c_char_p
import sys

# run with: python bindings/python.py base2 'yes mani !'
# another example: python bindings/python.py base64 '+++' | base64 -d ; echo

encoding_arg = sys.argv[1]
input_arg = sys.argv[2]

mb = ctypes.CDLL("./libmultibase.so")

mb.mb_encode.argtypes = [POINTER(c_uint8), c_size_t, c_uint, POINTER(c_uint8), c_size_t,  POINTER(c_size_t)]
mb.mb_encode_size.argtypes = [POINTER(c_uint8), c_size_t, c_uint]
mb.mb_encode_size.restype = c_size_t
mb.mb_encode_as.argtypes = [POINTER(c_uint8), c_size_t, c_uint, POINTER(c_uint8), c_size_t,  POINTER(c_size_t)]
mb.mb_encode_as_size.argtypes = [POINTER(c_uint8), c_size_t, c_uint]
mb.mb_encode_as_size.restype = c_size_t
mb.mb_enc_by_name.argtypes = [c_char_p, POINTER(c_uint)]
mb.mb_err_str.argtypes = [c_uint]
mb.mb_err_str.restype = c_char_p

def die_if_err(code):
    if code != 0:
        msg = mb.mb_err_str(res).decode()
        print(msg, file=sys.stderr)
        exit(1)

# lookup encoding
enc_name = ctypes.create_string_buffer(encoding_arg.encode())
enc = c_uint()
res = mb.mb_enc_by_name(enc_name, byref(enc))
die_if_err(res)

# encode
inp = input_arg.encode()

inp_b_t = ctypes.c_uint8 * len(inp)
inp_b = inp_b_t(*[c_uint8(b) for b in inp])
inp_b_size = c_size_t(len(inp))

result_buf_size = mb.mb_encode_as_size(inp_b, inp_b_size, enc)
result_buf = (c_uint8 * result_buf_size)()
result_size = c_size_t()

res = mb.mb_encode_as(inp_b, inp_b_size, enc, result_buf, c_size_t(result_buf_size), byref(result_size))
die_if_err(res)

print(bytes(result_buf[:result_size.value]).decode())
