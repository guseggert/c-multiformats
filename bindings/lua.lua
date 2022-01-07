local ffi = require("ffi")

ffi.cdef[[
	char* mb_err_str(int err);
	int mb_enc_by_name(char* name, int* enc);
	int mb_encode_as_size(uint8_t* input, size_t input_size, int encoding);
	int mb_encode_as(uint8_t* input, size_t input_size, int encoding, uint8_t* result_buf, size_t result_buf_size, size_t* result_size);
]]

local int_ptr = ffi.typeof"int[1]"
local size_t_ptr = ffi.typeof"size_t[1]"

local base_str = arg[1]
local input_str = arg[2]

local mb = ffi.load("./libmultibase.so.1")

function die_if_err (code)
   if code ~= 0 then
      local msg = mb.mb_err_str(code)
      io.stderr:write(ffi.string(msg))
      io.stderr:write("\n")
      os.exit(1)
   end
end

enc_ptr = int_ptr()
base_cstr = ffi.new("char[?]", #base_str + 1)
ffi.copy(base_cstr, base_str)

res = mb.mb_enc_by_name(base_cstr, enc_ptr)
die_if_err(res)

enc = enc_ptr[0]

input_bytes = ffi.new("uint8_t[?]", #input_str)
input_bytes_size = #input_str
ffi.copy(input_bytes, input_str, input_bytes_size)

size = mb.mb_encode_as_size(input_bytes, input_bytes_size, enc)

result_buf = ffi.new("uint8_t[?]", size)
result_size_ptr = size_t_ptr()
res = mb.mb_encode_as(input_bytes, input_bytes_size, enc, result_buf, size, result_size_ptr)
die_if_err(res)

result_size = result_size_ptr[0]

result_str = ffi.new("char[?]", result_size+1)
ffi.copy(result_str, result_buf, result_size)
result_str[result_size] = 0

print(ffi.string(result_str))
