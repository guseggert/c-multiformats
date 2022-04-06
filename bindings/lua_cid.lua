local ffi = require("ffi")

ffi.cdef[[
	char* cid_err_str(int err);
	int cid_str_to_bytes(char* cid, uint8_t* buf, size_t buf_size, size_t* bytes_size);
	int cid_validate(uint8_t* cid, size_t cid_size);
]]

local cid = ffi.load("./libcid.so.1")

local int_ptr = ffi.typeof"int[1]"
local size_t_ptr = ffi.typeof"size_t[1]"

local cid_str = arg[1]

function die_if_err (code)
   if code ~= 0 then
      local msg = cid.cid_err_str(code)
      io.stderr:write(ffi.string(msg))
      io.stderr:write("\n")
      os.exit(1)
   end
end

local cid_cstr = ffi.new("char[?]", #cid_str+1)
ffi.copy(cid_cstr, cid_str)

cid_bytes_buf_size_ptr = size_t_ptr()
res = cid.cid_str_to_bytes(cid_cstr, nil, 0, cid_bytes_buf_size_ptr)
die_if_err(res)

cid_bytes_buf = ffi.new("uint8_t[?]", cid_bytes_buf_size_ptr[0])
res = cid.cid_str_to_bytes(cid_cstr, cid_bytes_buf, cid_bytes_buf_size_ptr[0], cid_bytes_buf_size_ptr)
die_if_err(res)

res = cid.cid_validate(cid_bytes_buf, cid_bytes_buf_size_ptr[0])

if res == 0 then
   print("valid")
   os.exit(0)
else
   print("invalid: ", ffi.string(cid.cid_err_str(res)))
   os.exit(1)
end
