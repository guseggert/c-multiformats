require 'ffi'

# run with: ruby bindings/ruby.rb base2 'yes mani !'

module Multibase
  extend FFI::Library

  ffi_lib './libmultibase.so.1'
  attach_function :mb_encode_as, [:pointer, :size_t, :long, :pointer, :size_t, :pointer], :long
  attach_function :mb_encode_as_size, [:pointer, :size_t, :long], :size_t
  attach_function :mb_enc_by_name, [:string, :pointer], :long
end

encoding_str = ARGV[0]
input_str = ARGV[1]

raise "encoding required" unless encoding_str
raise "input string required" unless input_str

enc_ref = FFI::MemoryPointer.new(:long, 1)

res = Multibase.mb_enc_by_name(encoding_str, enc_ref)
raise "error finding encoding" unless res == 0

enc = enc_ref.get_long(0)
input_size = input_str.length
input = FFI::MemoryPointer.new(:uint8, input_size)
input.put_bytes(0, input_str)

result_buf_size = Multibase.mb_encode_as_size(input, input_size, enc)
result_buf = FFI::MemoryPointer.new(:uint8, result_buf_size)
result_size = FFI::MemoryPointer.new(:size_t, 1)

res = Multibase.mb_encode_as(input, input_size, enc, result_buf, result_buf_size, result_size)
raise "encoding error" unless res == 0

puts result_buf.get_string(0, result_size.get_long(0))

