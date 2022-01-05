@Grab(group='net.java.dev.jna', module='jna', version='5.10.0')

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Platform
import com.sun.jna.ptr.LongByReference
import com.sun.jna.ptr.IntByReference

// run with:
// groovy bindings/groovy.groovy base64 'yes mani !'

System.setProperty("java.library.path", System.getProperty("user.dir") + ":" + System.getProperty("java.library.path"))

enc = args[0]
input = args[1]

public interface Multibase extends Library {
	  int mb_encode_as(byte[] input, long inputSize, int encoding, byte[] resultBuf, long resultBufSize, LongByReference resultSize)
	  long mb_encode_as_size(byte[] input, long inputSize, int encoding)
	  int mb_enc_by_name(String name, IntByReference enc)
};

mb = Native.loadLibrary("multibase", Multibase.class)

encCodeRef = new IntByReference(0)

res = mb.mb_enc_by_name(enc, encCodeRef)
assert res == 0

encCode = encCodeRef.value

inputBytes = input.bytes
inputSize = (long) inputBytes.length

resultBufSize = mb.mb_encode_as_size(inputBytes, inputSize, encCode)

resultBuf = new byte[resultBufSize]
resultSizeRef = new LongByReference(0)

res = mb.mb_encode_as(inputBytes, inputSize, encCode, resultBuf, resultBufSize, resultSizeRef)
assert res == 0

resultSize = resultSizeRef.value

println(new String(resultBuf[0..(resultSize - 1)] as byte[]))