package LaeliaX.SecureKey

import LaeliaX.util.ShiftTo.ByteArrayToHex
import java.math.BigInteger
import java.security.SecureRandom

/*
* สร้างลายเซ็นและตรวจสอบ ECDSA
* */

object ECDSA {

    /*
    * https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
    */

    fun SignSignatures(privateKey: BigInteger, message: BigInteger): Pair<BigInteger, BigInteger> {
        val m = message
        //val k = BigInteger("42854675228720239947134362876390869888553449708741430898694136287991817016610")
        val k = BigInteger(256, SecureRandom())

        val point: EllipticCurve.Point = EllipticCurve.multiplyPoint(k)
        val kInv: BigInteger = EllipticCurve.modinv(k, EllipticCurve.N)

        val r: BigInteger = point.x % EllipticCurve.N
        var s: BigInteger = ((m + r * privateKey) * kInv) % EllipticCurve.N

        // * https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki
        if (s > EllipticCurve.N.shiftRight(1)) {
            s = EllipticCurve.N - s
        }

        return Pair(r, s)
    }

    fun VerifySignature(
        publicKeyPoint: EllipticCurve.Point,
        message: BigInteger,
        signature: Pair<BigInteger, BigInteger>
    ): Boolean {
        val (r, s) = signature

        val w = EllipticCurve.modinv(s, EllipticCurve.N)
        val u1 = (message * w) % EllipticCurve.N
        val u2 = (r * w) % EllipticCurve.N

        val point1 = EllipticCurve.multiplyPoint(u1)
        val point2 = EllipticCurve.multiplyPoint(u2, publicKeyPoint)

        val point = EllipticCurve.addPoint(point1, point2)

        val x = point.x % EllipticCurve.N

        return x == r
    }

    // * https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki
    fun toDERFormat(signature: Pair<BigInteger, BigInteger>): String {
        val (r, s) = signature
        val rb = r.toByteArray()
        val sb = s.toByteArray()

        val der_r = byteArrayOf(0x02.toByte()) + rb.size.toByte() + rb
        val der_s = byteArrayOf(0x02.toByte()) + sb.size.toByte() + sb
        val der_sig = byteArrayOf(0x30.toByte()) + (der_r.size + der_s.size).toByte() + der_r + der_s
        return der_sig.ByteArrayToHex()
    }

}