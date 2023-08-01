package LaeliaX.SecureKey


import LaeliaX.util.Hashing.SHA256
import LaeliaX.util.ShiftTo.ByteArrayToHex

import java.math.BigInteger
import java.security.SecureRandom


/*
    * สร้างลายเซ็นและตรวจสอบ Schnorr Signature
    * https://medium.com/bitbees/what-the-heck-is-schnorr-52ef5dba289f
    * */

// ! SchnorrSignature ยังใช้ไม่ได้

object SchnorrSignature {

    fun SignSignatures(privateKey: BigInteger, message: BigInteger): Pair<BigInteger, BigInteger> {

        val z = BigInteger(256, SecureRandom())
        val R = EllipticCurve.multiplyPoint(z) // R = z * G

        val r = R.x % EllipticCurve.N // พิกัด x ของ R

        val hashInput = r.toByteArray() + EllipticCurve.multiplyPoint(privateKey).x.toByteArray() + message.toByteArray()
        val hash = hashInput.ByteArrayToHex().SHA256() // Hash256(r || P || m)

        val k = privateKey
        val s = (z + BigInteger(hash, 16) * k) % EllipticCurve.N // s = z + Hash256(r || P || m) * k

        return Pair(r, s)
    }


    fun VerifySignature(publicKey: EllipticCurve.Point, message: BigInteger, signature: Pair<BigInteger, BigInteger>): Boolean {
        val (r, s) = signature

        val R = EllipticCurve.multiplyPoint(r) // Public key : R = r*G
        val hashInput = r.toByteArray() + publicKey.x.toByteArray() + message.toByteArray()
        val hash = hashInput.ByteArrayToHex().SHA256()  // Hash of (r || P || m)
        val PHash = EllipticCurve.multiplyPoint(BigInteger(hash, 16), publicKey) // Hash(r || P || m)*P

        val sG = EllipticCurve.multiplyPoint(s) // s*G

        val leftSide = EllipticCurve.addPoint(R, PHash) // R + Hash(r || P || m)*P

        return sG == leftSide // Check if s*G = R + Hash(r || P || m)*P
    }

}