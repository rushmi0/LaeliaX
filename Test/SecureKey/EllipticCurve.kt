package Laeliax.SecureKey

import Laeliax.SecureKey.EllipticCurve.ECDSA.Sign
import Laeliax.SecureKey.EllipticCurve.ECDSA.Verify
import Laeliax.SecureKey.EllipticCurve.ECDSA.toDERFormat
import Laeliax.SecureKey.EllipticCurve.compressed
import Laeliax.SecureKey.EllipticCurve.getPublicKey
import Laeliax.SecureKey.EllipticCurve.multiplyPoint

import Laeliax.util.Hashing.SHA256
import Laeliax.util.ShiftTo.ByteArrayToHex

import java.math.BigInteger
import java.security.SecureRandom


/*
* https://cryptobook.nakov.com/asymmetric-key-ciphers/elliptic-curve-cryptography-ecc
* https://www.secg.org/sec2-v2.pdf
* */

object EllipticCurve {

    // * Secp256k1 curve parameters:
    private val A = BigInteger.ZERO
    private val B = BigInteger.valueOf(7)
    private val P = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
    private val N = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
    private val G = Point(
        BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
        BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
    )


    // * จุดบนเส้นโค้งวงรี มีพิกัด x และ y
    data class Point(val x: BigInteger, val y: BigInteger)


    /* *  ------------------- Elliptic Curve cryptography -------------------  * */

    fun modinv(A: BigInteger, N: BigInteger = P) = A.modInverse(N)

    // Doubles a point on the elliptic curve
    fun doublePoint(point: Point): Point {
        val (x, y) = point

        // หาค่า slope = (3 * x * x + A) % P
        val slope = (BigInteger.valueOf(3) * x * x + A) % P

        // lam_denom = (2 * y) % P
        val lam_denom = (BigInteger.valueOf(2) * y) % P

        // lam = (slope * (Inverse Modulo  "lam_denom" ) % P
        val lam = (slope * modinv(lam_denom)) % P

        // xR = (lam * lam - (2 * x)) % P
        val xR = (lam * lam - BigInteger.valueOf(2) * x) % P

        // yR = (lam * (x - xR) - y) % P
        val yR = (lam * (x - xR) - y) % P

        // จุดใหม่ที่ได้หลังจากการคูณด้วย 2 บนเส้นโค้งวงรี
        return Point(xR, (yR + P) % P)
    }

    fun addPoint(point1: Point, point2: Point): Point {
        if (point1 == point2) {
            return doublePoint(point1)
        }
        val (x1, y1) = point1
        val (x2, y2) = point2

        // slope = (y2 - y1) / (x1 - x2)
        val slope = ((y2 - y1) * modinv(x2 - x1)) % P

        // new x = slope^2 - x1 - x2
        val xR = (slope * slope - x1 - x2) % P

        // new y = slope * (x1 - new x) - y1
        val yR = (slope * (x1 - xR) - y1) % P

        // ! จัดการพิกัด Y ที่เป็นค่าลบ
        val yResult = if (yR < BigInteger.ZERO) yR + P else yR

        return Point(xR, yResult)
    }

    fun multiplyPoint(k: BigInteger, point: Point? = null): Point {
        val current = point ?: G
        val binary = k.toString(2)
        var currentPoint = current
        for (i in 1 until binary.length) {
            currentPoint = doublePoint(currentPoint)
            if (binary[i] == '1') {
                currentPoint = addPoint(currentPoint, current)
            }
        }
        return currentPoint
    }


    /* *  ------------------- ปรับแต่ง Public key -------------------  * */


    fun BigInteger.getPublicKey(): String {
        val point = multiplyPoint(this)
        val publicKeyHex = "04${point.x.toString(16)}${point.y.toString(16)}"
        // * ถ้าขนาด public key Hex น้องกว่า 130 จะต้องแทรก "0" เข้าไปอยู่ระหว่าง "04" และพิกัด X
        if (publicKeyHex.length < 130) {
            // * "04" + "0" + X + Y
            return publicKeyHex.substring(0, 2) + "0" + publicKeyHex.substring(2)
        }
        return publicKeyHex
    }

    fun String.compressed(): String {
        if (this.length == 130 && this.substring(0, 2) != "04") {
            throw IllegalArgumentException("Invalid Public Key")
        }
        val x = BigInteger(this.substring(2, 66), 16)
        val y = BigInteger(this.substring(66), 16)

        val compressedKey = if (y and BigInteger.ONE == BigInteger.ZERO) {
            "02" + x.toString(16).padStart(64, '0')
        } else {
            "03" + x.toString(16).padStart(64, '0')
        }
        return compressedKey
    }


    /* *  ------------------- สร้างลายเซ็นและตรวจสอบ ECDSA -------------------  * */


    object ECDSA {

        /*
        * https://medium.com/bitbees/what-the-heck-is-schnorr-52ef5dba289f
        * https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
        * https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki
        */

        fun Sign(privateKey: BigInteger, message: BigInteger): Pair<BigInteger, BigInteger> {
            val m = message
            //val k = BigInteger("42854675228720239947134362876390869888553449708741430898694136287991817016610")
            val k = BigInteger(256, SecureRandom())
            var r = BigInteger.ZERO
            var s = BigInteger.ZERO
            while (r == BigInteger.ZERO || s == BigInteger.ZERO) {
                val point = multiplyPoint(k)
                val kInv = modinv(k, N)
                r = point.x % N
                s = ((m + r * privateKey) * kInv) % N
            }
            return Pair(r, s)
        }

        // * https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki
        fun toDERFormat(signature: Pair<BigInteger, BigInteger>): String {
            val (r, s) = signature
            val rb = r.toByteArray()
            val sb = s.toByteArray()

            val der_r = byteArrayOf(0x02.toByte()) + rb.size.toByte() + rb
            val der_s = byteArrayOf(0x02.toByte()) + sb.size.toByte() + sb
            val der_sig = byteArrayOf(0x30.toByte()) + (der_r.size + der_s.size).toByte() + der_r + der_s
            return der_sig.joinToString("") { String.format("%02x", it) }
        }

        fun Verify(publicKeyHex: Point, message: BigInteger, signature: Pair<BigInteger, BigInteger>): Boolean {
            val (r, s) = signature

            val w = modinv(s, N)
            val u1 = (message * w) % N
            val u2 = (r * w) % N

            val point1 = multiplyPoint(u1)
            val point2 = multiplyPoint(u2, publicKeyHex)

            val point = addPoint(point1, point2)
            val x = point.x % N
            return x == r
        }

    }


    /* *  ------------------- สร้างลายเซ็นและตรวจสอบ Schnorr Signature -------------------  * */

    // ! SchnorrSignature ยังใช้ไม่ได้

    object SchnorrSignature {

        fun Sign(privateKey: BigInteger, message: BigInteger): Pair<BigInteger, BigInteger> {

            val z = BigInteger(256, SecureRandom())
            val R = multiplyPoint(z) // R = z * G

            val r = R.x % N // พิกัด x ของ R

            val hashInput = r.toByteArray() + multiplyPoint(privateKey).x.toByteArray() + message.toByteArray()
            val hash = hashInput.ByteArrayToHex().SHA256() // Hash256(r || P || m)

            val k = privateKey
            val s = (z + BigInteger(hash, 16) * k) % N // s = z + Hash256(r || P || m) * k

            return Pair(r, s)
        }


        fun Verify(publicKey: Point, message: BigInteger, signature: Pair<BigInteger, BigInteger>): Boolean {
            val (r, s) = signature

            val R = multiplyPoint(r) // Public key : R = r*G
            val hashInput = r.toByteArray() + publicKey.x.toByteArray() + message.toByteArray()
            val hash = hashInput.ByteArrayToHex().SHA256()  // Hash of (r || P || m)
            val PHash = multiplyPoint(BigInteger(hash, 16), publicKey) // Hash(r || P || m)*P

            val sG = multiplyPoint(s) // s*G

            val leftSide = addPoint(R, PHash) // R + Hash(r || P || m)*P

            return sG == leftSide // Check if s*G = R + Hash(r || P || m)*P
        }

    }

}

// * ตัวอย่าง
fun main() {

    //val privateKey = BigInteger(256, SecureRandom())
    val privateKey = BigInteger("b8f28a772fccbf9b4f58a4f027e07dc2e35e7cd80529975e292ea34f84c4580c", 16)
    println("[H] Private key: ${privateKey.toString(16)}")
    println("Private key: $privateKey")

    val message = BigInteger("0e2bd2792e5b75cbb05561ce5836d12abbdc201b328a2626c27484458a1a9ee", 16)

    val curvePoint = multiplyPoint(privateKey)
    println("\nKey Point: $curvePoint")

    val publicKeyHex = privateKey.getPublicKey()
    println("[U] Public Key: $publicKeyHex")

    val compress = publicKeyHex.compressed()
    println("[C] Public Key: $compress")

    val sign = Sign(privateKey, message)
    println("\nSignature: $sign")

    val der = toDERFormat(sign)
    println("Der format: $der")

    val validate = Verify(curvePoint, message, sign)
    if (validate) {
        println("ECDSA Signature is Valid")
    } else {
        println("ECDSA Signature is Invalid")
    }

}
