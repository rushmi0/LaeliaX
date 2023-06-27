package Laeliax.SecureKey

import Laeliax.SecureKey.EllipticCurve.ECDSA.SignSignature
import Laeliax.SecureKey.EllipticCurve.ECDSA.VerifySignature
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


    // ──────────────────────────────────────────────────────────────────────────────────────── \\

    /*
    * < Elliptic Curve cryptography >
    * ในส่วนนี้เป็นการคำนวณค Public Key
    *
    * อ้างอิงจาก:
    * https://github.com/wobine/blackboard101/blob/master/EllipticCurvesPart5-TheMagic-SigningAndVerifying.py
    * */

    // * https://www.dcode.fr/modular-inverse
    fun modinv(A: BigInteger, N: BigInteger = P) = A.modInverse(N)


    fun doublePoint(point: Point): Point {
        val (x, y) = point

        // ! (3 * x * x + A) % P
        val slope = (BigInteger.valueOf(3) * x * x + A) % P

        val lam_denom = (BigInteger.valueOf(2) * y) % P

        val lam = (slope * modinv(lam_denom)) % P

        val xR = (lam * lam - BigInteger.valueOf(2) * x) % P

        val yR = (lam * (x - xR) - y) % P

        // * จุดใหม่ที่ได้หลังจากการคูณด้วย 2 บนเส้นโค้งวงรี
        return Point(xR, (yR + P) % P)
    }

    fun addPoint(point1: Point, point2: Point): Point {
        if (point1 == point2) {
            return doublePoint(point1)
        }
        val (x1, y1) = point1
        val (x2, y2) = point2

        val slope = ((y2 - y1) * modinv(x2 - x1)) % P

        val xR = (slope * slope - x1 - x2) % P

        val yR = (slope * (x1 - xR) - y1) % P

        // ! จัดการพิกัด Y ที่เป็นค่าลบ
        val yResult = if (yR < BigInteger.ZERO) yR + P else yR

        return Point(xR, yResult)
    }

    fun multiplyPoint(k: BigInteger, point: Point? = null): Point {
        // * ตัวแปร current ถูกกำหนดให้เป็น point ที่รับเข้ามา หากไม่มีการระบุ point ค่าเริ่มต้นจะเป็นจุด G ที่ใช้ในการคูณเช่นกับ private key
        val current = point ?: G

        // * แปลงจำนวนเต็ม k เป็นเลขฐานสอง
        val binary = k.toString(2)

        // * เริ่มต้นด้วยจุดเริ่มต้นปัจจุบัน
        var currentPoint = current

        // * วนลูปตามจำนวน binary digits ของ k
        for (i in 1 until binary.length) {
            currentPoint = doublePoint(currentPoint)

            // * ถ้า binary digit ที่ตำแหน่ง i เป็น '1'  ให้บวกจุดเริ่มต้น (current) เข้ากับจุดปัจจุบัน (currentPoint)
            if (binary[i] == '1') {
                currentPoint = addPoint(currentPoint, current)
            }

            // * Debug
            //println("binary[i] = $i:")
            //println("Current Point: $currentPoint \n")
        }

        // * ส่งคืนจุดที่คำนวณได้
        return currentPoint
    }


    // ──────────────────────────────────────────────────────────────────────────────────────── \\

    /*
    * ปรับแต่ง Public key
    * */

    fun BigInteger.getPublicKey(): String {
        val point = multiplyPoint(this)
        val publicKeyPoint = "04${point.x.toString(16)}${point.y.toString(16)}"
        // * ถ้าขนาด public key Hex น้องกว่า 130 จะต้องแทรก "0" เข้าไปอยู่ระหว่าง "04" และพิกัด X
        if (publicKeyPoint.length < 130) {
            // * "04" + "0" + X + Y
            return publicKeyPoint.substring(0, 2) + "0" + publicKeyPoint.substring(2)
        }
        return publicKeyPoint
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


    // ──────────────────────────────────────────────────────────────────────────────────────── \\

    /*
    * สร้างลายเซ็นและตรวจสอบ ECDSA
    * */

    object ECDSA {

        /*
        * https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
        */


        fun SignSignature(privateKey: BigInteger, message: BigInteger): Pair<BigInteger, BigInteger> {
            val m = message
            val k = BigInteger("42854675228720239947134362876390869888553449708741430898694136287991817016610")
            //val k = BigInteger(256, SecureRandom())

            val point = multiplyPoint(k)
            val kInv = modinv(k, N)

            val r: BigInteger = point.x % N
            var s: BigInteger = ((m + r * privateKey) * kInv) % N

            // * https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki
            if (s > N .shiftRight(1)) s = N - s else s

            return Pair(r, s)
        }

        fun VerifySignature(publicKeyPoint: Point, message: BigInteger, signature: Pair<BigInteger, BigInteger>): Boolean {
            val (r, s) = signature

            val w = modinv(s, N)
            val u1 = (message * w) % N
            val u2 = (r * w) % N

            val point1 = multiplyPoint(u1)
            val point2 = multiplyPoint(u2, publicKeyPoint)

            val point = addPoint(point1, point2)
            val x = point.x % N
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
            return der_sig.joinToString("") { String.format("%02x", it) }
        }

    }


    // ──────────────────────────────────────────────────────────────────────────────────────── \\

    /*
    * สร้างลายเซ็นและตรวจสอบ Schnorr Signature
    * https://medium.com/bitbees/what-the-heck-is-schnorr-52ef5dba289f
    * */

    // ! SchnorrSignature ยังใช้ไม่ได้

    object SchnorrSignature {

        fun SignSignature(privateKey: BigInteger, message: BigInteger): Pair<BigInteger, BigInteger> {

            val z = BigInteger(256, SecureRandom())
            val R = multiplyPoint(z) // R = z * G

            val r = R.x % N // พิกัด x ของ R

            val hashInput = r.toByteArray() + multiplyPoint(privateKey).x.toByteArray() + message.toByteArray()
            val hash = hashInput.ByteArrayToHex().SHA256() // Hash256(r || P || m)

            val k = privateKey
            val s = (z + BigInteger(hash, 16) * k) % N // s = z + Hash256(r || P || m) * k

            return Pair(r, s)
        }


        fun VerifySignature(publicKey: Point, message: BigInteger, signature: Pair<BigInteger, BigInteger>): Boolean {
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
    val privateKey = BigInteger("165F1C58AFB81B9D767FCEF47CBCDFFD3298E0480575AC8A0CA9FEC04F600C26", 16)
    println("[H] Private key: ${privateKey.toString(16)}")
    println("Private key: $privateKey")

    val message = BigInteger("0e2bd2792e5b75cbb05561ce5836d12abbdc201b328a2626c27484458a1a9ee", 16)
    println("Message: $message")

    val curvePoint = multiplyPoint(privateKey)
    println("\nKey Point: $curvePoint")

    val publicKeyPoint = privateKey.getPublicKey()
    println("[U] Public Key: $publicKeyPoint")

    val compress = publicKeyPoint.compressed()
    println("[C] Public Key: $compress")

    val sign = SignSignature(privateKey, message)
    println("\nSignature: $sign")

    val der = toDERFormat(sign)
    println("Der format: $der")

    val validate = VerifySignature(curvePoint, message, sign)
    if (validate) {
        println("ECDSA Signature is Valid")
    } else {
        println("ECDSA Signature is Invalid")
    }

}
