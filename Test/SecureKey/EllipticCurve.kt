package LaeliaX.SecureKey


import LaeliaX.SecureKey.EllipticCurve.ECDSA.SignSignatures
import LaeliaX.SecureKey.EllipticCurve.ECDSA.VerifySignature
import LaeliaX.SecureKey.EllipticCurve.ECDSA.toDERFormat

import LaeliaX.SecureKey.EllipticCurve.compressed
import LaeliaX.SecureKey.EllipticCurve.getPublicKey
import LaeliaX.SecureKey.EllipticCurve.multiplyPoint

import LaeliaX.util.Hashing.SHA256
import LaeliaX.util.ShiftTo.ByteArrayToBigInteger
import LaeliaX.util.ShiftTo.ByteArrayToHex
import LaeliaX.util.ShiftTo.HexToByteArray

import java.math.BigInteger
import java.security.SecureRandom


/*
* https://cryptobook.nakov.com/asymmetric-key-ciphers/elliptic-curve-cryptography-ecc
* https://www.secg.org/sec2-v2.pdf
* */

object EllipticCurve {

    // * Parameters secp256k1
    private val curve = Secp256K1

    // * จุดบนเส้นโค้งวงรี มีพิกัด x และ y
    data class Point(val x: BigInteger, val y: BigInteger)

    // ──────────────────────────────────────────────────────────────────────────────────────── \\

    /*
    * ตรวจสอบจุดบนโค้งวงรี Secp256k1
    * */

    fun isPointOnCurve(point: Pair<BigInteger, BigInteger>): Boolean {
        val (x, y) = point

        // * ตรวจสอบว่าจุดนั้นเป็นไปตามสมการเส้นโค้งวงรี หรือไม่: y^2 = x^3 + Ax + B (mod P)
        val leftSide = (y * y).mod(curve.P())
        val rightSide = (x.pow(3) + curve.A() * x + curve.B()).mod(curve.P())

        return leftSide == rightSide
    }

    // ──────────────────────────────────────────────────────────────────────────────────────── \\

    /*
    * < Elliptic Curve Cryptography >
    * ในส่วนนี้เป็นการคำนวณ Public Key
    *
    * อ้างอิงจาก:
    * https://github.com/wobine/blackboard101/blob/master/EllipticCurvesPart5-TheMagic-SigningAndVerifying.py
    * */

    // * https://www.dcode.fr/modular-inverse
    fun modinv(A: BigInteger, N: BigInteger = curve.P()) = A.modInverse(N)


    fun doublePoint(point: Point): Point {
        val (x, y) = point

        // ! (3 * x * x + A) % P
        val slope = (BigInteger.valueOf(3) * x * x + curve.A()) % curve.P()

        val lam_denom = (BigInteger.valueOf(2) * y) % curve.P()

        val lam = (slope * modinv(lam_denom)) % curve.P()

        val xR = (lam * lam - BigInteger.valueOf(2) * x) % curve.P()

        val yR = (lam * (x - xR) - y) % curve.P()

        // * จุดใหม่ที่ได้หลังจากการคูณด้วย 2 บนเส้นโค้งวงรี
        return Point(xR, (yR + curve.P()) % curve.P())
    }

    fun addPoint(point1: Point, point2: Point): Point {
        if (point1 == point2) {
            return doublePoint(point1)
        }
        val (x1, y1) = point1
        val (x2, y2) = point2

        val slope = ((y2 - y1) * modinv(x2 - x1)) % curve.P()

        val x = (slope * slope - x1 - x2) % curve.P()

        val y = (slope * (x1 - x) - y1) % curve.P()

        // ! จัดการพิกัด Y ที่เป็นค่าลบ
        val yResult = if (y < curve.A()) y + curve.P() else y

        return Point(x, yResult)
    }

    fun multiplyPoint(k: BigInteger, point: Point? = null): Point {
        // * ตัวแปร current ถูกกำหนดให้เป็น point ที่รับเข้ามา หากไม่มีการระบุ point ค่าเริ่มต้นจะเป็นจุด G ที่ใช้ในการคูณเช่นกับ private key
        val current: Point = point ?: curve.G()

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
        }
        // * ส่งคืนจุดที่คำนวณได้
        return currentPoint
    }


    // ──────────────────────────────────────────────────────────────────────────────────────── \\

    /*
    * ปรับแต่ง Public key
    * */

    private fun fullPublicKeyPoint(k: BigInteger): String {
        val point: Point = multiplyPoint(k)
        val publicKeyPoint = "04${point.x.toString(16)}${point.y.toString(16)}"

        // * ถ้าขนาด public key Hex น้องกว่า 130 จะต้องแทรก "0" เข้าไปอยู่ระหว่าง "04" และพิกัด X
        if (publicKeyPoint.length < 130) {

            // * "04" + "0" + X + Y
            return publicKeyPoint.substring(0, 2) + "0" + publicKeyPoint.substring(2)
        }
        return publicKeyPoint
    }

    private fun groupSelection(publicKey: String): String {
        if (publicKey.length == 130 && publicKey.substring(0, 2) != "04") {
            throw IllegalArgumentException("Invalid Public Key")
        }
        val x = BigInteger(publicKey.substring(2, 66), 16)
        val y = BigInteger(publicKey.substring(66), 16)

        val groupkeys = if (y and BigInteger.ONE == BigInteger.ZERO) {
            "02" + x.toString(16).padStart(64, '0')
        } else {
            "03" + x.toString(16).padStart(64, '0')
        }
        return groupkeys
    }

    private fun decompressPublicKey(compressedPublicKey: String): Point {
        val byteArray = compressedPublicKey.HexToByteArray()
        val xCoord = byteArray.copyOfRange(1, byteArray.size).ByteArrayToBigInteger()
        val isYEven = byteArray[0] == 2.toByte()

        val xSquare = (xCoord.modPow(BigInteger.valueOf(3), curve.N()) + curve.B()) % curve.N()
        val y = xSquare.modPow((curve.N() + BigInteger("1")) / BigInteger("4"), curve.N())
        val isYSquareEven = y.mod(BigInteger.TWO) == BigInteger.ZERO

        val computedY = if (isYSquareEven != isYEven) curve.N() - y else y

        return Point(xCoord, computedY)
    }


    fun String.getDecompress(): Point {
        return decompressPublicKey(this)
    }

    fun BigInteger.getPublicKey(): String {
        return fullPublicKeyPoint(this)
    }

    fun String.compressed(): String {
        return groupSelection(this)
    }


    // ──────────────────────────────────────────────────────────────────────────────────────── \\

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

            val point: Point = multiplyPoint(k)
            val kInv: BigInteger = modinv(k, curve.N())

            val r: BigInteger = point.x % curve.N()
            var s: BigInteger = ((m + r * privateKey) * kInv) % curve.N()

            // * https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki
            if (s > curve.N() . shiftRight(1)) {
                s = curve.N() - s
            }

            return Pair(r, s)
        }

        fun VerifySignature(publicKeyPoint: Point, message: BigInteger, signature: Pair<BigInteger, BigInteger>): Boolean {
            val (r, s) = signature

            val w = modinv(s, curve.N())
            val u1 = (message * w) % curve.N()
            val u2 = (r * w) % curve.N()

            val point1 = multiplyPoint(u1)
            val point2 = multiplyPoint(u2, publicKeyPoint)

            val point = addPoint(point1, point2)

            val x = point.x % curve.N()

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

        fun fromDERFormat(signature: String): Pair<BigInteger, BigInteger>? {
            val signatureBytes = signature.HexToByteArray()

            if (signatureBytes.size < 9 || signatureBytes[0] != 0x30.toByte()) {
                return null
            }

            var index = 1
            val length = signatureBytes[index++].toInt() and 0xFF

            if (length + index != signatureBytes.size || signatureBytes[index] != 0x02.toByte()) {
                return null
            }

            index++
            val rLength = signatureBytes[index++].toInt() and 0xFF
            val rBytes = signatureBytes.copyOfRange(index, index + rLength)
            val r = BigInteger(1, rBytes)

            index += rLength

            if (signatureBytes[index] != 0x02.toByte()) {
                return null
            }

            index++
            val sLength = signatureBytes[index++].toInt() and 0xFF
            val sBytes = signatureBytes.copyOfRange(index, index + sLength)
            val s = BigInteger(1, sBytes)

            return Pair(r, s)
        }



    }


    // ──────────────────────────────────────────────────────────────────────────────────────── \\

    /*
    * สร้างลายเซ็นและตรวจสอบ Schnorr Signature
    * https://medium.com/bitbees/what-the-heck-is-schnorr-52ef5dba289f
    * */

    // ! SchnorrSignature ยังใช้ไม่ได้

    object SchnorrSignature {

        fun SignSignatures(privateKey: BigInteger, message: BigInteger): Pair<BigInteger, BigInteger> {

            val z = BigInteger(256, SecureRandom())
            val R = multiplyPoint(z) // R = z * G

            val r = R.x % curve.N() // พิกัด x ของ R

            val hashInput = r.toByteArray() + multiplyPoint(privateKey).x.toByteArray() + message.toByteArray()
            val hash = hashInput.ByteArrayToHex().SHA256() // Hash256(r || P || m)

            val k = privateKey
            val s = (z + BigInteger(hash, 16) * k) % curve.N() // s = z + Hash256(r || P || m) * k

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

    val sign = SignSignatures(privateKey, message)
    println("\nSignature: \n r = ${sign.first} \n s = ${sign.second}")

    val der = toDERFormat(sign)
    println("Der format: $der")

    val validate = VerifySignature(curvePoint, message, sign)
    if (validate) {
        println("ECDSA Signature is Valid")
    } else {
        println("ECDSA Signature is Invalid")
    }

}
