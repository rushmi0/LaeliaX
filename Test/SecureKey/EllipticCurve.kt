package LaeliaX.SecureKey


import LaeliaX.SecureKey.ECDSA.SignSignatures
import LaeliaX.SecureKey.ECDSA.VerifySignature
import LaeliaX.SecureKey.ECDSA.derRecovered
import LaeliaX.SecureKey.ECDSA.toDERFormat
import LaeliaX.SecureKey.EllipticCurve.compressed
import LaeliaX.SecureKey.EllipticCurve.generateECDH

import LaeliaX.SecureKey.EllipticCurve.getDecompress
import LaeliaX.SecureKey.EllipticCurve.getPublicKey
import LaeliaX.SecureKey.EllipticCurve.isPointOnCurve
import LaeliaX.SecureKey.EllipticCurve.multiplyPoint
import LaeliaX.util.ShiftTo.ByteArrayToBigInteger
import LaeliaX.util.ShiftTo.HexToByteArray
import java.math.BigInteger
import java.security.SecureRandom

/*
* https://github.com/wobine/blackboard101/blob/master/EllipticCurvesPart5-TheMagic-SigningAndVerifying.py
* https://cryptobook.nakov.com/asymmetric-key-ciphers/elliptic-curve-cryptography-ecc
* https://www.secg.org/sec2-v2.pdf
*
* < Elliptic Curve Cryptography >
*  ในส่วนนี้เป็นการคำนวณ Public Key
* */

object EllipticCurve {

    // * Parameters secp256k1
    private val curveDomain: Secp256K1.CurveParams = Secp256K1.getCurveParams()

    private val A: BigInteger = curveDomain.A
    private val B: BigInteger = curveDomain.B
    private val P: BigInteger = curveDomain.P

    //private val N: BigInteger = curveDomain.N
    private val G: PointField = curveDomain.G


    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\

    /*
    * ตรวจสอบจุดบนโค้งวงรี Secp256k1
    * */

    fun isPointOnCurve(point: PointField?): Boolean {
        val (x, y) = point!!

        // * ตรวจสอบว่าจุดนั้นเป็นไปตามสมการเส้นโค้งวงรี หรือไม่: y^2 = x^3 + Ax + B (mod P)
        val leftSide = (y * y).mod(P)
        val rightSide = (x.pow(3) + A * x + B).mod(P)

        return leftSide == rightSide
    }

    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\

    /*
    * Function สำหรับคำนวณ modular inverse
    * https://www.dcode.fr/modular-inverse
    * */
    fun modinv(A: BigInteger, N: BigInteger = P) = A.modInverse(N)


    // * Function สำหรับคำนวณค่าจุดหลังการคูณด้วย 2 บนเส้นโค้งวงรี
    fun doublePoint(point: PointField): PointField {
        val (x, y) = point

        // * คำนวณค่า slope ด้วยสูตร (3 * x^2 + A) * (2 * y)^-1 mod P
        val slope = (BigInteger.valueOf(3) * x * x + A) % P

        // *  คำนวณค่า lam_denom = (2 * y) mod P
        val lam_denom = (BigInteger.valueOf(2) * y) % P

        // * คำนวณค่า lam = slope * (lam_denom)^-1 mod P
        val lam = (slope * modinv(lam_denom)) % P

        // * คำนวณค่า xR = (lam^2 - 2 * x) mod P
        val xR = (lam * lam - BigInteger.valueOf(2) * x) % P


        /*
        * < จุดใหม่ที่ได้หลังจากการคูณด้วย 2 บนเส้นโค้งวงรี >
        *  คำนวณค่า yR = (lam * (x - xR) - y) mod P เป็นส่วนที่คำนวณหาค่า y  ของจุดใหม่หลังจากการคูณด้วย 2 บนเส้นโค้งวงรี
        *
        *  lam   คือค่าเอียงของเส้นที่ผ่านจุดเดิมและจุดใหม่หลังจากการคูณด้วย 2 บนเส้นโค้งวงรี
        *  x      คือค่า x ของจุดเดิม
        *  xR    คือค่า x ของจุดใหม่หลังจากการคูณด้วย 2 บนเส้นโค้งวงรี
        *  y     คือค่า y ของจุดเดิม
        *
        * นำค่าเหล่านี้มาใช้เพื่อหาค่า yR ใหม่ที่ถูกปรับเพิ่มหรือลดจากค่า y ของจุดเดิม โดยการคูณ lam กับผลต่างระหว่าง x และ xR
        * */
        val yR = (lam * (x - xR) - y) % P

        return PointField(xR, (yR + P) % P)
    }


    fun addPoint(point1: PointField, point2: PointField): PointField {
        if (point1 == point2) {
            return doublePoint(point1)
        }
        val (x1, y1) = point1
        val (x2, y2) = point2

        val slope = ((y2 - y1) * modinv(x2 - x1)) % P

        val x = (slope * slope - x1 - x2) % P

        val y = (slope * (x1 - x) - y1) % P

        // ! จัดการพิกัด Y ที่เป็นค่าลบ
        val yResult = if (y < A) y + P else y

        return PointField(x, yResult)
    }

    fun multiplyPoint(k: BigInteger, point: PointField? = null): PointField {
        // * ตัวแปร current ถูกกำหนดให้เป็น point ที่รับเข้ามา หากไม่มีการระบุ point ค่าเริ่มต้นจะเป็นจุด G ที่ใช้ในการคูณเช่นกับ private key
        val current: PointField = point ?: G

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


    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\

    /*
    * ปรับแต่ง Public key
    * */

    private fun fullPublicKeyPoint(k: BigInteger): String {
        val point: PointField = multiplyPoint(k)
        val xHex = point.x.toString(16)
        val yHex = point.y.toString(16)

        // คำนวณขนาดของ public key Hex
        val size = (xHex.length + yHex.length) / 2

        if (size < 64) {
            // หากขนาดน้อยกว่า 64 ให้แทรก "0" ในตัวแปร xHex และ yHex
            val padding = "0".repeat(64 - size)
            return "04$padding$xHex$yHex"
        }

        return "04$xHex$yHex"
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

    private fun decompressPublicKey(compressedPublicKey: String): PointField? {
        try {
            // แปลง compressed public key ในรูปแบบ Hex เป็น ByteArray
            val byteArray = compressedPublicKey.HexToByteArray()

            // ดึงค่า x coordinate จาก ByteArray
            val xCoord = byteArray.copyOfRange(1, byteArray.size).ByteArrayToBigInteger()

            // ตรวจสอบว่า y เป็นเลขคู่หรือไม่
            val isYEven = byteArray[0] == 2.toByte()

            // คำนวณค่า x^3 (mod P)
            val xCubed = xCoord.modPow(BigInteger.valueOf(3), P)

            // คำนวณ Ax (mod P)
            val Ax = xCoord.multiply(A).mod(P)

            // คำนวณ y^2 = x^3 + Ax + B (mod P)
            val ySquared = xCubed.add(Ax).add(B).mod(P)

            // คำนวณค่า y จาก y^2 โดยใช้ square root
            val y = ySquared.modPow(P.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), P)

            // ตรวจสอบว่า y^2 เป็นเลขคู่หรือไม่
            val isYSquareEven = y.mod(BigInteger.TWO) == BigInteger.ZERO

            // คำนวณค่า y โดยแก้ไขเครื่องหมายตามผลลัพธ์ที่ได้จากการตรวจสอบ
            val computedY = if (isYSquareEven != isYEven) P.subtract(y) else y

            // สร้าง PointField จาก x และ y ที่ได้
            return PointField(xCoord, computedY)
        } catch (e: Exception) {
            println("Failed to decompress the public key: ${e.message}")
            return null
        }
    }


    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\

    /**
     * < https://asecuritysite.com/encryption/js08 >
     *
     * ECDH (Elliptic Curve Diffie-Hellman) คือ การสร้าง Shared Key ระหว่าง 2 ฝ่าย โดยใช้ Public Key จากฝ่ายตรงข้าม กับ Private Key ของตัวเอง
     * โดยที่ Shared Key ที่ได้จะเป็นค่าเดียวกันทั้งสองฝ่าย และสามารถนำไปใช้ในการเข้ารหัสแบบ Symmetric Key ได้
     * ในการสร้าง Public Key จะใช้เส้นโค้ง secp256K1 เนื่องจากเป็นเส้นโค้งที่มีคุณสมบัติที่ดีในด้านต่างๆ ดังนี้
     *
     * 1. ความปลอดภัย: เพราะเส้นโค้งนี้มีความยาว 256 bits ซึ่งมีความยาวที่เพียงพอที่จะทนต่อการโจมตีด้วย Brute Force
     * <p>
     * 2. ความเร็วในการคำนวณ: เพราะเส้นโค้งนี้มีความยาวที่สั้น และมีคุณสมบัติในการคำนวณที่ดี ทำให้สามารถคำนวณได้เร็วกว่าเส้นโค้งอื่นๆ
     * <p>
     * 3. ขนาดเล็ก: เพราะเส้นโค้งนี้มีความยาวที่สั้น ทำให้ขนาดของ Public Key ที่ได้เล็กลง ซึ่งจะทำให้การสื่อสารผ่านเครือข่ายที่เป็นแบบ Real-Time ได้รวดเร็วขึ้น
     * <p>
     * 4. ประสิทธิภาพ: การลงนามด้วยเส้นโค้ง secp256K1 จะทำให้การลงนามเร็วขึ้น และมีขนาดของลายเซ็นที่เล็กลง ประหยัดทรัพยากรคอมพิวเตอร์
     *
     * < ขั้นตอนการสร้าง Shared Key >
     *     1. ฝ่าย A สร้าง Public Key จาก Private Key ของตัวเอง และส่ง Public Key ไปให้ฝ่าย B
     *     2. ฝ่าย B สร้าง Public Key จาก Private Key ของตัวเอง และส่ง Public Key ไปให้ฝ่าย A
     *
     * */

    // ใช้สำหรับสร้าง Shared Key ระหว่าง 2 ฝ่าย เรียกว่า ECDH (Elliptic Curve Diffie-Hellman)
    fun generateECDH(
        publicKey: String, // Public Key ของฝ่ายตรงข้าม
        privateKey: BigInteger // Private Key ของตัวเอง
    ): String {
        // แปลง public key ให้อยู่ในรูปของ PointField นั้นก็คือ (x, y) ซึ่งเป็นพิกัดบนเส้นโค้งวงรี
        val point: PointField = publicKey.getDecompress()
            ?: // หากไม่สามารถแปลง public key ให้อยู่ในรูปของ PointField ได้
            // คุณควรจัดการข้อผิดพลาดที่เกิดขึ้นในที่นี้
            throw IllegalArgumentException("Invalid or unsupported public key format")

        val curvePoint = multiplyPoint(
            privateKey, // นี่เป็นค่า Private Key ของตัวเอง

            // นี่คือค่า x และ y ของจุดบนเส้นโค้งวงรีที่มาจาก public key ของฝ่ายตรงข้าม
            point
        )

        return curvePoint.x.toString(16)
    }



    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\


    fun String.getDecompress(): PointField? {
        return decompressPublicKey(this)
    }

    fun BigInteger.getPublicKey(): String {
        return fullPublicKeyPoint(this)
    }

    fun String.compressed(): String {
        return groupSelection(this)
    }


    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\

}

// * ตัวอย่าง
fun main() {

    //val privateKey = BigInteger(256, SecureRandom())
    val privateKey = BigInteger("97ddae0f3a25b92268175400149d65d6887b9cefaf28ea2c078e05cdc15a3c0a", 16)
    println("[H] Private key: ${privateKey.toString(16)}")
    println("Private key: $privateKey")

    val message = BigInteger("ce7df6b1b2852c5c156b683a9f8d4a8daeda2f35f025cb0cf34943dcac70d6a3", 16)
    println("Message: $message")

    val curvePoint = multiplyPoint(privateKey)
    println("\nKey PointField: $curvePoint")

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

    println()

    val signatureRecovered = derRecovered(der)
    println("Signature Recovered: \n\tr = ${signatureRecovered?.first} \n\ts = ${signatureRecovered?.second}")

    val authKey = compress
    println("AuthKey = $authKey")

    val pubKeyRecovered = compress.getDecompress()
    println("Pub Key Recovered: \n\t$pubKeyRecovered")

    val test = isPointOnCurve(pubKeyRecovered)
    println(test)

    val server: Boolean = VerifySignature(pubKeyRecovered!!, message, signatureRecovered!!)
    println(server!!)


    // * ตัวอย่างการใช้งาน ECDH
    val privateKeyA = BigInteger("79625421569768853913552101372473036721620627201397836988747447632291648962205")//BigInteger(256, SecureRandom())
    val privateKeyB = BigInteger("67914844877053552625417144116446677376217396135678097020919636085202412362945")//BigInteger(256, SecureRandom())

    println("\nPrivate Key A: $privateKeyA")
    println("Private Key B: $privateKeyB")

    val privateKeyC = BigInteger("97ddae0f3a25b92268175400149d65d6887b9cefaf28ea2c078e05cdc15a3c0a", 16)

    val publicKeyA = privateKeyA.getPublicKey().compressed()
    val publicKeyB = privateKeyB.getPublicKey().compressed()

    println("\nPublic Key A: $publicKeyA")
    println("Public Key B: $publicKeyB")

    val publicKeyC = privateKeyC.getPublicKey().compressed()

    val sharedKeyA = generateECDH(
        publicKeyB,
        privateKeyA
    )

    val sharedKeyB = generateECDH(
        publicKeyA,
        privateKeyB
    )

    val sharedKeyC = generateECDH(
        publicKeyA,
        privateKeyC
    )

    println("\nShared Key A: $sharedKeyA")
    println("Shared Key B: $sharedKeyB")
    //println("Shared Key C: $sharedKeyC")

    if (sharedKeyA == sharedKeyB) {
        println("Shared Keys Match")
    } else {
        println("Shared Keys Do Not Match")
    }
}