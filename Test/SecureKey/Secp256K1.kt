package LaeliaX.SecureKey

import java.math.BigInteger

object Secp256K1 {

    // * Secp256K1 curve parameters:
    private val A = BigInteger.ZERO
    private val B = BigInteger.valueOf(7)
    private val P = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
    private val N = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
    private val G = EllipticCurve.Point(
        BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
        BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
    )

    fun A(): BigInteger = this.A

    fun B(): BigInteger = this.B

    fun P(): BigInteger = this.P

    fun N(): BigInteger = this.N

    fun G(): EllipticCurve.Point = this.G
}
