package LaeliaX.MiniScript


object OP_ {

    // * Constants
    const val FALSE: Byte = 0x00.toByte()

    // OP_2 - OP_16
    val CODE = mapOf(
         2 to 82,
         3 to 83,
         4 to 84,
         5 to 85,
         6 to 86,
         7 to 87,
         8 to 88,
         9 to 89,
        10 to 90,
        11 to 91,
        12 to 92,
        13 to 93,
        14 to 94,
        15 to 95,
        16 to 96,
    )

    const val TRUE: Byte = 81.toByte()

    // * Flow control
    const val NOP: Byte = 97.toByte()
    const val IF: Byte = 99.toByte()
    const val NOTIF: Byte = 100.toByte()
    const val ELSE: Byte = 103.toByte()
    const val ENDIF: Byte = 104.toByte()
    const val VERIFY: Byte = 105.toByte()
    const val RETURN: Byte = 106.toByte()

    // * Stack
    const val TOALTSTACK: Byte = 107.toByte()
    const val DROP: Byte = 117.toByte()
    const val DUP: Byte = 118.toByte()

    // * Splice
    const val SIZE: Byte = 130.toByte()

    // * Bitwise logic
    const val EQUAL: Byte = 135.toByte()
    const val EQUALVERIFY: Byte = 136.toByte()

    // * Arithmetic
    const val ADD: Byte = 147.toByte()
    const val SUB: Byte = 148.toByte()
    const val MUL: Byte = 149.toByte()

    // * Crypto
    const val RIPEMD160: Byte = 166.toByte()
    const val SHA1: Byte = 167.toByte()
    const val SHA256: Byte = 168.toByte()
    const val HASH160: Byte = 169.toByte()
    const val HASH256: Byte = 170.toByte()
    const val CODESEPARATOR: Byte = 171.toByte()
    const val CHECKSIG: Byte = 172.toByte()
    const val CHECKSIGVERIFY: Byte = 173.toByte()
    const val CHECKMULTISIG: Byte = 174.toByte()
    const val CHECKMULTISIGVERIFY: Byte = 175.toByte()

    // * Lock time
    const val CHECKLOCKTIMEVERIFY: Byte = 177.toByte()
    const val CHECKSEQUENCEVERIFY: Byte = 178.toByte()

  }

fun main() {

}