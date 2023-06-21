package Laeliax.SecureKey


import Laeliax.SecureKey.WIF.extractWIF
import Laeliax.SecureKey.WIF.toWIF
import Laeliax.util.Address.verify.getChecksum

import Laeliax.util.ShiftTo.ByteArrayToHex
import Laeliax.util.ShiftTo.HexToByteArray
import Laeliax.util.ShiftTo.decodeBase58
import Laeliax.util.ShiftTo.encodeBase58


object WIF {

    val MAINNET = 0x80.toByte()
    val TESTNET = 0Xef.toByte()

    fun WIF_U(NETWORK: String, privateKeyHex: String): String {

        /*
         *
         *  ฟังก์ชั่น Private_to_WIF_compressed
         *     ├──  รับค่า Hash sha256  ::  <- 9454a5235cf34e382d7e927eb5709dc4f4ed08eed177cb3f2d4ea359071962d7
         *          └──  ผลลัพธ์ WIF Key  ::  -> 5JwcVJQfQbzAfXnMYQXzLjzczGi22v8BvyyHkUBTmYwN7Z3Qswa
         *
         */

        val privateKeyBytes = privateKeyHex.HexToByteArray()

        val prefix: ByteArray = when (NETWORK) {
            "main" -> {
                byteArrayOf(MAINNET)
            }
            "test" -> {
                byteArrayOf(TESTNET)
            }
            else -> {
                return "inValid"
            }
        }

        val extendedKey = prefix + privateKeyBytes
        val checksum = extendedKey.getChecksum()

        val wifBytes = extendedKey + checksum
        return wifBytes.ByteArrayToHex().encodeBase58()
    }


    fun WIF_C(NETWORK: String, privateKeyHex: String): String {

        /*
         *
         *  ฟังก์ชั่น Private_to_WIF_compressed
         *     ├──  รับค่า Hash sha256  ::  <- 9454a5235cf34e382d7e927eb5709dc4f4ed08eed177cb3f2d4ea359071962d7
         *          └──  ผลลัพธ์ WIF Key  ::  -> L2C3duqSXBRKf4sBfcsn68mKqnL3ZTUjFGTSvryB9dxxBche5CNY
         *
         */

        val privateKeyBytes = privateKeyHex.HexToByteArray()

        val prefix: ByteArray = when (NETWORK) {
            "main" -> {
                byteArrayOf(MAINNET)
            }
            "test" -> {
                byteArrayOf(TESTNET)
            }
            else -> {
                return "inValid"
            }
        }

        val compressed = byteArrayOf(0x01.toByte())

        val extendedKey = prefix + privateKeyBytes + compressed
        val checksum = extendedKey.getChecksum()

        val wifBytes = extendedKey + checksum
        return wifBytes.ByteArrayToHex().encodeBase58()
    }


    fun String.toWIF(network: String, option: Boolean): String {
        return if (option == true) {
            WIF_C(network, this)
        } else {
            WIF_U(network, this)
        }
    }

    fun String.extractWIF(): String {
        val data = this.decodeBase58().HexToByteArray()
        return data.copyOfRange(1, 33).ByteArrayToHex()
    }

}


fun main() {

    val private_key = "c51a52e294165cfde3342e8c12c5f3370d29d12401c03803fe34de78c80b1804"
    println("Private Key: ${private_key.length} length\n\t└── $private_key\n")

    val WIF = private_key.toWIF("main", true)
    println("WIF Key: ${WIF.length} length\n\t└── $WIF\n")

    val wifC = private_key.toWIF("main", false)
    println("WIF Key [Compress]: ${wifC.length} length\n\t└── $wifC\n")

    val data = WIF.extractWIF()
    println("Original Key U: ${data.length} length\n\t└── ${data}")

}

