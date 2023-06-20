package Laeliax.util

import Laeliax.util.ShiftTo.ByteArrayToHex
import Laeliax.util.ShiftTo.ByteToHex
import Laeliax.util.ShiftTo.HexToByteArray
import Laeliax.util.ShiftTo.encodeBase58

import Laeliax.util.Hashing.RIPEMD160
import Laeliax.util.Hashing.SHA256
import Laeliax.MiniScript.OP_
import Laeliax.util.Hashing.doubleSHA256
import Laeliax.util.ShiftTo.decodeBase58

object Address {

    private val PREFIX_NESTED: String = "05"
    private val PREFIX_KEYHASH: String = OP_.FALSE.ByteToHex()

    // Pay-to-Witness-Script-Hash
    fun String.P2WSH(): String {
        val script = this.SHA256()
        val scriptHash = script.HexToByteArray()
        return Bech32.segwitToBech32("bc", 0, scriptHash)
    }

    fun ByteArray.P2WSH(): String {
        val script = this.SHA256()
        val scriptHash = script.HexToByteArray()
        return Bech32.segwitToBech32("bc", 0, scriptHash)
    }

    // Pay-to-Witness-Public-Key-Hash
    fun String.P2WPKH(): String {
        val pubkey = this.SHA256()
        val pubkeyHas = pubkey.RIPEMD160().HexToByteArray()
        return Bech32.segwitToBech32("bc", 0, pubkeyHas)
    }

    // Pay-to-Public-Key-Hash
    fun String.P2PKH(): String {
        val PREFIX_NESTED: String = PREFIX_KEYHASH
        val pubkey: String = this.SHA256()
        val pubkeyHas: String = pubkey.RIPEMD160()

        val components: String = PREFIX_NESTED + pubkeyHas
        val checksum: String = components.SHA256().SHA256().HexToByteArray()
            .copyOfRange(0, 4).ByteArrayToHex()

        val combine: String = components + checksum
        return combine.encodeBase58()
    }

    // Nested SegWit (P2SH-P2WPKH)
    fun String.segwitP2SH(): String {
        val dataHash256: String = this.SHA256()
        val size = dataHash256.HexToByteArray().size.toString(16)

        val redeemScript: String = PREFIX_KEYHASH + size + dataHash256
        val NESTED = redeemScript.P2SH()
        return NESTED
    }

    // Pay-to-Script-Hash
    fun String.P2SH(): String {

        val redeemScript: String = this.SHA256()
        val redeemScriptHas: String = redeemScript.RIPEMD160()

        val components: String = PREFIX_NESTED + redeemScriptHas
        val checksum: String = components.SHA256().SHA256().HexToByteArray()
            .copyOfRange(0, 4).ByteArrayToHex()

        val combine: String = components + checksum
        val addr = combine.encodeBase58()
        return addr
    }

    object verify {

        fun calculateChecksum(data: ByteArray): ByteArray {
            val hash = data.doubleSHA256()
            return hash.sliceArray(0 until 4)
        }

        fun P2PKH(address: String): Boolean {
            val decodedAddress = address.decodeBase58().HexToByteArray()
            if (decodedAddress.size != 25) {
                return false
            }

            val checksum = calculateChecksum(decodedAddress.sliceArray(0 until 21))
            if (!decodedAddress.sliceArray(21 until 25).contentEquals(checksum)) {
                return false
            }

            val networkPrefix = decodedAddress[0]
            return networkPrefix == 0x00.toByte()
        }

        fun P2WSH(address: String): Boolean {

            val decodedAddress = Bech32.bech32ToSegwit(address)
            val humanPart = decodedAddress[0] as String
            val witVer = decodedAddress[1] as Int
            val witProg = decodedAddress[2] as ByteArray

            return witVer == 0 || humanPart == "bc" && witProg.size == 32
        }

        fun P2WPKH(address: String): Boolean {

            val decodedAddress = Bech32.bech32ToSegwit(address)
            val humanPart = decodedAddress[0] as String
            val witVer = decodedAddress[1] as Int
            val witProg = decodedAddress[2] as ByteArray

            return witVer == 0 || humanPart == "bc" && witProg.size == 20
        }



    }
}

fun main() {


    val P2PKH = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
    val isValidP2PKH = Address.verify.P2PKH(P2PKH)

    if (isValidP2PKH) {
        println("The address is valid.")
    } else {
        println("The address is not valid.")
    }


    val P2WSH = "bc1qqsa8rpm5c4etmz394kltr07dtsp9dts3em8el8pljfwsu54747ys0t028e"
    val isValidP2WSH = Address.verify.P2WSH(P2WSH)

    if (isValidP2WSH) {
        println("The address is valid.")
    } else {
        println("The address is not valid.")
    }


    val P2WPKH = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    val isValidP2WPKH = Address.verify.P2WPKH(P2WPKH)

    if (isValidP2WPKH) {
        println("The address is valid.")
    } else {
        println("The address is not valid.")
    }

}