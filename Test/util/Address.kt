package Laeliax.util


import Laeliax.util.ShiftTo.ByteArrayToHex
import Laeliax.util.ShiftTo.ByteToHex
import Laeliax.util.ShiftTo.HexToByteArray
import Laeliax.util.ShiftTo.encodeBase58
import Laeliax.util.ShiftTo.decodeBase58

import Laeliax.util.Hashing.RIPEMD160
import Laeliax.util.Hashing.SHA256
import Laeliax.util.Hashing.doubleSHA256

import Laeliax.util.Address.verify.isP2PKH
import Laeliax.util.Address.verify.isP2WPKH
import Laeliax.util.Address.verify.isP2WSH

import Laeliax.Transaction.NETWORKS
import Laeliax.util.Address.verify.getChecksum


object Address {

    private val CHAIN = NETWORKS.MAIN


    private fun P2WSH(network: String, data: String): String {
        val script = data.SHA256()
        val scriptHash = script.HexToByteArray()
        return Bech32.segwitToBech32("bc", 0, scriptHash)
    }

    private fun P2WPKH(network: String, data: String): String {
        val pubkey = data.SHA256()
        val pubkeyHas = pubkey.RIPEMD160().HexToByteArray()
        return Bech32.segwitToBech32("bc", 0, pubkeyHas)
    }

    private fun P2PKH(network: String, data: String): String {
        val PREFIX_NESTED: String = CHAIN["p2pkh"].toString()
        val pubkey: String = data.SHA256()
        val pubkeyHas: String = pubkey.RIPEMD160()

        val components: String = PREFIX_NESTED + pubkeyHas
        val checksum: ByteArray = components.HexToByteArray().getChecksum()

        val combine: String = components + checksum.ByteArrayToHex()
        return combine.encodeBase58()
    }

    private fun NestedSegWit(network: String, data: String): String {
        val dataHash256: String = data.SHA256()
        val size = dataHash256.HexToByteArray().size.toString(16)

        val redeemScript: String = CHAIN["p2pkh"].toString() + size + dataHash256
        return redeemScript.getP2SH("main")
    }

    private fun P2SH(network: String, data: String): String {
        val redeemScript: String = data.SHA256()
        val redeemScriptHas: String = redeemScript.RIPEMD160()

        val components: String = CHAIN["p2sh"].toString() + redeemScriptHas
        val checksum: ByteArray = components.HexToByteArray().getChecksum()

        val combine: String = components + checksum.ByteArrayToHex()
        return combine.encodeBase58()
    }

    // ──────────────────────────────────────────────────────────────────────────────────────── \\

    // Pay-to-Witness-Script-Hash
    fun String.getP2WSH(network: String): String {
        return P2WSH(network, this)
    }

    // Pay-to-Witness-Public-Key-Hash
    fun String.getP2WPKH(network: String): String {
        return P2WPKH(network, this)
    }

    // Pay-to-Public-Key-Hash
    fun String.getP2PKH(network: String): String {
        return P2PKH(network, this)
    }

    // Nested SegWit (P2SH-P2WPKH)
    fun String.segwitP2SH(network: String): String {
        return NestedSegWit(network, this)
    }

    // Pay-to-Script-Hash
    fun String.getP2SH(network: String): String {
        return P2SH(network, this)
    }

    // ──────────────────────────────────────────────────────────────────────────────────────── \\

    /*
    * ในส่วนนี้ ใช้สำหรับการตรวจสอบความถูกต้องของ Locking Script ต่าง ๆ
    * */
    object verify {

        private fun findeChecksum(data: ByteArray): ByteArray {
            val hash = data.doubleSHA256()
            return hash.sliceArray(0 until 4)
        }

        private fun P2PKH(address: String): Boolean {
            val decodedAddress = address.decodeBase58().HexToByteArray()
            if (decodedAddress.size != 25) {
                return false
            }

            val checksum = findeChecksum(decodedAddress.sliceArray(0 until 21))
            if (!decodedAddress.sliceArray(21 until 25).contentEquals(checksum)) {
                return false
            }

            val networkPrefix = decodedAddress[0]
            return networkPrefix == 0x00.toByte()
        }

        private fun P2WSH(address: String): Boolean {
            val decodedAddress = Bech32.bech32ToSegwit(address)
            val humanPart = decodedAddress[0] as String
            val witVer = decodedAddress[1] as Int
            val witProg = decodedAddress[2] as ByteArray

            return witVer == 0 || humanPart == "bc" && witProg.size == 32
        }

        private fun P2WPKH(address: String): Boolean {
            val decodedAddress = Bech32.bech32ToSegwit(address)
            val humanPart = decodedAddress[0] as String
            val witVer = decodedAddress[1] as Int
            val witProg = decodedAddress[2] as ByteArray

            return witVer == 0 || humanPart == "bc" && witProg.size == 20
        }

        // ──────────────────────────────────────────────────────────────────────────────────────── \\

        fun ByteArray.getChecksum(): ByteArray {
            return findeChecksum(this)
        }

        fun String.isP2PKH(): Boolean {
            return P2PKH(this)
        }

        fun String.isP2WSH(): Boolean {
            return P2WSH(this)
        }

        fun String.isP2WPKH(): Boolean {
            return P2WPKH(this)
        }

    }
}

fun main() {


    val P2PKH = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
    val isValidP2PKH = P2PKH.isP2PKH()

    if (isValidP2PKH) {
        println("The address is valid.")
    } else {
        println("The address is not valid.")
    }


    val P2WSH = "bc1qqsa8rpm5c4etmz394kltr07dtsp9dts3em8el8pljfwsu54747ys0t028e"
    val isValidP2WSH = P2WSH.isP2WSH()

    if (isValidP2WSH) {
        println("The address is valid.")
    } else {
        println("The address is not valid.")
    }


    val P2WPKH = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    val isValidP2WPKH = P2WPKH.isP2WPKH()

    if (isValidP2WPKH) {
        println("The address is valid.")
    } else {
        println("The address is not valid.")
    }

}