package LaeliaX.Transaction


import LaeliaX.SecureKey.ECDSA
import LaeliaX.util.ShiftTo.DeciToHex
import LaeliaX.util.ShiftTo.HexToByteArray
import java.math.BigInteger

import LaeliaX.Transaction.digitTx.ScriptSigComponents
import LaeliaX.Transaction.digitTx.mergeDataAtIndex


object digitTx {

    fun ScriptSigComponents(scriptContract: String, SignaturePoint: Pair<BigInteger, BigInteger>): String {

        val Signature = ECDSA.toDERFormat(SignaturePoint) + "01"
        val SignatureLength: String = Signature.HexToByteArray().size.DeciToHex()

        val RedeemLength: String = scriptContract.HexToByteArray().size.DeciToHex()
        val RedeemScript: String = scriptContract

        val scriptSigLength: String = (
                SignatureLength +
                Signature +
                RedeemLength +
                RedeemScript
        ).HexToByteArray().size.DeciToHex()

        val ScritpSig = scriptSigLength + SignatureLength + Signature + RedeemLength + RedeemScript
        return ScritpSig
    }

    fun mergeDataAtIndex(stack: String, ScriptSig: String): String {

        //val countIndex = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(time).array().ByteArrayToHex()

        // Pattern to detect and capture data
        val pattern = "00000000(.*?)f(.?)ffffff"

        // Step 1: Find the first occurrence of the pattern
        val regex = Regex(pattern)
        val match = regex.find(stack)

        if (match != null) {
            val originalData = match.groupValues[1]
            val modifiedData = ScriptSig

            // Step 2: Replace data with new data at the identified index
            val result = stack.replaceFirst(originalData, modifiedData)

            return result
        }

        return stack // Return the original stack if the pattern is not found
    }


    fun mergeDataAtIndex(stack: String, index: Int, scriptSig: String): String {
         // Pattern to detect and count occurrences
        val matches = mutableListOf<String>()
        var lastIndex = 0

        val pattern = "00000000(.*?)f(.?)ffffff"
        val regex = Regex(pattern)

        // Step 1: Detect and count patterns using a loop
        while (true) {
            
            val matchResult = regex.find(stack, lastIndex)
            if (matchResult != null) {
                val match = matchResult.value
                matches.add(match)
                lastIndex = matchResult.range.last + 1
            } else {
                break
            }
        }

        if (index in 1..matches.size) {
            val targetMatch = matches[index - 1]

            // Step 2: Find occurrence at specific index
            val originalData = targetMatch.substring(8, targetMatch.length - 8)
            val modifiedData = scriptSig// Prepend "00000000" to the new data

            // Step 3: Replace data with new data at the identified index
            val result = stack.replaceFirst(originalData, modifiedData)

            return result
        }

        return stack // Return the original stack if the specified index is out of range
    }


}

fun main() {

    val r = BigInteger("A39E93B55AAF7AEE63A6920A10A07CDD98D21AD4EF148BF19D923A69910A1F62", 16)
    val s = BigInteger("073125ADC658725A680E11727314939C62715A5869BF4B8907A36C7F1588A99B", 16)
    val sig: Pair<BigInteger, BigInteger> = Pair(r, s)

    val scriptContract = "030c3725b1752102aa36a1958e2fc5e5de75d05bcf6f3ccc0799be4905f4e418505dc6ab4422a8dbac"

    val scriptSig = ScriptSigComponents(scriptContract, sig)
    println(scriptSig)

    //val stack = "0100000001fc3adf56a9b345dd394479b5438365777ba7d91eb3954d9f2b5e2c7a68d06b980000000029030c3725b1752102aa36a1958e2fc5e5de75d05bcf6f3ccc0799be4905f4e418505dc6ab4422a8dbacfdffffff01d36f0300000000001600149058b7a55f5d5f88667a01fd66dd59e379002f5d0c372500"
    val stack = "0100000002cb1a50fbd2437ac064bd7306984d5fe2154c929e75b1ca0ea25261ceb13950c9000000002903abb915b1752102aa36a1958e2fc5e5de75d05bcf6f3ccc0799be4905f4e418505dc6ab4422a8dbacfdffffff03db4904d6b861b13331d4cfdf7b46e557f6b49a9090570d152c4bd309ecf394020000007003abb915b17552210387cb20433e452a106312107c4885c27f209d6ece38055c8bea56bcbc8b1e29af2102635073d61f689a9dd38be41de286ebb3b7137394164d1e00d4eeb4d7bb9ff48b21024bc043a0c094c5f2865dad0c494e6e9e76b3d6034e4ce55895b4ea8285274dd753aeacfdffffff02983a000000000000160014342329383239d2f100a425ecf5112142e85ad10e0088526a74000000160014b2863de4442be1b0cec91b6c28bea1c9806e7317abb91500"
    val index = 1

    val result = mergeDataAtIndex(stack, scriptSig)
    println(result)

    val result_2 = mergeDataAtIndex(stack, index, scriptSig)
    println(result_2)



}