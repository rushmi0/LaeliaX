package LaeliaX.util

fun main() {
    val txID = "15e10745f15593a899cef391191bdd3d7c12412cc4696b7bcb669d0feadc8521"
    val command = "curl -sSL \"https://mempool.space/api/tx/${txID}/status\""
    val output = executeCommand(command)
    println(output)
}

fun executeCommand(command: String): String {
    val process = ProcessBuilder("/bin/bash", "-c", command)
        .redirectOutput(ProcessBuilder.Redirect.PIPE)
        .redirectError(ProcessBuilder.Redirect.PIPE)
        .start()

    process.waitFor()

    val output: String = process.inputStream.bufferedReader().readText()
    val error = process.errorStream.bufferedReader().readText()

    if (error.isNotEmpty()) {
        executeCommand(command)
        throw RuntimeException("Command execution error: $error")
    }
    return output
}
