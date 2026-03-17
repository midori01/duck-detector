package com.eltavine.duckdetector.features.tee.data.verification.keystore

import android.os.Build
import android.os.IBinder
import android.os.Parcel

class Keystore2HookProbe {

    fun inspect(): Keystore2HookResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return Keystore2HookResult(
                available = false,
                detail = "Keystore2 raw transaction probe requires Android 12 or newer.",
            )
        }
        val binder = lookupKeystoreBinder() ?: return Keystore2HookResult(
            available = false,
            detail = "Keystore2 binder endpoint was not available.",
        )
        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        return runCatching {
            data.writeInterfaceToken(INTERFACE_DESCRIPTOR)
            data.writeInt(1)
            data.writeInt(0)
            data.writeLong(-1L)
            data.writeString("duck_missing_key_${System.nanoTime()}")
            data.writeByteArray(null)
            val success = binder.transact(TRANSACTION_GET_KEY_ENTRY, data, reply, 0)
            if (!success) {
                return Keystore2HookResult(
                    available = true,
                    detail = "Keystore2 transact() returned false.",
                )
            }
            parseReply(reply)
        }.getOrElse { throwable ->
            Keystore2HookResult(
                available = true,
                detail = throwable.message ?: "Keystore2 hook probe failed.",
            )
        }.also {
            data.recycle()
            reply.recycle()
        }
    }

    private fun parseReply(reply: Parcel): Keystore2HookResult {
        val rawPrefix = captureRawPrefix(reply, minOf(32, reply.dataSize()))
        reply.setDataPosition(0)
        if (reply.dataSize() < 8) {
            return Keystore2HookResult(
                available = true,
                rawPrefix = rawPrefix,
                detail = "Keystore2 reply was too small to fingerprint.",
            )
        }
        val exceptionCode = reply.readInt()
        if (exceptionCode != EX_SERVICE_SPECIFIC) {
            return Keystore2HookResult(
                available = true,
                rawPrefix = rawPrefix,
                detail = if (exceptionCode == 0) {
                    "Missing-key transaction unexpectedly succeeded."
                } else {
                    "Keystore2 reply used exception code $exceptionCode."
                },
            )
        }
        val secondWord = reply.readInt()
        return when {
            secondWord == RESPONSE_KEY_NOT_FOUND -> Keystore2HookResult(
                available = true,
                javaHookDetected = true,
                nativeStyleResponse = false,
                errorCode = RESPONSE_KEY_NOT_FOUND,
                rawPrefix = rawPrefix,
                detail = "Keystore2 reply skipped the String16 slot and jumped straight to KEY_NOT_FOUND.",
            )

            secondWord == STRING16_NULL || secondWord >= 0 -> {
                val messageLength = secondWord
                if (messageLength > 0) {
                    val utf16Bytes = (messageLength + 1) * 2
                    val padded = (utf16Bytes + 3) and 3.inv()
                    reply.setDataPosition(reply.dataPosition() + padded)
                }
                val stackHeader =
                    if (reply.dataPosition() + 4 <= reply.dataSize()) reply.readInt() else null
                val errorCode =
                    if (reply.dataPosition() + 4 <= reply.dataSize()) reply.readInt() else null
                Keystore2HookResult(
                    available = true,
                    javaHookDetected = false,
                    nativeStyleResponse = true,
                    messageLength = messageLength,
                    errorCode = errorCode,
                    rawPrefix = rawPrefix,
                    detail = buildString {
                        append("Native-style Keystore2 reply")
                        append(" msgLen=")
                        append(messageLength)
                        stackHeader?.let {
                            append(" stack=")
                            append(it)
                        }
                        errorCode?.let {
                            append(" error=")
                            append(it)
                        }
                    },
                )
            }

            else -> Keystore2HookResult(
                available = true,
                rawPrefix = rawPrefix,
                detail = "Keystore2 reply used an unknown serialization fingerprint ($secondWord).",
            )
        }
    }

    private fun captureRawPrefix(parcel: Parcel, bytesToRead: Int): String {
        val originalPosition = parcel.dataPosition()
        parcel.setDataPosition(0)
        val bytes = ByteArray(bytesToRead)
        var cursor = 0
        while (cursor < bytesToRead && parcel.dataPosition() < parcel.dataSize()) {
            bytes[cursor] = parcel.readByte()
            cursor += 1
        }
        parcel.setDataPosition(originalPosition)
        return bytes.take(cursor).joinToString(" ") { byte ->
            "%02X".format(byte.toInt() and 0xFF)
        }
    }

    @Suppress("PrivateApi")
    private fun lookupKeystoreBinder(): IBinder? {
        return runCatching {
            val serviceManager = Class.forName("android.os.ServiceManager")
            val getService = serviceManager.getMethod("getService", String::class.java)
            getService.invoke(null, "$INTERFACE_DESCRIPTOR/default") as? IBinder
        }.getOrNull()
    }

    companion object {
        private const val INTERFACE_DESCRIPTOR = "android.system.keystore2.IKeystoreService"
        private const val TRANSACTION_GET_KEY_ENTRY = 2
        private const val EX_SERVICE_SPECIFIC = -8
        private const val STRING16_NULL = -1
        private const val RESPONSE_KEY_NOT_FOUND = 7
    }
}

data class Keystore2HookResult(
    val available: Boolean,
    val javaHookDetected: Boolean = false,
    val nativeStyleResponse: Boolean = false,
    val messageLength: Int? = null,
    val errorCode: Int? = null,
    val rawPrefix: String? = null,
    val detail: String,
)
