package com.eltavine.duckdetector.features.zygisk.data.fdtrap

import android.os.IBinder
import android.os.Parcel
import android.os.ParcelFileDescriptor

class ZygiskFdTrapDetectorProxy(
    private val remote: IBinder,
) {

    fun performDetection(
        pfd: ParcelFileDescriptor,
    ): Int {
        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        return try {
            data.writeInterfaceToken(ZygiskFdTrapDetectorService.DESCRIPTOR)
            data.writeInt(1)
            pfd.writeToParcel(data, 0)
            remote.transact(
                ZygiskFdTrapDetectorService.TRANSACTION_PERFORM_DETECTION,
                data,
                reply,
                0
            )
            reply.readException()
            reply.readInt()
        } finally {
            data.recycle()
            reply.recycle()
        }
    }

    fun getDetectionDetails(): String {
        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        return try {
            data.writeInterfaceToken(ZygiskFdTrapDetectorService.DESCRIPTOR)
            remote.transact(ZygiskFdTrapDetectorService.TRANSACTION_GET_DETAILS, data, reply, 0)
            reply.readException()
            reply.readString() ?: "No details."
        } finally {
            data.recycle()
            reply.recycle()
        }
    }

    fun isNativeAvailable(): Boolean {
        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        return try {
            data.writeInterfaceToken(ZygiskFdTrapDetectorService.DESCRIPTOR)
            remote.transact(
                ZygiskFdTrapDetectorService.TRANSACTION_IS_NATIVE_AVAILABLE,
                data,
                reply,
                0
            )
            reply.readException()
            reply.readInt() != 0
        } finally {
            data.recycle()
            reply.recycle()
        }
    }
}
