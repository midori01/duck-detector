package com.eltavine.duckdetector.features.tee.data.verification.keystore

import android.os.Build
import android.os.IBinder
import android.os.Parcel
import org.lsposed.hiddenapibypass.HiddenApiBypass
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.lang.reflect.Proxy
import java.security.SecureRandom

class Keystore2PrivateBinderClient {

    fun lookupBinder(): IBinder? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return null
        }
        ensureHiddenApiAccess()
        return runCatching {
            val serviceManager = loadClass("android.os.ServiceManager")
            val getService = serviceManager.getMethod("getService", String::class.java)
            getService.invoke(null, SERVICE_NAME) as? IBinder
        }.getOrNull()
    }

    fun buildGetKeyEntryRequest(alias: String): Keystore2BinderRequest {
        return Keystore2BinderRequest(
            interfaceDescriptor = INTERFACE_DESCRIPTOR,
            transactionCode = TRANSACTION_GET_KEY_ENTRY,
            alias = alias,
        ) { data ->
            data.writeInterfaceToken(INTERFACE_DESCRIPTOR)
            data.writeInt(1)
            data.writeInt(0)
            data.writeLong(-1L)
            data.writeString(alias)
            data.writeByteArray(null)
        }
    }

    fun executeRequest(
        binder: IBinder,
        request: Keystore2BinderRequest,
    ): BinderTransactionResult {
        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        return try {
            request.writeTo(data)
            val success = binder.transact(request.transactionCode, data, reply, 0)
            val snapshot = captureReplySnapshot(reply)
            BinderTransactionResult(
                success = success,
                replySnapshot = snapshot,
                replyFailureReason = if (success) null else "Keystore2 transact() returned false for alias=${request.alias}",
            )
        } catch (throwable: Throwable) {
            BinderTransactionResult(
                success = false,
                throwable = throwable,
                replyFailureReason = throwable.message ?: "Keystore2 transact failed for alias=${request.alias}",
            )
        } finally {
            data.recycle()
            reply.recycle()
        }
    }

    fun transactGetKeyEntry(binder: IBinder, alias: String): BinderTransactionResult {
        return executeRequest(binder, buildGetKeyEntryRequest(alias))
    }

    fun openSession(useStrongBox: Boolean = false): Keystore2PrivateSessionResult {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return Keystore2PrivateSessionResult(
                failureReason = "Keystore2 private binder proxy requires Android 12 or newer.",
            )
        }

        ensureHiddenApiAccess()
        val proxyInstalled = installPrivateBinderProxy()
        val binder = lookupBinder() ?: return Keystore2PrivateSessionResult(
            failureReason = "Keystore2 binder endpoint was not available.",
        )
        val service = getKeystoreService() ?: return Keystore2PrivateSessionResult(
            failureReason = "Keystore2 service interface was not available after installing the private binder proxy.",
        )
        val securityLevel = resolveSecurityLevel(
            service = service,
            level = if (useStrongBox) SECURITY_LEVEL_STRONGBOX else SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
        ) ?: return Keystore2PrivateSessionResult(
            failureReason = "Keystore2 security level proxy was not available.",
        )

        val session = Keystore2PrivateSession(
            binder = binder,
            service = service,
            securityLevel = securityLevel,
            proxyInstalled = proxyInstalled,
            serviceProxyActive = Proxy.isProxyClass(service.javaClass),
            securityLevelProxyActive = Proxy.isProxyClass(securityLevel.javaClass),
        )
        return if (!session.serviceProxyActive || !session.securityLevelProxyActive) {
            Keystore2PrivateSessionResult(
                failureReason = "Keystore2 private binder proxy did not wrap both service and security-level interfaces.",
            )
        } else {
            Keystore2PrivateSessionResult(session = session)
        }
    }

    fun createKeyDescriptor(alias: String): Any {
        val descriptorClass = loadClass(CLASS_KEY_DESCRIPTOR)
        val descriptor = descriptorClass.getDeclaredConstructor().newInstance()
        setField(descriptor, "domain", 0)
        setField(descriptor, "nspace", -1L)
        setField(descriptor, "alias", alias)
        setField(descriptor, "blob", null)
        return descriptor
    }

    fun generateAttestationKey(securityLevel: Any, keyDescriptor: Any) {
        var lastFailure: Throwable? = null
        val parameterSets = listOf(
            listOf(
                createKeyParameter(0x10000002, 3),
                createKeyParameter(0x30000003, 256),
                createKeyParameter(0x1000000A, 1),
                createKeyParameter(0x20000001, 7),
                createKeyParameter(0x20000005, 4),
                createKeyParameter(0x700001F7, true),
            ),
            listOf(
                createKeyParameter(0x10000002, 3),
                createKeyParameter(0x30000003, 256),
                createKeyParameter(0x1000000A, 1),
                createKeyParameter(0x20000001, 7),
                createKeyParameter(0x20000005, 0),
                createKeyParameter(0x700001F7, true),
            ),
            listOf(
                createKeyParameter(0x10000002, 3),
                createKeyParameter(0x30000003, 256),
                createKeyParameter(0x1000000A, 1),
                createKeyParameter(0x20000001, 7),
                createKeyParameter(0x700001F7, true),
            ),
        )

        for (parameters in parameterSets) {
            try {
                invokeGenerateKey(securityLevel, keyDescriptor, null, parameters)
                return
            } catch (throwable: Throwable) {
                lastFailure = throwable
            }
        }

        throw lastFailure ?: IllegalStateException("Unable to provision PURPOSE_ATTEST_KEY test key.")
    }

    fun generateSigningKey(
        securityLevel: Any,
        keyDescriptor: Any,
        attestationKeyDescriptor: Any?,
        attest: Boolean,
    ) {
        val parameters = buildSigningKeyParameters(attest)
        invokeGenerateKey(securityLevel, keyDescriptor, attestationKeyDescriptor, parameters)
    }

    fun captureGenerateKeyReply(useStrongBox: Boolean = false): GenerateKeyReplyCaptureResult {
        val sessionResult = openSession(useStrongBox = useStrongBox)
        val session = sessionResult.session ?: return GenerateKeyReplyCaptureResult(
            available = false,
            detail = sessionResult.failureReason ?: "Keystore2 private binder proxy session unavailable.",
        )
        val alias = "${DEFAULT_GENERATE_MODE_ALIAS_PREFIX}_${System.nanoTime()}"
        val keyDescriptor = createKeyDescriptor(alias)

        return try {
            val capture = invokeGenerateKeyWithReplyCapture(
                securityLevel = session.securityLevel,
                keyDescriptor = keyDescriptor,
                attestationKeyDescriptor = null,
                parameters = buildGenerateModeSigningKeyParameters(),
            )
            when {
                capture.rawReply != null -> GenerateKeyReplyCaptureResult(
                    available = true,
                    rawReply = capture.rawReply,
                    rawPrefix = capture.rawPrefix,
                    detail = buildString {
                        append("Captured generateKey reply via private binder proxy transact")
                        append("; bytes=")
                        append(capture.rawReply.size)
                        capture.transactionCode?.let {
                            append(", code=")
                            append(it)
                        }
                        capture.transactReturned?.let {
                            append(", transactReturned=")
                            append(it)
                        }
                        capture.throwable?.let {
                            append(", invocation=")
                            append(describeThrowable(it))
                        }
                    },
                )
                else -> GenerateKeyReplyCaptureResult(
                    available = false,
                    detail = capture.failureReason
                        ?: capture.throwable?.let(::describeThrowable)
                        ?: "generateKey reply capture did not observe a marshalled reply.",
                )
            }
        } catch (throwable: Throwable) {
            GenerateKeyReplyCaptureResult(
                available = false,
                detail = describeThrowable(throwable),
            )
        } finally {
            deleteKey(session.service, keyDescriptor)
        }
    }

    fun getKeyEntry(service: Any, keyDescriptor: Any) {
        getKeyEntryResponse(service, keyDescriptor)
    }

    fun getKeyEntryResponse(service: Any, keyDescriptor: Any): Any? {
        return service.javaClass
            .getMethod("getKeyEntry", keyDescriptor.javaClass)
            .invoke(service, keyDescriptor)
    }

    fun getMetadata(keyEntryResponse: Any): Any? = getFieldValue(keyEntryResponse, "metadata")

    fun getReturnedDescriptor(keyEntryResponse: Any): Any? {
        return getMetadata(keyEntryResponse)?.let { metadata ->
            getFieldValue(metadata, "key")
        } ?: getFieldValue(keyEntryResponse, "key")
    }

    fun getSecurityLevelBinder(keyEntryResponse: Any): Any? = getFieldValue(keyEntryResponse, "iSecurityLevel")

    fun getMetadataSecurityLevel(keyEntryResponse: Any): Any? {
        val metadata = getMetadata(keyEntryResponse) ?: return null
        return getFieldValue(metadata, "keySecurityLevel")
    }

    fun getPureCertSecurityLevel(keyEntryResponse: Any): Any? {
        getSecurityLevelBinder(keyEntryResponse)?.let { return it }
        return getMetadataSecurityLevel(keyEntryResponse)
    }

    fun getMetadataModificationTimeMs(metadata: Any): Long? {
        val raw = getFieldValue(metadata, "modificationTimeMs") ?: return null
        return when (raw) {
            is Long -> raw
            is Int -> raw.toLong()
            else -> null
        }
    }

    fun getMetadataAuthorizations(metadata: Any): Array<Any?> {
        return toObjectArray(getFieldValue(metadata, "authorizations"))
    }

    fun getAuthorizationTag(authorization: Any): Int? {
        val keyParameter = getFieldValue(authorization, "keyParameter") ?: return null
        return getFieldValue(keyParameter, "tag") as? Int
    }

    fun createKeyIdDescriptor(nspace: Long, aliasHint: String? = null): Any {
        val descriptorClass = loadClass(CLASS_KEY_DESCRIPTOR)
        val descriptor = descriptorClass.getDeclaredConstructor().newInstance()
        setField(descriptor, "domain", getDomainKeyId())
        setField(descriptor, "nspace", nspace)
        setField(descriptor, "alias", aliasHint)
        setField(descriptor, "blob", null)
        return descriptor
    }

    fun getDescriptorDomain(descriptor: Any): Int? = getFieldValue(descriptor, "domain") as? Int

    fun getDescriptorAlias(descriptor: Any): String? = getFieldValue(descriptor, "alias") as? String

    fun getDescriptorNamespace(descriptor: Any): Long? {
        val raw = getFieldValue(descriptor, "nspace") ?: return null
        return when (raw) {
            is Long -> raw
            is Int -> raw.toLong()
            else -> null
        }
    }

    fun getDomainKeyId(): Int {
        return runCatching {
            val domainClass = loadClass("android.system.keystore2.Domain")
            domainClass.getField("KEY_ID").getInt(null)
        }.getOrDefault(DOMAIN_KEY_ID_FALLBACK)
    }

    fun getTagValue(name: String): Int? {
        return runCatching {
            val tagClass = loadClass("android.hardware.security.keymint.Tag")
            tagClass.getField(name).getInt(null)
        }.getOrNull()
    }

    fun getKeyPurposeValue(name: String): Int? {
        return runCatching {
            val purposeClass = loadClass("android.hardware.security.keymint.KeyPurpose")
            purposeClass.getField(name).getInt(null)
        }.getOrNull()
    }

    fun getDigestValue(name: String): Int? {
        return runCatching {
            val digestClass = loadClass("android.hardware.security.keymint.Digest")
            digestClass.getField(name).getInt(null)
        }.getOrNull()
    }

    fun getAlgorithmValue(name: String): Int? {
        return runCatching {
            val algorithmClass = loadClass("android.hardware.security.keymint.Algorithm")
            algorithmClass.getField(name).getInt(null)
        }.getOrNull()
    }

    fun getKeyMintErrorCodeValue(name: String): Int? {
        return runCatching {
            val errorCodeClass = loadClass("android.hardware.security.keymint.ErrorCode")
            errorCodeClass.getField(name).getInt(null)
        }.getOrNull()
    }

    fun deleteKey(service: Any, keyDescriptor: Any) {
        runCatching {
            service.javaClass
                .getMethod("deleteKey", keyDescriptor.javaClass)
                .invoke(service, keyDescriptor)
        }
    }

    fun listEntries(service: Any): Array<Any?> {
        val method = service.javaClass.methods.firstOrNull {
            it.name == "listEntries" && it.parameterTypes.size >= 2
        } ?: throw NoSuchMethodException("Unable to find hidden listEntries on ${service.javaClass.name}")
        method.isAccessible = true
        return toObjectArray(method.invoke(service, *buildListEntriesArgs(method.parameterTypes)))
    }

    fun listEntriesBatched(service: Any, startPastAlias: String): Array<Any?> {
        val method = service.javaClass.methods.firstOrNull {
            it.name == "listEntriesBatched" && it.parameterTypes.size >= 3
        } ?: throw NoSuchMethodException("Unable to find hidden listEntriesBatched on ${service.javaClass.name}")
        method.isAccessible = true
        return toObjectArray(method.invoke(service, *buildListEntriesArgs(method.parameterTypes, startPastAlias)))
    }

    fun createTimingAliases(prefix: String = DEFAULT_ALIAS_PREFIX): TimingKeyAliases {
        val suffix = System.nanoTime()
        return TimingKeyAliases(
            aliasPrefix = prefix,
            attestedAlias = "${prefix}_Attested_$suffix",
            nonAttestedAlias = "${prefix}_NonAttested_$suffix",
            attestKeyAlias = "${prefix}_AttestKey_$suffix",
        )
    }

    fun createSigningOperationParameters(): List<Any> {
        val purposeTag = getTagValue("PURPOSE") ?: 0x10000001
        val digestTag = getTagValue("DIGEST") ?: 0x20000005
        val signPurpose = getKeyPurposeValue("SIGN") ?: 2
        val sha256Digest = getDigestValue("SHA_2_256") ?: 4
        return listOf(
            createKeyParameter(purposeTag, signPurpose),
            createKeyParameter(digestTag, sha256Digest),
        )
    }

    fun createSigningOperationParametersWithAlgorithm(): List<Any> {
        val algorithmTag = getTagValue("ALGORITHM") ?: 0x10000002
        val ecAlgorithm = getAlgorithmValue("EC") ?: 3
        return createSigningOperationParameters() + createKeyParameter(algorithmTag, ecAlgorithm)
    }

    fun createOperation(
        securityLevel: Any,
        keyDescriptor: Any,
        parameters: List<Any>,
    ): Any? {
        val keyParameterClass = loadClass(CLASS_KEY_PARAMETER)
        val array = java.lang.reflect.Array.newInstance(keyParameterClass, parameters.size)
        parameters.forEachIndexed { index, value ->
            java.lang.reflect.Array.set(array, index, value)
        }
        securityLevel.javaClass.methods.firstOrNull {
            it.name == "createOperation" &&
                it.parameterTypes.size == 3 &&
                it.parameterTypes[0].isAssignableFrom(keyDescriptor.javaClass) &&
                it.parameterTypes[1].isArray &&
                (it.parameterTypes[2] == Boolean::class.javaPrimitiveType ||
                    it.parameterTypes[2] == Boolean::class.java)
        }?.let { exactMethod ->
            exactMethod.isAccessible = true
            return exactMethod.invoke(securityLevel, keyDescriptor, array, false)
        }
        val createOperationMethod = securityLevel.javaClass.methods.firstOrNull {
            it.name == "createOperation" && it.parameterTypes.isNotEmpty()
        } ?: throw NoSuchMethodException("Unable to find hidden createOperation on ${securityLevel.javaClass.name}")
        createOperationMethod.isAccessible = true
        val args = createOperationMethod.parameterTypes.mapIndexed { index, type ->
            when {
                index == 0 -> keyDescriptor
                index == 1 && type.isArray -> array
                type == Boolean::class.javaPrimitiveType || type == Boolean::class.java -> false
                type == Int::class.javaPrimitiveType || type == Int::class.java -> 0
                type == Long::class.javaPrimitiveType || type == Long::class.java -> 0L
                type == ByteArray::class.java -> ByteArray(0)
                else -> null
            }
        }.toTypedArray()
        return createOperationMethod.invoke(securityLevel, *args)
    }

    fun getOperationHandle(createOperationResponse: Any?): Any? {
        if (createOperationResponse == null) {
            return null
        }
        return getFieldValue(createOperationResponse, "iOperation")
            ?: getFieldValue(createOperationResponse, "operation")
    }

    fun getCertificateBlob(keyEntryResponse: Any): ByteArray? {
        return (getFieldValue(keyEntryResponse, "certificate") as? ByteArray)
            ?: (getMetadata(keyEntryResponse)?.let { getFieldValue(it, "certificate") } as? ByteArray)
    }

    fun getCertificateChainBlob(keyEntryResponse: Any): ByteArray? {
        return (getFieldValue(keyEntryResponse, "certificateChain") as? ByteArray)
            ?: (getMetadata(keyEntryResponse)?.let { getFieldValue(it, "certificateChain") } as? ByteArray)
    }

    fun abortOperation(operation: Any?) {
        if (operation == null) {
            return
        }
        operation.javaClass.getMethod("abort").invoke(operation)
    }

    fun updateOperation(operation: Any, input: ByteArray): Any? {
        return operation.javaClass.getMethod("update", ByteArray::class.java).invoke(operation, input)
    }

    fun updateAadOperation(operation: Any, input: ByteArray): Any? {
        return operation.javaClass.getMethod("updateAad", ByteArray::class.java).invoke(operation, input)
    }

    fun isServiceSpecificException(throwable: Throwable): Boolean {
        return findThrowable(throwable) { it.javaClass.name == "android.os.ServiceSpecificException" } != null
    }

    fun extractServiceSpecificErrorCode(throwable: Throwable): Int? {
        val serviceSpecific = findThrowable(throwable) {
            it.javaClass.name == "android.os.ServiceSpecificException"
        } ?: return null
        return getFieldValue(serviceSpecific, "errorCode") as? Int
    }

    fun describeThrowable(throwable: Throwable): String {
        val root = findRootCause(throwable)
        val detail = root.message?.takeIf { it.isNotBlank() }
        return if (detail != null) {
            "${root.javaClass.simpleName}: $detail"
        } else {
            root.javaClass.simpleName
        }
    }

    private fun invokeGenerateKey(
        securityLevel: Any,
        keyDescriptor: Any,
        attestationKeyDescriptor: Any?,
        parameters: List<Any>,
    ) {
        val invocation = buildGenerateKeyInvocation(
            securityLevel = securityLevel,
            keyDescriptor = keyDescriptor,
            attestationKeyDescriptor = attestationKeyDescriptor,
            parameters = parameters,
        )
        invokeProxyMethod(invocation.target, invocation.method, invocation.args)
    }

    private fun invokeGenerateKeyWithReplyCapture(
        securityLevel: Any,
        keyDescriptor: Any,
        attestationKeyDescriptor: Any?,
        parameters: List<Any>,
    ): GenerateKeyReplyCaptureSnapshot {
        val invocation = buildGenerateKeyInvocation(
            securityLevel = securityLevel,
            keyDescriptor = keyDescriptor,
            attestationKeyDescriptor = attestationKeyDescriptor,
            parameters = parameters,
        )
        val slot = GenerateKeyReplyCaptureSlot()
        generateKeyReplyCaptureSlot.set(slot)
        return try {
            runCatching {
                invokeProxyMethod(invocation.target, invocation.method, invocation.args)
            }.fold(
                onSuccess = {
                    slot.toSnapshot(
                        defaultFailureReason = "generateKey completed without an observable reply payload.",
                    )
                },
                onFailure = { throwable ->
                    slot.toSnapshot(
                        throwable = throwable,
                        defaultFailureReason = "generateKey failed before the private binder proxy captured a reply.",
                    )
                },
            )
        } finally {
            generateKeyReplyCaptureSlot.remove()
        }
    }

    private fun buildGenerateKeyInvocation(
        securityLevel: Any,
        keyDescriptor: Any,
        attestationKeyDescriptor: Any?,
        parameters: List<Any>,
    ): HiddenMethodInvocation {
        val keyParameterClass = loadClass(CLASS_KEY_PARAMETER)
        val array = java.lang.reflect.Array.newInstance(keyParameterClass, parameters.size)
        parameters.forEachIndexed { index, value ->
            java.lang.reflect.Array.set(array, index, value)
        }
        val generateKeyMethod = securityLevel.javaClass.methods.firstOrNull {
            it.name == "generateKey" && it.parameterTypes.size == 5
        } ?: throw NoSuchMethodException("Unable to find hidden generateKey signature on ${securityLevel.javaClass.name}")
        generateKeyMethod.isAccessible = true
        return HiddenMethodInvocation(
            target = securityLevel,
            method = generateKeyMethod,
            args = arrayOf(
                keyDescriptor,
                attestationKeyDescriptor,
                array,
                0,
                ByteArray(0),
            ),
        )
    }

    private fun buildSigningKeyParameters(attest: Boolean): List<Any> {
        return buildList {
            add(createKeyParameter(0x10000002, 3))
            add(createKeyParameter(0x30000003, 256))
            add(createKeyParameter(0x1000000A, 1))
            add(createKeyParameter(0x20000001, 2))
            add(createKeyParameter(0x20000005, 4))
            add(createKeyParameter(0x700001F7, true))
            if (attest) {
                add(createKeyParameter(0x900002C4.toInt(), ByteArray(32).also(SecureRandom()::nextBytes)))
            }
        }
    }

    private fun buildGenerateModeSigningKeyParameters(): List<Any> {
        return buildList {
            add(createKeyParameter(0x10000002, 3))
            add(createKeyParameter(0x1000000A, 1))
            add(createKeyParameter(0x20000005, 4))
            add(createKeyParameter(0x20000001, 2))
            add(createKeyParameter(0x900002C4.toInt(), ByteArray(32).also(SecureRandom()::nextBytes)))
            add(createKeyParameter(0x700001F7, true))
        }
    }

    private fun createKeyParameter(tag: Int, value: Any): Any {
        val parameterClass = loadClass(CLASS_KEY_PARAMETER)
        val parameter = parameterClass.getDeclaredConstructor().newInstance()
        setField(parameter, "tag", tag)

        val valueClass = loadClass(CLASS_KEY_PARAMETER_VALUE)
        val valueObject = createKeyParameterValue(valueClass, tag, value)
        setField(parameter, "value", valueObject)
        return parameter
    }

    private fun createKeyParameterValue(valueClass: Class<*>, tag: Int, value: Any): Any {
        val factoryName = factoryNameForTag(tag)
        if (factoryName != null) {
            valueClass.methods.firstOrNull {
                it.name == factoryName && it.parameterTypes.size == 1
            }?.let { factory ->
                factory.isAccessible = true
                return factory.invoke(null, value)
            }
        }

        val valueObject = valueClass.getDeclaredConstructor().newInstance()
        val setterName = setterNameForTag(tag)
        val setter = valueClass.declaredMethods.firstOrNull {
            it.name == setterName && it.parameterTypes.size == 1
        } ?: throw NoSuchMethodException("Unable to find $setterName on ${valueClass.name}")
        setter.isAccessible = true
        setter.invoke(valueObject, value)
        return valueObject
    }

    private fun factoryNameForTag(tag: Int): String? {
        return when (tag and 0xf0000000.toInt()) {
            0x10000000, 0x20000000 -> when (tag and 0x0fffffff) {
                1 -> "keyPurpose"
                2 -> "algorithm"
                5 -> "digest"
                else -> null
            }
            0x30000000, 0x40000000 -> "integer"
            0x70000000 -> "boolValue"
            0x80000000.toInt(), 0x90000000.toInt() -> "blob"
            else -> null
        }
    }

    private fun setterNameForTag(tag: Int): String {
        return when (tag and 0xf0000000.toInt()) {
            0x10000000, 0x20000000 -> when (tag and 0x0fffffff) {
                1 -> "setKeyPurpose"
                2 -> "setAlgorithm"
                5 -> "setDigest"
                10 -> "setEcCurve"
                else -> "setInteger"
            }
            0x30000000, 0x40000000 -> "setInteger"
            0x70000000 -> "setBoolValue"
            0x80000000.toInt(), 0x90000000.toInt() -> "setBlob"
            else -> "setInteger"
        }
    }

    private fun ensureHiddenApiAccess() {
        runCatching { HiddenApiBypass.addHiddenApiExemptions("") }
    }

    fun getKeystoreService(): Any? {
        return runCatching {
            val binder = lookupBinder() ?: return null
            val stubClass = loadClass("${CLASS_IKEYSTORE_SERVICE}\$Stub")
            val asInterface = stubClass.getMethod("asInterface", IBinder::class.java)
            asInterface.invoke(null, binder)
        }.getOrNull()
    }

    fun resolveSecurityLevel(service: Any, level: Int): Any? {
        return runCatching {
            val method = service.javaClass.methods.firstOrNull {
                it.name == "getSecurityLevel" && it.parameterTypes.size == 1
            } ?: throw NoSuchMethodException("Unable to find hidden getSecurityLevel(int) on ${service.javaClass.name}")
            method.isAccessible = true
            method.invoke(service, level)
        }.getOrNull()
    }

    private fun installPrivateBinderProxy(): Boolean {
        return runCatching {
            val serviceManager = loadClass("android.os.ServiceManager")
            val cacheField = serviceManager.getDeclaredField("sCache")
            cacheField.isAccessible = true
            @Suppress("UNCHECKED_CAST")
            val cache = cacheField.get(null) as? MutableMap<String, IBinder>
                ?: return false
            cache.remove(SERVICE_NAME)
            val getService = serviceManager.getDeclaredMethod("getService", String::class.java)
            val rawBinder = getService.invoke(null, SERVICE_NAME) as? IBinder ?: return false
            cache[SERVICE_NAME] = createKeystoreServiceBinderProxy(rawBinder)
            true
        }.getOrDefault(false)
    }

    private fun createKeystoreServiceBinderProxy(rawBinder: IBinder): IBinder {
        val serviceInterface = loadClass(CLASS_IKEYSTORE_SERVICE)
        val serviceProxyClass = loadClass("${CLASS_IKEYSTORE_SERVICE}\$Stub\$Proxy")
        val constructor = serviceProxyClass.getDeclaredConstructor(IBinder::class.java)
        constructor.isAccessible = true
        val stubProxy = constructor.newInstance(rawBinder)

        val serviceProxy = Proxy.newProxyInstance(
            ClassLoader.getSystemClassLoader(),
            arrayOf(serviceInterface),
        ) { _, method, args ->
            invokeProxyMethod(stubProxy, method, args) { result ->
                if (method.name == "getSecurityLevel" && result != null) {
                    createSecurityLevelProxy(result)
                } else {
                    result
                }
            }
        }

        return Proxy.newProxyInstance(
            ClassLoader.getSystemClassLoader(),
            arrayOf(IBinder::class.java),
        ) { _, method, args ->
            when (method.name) {
                "queryLocalInterface" -> serviceProxy
                "transact" -> rawBinder.transact(
                    args[0] as Int,
                    args[1] as Parcel,
                    args[2] as? Parcel,
                    args[3] as Int,
                )
                else -> invokeProxyMethod(rawBinder, method, args)
            }
        } as IBinder
    }

    private fun createSecurityLevelProxy(realSecurityLevel: Any): Any {
        return runCatching {
            val securityLevelInterface = loadClass(CLASS_IKEYSTORE_SECURITY_LEVEL)
            val securityLevelProxyClass = loadClass("${CLASS_IKEYSTORE_SECURITY_LEVEL}\$Stub\$Proxy")
            val asBinderMethod = realSecurityLevel.javaClass.getMethod("asBinder")
            val rawBinder = asBinderMethod.invoke(realSecurityLevel) as IBinder

            val binderProxy = Proxy.newProxyInstance(
                ClassLoader.getSystemClassLoader(),
                arrayOf(IBinder::class.java),
            ) { _, method, args ->
                when (method.name) {
                    "queryLocalInterface" -> null
                    "transact" -> {
                        val transactionCode = args[0] as Int
                        val reply = args[2] as? Parcel
                        val success = rawBinder.transact(
                            transactionCode,
                            args[1] as Parcel,
                            reply,
                            args[3] as Int,
                        )
                        captureGenerateKeyReplyFromTransact(
                            transactionCode = transactionCode,
                            reply = reply,
                            transactReturned = success,
                        )
                        success
                    }
                    else -> invokeProxyMethod(rawBinder, method, args)
                }
            } as IBinder

            val constructor = securityLevelProxyClass.getDeclaredConstructor(IBinder::class.java)
            constructor.isAccessible = true
            val stubProxy = constructor.newInstance(binderProxy)
            Proxy.newProxyInstance(
                ClassLoader.getSystemClassLoader(),
                arrayOf(securityLevelInterface),
            ) { _, method, args ->
                if (method.name == "asBinder") {
                    binderProxy
                } else {
                    invokeProxyMethod(stubProxy, method, args)
                }
            }
        }.getOrElse { realSecurityLevel }
    }

    private fun invokeProxyMethod(
        target: Any,
        method: Method,
        args: Array<out Any?>?,
        mapper: ((Any?) -> Any?)? = null,
    ): Any? {
        return try {
            val result = method.invoke(target, *(args ?: emptyArray()))
            mapper?.invoke(result) ?: result
        } catch (throwable: InvocationTargetException) {
            throw throwable.cause ?: throwable
        }
    }

    private fun captureReplySnapshot(reply: Parcel): Keystore2ReplySnapshot? {
        val rawBytes = runCatching { reply.marshall() }.getOrDefault(ByteArray(0))
        if (rawBytes.isEmpty() && reply.dataSize() == 0) {
            return null
        }
        reply.setDataPosition(0)
        val exceptionCode = if (reply.dataSize() >= 4) reply.readInt() else null
        val secondWord = if (reply.dataSize() >= 8) reply.readInt() else null
        val trailingInts = buildList {
            while (reply.dataPosition() + 4 <= reply.dataSize() && size < 4) {
                add(reply.readInt())
            }
        }
        reply.setDataPosition(0)
        return Keystore2ReplySnapshot(
            rawPrefix = rawReplyPrefix(rawBytes),
            exceptionCode = exceptionCode,
            secondWord = secondWord,
            trailingInts = trailingInts,
            dataSize = rawBytes.size,
        )
    }

    private fun captureGenerateKeyReplyFromTransact(
        transactionCode: Int,
        reply: Parcel?,
        transactReturned: Boolean,
    ) {
        val slot = generateKeyReplyCaptureSlot.get() ?: return
        if (transactionCode != generateKeyTransactionCode()) {
            return
        }
        if (slot.completed) {
            return
        }
        slot.transactionCode = transactionCode
        slot.transactReturned = transactReturned
        if (reply == null) {
            slot.failureReason = "generateKey transact completed without a reply parcel."
            slot.completed = true
            return
        }
        val rawReply = runCatching { reply.marshall() }.getOrElse { throwable ->
            slot.failureReason = throwable.message ?: "generateKey reply marshalling failed."
            slot.completed = true
            return
        }
        if (rawReply.isEmpty() && reply.dataSize() == 0) {
            slot.failureReason = "generateKey reply parcel was empty."
            slot.completed = true
            return
        }
        slot.rawReply = rawReply
        slot.rawPrefix = rawReplyPrefix(rawReply)
        slot.completed = true
    }

    private fun rawReplyPrefix(rawReply: ByteArray): String {
        return rawReply
            .take(MAX_REPLY_PREFIX_BYTES)
            .joinToString(" ") { "%02X".format(it.toInt() and 0xFF) }
    }

    private fun generateKeyTransactionCode(): Int {
        cachedGenerateKeyTransactionCode?.let { return it }
        val resolved = runCatching {
            val stubClass = loadClass("${CLASS_IKEYSTORE_SECURITY_LEVEL}\$Stub")
            stubClass.getField("TRANSACTION_generateKey").getInt(null)
        }.getOrDefault(TRANSACTION_GENERATE_KEY)
        cachedGenerateKeyTransactionCode = resolved
        return resolved
    }

    private fun setField(target: Any, name: String, value: Any?) {
        val field = target.javaClass.getDeclaredField(name)
        field.isAccessible = true
        field.set(target, value)
    }

    private fun getFieldValue(target: Any, name: String): Any? {
        return runCatching {
            val field = target.javaClass.getField(name)
            field.isAccessible = true
            field.get(target)
        }.recoverCatching {
            val field = target.javaClass.getDeclaredField(name)
            field.isAccessible = true
            field.get(target)
        }.getOrNull()
    }

    fun toObjectArray(value: Any?): Array<Any?> {
        if (value == null || !value.javaClass.isArray) {
            return emptyArray()
        }
        val length = java.lang.reflect.Array.getLength(value)
        return Array(length) { index -> java.lang.reflect.Array.get(value, index) }
    }

    private fun buildListEntriesArgs(
        parameterTypes: Array<Class<*>>,
        startPastAlias: String? = null,
    ): Array<Any?> {
        return parameterTypes.map { type ->
            when {
                type == Int::class.javaPrimitiveType || type == Int::class.java -> 0
                type == Long::class.javaPrimitiveType || type == Long::class.java -> -1L
                type == String::class.java -> startPastAlias
                type == Boolean::class.javaPrimitiveType || type == Boolean::class.java -> false
                else -> null
            }
        }.toTypedArray()
    }

    private fun findThrowable(
        throwable: Throwable,
        predicate: (Throwable) -> Boolean,
    ): Throwable? {
        var current: Throwable? = throwable
        while (current != null) {
            if (predicate(current)) {
                return current
            }
            current = current.cause
        }
        return null
    }

    private fun findRootCause(throwable: Throwable): Throwable {
        var current = throwable
        while (current.cause != null && current.cause !== current) {
            current = current.cause!!
        }
        return current
    }

    private fun loadClass(className: String): Class<*> {
        return try {
            Class.forName(className)
        } catch (primary: ClassNotFoundException) {
            try {
                ClassLoader.getSystemClassLoader().loadClass(className)
            } catch (secondary: ClassNotFoundException) {
                try {
                    HiddenApiBypass.invoke(Class::class.java, null, "forName", className) as Class<*>
                } catch (throwable: Throwable) {
                    throw ClassNotFoundException("Unable to load hidden class $className", throwable)
                }
            }
        }
    }

    companion object {
        const val SERVICE_NAME = "android.system.keystore2.IKeystoreService/default"
        const val INTERFACE_DESCRIPTOR = "android.system.keystore2.IKeystoreService"
        const val TRANSACTION_GET_KEY_ENTRY = 2
        const val TRANSACTION_GENERATE_KEY = 2
        const val SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1
        const val SECURITY_LEVEL_STRONGBOX = 2
        const val DEFAULT_ALIAS_PREFIX = "Budin_Key_DuckTiming"
        const val DEFAULT_GENERATE_MODE_ALIAS_PREFIX = "Budin_Key_DuckGenerateMode"
        const val DOMAIN_KEY_ID_FALLBACK = 4

        private const val CLASS_IKEYSTORE_SERVICE = "android.system.keystore2.IKeystoreService"
        private const val CLASS_IKEYSTORE_SECURITY_LEVEL = "android.system.keystore2.IKeystoreSecurityLevel"
        private const val CLASS_KEY_DESCRIPTOR = "android.system.keystore2.KeyDescriptor"
        private const val CLASS_KEY_PARAMETER = "android.hardware.security.keymint.KeyParameter"
        private const val CLASS_KEY_PARAMETER_VALUE = "android.hardware.security.keymint.KeyParameterValue"
        private const val MAX_REPLY_PREFIX_BYTES = 32

        @Volatile
        private var cachedGenerateKeyTransactionCode: Int? = null
        private val generateKeyReplyCaptureSlot = ThreadLocal<GenerateKeyReplyCaptureSlot?>()
    }
}

private data class HiddenMethodInvocation(
    val target: Any,
    val method: Method,
    val args: Array<Any?>,
)

private data class GenerateKeyReplyCaptureSnapshot(
    val rawReply: ByteArray? = null,
    val rawPrefix: String? = null,
    val transactionCode: Int? = null,
    val transactReturned: Boolean? = null,
    val throwable: Throwable? = null,
    val failureReason: String? = null,
)

private class GenerateKeyReplyCaptureSlot {
    var rawReply: ByteArray? = null
    var rawPrefix: String? = null
    var transactionCode: Int? = null
    var transactReturned: Boolean? = null
    var failureReason: String? = null
    var completed: Boolean = false

    fun toSnapshot(
        throwable: Throwable? = null,
        defaultFailureReason: String,
    ): GenerateKeyReplyCaptureSnapshot {
        return GenerateKeyReplyCaptureSnapshot(
            rawReply = rawReply,
            rawPrefix = rawPrefix,
            transactionCode = transactionCode,
            transactReturned = transactReturned,
            throwable = throwable,
            failureReason = failureReason ?: if (rawReply == null) defaultFailureReason else null,
        )
    }
}

data class GenerateKeyReplyCaptureResult(
    val available: Boolean,
    val rawReply: ByteArray? = null,
    val rawPrefix: String? = null,
    val detail: String,
)

data class Keystore2BinderRequest(
    val interfaceDescriptor: String,
    val transactionCode: Int,
    val alias: String,
    val writeTo: (Parcel) -> Unit,
)

data class Keystore2ReplySnapshot(
    val rawPrefix: String? = null,
    val exceptionCode: Int? = null,
    val secondWord: Int? = null,
    val trailingInts: List<Int> = emptyList(),
    val dataSize: Int = 0,
)

data class BinderTransactionResult(
    val success: Boolean,
    val replySnapshot: Keystore2ReplySnapshot? = null,
    val replyFailureReason: String? = null,
    val throwable: Throwable? = null,
)

data class Keystore2PrivateSessionResult(
    val session: Keystore2PrivateSession? = null,
    val failureReason: String? = null,
)

data class Keystore2PrivateSession(
    val binder: IBinder,
    val service: Any,
    val securityLevel: Any,
    val proxyInstalled: Boolean,
    val serviceProxyActive: Boolean,
    val securityLevelProxyActive: Boolean,
)

data class TimingKeyAliases(
    val aliasPrefix: String,
    val attestedAlias: String,
    val nonAttestedAlias: String,
    val attestKeyAlias: String,
)
