package com.eltavine.duckdetector.features.tee.domain

data class TeeCertificateItem(
    val slotLabel: String,
    val subject: String,
    val issuer: String,
    val serialNumber: String,
    val validFrom: String,
    val validUntil: String,
    val signatureAlgorithm: String,
    val publicKeySummary: String,
)
