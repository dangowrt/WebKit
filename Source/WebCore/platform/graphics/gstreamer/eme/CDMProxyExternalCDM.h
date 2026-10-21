/*
 * Copyright (C) 2020 Metrological Group B.V.
 * Copyright (C) 2020 Igalia S.L.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once

#if ENABLE(ENCRYPTED_MEDIA) && ENABLE(EXTERNAL_CDM)

#include "CDMProxy.h"
#include "GStreamerEMEUtilities.h"
#include "SharedBuffer.h"
#include "cdm/media/cdm/cdm_adapter.h"
#include <cstdlib>
#include <gcrypt.h>
#include <memory>
#include <wtf/text/WTFString.h>

namespace WebCore {

// Heap-backed cdm::Buffer, as proven by the de-risk harness: a thin owner over
// a plain allocation the CDM fills, used for the decrypt output and as the
// fallback the CDM host Allocate() falls back to.
class ExternalCdmHeapBuffer final : public cdm::Buffer {
public:
    explicit ExternalCdmHeapBuffer(size_t capacity)
        : m_capacity(capacity)
    {
        m_data = capacity ? static_cast<uint8_t*>(malloc(capacity)) : nullptr;
    }

    ~ExternalCdmHeapBuffer() override { free(m_data); }

    void Destroy() override { delete this; }
    uint32_t Capacity() const override { return static_cast<uint32_t>(m_capacity); }
    uint8_t* Data() override { return m_data; }
    void SetSize(uint32_t size) override { m_size = size; }
    uint32_t Size() const override { return m_size; }

private:
    uint8_t* m_data { nullptr };
    size_t m_capacity { 0 };
    uint32_t m_size { 0 };
};

// Handle to one session inside an external Chromium CDM, boxed into the shared
// key store as the value of a KeyHandle (the Widevine analogue of Thunder's
// BoxPtr<OpenCDMSession>). The key bytes stay in the CDM; this carries a strong
// reference to the CdmAdapter so a decode thread can call Decrypt() by key id
// after the JS-facing instance is gone, plus the CDM's session id string.
class ExternalCdmSession {
public:
    ExternalCdmSession(std::shared_ptr<media::CdmAdapter> adapter, const String& sessionID)
        : m_adapter(WTF::move(adapter))
        , m_sessionID(sessionID)
    {
    }

    media::CdmAdapter* adapter() const { return m_adapter.get(); }
    const String& sessionID() const LIFETIME_BOUND { return m_sessionID; }

private:
    std::shared_ptr<media::CdmAdapter> m_adapter;
    String m_sessionID;
};

// Thread-safe API that decode threads use to drive the external CDM. ClearKey
// decrypts in process with libgcrypt against the raw key bytes the session
// placed in the shared key store; Widevine (and other blob-backed key systems)
// decrypt through the Chromium CDM, which the session reaches by the boxed
// ExternalCdmSession handle. The decryptor dispatches on the key-handle variant.
class CDMProxyExternalCDM final : public CDMProxy, public CanMakeWeakPtr<CDMProxyExternalCDM, WeakPtrFactoryInitialization::Eager> {
public:
    CDMProxyExternalCDM(const String& keySystem)
        : m_keySystem(keySystem) { }
    virtual ~CDMProxyExternalCDM();

    struct cencDecryptContext {
        const uint8_t* keyID;
        size_t keyIDSizeInBytes;

        const uint8_t* iv;
        size_t ivSizeInBytes;

        uint8_t* encryptedBuffer;
        size_t encryptedBufferSizeInBytes;

        const uint8_t* subsamplesBuffer;
        size_t subsamplesBufferSizeInBytes;
        size_t numSubsamples;
        WeakPtr<CDMProxyDecryptionClient> cdmProxyDecryptionClient;

        // Only consulted by blob-backed key systems; ClearKey is always AES-CTR.
        cdm::EncryptionScheme encryptionScheme { cdm::EncryptionScheme::kCenc };
        uint32_t cryptByteBlock { 0 };
        uint32_t skipByteBlock { 0 };

        bool isSubsampled() const { return numSubsamples; }
    };

    DecryptionResult cencDecrypt(cencDecryptContext&);
    const String& keySystem() const LIFETIME_BOUND { return m_keySystem; }

private:
    // ClearKey, libgcrypt in process.
    gcry_cipher_hd_t& gCryptHandle();
    bool cencSetCounterVector(const cencDecryptContext&);
    bool cencDecryptFullSample(cencDecryptContext&);
    bool cencDecryptSubsampled(cencDecryptContext&);
    DecryptionResult clearKeyDecrypt(cencDecryptContext&, const Vector<uint8_t>& keyValue);
    void closeGCryptHandle();

    // Blob-backed key systems, Chromium CDM.
    DecryptionResult externalCdmDecrypt(cencDecryptContext&, const BoxPtr<ExternalCdmSession>&);

    String m_keySystem;
    std::optional<gcry_cipher_hd_t> m_gCryptHandle { std::nullopt };
};

} // namespace WebCore

#endif // ENABLE(ENCRYPTED_MEDIA) && ENABLE(EXTERNAL_CDM)
