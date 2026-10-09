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
#include <gcrypt.h>

namespace WebCore {

// Thread-safe API that decode threads use to drive the external CDM. For the
// ClearKey key system the decryption runs in-process against the keys the
// CDMInstanceSession placed in the shared key store; blob-backed key systems
// are a later iteration.
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

        bool isSubsampled() const { return numSubsamples; }
    };

    DecryptionResult cencDecrypt(cencDecryptContext&);
    const String& keySystem() const LIFETIME_BOUND { return m_keySystem; }

private:
    gcry_cipher_hd_t& gCryptHandle();
    bool cencSetCounterVector(const cencDecryptContext&);
    bool cencDecryptFullSample(cencDecryptContext&);
    bool cencDecryptSubsampled(cencDecryptContext&);
    void closeGCryptHandle();

    String m_keySystem;
    std::optional<gcry_cipher_hd_t> m_gCryptHandle { std::nullopt };
};

} // namespace WebCore

#endif // ENABLE(ENCRYPTED_MEDIA) && ENABLE(EXTERNAL_CDM)
