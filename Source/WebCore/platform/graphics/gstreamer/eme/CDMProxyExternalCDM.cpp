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

#include "config.h"
#include "CDMProxyExternalCDM.h"

#if ENABLE(ENCRYPTED_MEDIA) && ENABLE(EXTERNAL_CDM)

#include "CDMClearKey.h"
#include "Logging.h"
#include <wtf/ByteOrder.h>

namespace WebCore {

static bool readUInt32(const uint8_t* buffer, size_t bufferSize, size_t& offset, uint32_t& value)
{
    ASSERT_ARG(offset, offset <= bufferSize);
    if (bufferSize - offset < sizeof(value))
        return false;

    value = ntohl(*reinterpret_cast_ptr<const uint32_t*>(buffer + offset));
    offset += sizeof(value);

    return true;
}

static bool readUInt16(const uint8_t* buffer, size_t bufferSize, size_t& offset, uint16_t& value)
{
    ASSERT_ARG(offset, offset <= bufferSize);
    if (bufferSize - offset < sizeof(value))
        return false;

    value = ntohs(*reinterpret_cast_ptr<const uint16_t*>(buffer + offset));
    offset += sizeof(value);

    return true;
}

CDMProxyExternalCDM::~CDMProxyExternalCDM()
{
    closeGCryptHandle();
}

bool CDMProxyExternalCDM::cencSetCounterVector(const cencDecryptContext& input)
{
    uint8_t ctr[ClearKey::AES128CTRBlockSizeInBytes];
    if (input.ivSizeInBytes == 8) {
        // ISO/IEC 23001-7:2016 Section 9.3: for an 8-byte IV the least
        // significant 8 bytes of the 16-byte counter block are zero.
        memset(ctr + 8, 0, 8);
        memcpy(ctr, input.iv, 8);
    } else
        memcpy(ctr, input.iv, ClearKey::IVSizeInBytes);

    if (gcry_error_t cipherError = gcry_cipher_setctr(gCryptHandle(), ctr, ClearKey::IVSizeInBytes)) {
#if !LOG_DISABLED
        LOG(EME, "EME - CDMProxyExternalCDM - ERROR(gcry_cipher_setctr): %s", gpg_strerror(cipherError));
#else
        UNUSED_VARIABLE(cipherError);
#endif
        return false;
    }

    return true;
}

bool CDMProxyExternalCDM::cencDecryptFullSample(cencDecryptContext& in)
{
    if (!in.encryptedBufferSizeInBytes)
        return true;

    if (gcry_error_t cipherError = gcry_cipher_decrypt(gCryptHandle(), in.encryptedBuffer, in.encryptedBufferSizeInBytes, 0, 0)) {
#if !LOG_DISABLED
        LOG(EME, "EME - CDMProxyExternalCDM - ERROR(gcry_cipher_decrypt): %s", gpg_strerror(cipherError));
#else
        UNUSED_VARIABLE(cipherError);
#endif
        return false;
    }

    return true;
}

bool CDMProxyExternalCDM::cencDecryptSubsampled(cencDecryptContext& input)
{
    unsigned encryptedBufferByteOffset = 0;
    size_t subSampleBufferByteOffset = 0;
    unsigned subsampleIndex = 0;
    while (encryptedBufferByteOffset < input.encryptedBufferSizeInBytes) {
        uint16_t subsampleNumClearBytes = 0;
        uint32_t subsampleNumEncryptedBytes = 0;

        if (subsampleIndex < input.numSubsamples) {
            if (!readUInt16(input.subsamplesBuffer, input.subsamplesBufferSizeInBytes, subSampleBufferByteOffset, subsampleNumClearBytes)) {
                LOG(EME, "EME - CDMProxyExternalCDM - could not read number of clear bytes in subsample at index %u", subsampleIndex);
                return false;
            }
            if (!readUInt32(input.subsamplesBuffer, input.subsamplesBufferSizeInBytes, subSampleBufferByteOffset, subsampleNumEncryptedBytes)) {
                LOG(EME, "EME - CDMProxyExternalCDM - could not read number of encrypted bytes in subsample at index %u", subsampleIndex);
                return false;
            }
            subsampleIndex++;
        } else {
            subsampleNumClearBytes = 0;
            subsampleNumEncryptedBytes = input.encryptedBufferSizeInBytes - encryptedBufferByteOffset;
        }

        encryptedBufferByteOffset += subsampleNumClearBytes;

        if (subsampleNumEncryptedBytes) {
            if (gcry_error_t cipherError = gcry_cipher_decrypt(gCryptHandle(), input.encryptedBuffer + encryptedBufferByteOffset, subsampleNumEncryptedBytes, 0, 0)) {
#if !LOG_DISABLED
                LOG(EME, "EME - CDMProxyExternalCDM - ERROR(gcry_cipher_decrypt): %s", gpg_strerror(cipherError));
#else
                UNUSED_VARIABLE(cipherError);
#endif
                return false;
            }

            encryptedBufferByteOffset += subsampleNumEncryptedBytes;
        }
    }

    return true;
}

DecryptionResult CDMProxyExternalCDM::cencDecrypt(CDMProxyExternalCDM::cencDecryptContext& input)
{
    Vector<uint8_t> keyIDVec;
    keyIDVec.append(unsafeMakeSpan(input.keyID, input.keyIDSizeInBytes));

    auto keyData = getOrWaitForKeyValue(keyIDVec, WTF::move(input.cdmProxyDecryptionClient));
    if (!keyData) {
        LOG(EME, "EME - CDMProxyExternalCDM - key unavailable or operation aborted");
        return DecryptionResult::NoKey;
    }

    ASSERT(std::holds_alternative<Vector<uint8_t>>(keyData.value()));
    auto& keyDataValue = std::get<Vector<uint8_t>>(keyData.value());

    if (gcry_error_t cipherError = gcry_cipher_setkey(gCryptHandle(), keyDataValue.span().data(), keyDataValue.size())) {
#if !LOG_DISABLED
        LOG(EME, "EME - CDMProxyExternalCDM - ERROR(gcry_cipher_setkey): %s", gpg_strerror(cipherError));
#else
        UNUSED_VARIABLE(cipherError);
#endif
        return DecryptionResult::Failure;
    }

    if (!cencSetCounterVector(input))
        return DecryptionResult::Failure;

    bool success = input.isSubsampled() ? cencDecryptSubsampled(input) : cencDecryptFullSample(input);
    return success ? DecryptionResult::Success : DecryptionResult::Failure;
}

void CDMProxyExternalCDM::closeGCryptHandle()
{
    if (m_gCryptHandle) {
        gcry_cipher_close(*m_gCryptHandle);
        m_gCryptHandle.reset();
    }
}

gcry_cipher_hd_t& CDMProxyExternalCDM::gCryptHandle()
{
    if (!m_gCryptHandle) {
        m_gCryptHandle.emplace();
        if (gcry_error_t error = gcry_cipher_open(&m_gCryptHandle.value(), GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, GCRY_CIPHER_SECURE)) {
#if !LOG_DISABLED
            LOG(EME, "EME - CDMProxyExternalCDM - ERROR(gcry_cipher_open): %s", gpg_strerror(error));
#else
            UNUSED_VARIABLE(error);
#endif
            RELEASE_ASSERT(false && "Should not get this far with a functional GCrypt!");
        }
    }

    return *m_gCryptHandle;
}

} // namespace WebCore

#endif // ENABLE(ENCRYPTED_MEDIA) && ENABLE(EXTERNAL_CDM)
