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
#include <cstdlib>
#include <wtf/ByteOrder.h>

namespace WebCore {

void externalCdmSessionDestroy(ExternalCdmSession* session)
{
    delete session;
}

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

DecryptionResult CDMProxyExternalCDM::clearKeyDecrypt(cencDecryptContext& input, const Vector<uint8_t>& keyValue)
{
    if (gcry_error_t cipherError = gcry_cipher_setkey(gCryptHandle(), keyValue.span().data(), keyValue.size())) {
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

namespace {

class HeapDecryptedBlock final : public cdm::DecryptedBlock {
public:
    void SetDecryptedBuffer(cdm::Buffer* buffer) override { m_buffer = buffer; }
    cdm::Buffer* DecryptedBuffer() override { return m_buffer; }
    void SetTimestamp(int64_t timestamp) override { m_timestamp = timestamp; }
    int64_t Timestamp() const override { return m_timestamp; }

private:
    cdm::Buffer* m_buffer { nullptr };
    int64_t m_timestamp { 0 };
};

} // namespace

bool CDMProxyExternalCDM::externalCdmInputFromContext(const cencDecryptContext& input, ExternalCdmInput& cdmInput)
{
    // cbcs restarts the CBC chain and the pattern in every subsample, so the
    // CDM gets the whole sample with its subsample table, as Chromium passes it.
    size_t coveredBytes = 0;

    if (input.isSubsampled()) {
        size_t subOffset = 0;
        for (size_t i = 0; i < input.numSubsamples; ++i) {
            uint16_t clearBytes = 0;
            uint32_t cipherBytes = 0;
            if (!readUInt16(input.subsamplesBuffer, input.subsamplesBufferSizeInBytes, subOffset, clearBytes)
                || !readUInt32(input.subsamplesBuffer, input.subsamplesBufferSizeInBytes, subOffset, cipherBytes)) {
                LOG(EME, "EME - CDMProxyExternalCDM - could not read subsample %zu", i);
                return false;
            }
            cdmInput.subsamples.append(cdm::SubsampleEntry { clearBytes, cipherBytes });
            coveredBytes += clearBytes + static_cast<size_t>(cipherBytes);
            cdmInput.cipherBytes += cipherBytes;
        }
    } else {
        cdmInput.subsamples.append(cdm::SubsampleEntry { 0, static_cast<uint32_t>(input.encryptedBufferSizeInBytes) });
        coveredBytes = cdmInput.cipherBytes = input.encryptedBufferSizeInBytes;
    }

    if (coveredBytes > input.encryptedBufferSizeInBytes) {
        LOG(EME, "EME - CDMProxyExternalCDM - subsample layout overruns the buffer");
        return false;
    }
    if (coveredBytes < input.encryptedBufferSizeInBytes)
        cdmInput.subsamples.append(cdm::SubsampleEntry { static_cast<uint32_t>(input.encryptedBufferSizeInBytes - coveredBytes), 0 });

    memset(cdmInput.iv, 0, sizeof(cdmInput.iv));
    memcpy(cdmInput.iv, input.iv, std::min(input.ivSizeInBytes, sizeof(cdmInput.iv)));

    cdmInput.buffer.data = input.encryptedBuffer;
    cdmInput.buffer.data_size = static_cast<uint32_t>(input.encryptedBufferSizeInBytes);
    cdmInput.buffer.encryption_scheme = input.encryptionScheme;
    cdmInput.buffer.key_id = input.keyID;
    cdmInput.buffer.key_id_size = static_cast<uint32_t>(input.keyIDSizeInBytes);
    cdmInput.buffer.iv = cdmInput.iv;
    cdmInput.buffer.iv_size = sizeof(cdmInput.iv);
    cdmInput.buffer.subsamples = cdmInput.subsamples.span().data();
    cdmInput.buffer.num_subsamples = static_cast<uint32_t>(cdmInput.subsamples.size());
    cdmInput.buffer.pattern = { input.cryptByteBlock, input.skipByteBlock };
    cdmInput.buffer.timestamp = input.timestampUs;
    return true;
}

DecryptionResult CDMProxyExternalCDM::externalCdmDecrypt(cencDecryptContext& input, const BoxPtr<ExternalCdmSession>& session)
{
    if (!session || !session->get() || !session->get()->adapter()) {
        LOG(EME, "EME - CDMProxyExternalCDM - no CDM session to decrypt against");
        return DecryptionResult::Failure;
    }
    media::CdmAdapter* cdm = session->get()->adapter();

    ExternalCdmInput cdmInput;
    if (!externalCdmInputFromContext(input, cdmInput))
        return DecryptionResult::Failure;

    if (!cdmInput.cipherBytes)
        return DecryptionResult::Success;

    ExternalCdmHeapBuffer output(input.encryptedBufferSizeInBytes);
    HeapDecryptedBlock block;
    block.SetDecryptedBuffer(&output);

    cdm::Status status = cdm->Decrypt(cdmInput.buffer, &block);
    if (status != cdm::kSuccess) {
        LOG(EME, "EME - CDMProxyExternalCDM - CDM Decrypt failed, status %d", static_cast<int>(status));
        return status == cdm::kNoKey ? DecryptionResult::NoKey : DecryptionResult::Failure;
    }

    if (output.Size() < input.encryptedBufferSizeInBytes) {
        LOG(EME, "EME - CDMProxyExternalCDM - CDM returned %u bytes, expected %zu", output.Size(), input.encryptedBufferSizeInBytes);
        return DecryptionResult::Failure;
    }

    memcpy(input.encryptedBuffer, output.Data(), input.encryptedBufferSizeInBytes);
    return DecryptionResult::Success;
}

DecryptionResult CDMProxyExternalCDM::cencDecrypt(CDMProxyExternalCDM::cencDecryptContext& input)
{
    Vector<uint8_t> keyIDVec;
    keyIDVec.append(unsafeMakeSpan(input.keyID, input.keyIDSizeInBytes));

    auto keyHandle = getOrWaitForKeyHandle(keyIDVec, WTF::move(input.cdmProxyDecryptionClient));
    if (!keyHandle) {
        LOG(EME, "EME - CDMProxyExternalCDM - key unavailable or operation aborted");
        return DecryptionResult::NoKey;
    }

    const KeyHandleValueVariant& keyValue = keyHandle.value()->value();

    if (std::holds_alternative<Vector<uint8_t>>(keyValue))
        return clearKeyDecrypt(input, std::get<Vector<uint8_t>>(keyValue));

    if (std::holds_alternative<BoxPtr<ExternalCdmSession>>(keyValue)) {
        if (!keyHandle.value()->isStatusCurrentlyValid()) {
            LOG(EME, "EME - CDMProxyExternalCDM - key present but not usable");
            return DecryptionResult::NoKey;
        }
        return externalCdmDecrypt(input, std::get<BoxPtr<ExternalCdmSession>>(keyValue));
    }

    LOG(EME, "EME - CDMProxyExternalCDM - key handle carries no usable value");
    return DecryptionResult::Failure;
}

void CDMProxyExternalCDM::setAdapter(std::shared_ptr<media::CdmAdapter> adapter)
{
    Locker locker { m_adapterLock };
    m_adapter = WTF::move(adapter);
    m_adapterCondition.notifyAll();
}

void CDMProxyExternalCDM::abortWaitingForAdapter()
{
    Locker locker { m_adapterLock };
    m_adapterCondition.notifyAll();
}

std::shared_ptr<media::CdmAdapter> CDMProxyExternalCDM::getOrWaitForVideoAdapter(const cencDecryptContext& input, DecryptionResult& result)
{
    result = DecryptionResult::Failure;

    if (!input.isEncrypted()) {
        Locker locker { m_adapterLock };
        m_adapterCondition.waitFor(m_adapterLock, CDMProxy::MaxKeyWaitTimeSeconds, [this, &input] {
            assertIsHeld(m_adapterLock);
            CheckedPtr client = input.cdmProxyDecryptionClient.get();
            return m_adapter || !client || client->isAborting();
        });
        if (!m_adapter) {
            LOG(EME, "EME - CDMProxyExternalCDM - no CDM loaded to decode clear video with");
            return nullptr;
        }
        result = DecryptionResult::Success;
        return m_adapter;
    }

    Vector<uint8_t> keyIDVec;
    keyIDVec.append(unsafeMakeSpan(input.keyID, input.keyIDSizeInBytes));

    WeakPtr<CDMProxyDecryptionClient> client = input.cdmProxyDecryptionClient;
    auto keyHandle = getOrWaitForKeyHandle(keyIDVec, WTF::move(client));
    if (!keyHandle) {
        LOG(EME, "EME - CDMProxyExternalCDM - key unavailable or operation aborted");
        result = DecryptionResult::NoKey;
        return nullptr;
    }

    const KeyHandleValueVariant& keyValue = keyHandle.value()->value();
    if (!std::holds_alternative<BoxPtr<ExternalCdmSession>>(keyValue)) {
        LOG(EME, "EME - CDMProxyExternalCDM - key is not held by a CDM that decodes video");
        return nullptr;
    }

    if (!keyHandle.value()->isStatusCurrentlyValid()) {
        LOG(EME, "EME - CDMProxyExternalCDM - key present but not usable");
        result = DecryptionResult::NoKey;
        return nullptr;
    }

    const auto& session = std::get<BoxPtr<ExternalCdmSession>>(keyValue);
    if (!session || !session->get() || !session->get()->sharedAdapter()) {
        LOG(EME, "EME - CDMProxyExternalCDM - no CDM session to decode against");
        return nullptr;
    }

    result = DecryptionResult::Success;
    return session->get()->sharedAdapter();
}

cdm::Status CDMProxyExternalCDM::decryptAndDecodeVideoFrame(media::CdmAdapter& adapter, const cencDecryptContext* input, media::CdmVideoFrame& frame)
{
    ExternalCdmInput cdmInput;

    if (input && input->isEncrypted()) {
        if (!externalCdmInputFromContext(*input, cdmInput))
            return cdm::kDecryptError;
    } else if (input) {
        cdmInput.buffer.data = input->encryptedBuffer;
        cdmInput.buffer.data_size = static_cast<uint32_t>(input->encryptedBufferSizeInBytes);
        cdmInput.buffer.encryption_scheme = cdm::EncryptionScheme::kUnencrypted;
        cdmInput.buffer.timestamp = input->timestampUs;
    }

    return adapter.DecryptAndDecodeFrame(cdmInput.buffer, &frame);
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
