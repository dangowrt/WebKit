/*
 * Copyright (C) 2016 Metrological Group B.V.
 * Copyright (C) 2016 Igalia S.L.
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

#include "CDMFactory.h"
#include "CDMInstanceSession.h"
#include "CDMPrivate.h"
#include "CDMProxy.h"
#include "CDMProxyExternalCDM.h"
#include "SharedBuffer.h"
#include "cdm/media/cdm/cdm_adapter.h"
#include <memory>
#include <wtf/CompletionHandler.h>
#include <wtf/Deque.h>
#include <wtf/HashMap.h>
#include <wtf/ThreadSafeRefCounted.h>
#include <wtf/TZoneMalloc.h>
#include <wtf/WeakPtr.h>
#include <wtf/text/WTFString.h>

namespace WebCore {

class CDMInstanceExternalCDM;
class CDMInstanceSessionExternalCDM;

class CDMFactoryExternalCDM final : public CDMFactory, public CDMProxyFactory {
    WTF_MAKE_TZONE_ALLOCATED(CDMFactoryExternalCDM);
public:
    static CDMFactoryExternalCDM& singleton();

    virtual ~CDMFactoryExternalCDM() = default;

    // Do nothing since this is a singleton object.
    void ref() const final { }
    void deref() const final { }

    std::unique_ptr<CDMPrivate> createCDM(const String& keySystem, const String& mediaKeysHashSalt, const CDMPrivateClient&) final;
    RefPtr<CDMProxy> createCDMProxy(const String&) final;
    bool supportsKeySystem(const String&) final;
    const Vector<String>& supportedKeySystems() const LIFETIME_BOUND { return m_supportedKeySystems; }

private:
    friend class NeverDestroyed<CDMFactoryExternalCDM>;
    CDMFactoryExternalCDM();
    Vector<String> m_supportedKeySystems;
};

class CDMPrivateExternalCDM final : public CDMPrivate {
    WTF_MAKE_TZONE_ALLOCATED(CDMPrivateExternalCDM);
    WTF_OVERRIDE_DELETE_FOR_CHECKED_PTR(CDMPrivateExternalCDM);
public:
    CDMPrivateExternalCDM(const String& keySystem);
    virtual ~CDMPrivateExternalCDM() = default;

    Vector<String> supportedInitDataTypes() const final;
    bool supportsConfiguration(const CDMKeySystemConfiguration&) const final;
    bool supportsConfigurationWithRestrictions(const CDMKeySystemConfiguration&, const CDMRestrictions&) const final;
    bool supportsSessionTypeWithConfiguration(const CDMSessionType&, const CDMKeySystemConfiguration&) const final;
    Vector<String> supportedRobustnesses() const final;
    CDMRequirement distinctiveIdentifiersRequirement(const CDMKeySystemConfiguration&, const CDMRestrictions&) const final;
    CDMRequirement persistentStateRequirement(const CDMKeySystemConfiguration&, const CDMRestrictions&) const final;
    bool distinctiveIdentifiersAreUniquePerOriginAndClearable(const CDMKeySystemConfiguration&) const final;
    RefPtr<CDMInstance> createInstance() final;
    void loadAndInitialize() final;
    bool supportsServerCertificates() const final;
    bool supportsSessions() const final;
    bool supportsInitData(const String&, const SharedBuffer&) const final;
    RefPtr<SharedBuffer> sanitizeResponse(const SharedBuffer&) const final;
    std::optional<String> sanitizeSessionId(const String&) const final;

private:
    bool isWidevine() const;
    String m_keySystem;
};

// Routes the Chromium CDM's host callbacks, which arrive on CDM-owned threads,
// onto the main thread and into the owning instance. Kept alive by the posted
// tasks so a late callback after the instance is gone is a safe no-op.
class ExternalCdmClient final : public media::CdmAdapterClient, public ThreadSafeRefCounted<ExternalCdmClient> {
public:
    static Ref<ExternalCdmClient> create(CDMInstanceExternalCDM& instance)
    {
        return adoptRef(*new ExternalCdmClient(instance));
    }

    // Main thread only.
    void clearInstance();

    void OnCDMMessage(const char* session, uint32_t session_size, CDMADPMSG, const uint8_t* data, size_t data_size, uint32_t status) final;
    void OnKeyStatusChange(const std::string& sessionId, const std::vector<KeyInfo>&) final;
    cdm::Buffer* AllocateBuffer(size_t) final;
    void OnPromiseResolved(uint32_t promiseId) final;
    void OnPromiseRejected(uint32_t promiseId, uint32_t systemCode, const std::string& message) final;

private:
    explicit ExternalCdmClient(CDMInstanceExternalCDM&);
    // Read only on the main thread; set at construction and cleared by the
    // instance destructor after the adapter's client has been removed.
    CDMInstanceExternalCDM* m_instance { nullptr };
};

class CDMInstanceExternalCDM final : public CDMInstanceProxy {
    WTF_MAKE_TZONE_ALLOCATED(CDMInstanceExternalCDM);
    WTF_OVERRIDE_DELETE_FOR_CHECKED_PTR(CDMInstanceExternalCDM);
public:
    CDMInstanceExternalCDM(const String& keySystem);
    virtual ~CDMInstanceExternalCDM();

    uint32_t getNextSessionIdValue() { return m_nextSessionIdValue++; }
    bool isWidevine() const;

    // CDMInstance
    ImplementationType implementationType() const final { return ImplementationType::ExternalCDM; }
    void initializeWithConfiguration(const CDMKeySystemConfiguration&, AllowDistinctiveIdentifiers, AllowPersistentState, SuccessCallback&&) final;
    void setServerCertificate(Ref<SharedBuffer>&&, SuccessCallback&&) final;
    void setStorageDirectory(const String&) final;
    const String& keySystem() const LIFETIME_BOUND final { return m_keySystem; }
    RefPtr<CDMInstanceSession> createSession() final;

    // Widevine path, all main thread.
    std::shared_ptr<media::CdmAdapter> ensureAdapter();
    uint32_t nextPromiseId() { return m_nextPromiseId++; }
    using PromiseCallback = CompletionHandler<void(bool succeeded)>;
    uint32_t registerPromise(PromiseCallback&&);
    void settlePromise(uint32_t promiseId, bool succeeded);
    void registerPendingSession(CDMInstanceSessionExternalCDM&);
    void unregisterSession(const String& sessionID);

    // Called on the main thread by ExternalCdmClient.
    void dispatchCdmMessage(const String& sessionID, media::CdmAdapterClient::CDMADPMSG, Ref<SharedBuffer>&&);
    void dispatchKeyStatusChange(const String& sessionID, Vector<media::CdmAdapterClient::KeyInfo>&&);

private:
    RefPtr<CDMInstanceSessionExternalCDM> sessionForID(const String& sessionID);
    RefPtr<CDMInstanceSessionExternalCDM> takePendingSession();

    String m_keySystem;
    uint32_t m_nextSessionIdValue { 0 };

    std::shared_ptr<media::CdmAdapter> m_adapter;
    RefPtr<ExternalCdmClient> m_client;
    String m_storageDirectory;
    bool m_adapterLoadFailed { false };
    bool m_allowPersistentState { true };
    uint32_t m_nextPromiseId { 1 };
    HashMap<uint32_t, PromiseCallback> m_pendingPromises;

    HashMap<String, WeakPtr<CDMInstanceSessionProxy>> m_sessionsByID;
    Deque<WeakPtr<CDMInstanceSessionProxy>> m_pendingSessions;
};

class CDMInstanceSessionExternalCDM final : public CDMInstanceSessionProxy {
public:
    CDMInstanceSessionExternalCDM(CDMInstanceExternalCDM&);

    void requestLicense(LicenseType, KeyGroupingStrategy, const String& initDataType, Ref<SharedBuffer>&& initData, LicenseCallback&&) final;
    void updateLicense(const String&, LicenseType, Ref<SharedBuffer>&&, LicenseUpdateCallback&&) final;
    void loadSession(LicenseType, const String&, const String&, LoadSessionCallback&&) final;
    void closeSession(const String&, CloseSessionCallback&&) final;
    void removeSessionData(const String&, LicenseType, RemoveSessionDataCallback&&) final;
    void storeRecordOfKeyUsage(const String&) final;

    void setClient(WeakPtr<CDMInstanceSessionClient>&& client) final { m_client = WTF::move(client); }
    void clearClient() final { m_client.clear(); }

    // Main thread, driven by the instance for the Widevine path.
    void setCdmSessionID(const String& sessionID);
    const String& cdmSessionID() const LIFETIME_BOUND { return m_sessionID; }
    void onCdmMessage(media::CdmAdapterClient::CDMADPMSG, Ref<SharedBuffer>&&);
    void onKeyStatusChange(const Vector<media::CdmAdapterClient::KeyInfo>&);

private:
    CDMInstanceExternalCDM* cdmInstanceExternalCDM() const;

    void requestLicenseClearKey(const String& initDataType, Ref<SharedBuffer>&& initData, LicenseCallback&&);
    void requestLicenseWidevine(LicenseType, const String& initDataType, Ref<SharedBuffer>&& initData, LicenseCallback&&);
    void updateLicenseClearKey(const String&, Ref<SharedBuffer>&&, LicenseUpdateCallback&&);
    void updateLicenseWidevine(const String&, Ref<SharedBuffer>&&, LicenseUpdateCallback&&);

    String m_sessionID;
    KeyStore m_keyStore;

    // Widevine only.
    BoxPtr<ExternalCdmSession> m_externalSession;
    LicenseCallback m_challengeCallback;
    WeakPtr<CDMInstanceSessionClient> m_client;
};

} // namespace WebCore

SPECIALIZE_TYPE_TRAITS_CDM_INSTANCE(WebCore::CDMInstanceExternalCDM, WebCore::CDMInstance::ImplementationType::ExternalCDM);

#endif // ENABLE(ENCRYPTED_MEDIA) && ENABLE(EXTERNAL_CDM)
