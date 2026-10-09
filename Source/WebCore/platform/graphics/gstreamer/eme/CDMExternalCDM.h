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
#include "SharedBuffer.h"
#include <wtf/TZoneMalloc.h>
#include <wtf/WeakPtr.h>

namespace WebCore {

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
    String m_keySystem;
};

class CDMInstanceExternalCDM final : public CDMInstanceProxy {
    WTF_MAKE_TZONE_ALLOCATED(CDMInstanceExternalCDM);
    WTF_OVERRIDE_DELETE_FOR_CHECKED_PTR(CDMInstanceExternalCDM);
public:
    CDMInstanceExternalCDM(const String& keySystem);
    virtual ~CDMInstanceExternalCDM() = default;

    uint32_t getNextSessionIdValue() { return m_nextSessionIdValue++; }

    // CDMInstance
    ImplementationType implementationType() const final { return ImplementationType::ExternalCDM; }
    void initializeWithConfiguration(const CDMKeySystemConfiguration&, AllowDistinctiveIdentifiers, AllowPersistentState, SuccessCallback&&) final;
    void setServerCertificate(Ref<SharedBuffer>&&, SuccessCallback&&) final;
    void setStorageDirectory(const String&) final;
    const String& keySystem() const LIFETIME_BOUND final { return m_keySystem; }
    RefPtr<CDMInstanceSession> createSession() final;

private:
    String m_keySystem;
    uint32_t m_nextSessionIdValue { 0 };
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

private:
    CDMInstanceExternalCDM* cdmInstanceExternalCDM() const;

    String m_sessionID;
    KeyStore m_keyStore;
};

} // namespace WebCore

SPECIALIZE_TYPE_TRAITS_CDM_INSTANCE(WebCore::CDMInstanceExternalCDM, WebCore::CDMInstance::ImplementationType::ExternalCDM);

#endif // ENABLE(ENCRYPTED_MEDIA) && ENABLE(EXTERNAL_CDM)
