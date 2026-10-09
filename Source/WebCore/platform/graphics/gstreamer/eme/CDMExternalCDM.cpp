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

#include "config.h"
#include "CDMExternalCDM.h"

#if ENABLE(ENCRYPTED_MEDIA) && ENABLE(EXTERNAL_CDM)

#include "CDMClearKey.h"
#include "CDMKeySystemConfiguration.h"
#include "CDMProxyExternalCDM.h"
#include "CDMRestrictions.h"
#include "CDMSessionType.h"
#include "CDMUtilities.h"
#include "GStreamerCommon.h"
#include "GStreamerEMEUtilities.h"
#include "Logging.h"
#include <ranges>
#include <wtf/JSONValues.h>
#include <wtf/MainThread.h>
#include <wtf/NeverDestroyed.h>
#include <wtf/TZoneMallocInlines.h>
#include <wtf/text/Base64.h>
#include <wtf/text/StringToIntegerConversion.h>

namespace WebCore {

WTF_MAKE_TZONE_ALLOCATED_IMPL(CDMFactoryExternalCDM);
WTF_MAKE_TZONE_ALLOCATED_IMPL(CDMPrivateExternalCDM);
WTF_MAKE_TZONE_ALLOCATED_IMPL(CDMInstanceExternalCDM);

CDMFactoryExternalCDM& CDMFactoryExternalCDM::singleton()
{
    static std::once_flag onceFlag;
    std::call_once(onceFlag, [] {
        ensureGStreamerInitialized();
    });
    static NeverDestroyed<CDMFactoryExternalCDM> s_factory;
    return s_factory;
}

CDMFactoryExternalCDM::CDMFactoryExternalCDM()
{
    ASSERT(isMainThread());

    // ClearKey is software-only and always available. Widevine and other
    // blob-backed key systems are a later iteration of this backend.
    m_supportedKeySystems.append(String::fromLatin1(GStreamerEMEUtilities::s_ClearKeyKeySystem));
}

std::unique_ptr<CDMPrivate> CDMFactoryExternalCDM::createCDM(const String& keySystem, const String& mediaKeysHashSalt, const CDMPrivateClient&)
{
    UNUSED_PARAM(mediaKeysHashSalt);
    ASSERT(supportsKeySystem(keySystem));
    return makeUnique<CDMPrivateExternalCDM>(keySystem);
}

RefPtr<CDMProxy> CDMFactoryExternalCDM::createCDMProxy(const String& keySystem)
{
    ASSERT(supportsKeySystem(keySystem));
    return adoptRef(new CDMProxyExternalCDM(keySystem));
}

bool CDMFactoryExternalCDM::supportsKeySystem(const String& keySystem)
{
    return m_supportedKeySystems.contains(keySystem);
}

CDMPrivateExternalCDM::CDMPrivateExternalCDM(const String& keySystem)
    : m_keySystem(keySystem)
{
}

Vector<String> CDMPrivateExternalCDM::supportedInitDataTypes() const
{
    return { "keyids"_s, "cenc"_s, "webm"_s };
}

static bool containsPersistentLicenseType(const Vector<CDMSessionType>& types)
{
    return std::ranges::find(types, CDMSessionType::PersistentLicense) != types.end();
}

bool CDMPrivateExternalCDM::supportsConfiguration(const CDMKeySystemConfiguration& configuration) const
{
    if (configuration.distinctiveIdentifier == CDMRequirement::Required)
        return false;

    if (configuration.persistentState == CDMRequirement::Required && !containsPersistentLicenseType(configuration.sessionTypes))
        return false;

    return true;
}

bool CDMPrivateExternalCDM::supportsConfigurationWithRestrictions(const CDMKeySystemConfiguration& configuration, const CDMRestrictions& restrictions) const
{
    if ((configuration.distinctiveIdentifier == CDMRequirement::Optional && restrictions.distinctiveIdentifierDenied)
        || configuration.distinctiveIdentifier == CDMRequirement::Required)
        return false;

    if (configuration.persistentState == CDMRequirement::Optional && restrictions.persistentStateDenied)
        return false;

    if (configuration.persistentState == CDMRequirement::Required && !containsPersistentLicenseType(configuration.sessionTypes))
        return false;

    return true;
}

bool CDMPrivateExternalCDM::supportsSessionTypeWithConfiguration(const CDMSessionType& sessionType, const CDMKeySystemConfiguration& configuration) const
{
    if (sessionType != CDMSessionType::Temporary && sessionType != CDMSessionType::PersistentLicense)
        return false;
    return supportsConfiguration(configuration);
}

Vector<String> CDMPrivateExternalCDM::supportedRobustnesses() const
{
    return { emptyString() };
}

CDMRequirement CDMPrivateExternalCDM::distinctiveIdentifiersRequirement(const CDMKeySystemConfiguration&, const CDMRestrictions& restrictions) const
{
    if (restrictions.distinctiveIdentifierDenied)
        return CDMRequirement::NotAllowed;
    return CDMRequirement::Optional;
}

CDMRequirement CDMPrivateExternalCDM::persistentStateRequirement(const CDMKeySystemConfiguration&, const CDMRestrictions& restrictions) const
{
    if (restrictions.persistentStateDenied)
        return CDMRequirement::NotAllowed;
    return CDMRequirement::Optional;
}

bool CDMPrivateExternalCDM::distinctiveIdentifiersAreUniquePerOriginAndClearable(const CDMKeySystemConfiguration&) const
{
    return false;
}

RefPtr<CDMInstance> CDMPrivateExternalCDM::createInstance()
{
    return adoptRef(new CDMInstanceExternalCDM(m_keySystem));
}

void CDMPrivateExternalCDM::loadAndInitialize()
{
    // No-op.
}

bool CDMPrivateExternalCDM::supportsServerCertificates() const
{
    // ClearKey does not use server certificates.
    return false;
}

bool CDMPrivateExternalCDM::supportsSessions() const
{
    return true;
}

bool CDMPrivateExternalCDM::supportsInitData(const String& initDataType, const SharedBuffer& initData) const
{
    if (equalLettersIgnoringASCIICase(initDataType, "keyids"_s) && CDMUtilities::parseJSONObject(initData))
        return true;

    if (equalLettersIgnoringASCIICase(initDataType, "cenc"_s) && !initData.isEmpty())
        return true;

    if (equalLettersIgnoringASCIICase(initDataType, "webm"_s) && !initData.isEmpty())
        return true;

    return false;
}

RefPtr<SharedBuffer> CDMPrivateExternalCDM::sanitizeResponse(const SharedBuffer& response) const
{
    if (!CDMUtilities::parseJSONObject(response))
        return nullptr;
    return response.makeContiguous();
}

std::optional<String> CDMPrivateExternalCDM::sanitizeSessionId(const String& sessionId) const
{
    if (!parseInteger<uint32_t>(sessionId))
        return std::nullopt;
    return sessionId;
}

CDMInstanceExternalCDM::CDMInstanceExternalCDM(const String& keySystem)
    : CDMInstanceProxy(keySystem)
    , m_keySystem(keySystem)
{
}

void CDMInstanceExternalCDM::initializeWithConfiguration(const CDMKeySystemConfiguration&, AllowDistinctiveIdentifiers distinctiveIdentifiers, AllowPersistentState persistentState, SuccessCallback&& callback)
{
    SuccessValue succeeded = (distinctiveIdentifiers == AllowDistinctiveIdentifiers::No && persistentState == AllowPersistentState::No)
        ? CDMInstanceSuccessValue::Succeeded : CDMInstanceSuccessValue::Failed;
    callback(succeeded);
}

void CDMInstanceExternalCDM::setServerCertificate(Ref<SharedBuffer>&&, SuccessCallback&& callback)
{
    callback(CDMInstanceSuccessValue::Failed);
}

void CDMInstanceExternalCDM::setStorageDirectory(const String&)
{
}

RefPtr<CDMInstanceSession> CDMInstanceExternalCDM::createSession()
{
    return adoptRef(new CDMInstanceSessionExternalCDM(*this));
}

CDMInstanceSessionExternalCDM::CDMInstanceSessionExternalCDM(CDMInstanceExternalCDM& instance)
    : CDMInstanceSessionProxy(instance)
{
}

CDMInstanceExternalCDM* CDMInstanceSessionExternalCDM::cdmInstanceExternalCDM() const
{
    return dynamicDowncast<CDMInstanceExternalCDM>(cdmInstanceProxy().get());
}

void CDMInstanceSessionExternalCDM::requestLicense(LicenseType, KeyGroupingStrategy, const String& initDataType, Ref<SharedBuffer>&& initData, LicenseCallback&& callback)
{
    if (RefPtr instance = cdmInstanceExternalCDM())
        m_sessionID = String::number(instance->getNextSessionIdValue());
    else
        m_sessionID = emptyString();

    // The licence request is the list of key IDs, derived from the init data
    // exactly as the cross-platform ClearKey CDM does it.
    if (equalLettersIgnoringASCIICase(initDataType, "cenc"_s))
        initData = ClearKey::extractKeyidsFromCencInitData(initData.get());

    if (equalLettersIgnoringASCIICase(initDataType, "webm"_s))
        initData = ClearKey::extractKeyIdFromWebMInitData(initData.get());

    callOnMainThread(
        [sessionID = m_sessionID, callback = WTF::move(callback), initData = WTF::move(initData)]() mutable {
            callback(WTF::move(initData), sessionID, false, Succeeded);
        });
}

void CDMInstanceSessionExternalCDM::updateLicense(const String& sessionID, LicenseType, Ref<SharedBuffer>&& response, LicenseUpdateCallback&& callback)
{
    auto dispatchCallback =
        [weakThis = WeakPtr { *this }, &callback](bool sessionWasClosed, std::optional<KeyStatusVector>&& changedKeys, SuccessValue succeeded) {
            callOnMainThread(
                [weakThis = WeakPtr { *weakThis }, callback = WTF::move(callback), sessionWasClosed, changedKeys = WTF::move(changedKeys), succeeded]() mutable {
                    if (!weakThis)
                        return;
                    callback(sessionWasClosed, WTF::move(changedKeys), std::nullopt, std::nullopt, succeeded);
                });
        };

    RefPtr<JSON::Object> root = CDMUtilities::parseJSONObject(response);
    if (!root) {
        LOG(EME, "EME - ExternalCDM - session %s update payload was not valid JSON", sessionID.utf8().data());
        dispatchCallback(false, std::nullopt, SuccessValue::Failed);
        return;
    }

    RefPtr instance = cdmInstanceExternalCDM();
    if (!instance) {
        LOG(EME, "EME - ExternalCDM - session %s is in an invalid state", sessionID.utf8().data());
        dispatchCallback(false, std::nullopt, SuccessValue::Failed);
        return;
    }

    if (auto decodedKeys = ClearKey::parseLicenseFormat(*root)) {
        bool keysChanged = m_keyStore.addKeys(WTF::move(*decodedKeys));

        std::optional<KeyStatusVector> changedKeys;
        if (keysChanged) {
            instance->mergeKeysFrom(m_keyStore);
            changedKeys = m_keyStore.convertToJSKeyStatusVector();
        }

        dispatchCallback(false, WTF::move(changedKeys), SuccessValue::Succeeded);
        return;
    }

    if (ClearKey::parseLicenseReleaseAcknowledgementFormat(*root)) {
        instance->unrefAllKeysFrom(m_keyStore);
        m_keyStore.clear();
        dispatchCallback(true, std::nullopt, SuccessValue::Succeeded);
        return;
    }

    LOG(EME, "EME - ExternalCDM - session %s update payload was an unrecognized format", sessionID.utf8().data());
    dispatchCallback(false, std::nullopt, SuccessValue::Failed);
}

void CDMInstanceSessionExternalCDM::loadSession(LicenseType, const String& sessionID, const String&, LoadSessionCallback&& callback)
{
    ASSERT_UNUSED(sessionID, sessionID == m_sessionID);
    KeyStatusVector keyStatusVector = m_keyStore.convertToJSKeyStatusVector();
    callOnMainThread([weakThis = WeakPtr { *this }, callback = WTF::move(callback), keyStatusVector = WTF::move(keyStatusVector)]() mutable {
        if (!weakThis)
            return;
        callback(WTF::move(keyStatusVector), std::nullopt, std::nullopt, Succeeded, SessionLoadFailure::None);
    });
}

void CDMInstanceSessionExternalCDM::closeSession(const String&, CloseSessionCallback&& callback)
{
    callOnMainThread([weakThis = WeakPtr { *this }, callback = WTF::move(callback)]() mutable {
        if (!weakThis)
            return;
        callback();
    });
}

void CDMInstanceSessionExternalCDM::removeSessionData(const String& sessionID, LicenseType, RemoveSessionDataCallback&& callback)
{
    ASSERT_UNUSED(sessionID, sessionID == m_sessionID);

    auto dispatchCallback =
        [weakThis = WeakPtr { *this }, &callback](KeyStatusVector&& keyStatusVector, RefPtr<SharedBuffer>&& message, SuccessValue success) {
            callOnMainThread(
                [weakThis = WeakPtr { *weakThis }, callback = WTF::move(callback), keyStatusVector = WTF::move(keyStatusVector), message = WTF::move(message), success]() mutable {
                    if (!weakThis)
                        return;
                    callback(WTF::move(keyStatusVector), WTF::move(message), success);
                });
        };

    KeyStatusVector keyStatusVector = m_keyStore.allKeysAs(CDMInstanceSession::KeyStatus::Released);
    RefPtr<SharedBuffer> message;
    {
        auto rootObject = JSON::Object::create();
        {
            auto array = JSON::Array::create();
            for (const auto& key : m_keyStore.values())
                array->pushString(base64URLEncodeToString(key->id().span()));
            rootObject->setArray("kids"_s, WTF::move(array));
        }
        String messageString = rootObject->toJSONString();
        message = SharedBuffer::create(messageString.utf8().span());
    }

    if (RefPtr instance = cdmInstanceExternalCDM())
        instance->unrefAllKeysFrom(m_keyStore);
    m_keyStore.clear();
    dispatchCallback(WTF::move(keyStatusVector), Ref<SharedBuffer>(*message), SuccessValue::Succeeded);
}

void CDMInstanceSessionExternalCDM::storeRecordOfKeyUsage(const String&)
{
}

} // namespace WebCore

#endif // ENABLE(ENCRYPTED_MEDIA) && ENABLE(EXTERNAL_CDM)
