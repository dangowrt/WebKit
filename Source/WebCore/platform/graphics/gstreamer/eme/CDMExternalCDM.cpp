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
#include "CDMMessageType.h"
#include "CDMProxyExternalCDM.h"
#include "CDMRestrictions.h"
#include "CDMSessionType.h"
#include "CDMUtilities.h"
#include "GStreamerCommon.h"
#include "GStreamerEMEUtilities.h"
#include "Logging.h"
#include <cstdlib>
#include <ranges>
#include <wtf/FileSystem.h>
#include <wtf/JSONValues.h>
#include <wtf/MainThread.h>
#include <wtf/NeverDestroyed.h>
#include <wtf/TZoneMallocInlines.h>
#include <wtf/text/Base64.h>
#include <wtf/text/MakeString.h>
#include <wtf/text/StringToIntegerConversion.h>

namespace WebCore {

WTF_MAKE_TZONE_ALLOCATED_IMPL(CDMFactoryExternalCDM);
WTF_MAKE_TZONE_ALLOCATED_IMPL(CDMPrivateExternalCDM);
WTF_MAKE_TZONE_ALLOCATED_IMPL(CDMInstanceExternalCDM);

static String widevineBlobPath()
{
    if (const char* env = getenv("WPE_WIDEVINE_CDM_PATH")) {
        if (*env)
            return String::fromUTF8(env);
    }
    return { };
}

static CDMInstanceSession::KeyStatus keyStatusFromCdm(media::CdmAdapterClient::CDMKeyStatus status)
{
    switch (status) {
    case media::CdmAdapterClient::CDMKeyStatus::kUsable:
        return CDMInstanceSession::KeyStatus::Usable;
    case media::CdmAdapterClient::CDMKeyStatus::kExpired:
        return CDMInstanceSession::KeyStatus::Expired;
    case media::CdmAdapterClient::CDMKeyStatus::kReleased:
        return CDMInstanceSession::KeyStatus::Released;
    case media::CdmAdapterClient::CDMKeyStatus::kOutputRestricted:
        return CDMInstanceSession::KeyStatus::OutputRestricted;
    case media::CdmAdapterClient::CDMKeyStatus::kOutputDownscaled:
        return CDMInstanceSession::KeyStatus::OutputDownscaled;
    case media::CdmAdapterClient::CDMKeyStatus::kStatusPending:
    case media::CdmAdapterClient::CDMKeyStatus::kUsableInFuture:
        return CDMInstanceSession::KeyStatus::StatusPending;
    case media::CdmAdapterClient::CDMKeyStatus::kInternalError:
    default:
        return CDMInstanceSession::KeyStatus::InternalError;
    }
}

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

    // ClearKey is software-only and always available. Widevine is offered when
    // the Chromium CDM blob is present; it is loaded lazily per instance.
    m_supportedKeySystems.append(String::fromLatin1(GStreamerEMEUtilities::s_ClearKeyKeySystem));

    if (FileSystem::fileExists(widevineBlobPath()))
        m_supportedKeySystems.append(String::fromLatin1(GStreamerEMEUtilities::s_WidevineKeySystem));
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

bool CDMPrivateExternalCDM::isWidevine() const
{
    return GStreamerEMEUtilities::isWidevineKeySystem(m_keySystem);
}

Vector<String> CDMPrivateExternalCDM::supportedInitDataTypes() const
{
    if (isWidevine())
        return { "keyids"_s, "cenc"_s, "cbcs"_s, "webm"_s };
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

    // Widevine persists device state through CreateFileIO regardless of session
    // type; the persistent-license requirement is a ClearKey-only rule.
    if (configuration.persistentState == CDMRequirement::Required && !isWidevine()
        && !containsPersistentLicenseType(configuration.sessionTypes))
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

    if (configuration.persistentState == CDMRequirement::Required
        && (restrictions.persistentStateDenied
            || (!isWidevine() && !containsPersistentLicenseType(configuration.sessionTypes))))
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
    if (isWidevine())
        return { emptyString(), "SW_SECURE_CRYPTO"_s, "SW_SECURE_DECODE"_s };
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
    return isWidevine();
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

    if (isWidevine() && equalLettersIgnoringASCIICase(initDataType, "cbcs"_s) && !initData.isEmpty())
        return true;

    if (equalLettersIgnoringASCIICase(initDataType, "webm"_s) && !initData.isEmpty())
        return true;

    return false;
}

RefPtr<SharedBuffer> CDMPrivateExternalCDM::sanitizeResponse(const SharedBuffer& response) const
{
    // A Widevine licence is an opaque binary blob; ClearKey is JSON.
    if (isWidevine())
        return response.makeContiguous();

    if (!CDMUtilities::parseJSONObject(response))
        return nullptr;
    return response.makeContiguous();
}

std::optional<String> CDMPrivateExternalCDM::sanitizeSessionId(const String& sessionId) const
{
    if (isWidevine())
        return sessionId.isEmpty() ? std::nullopt : std::make_optional(sessionId);

    if (!parseInteger<uint32_t>(sessionId))
        return std::nullopt;
    return sessionId;
}

ExternalCdmClient::ExternalCdmClient(CDMInstanceExternalCDM& instance)
    : m_instance(&instance)
{
    ASSERT(isMainThread());
}

void ExternalCdmClient::clearInstance()
{
    ASSERT(isMainThread());
    m_instance = nullptr;
}

void ExternalCdmClient::OnCDMMessage(const char* session, uint32_t sessionSize, CDMADPMSG msg, const uint8_t* data, size_t dataSize, uint32_t)
{
    String sessionID = session ? String::fromUTF8(unsafeMakeSpan(session, static_cast<size_t>(sessionSize))) : emptyString();
    auto buffer = (data && dataSize) ? SharedBuffer::create(unsafeMakeSpan(data, dataSize)) : SharedBuffer::create();
    callOnMainThread([protectedThis = Ref { *this }, sessionID = sessionID.isolatedCopy(), msg, buffer = WTF::move(buffer)]() mutable {
        if (protectedThis->m_instance)
            protectedThis->m_instance->dispatchCdmMessage(sessionID, msg, WTF::move(buffer));
    });
}

void ExternalCdmClient::OnKeyStatusChange(const std::string& sessionId, const std::vector<KeyInfo>& keysInfo)
{
    String sessionID = String::fromUTF8(unsafeMakeSpan(sessionId.data(), sessionId.size()));
    Vector<KeyInfo> keys;
    keys.reserveInitialCapacity(keysInfo.size());
    for (const auto& key : keysInfo)
        keys.append(key);
    callOnMainThread([protectedThis = Ref { *this }, sessionID = sessionID.isolatedCopy(), keys = WTF::move(keys)]() mutable {
        if (protectedThis->m_instance)
            protectedThis->m_instance->dispatchKeyStatusChange(sessionID, WTF::move(keys));
    });
}

cdm::Buffer* ExternalCdmClient::AllocateBuffer(size_t size)
{
    return new ExternalCdmHeapBuffer(size);
}

void ExternalCdmClient::OnPromiseResolved(uint32_t promiseId)
{
    callOnMainThread([protectedThis = Ref { *this }, promiseId] {
        if (protectedThis->m_instance)
            protectedThis->m_instance->settlePromise(promiseId, true);
    });
}

void ExternalCdmClient::OnPromiseRejected(uint32_t promiseId, uint32_t systemCode, const std::string& message)
{
    String reason = String::fromUTF8(unsafeMakeSpan(message.data(), message.size()));
    callOnMainThread([protectedThis = Ref { *this }, promiseId, systemCode, reason = reason.isolatedCopy()] {
        LOG(EME, "EME - ExternalCDM - promise %u rejected, system code %u: %s", promiseId, systemCode, reason.utf8().data());
        if (protectedThis->m_instance)
            protectedThis->m_instance->settlePromise(promiseId, false);
    });
}

CDMInstanceExternalCDM::CDMInstanceExternalCDM(const String& keySystem)
    : CDMInstanceProxy(keySystem)
    , m_keySystem(keySystem)
{
}

CDMInstanceExternalCDM::~CDMInstanceExternalCDM()
{
    if (m_adapter)
        m_adapter->RemoveClient();
    if (m_client)
        m_client->clearInstance();
    for (auto& callback : std::exchange(m_pendingPromises, { }).values())
        callback(false);
}

uint32_t CDMInstanceExternalCDM::registerPromise(PromiseCallback&& callback)
{
    ASSERT(isMainThread());
    uint32_t promiseId = nextPromiseId();
    m_pendingPromises.add(promiseId, WTF::move(callback));
    return promiseId;
}

void CDMInstanceExternalCDM::settlePromise(uint32_t promiseId, bool succeeded)
{
    ASSERT(isMainThread());
    if (auto callback = m_pendingPromises.take(promiseId))
        callback(succeeded);
}

bool CDMInstanceExternalCDM::isWidevine() const
{
    return GStreamerEMEUtilities::isWidevineKeySystem(m_keySystem);
}

std::shared_ptr<media::CdmAdapter> CDMInstanceExternalCDM::ensureAdapter()
{
    ASSERT(isMainThread());

    if (m_adapter)
        return m_adapter;
    if (m_adapterLoadFailed)
        return nullptr;

    String base = m_storageDirectory.isEmpty() ? String("/tmp/wpe-cdm"_s) : m_storageDirectory;
    if (!base.endsWith('/'))
        base = makeString(base, '/');
    FileSystem::makeAllDirectories(base);

    m_client = ExternalCdmClient::create(*this);

    auto adapter = std::make_shared<media::CdmAdapter>(
        std::string(m_keySystem.utf8().data()),
        std::string(widevineBlobPath().utf8().data()),
        std::string(base.utf8().data()),
        media::CdmConfig(false, m_allowPersistentState, false),
        m_client.get());

    if (!adapter->LoadCDM() || !adapter->Initialize()) {
        LOG(EME, "EME - ExternalCDM - failed to load or initialise the Widevine CDM");
        adapter->RemoveClient();
        m_client = nullptr;
        m_adapterLoadFailed = true;
        return nullptr;
    }

    m_adapter = WTF::move(adapter);
    if (RefPtr cdmProxy = proxy())
        static_cast<CDMProxyExternalCDM&>(*cdmProxy).setAdapter(m_adapter);
    return m_adapter;
}

void CDMInstanceExternalCDM::initializeWithConfiguration(const CDMKeySystemConfiguration&, AllowDistinctiveIdentifiers distinctiveIdentifiers, AllowPersistentState persistentState, SuccessCallback&& callback)
{
    if (isWidevine()) {
        m_allowPersistentState = persistentState == AllowPersistentState::Yes;
        callback(CDMInstanceSuccessValue::Succeeded);
        return;
    }

    SuccessValue succeeded = (distinctiveIdentifiers == AllowDistinctiveIdentifiers::No && persistentState == AllowPersistentState::No)
        ? CDMInstanceSuccessValue::Succeeded : CDMInstanceSuccessValue::Failed;
    callback(succeeded);
}

void CDMInstanceExternalCDM::setServerCertificate(Ref<SharedBuffer>&& certificate, SuccessCallback&& callback)
{
    if (!isWidevine()) {
        callback(CDMInstanceSuccessValue::Failed);
        return;
    }

    auto adapter = ensureAdapter();
    if (!adapter) {
        callback(CDMInstanceSuccessValue::Failed);
        return;
    }

    auto data = certificate->extractData();
    uint32_t promiseId = registerPromise([callback = WTF::move(callback)](bool succeeded) mutable {
        callback(succeeded ? CDMInstanceSuccessValue::Succeeded : CDMInstanceSuccessValue::Failed);
    });
    adapter->SetServerCertificate(promiseId, data.span().data(), static_cast<uint32_t>(data.size()));
}

void CDMInstanceExternalCDM::setStorageDirectory(const String& storageDirectory)
{
    m_storageDirectory = storageDirectory;
    if (!storageDirectory.isEmpty())
        FileSystem::makeAllDirectories(storageDirectory);
}

RefPtr<CDMInstanceSession> CDMInstanceExternalCDM::createSession()
{
    return adoptRef(new CDMInstanceSessionExternalCDM(*this));
}

void CDMInstanceExternalCDM::registerPendingSession(CDMInstanceSessionExternalCDM& session)
{
    ASSERT(isMainThread());
    m_pendingSessions.append(WeakPtr { session });
}

void CDMInstanceExternalCDM::unregisterSession(const String& sessionID)
{
    ASSERT(isMainThread());
    if (!sessionID.isEmpty())
        m_sessionsByID.remove(sessionID);
}

RefPtr<CDMInstanceSessionExternalCDM> CDMInstanceExternalCDM::sessionForID(const String& sessionID)
{
    auto it = m_sessionsByID.find(sessionID);
    if (it == m_sessionsByID.end())
        return nullptr;
    RefPtr<CDMInstanceSessionProxy> base = it->value.get();
    if (!base) {
        m_sessionsByID.remove(it);
        return nullptr;
    }
    return static_cast<CDMInstanceSessionExternalCDM*>(base.get());
}

RefPtr<CDMInstanceSessionExternalCDM> CDMInstanceExternalCDM::takePendingSession()
{
    while (!m_pendingSessions.isEmpty()) {
        RefPtr<CDMInstanceSessionProxy> base = m_pendingSessions.takeFirst().get();
        if (base)
            return static_cast<CDMInstanceSessionExternalCDM*>(base.get());
    }
    return nullptr;
}

void CDMInstanceExternalCDM::dispatchCdmMessage(const String& sessionID, media::CdmAdapterClient::CDMADPMSG msg, Ref<SharedBuffer>&& data)
{
    ASSERT(isMainThread());

    RefPtr<CDMInstanceSessionExternalCDM> session = sessionForID(sessionID);
    if (!session) {
        session = takePendingSession();
        if (session) {
            session->setCdmSessionID(sessionID);
            m_sessionsByID.set(sessionID, WeakPtr { *session });
        }
    }

    if (!session) {
        LOG(EME, "EME - ExternalCDM - message for unknown session %s dropped", sessionID.utf8().data());
        return;
    }

    session->onCdmMessage(msg, WTF::move(data));
}

void CDMInstanceExternalCDM::dispatchKeyStatusChange(const String& sessionID, Vector<media::CdmAdapterClient::KeyInfo>&& keys)
{
    ASSERT(isMainThread());

    RefPtr<CDMInstanceSessionExternalCDM> session = sessionForID(sessionID);
    if (!session) {
        session = takePendingSession();
        if (session) {
            session->setCdmSessionID(sessionID);
            m_sessionsByID.set(sessionID, WeakPtr { *session });
        }
    }

    if (!session) {
        LOG(EME, "EME - ExternalCDM - key status change for unknown session %s dropped", sessionID.utf8().data());
        return;
    }

    session->onKeyStatusChange(keys);
}

CDMInstanceSessionExternalCDM::CDMInstanceSessionExternalCDM(CDMInstanceExternalCDM& instance)
    : CDMInstanceSessionProxy(instance)
{
}

CDMInstanceExternalCDM* CDMInstanceSessionExternalCDM::cdmInstanceExternalCDM() const
{
    return dynamicDowncast<CDMInstanceExternalCDM>(cdmInstanceProxy().get());
}

void CDMInstanceSessionExternalCDM::setCdmSessionID(const String& sessionID)
{
    ASSERT(isMainThread());
    m_sessionID = sessionID;
    if (RefPtr instance = cdmInstanceExternalCDM()) {
        if (auto adapter = instance->ensureAdapter())
            m_externalSession = adoptInBoxPtr(new ExternalCdmSession(adapter, sessionID));
    }
}

void CDMInstanceSessionExternalCDM::onCdmMessage(media::CdmAdapterClient::CDMADPMSG msg, Ref<SharedBuffer>&& data)
{
    ASSERT(isMainThread());

    if (msg != media::CdmAdapterClient::kSessionMessage)
        return;

    if (m_challengeCallback) {
        m_challengeCallback(WTF::move(data), m_sessionID, false, Succeeded);
        return;
    }

    if (m_client)
        m_client->sendMessage(CDMMessageType::LicenseRenewal, WTF::move(data));
}

void CDMInstanceSessionExternalCDM::onKeyStatusChange(const Vector<media::CdmAdapterClient::KeyInfo>& keys)
{
    ASSERT(isMainThread());

    RefPtr instance = cdmInstanceExternalCDM();
    if (!instance)
        return;

    bool keysChanged = false;
    for (const auto& key : keys) {
        KeyIDType keyID;
        keyID.append(unsafeMakeSpan(key.kid.data(), key.kid.size()));
        keysChanged |= m_keyStore.add(KeyHandle::create(keyStatusFromCdm(key.status), WTF::move(keyID), BoxPtr<ExternalCdmSession>(m_externalSession)));
    }

    if (keysChanged)
        instance->mergeKeysFrom(m_keyStore);

    if (m_client)
        m_client->updateKeyStatuses(m_keyStore.convertToJSKeyStatusVector());
}

void CDMInstanceSessionExternalCDM::requestLicense(LicenseType licenseType, KeyGroupingStrategy, const String& initDataType, Ref<SharedBuffer>&& initData, LicenseCallback&& callback)
{
    RefPtr instance = cdmInstanceExternalCDM();
    if (instance && instance->isWidevine()) {
        requestLicenseWidevine(licenseType, initDataType, WTF::move(initData), WTF::move(callback));
        return;
    }
    requestLicenseClearKey(initDataType, WTF::move(initData), WTF::move(callback));
}

void CDMInstanceSessionExternalCDM::requestLicenseClearKey(const String& initDataType, Ref<SharedBuffer>&& initData, LicenseCallback&& callback)
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

void CDMInstanceSessionExternalCDM::requestLicenseWidevine(LicenseType licenseType, const String& initDataType, Ref<SharedBuffer>&& initData, LicenseCallback&& callback)
{
    ASSERT(isMainThread());

    RefPtr instance = cdmInstanceExternalCDM();
    auto adapter = instance ? instance->ensureAdapter() : nullptr;
    if (!adapter) {
        callback(WTF::move(initData), emptyString(), false, Failed);
        return;
    }

    cdm::InitDataType cdmInitDataType = cdm::InitDataType::kCenc;
    if (equalLettersIgnoringASCIICase(initDataType, "keyids"_s))
        cdmInitDataType = cdm::InitDataType::kKeyIds;
    else if (equalLettersIgnoringASCIICase(initDataType, "webm"_s))
        cdmInitDataType = cdm::InitDataType::kWebM;

    cdm::SessionType cdmSessionType = (licenseType == LicenseType::PersistentLicense)
        ? cdm::SessionType::kPersistentLicense : cdm::SessionType::kTemporary;

    m_challengeCallback = WTF::move(callback);
    instance->registerPendingSession(*this);

    // The CDM delivers the challenge through a session message on success, so
    // only a rejection needs handling here: without it generateRequest() hangs
    // until the player times out. The session id is learned from the message.
    uint32_t promiseId = instance->registerPromise([weakThis = WeakPtr { *this }](bool succeeded) mutable {
        RefPtr protectedThis = weakThis.get();
        if (!protectedThis || succeeded)
            return;
        if (auto callback = std::exchange(protectedThis->m_challengeCallback, { }))
            callback(SharedBuffer::create(), emptyString(), false, Failed);
    });

    auto data = initData->extractData();
    adapter->CreateSessionAndGenerateRequest(promiseId, cdmSessionType, cdmInitDataType, data.span().data(), static_cast<uint32_t>(data.size()));
}

void CDMInstanceSessionExternalCDM::updateLicense(const String& sessionID, LicenseType, Ref<SharedBuffer>&& response, LicenseUpdateCallback&& callback)
{
    RefPtr instance = cdmInstanceExternalCDM();
    if (instance && instance->isWidevine()) {
        updateLicenseWidevine(sessionID, WTF::move(response), WTF::move(callback));
        return;
    }
    updateLicenseClearKey(sessionID, WTF::move(response), WTF::move(callback));
}

void CDMInstanceSessionExternalCDM::updateLicenseClearKey(const String& sessionID, Ref<SharedBuffer>&& response, LicenseUpdateCallback&& callback)
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

void CDMInstanceSessionExternalCDM::updateLicenseWidevine(const String& sessionID, Ref<SharedBuffer>&& response, LicenseUpdateCallback&& callback)
{
    ASSERT(isMainThread());
    ASSERT_UNUSED(sessionID, sessionID == m_sessionID);

    RefPtr instance = cdmInstanceExternalCDM();
    auto adapter = instance ? instance->ensureAdapter() : nullptr;
    if (!adapter || m_sessionID.isEmpty()) {
        callback(false, std::nullopt, std::nullopt, std::nullopt, Failed);
        return;
    }

    // Key statuses arrive separately, through onKeyStatusChange().
    uint32_t promiseId = instance->registerPromise([callback = WTF::move(callback)](bool succeeded) mutable {
        callback(false, std::nullopt, std::nullopt, std::nullopt, succeeded ? Succeeded : Failed);
    });

    auto data = response->extractData();
    auto sid = m_sessionID.utf8();
    adapter->UpdateSession(promiseId, sid.data(), sid.length(), data.span().data(), static_cast<uint32_t>(data.size()));
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
    RefPtr instance = cdmInstanceExternalCDM();
    if (instance && instance->isWidevine()) {
        auto adapter = instance->ensureAdapter();
        bool isClosingInCdm = adapter && !m_sessionID.isEmpty();
        if (isClosingInCdm) {
            uint32_t promiseId = instance->registerPromise([callback = WTF::move(callback)](bool) mutable {
                callback();
            });
            auto sid = m_sessionID.utf8();
            adapter->CloseSession(promiseId, sid.data(), sid.length());
        }
        instance->unrefAllKeysFrom(m_keyStore);
        instance->unregisterSession(m_sessionID);
        m_keyStore.clear();
        m_externalSession = BoxPtr<ExternalCdmSession>();
        if (isClosingInCdm)
            return;
    }

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

    RefPtr instance = cdmInstanceExternalCDM();
    std::shared_ptr<media::CdmAdapter> adapter;
    if (instance && instance->isWidevine())
        adapter = instance->ensureAdapter();

    if (instance)
        instance->unrefAllKeysFrom(m_keyStore);
    m_keyStore.clear();

    if (adapter && !m_sessionID.isEmpty()) {
        uint32_t promiseId = instance->registerPromise([callback = WTF::move(callback), keyStatusVector = WTF::move(keyStatusVector), message = WTF::move(message)](bool succeeded) mutable {
            callback(WTF::move(keyStatusVector), WTF::move(message), succeeded ? SuccessValue::Succeeded : SuccessValue::Failed);
        });
        auto sid = m_sessionID.utf8();
        adapter->RemoveSession(promiseId, sid.data(), sid.length());
        return;
    }

    dispatchCallback(WTF::move(keyStatusVector), Ref<SharedBuffer>(*message), SuccessValue::Succeeded);
}

void CDMInstanceSessionExternalCDM::storeRecordOfKeyUsage(const String&)
{
}

} // namespace WebCore

#endif // ENABLE(ENCRYPTED_MEDIA) && ENABLE(EXTERNAL_CDM)
