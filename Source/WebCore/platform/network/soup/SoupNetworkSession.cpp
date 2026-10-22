/*
 * Copyright (C) 2014 Igalia S.L.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#if USE(SOUP)

#include "SoupNetworkSession.h"

#include "AuthenticationChallenge.h"
#include "GUniquePtrSoup.h"
#include "Logging.h"
#include "WebKitAutoconfigProxyResolver.h"
#include <arpa/inet.h>
#include <glib/gstdio.h>
#include <ifaddrs.h>
#include <libsoup/soup.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pal/crypto/CryptoDigest.h>
#include <wtf/FileSystem.h>
#include <wtf/HashSet.h>
#include <wtf/NeverDestroyed.h>
#include <wtf/TZoneMallocInlines.h>
#include <wtf/glib/GLibExtras.h>
#include <wtf/glib/GSpanExtras.h>
#include <wtf/text/Base64.h>
#include <wtf/text/CString.h>
#include <wtf/text/StringToIntegerConversion.h>

namespace WebCore {

WTF_MAKE_TZONE_ALLOCATED_IMPL(SoupNetworkSession);

static UTF8CString& initialAcceptLanguages()
{
    static NeverDestroyed<UTF8CString> storage;
    return storage.get();
}

#if !LOG_DISABLED || !RELEASE_LOG_DISABLED
inline static void soupLogPrinter(SoupLogger*, SoupLoggerLogLevel, char direction, const char* data, gpointer)
{
#if !LOG_DISABLED
    LOG(Network, "%c %s", direction, data);
#elif !RELEASE_LOG_DISABLED
    RELEASE_LOG(Network, "%c %s", direction, data);
#endif
}
#endif

class HostTLSCertificateSet {
public:
    void add(GTlsCertificate* certificate)
    {
        String certificateHash = computeCertificateHash(certificate);
        if (!certificateHash.isEmpty())
            m_certificates.add(certificateHash);
    }

    bool contains(GTlsCertificate* certificate) const
    {
        return m_certificates.contains(computeCertificateHash(certificate));
    }

private:
    static String computeCertificateHash(GTlsCertificate* certificate)
    {
        GRefPtr<GByteArray> certificateData;
        g_object_get(G_OBJECT(certificate), "certificate", &certificateData.outPtr(), nullptr);
        if (!certificateData)
            return String();

        auto digest = PAL::Crypto::CryptoDigest::create(PAL::Crypto::CryptoDigest::Algorithm::SHA_256);
        digest->addBytes(span(certificateData));

        return base64EncodeToString(digest->computeHash());
    }

    HashSet<String> m_certificates;
};

SoupNetworkSession::SoupNetworkSession(PAL::SessionID sessionID)
    : m_sessionID(sessionID)
{
    // These values match Chrome 81. https://stackoverflow.com/a/30064610
    static const int maxConnections = 256;
    static const int maxConnectionsPerHost = 6;

    // libsoup's default idle-timeout is 60s. Raise it to 115s, matching
    // Firefox's network.http.keep-alive.timeout default, to keep connections
    // warm for same-origin renavigation within a browsing session.
    // Firefox flags a problem with IIS7 servers' default timeout of 120s, so
    // the timeout chosen is a little shorter to keep a reserve for cases
    // when the packet is lost or delayed on the route.
    static const int idleTimeout = 115;

    m_soupSession = adoptGRef(soup_session_new_with_options(
        "max-conns", maxConnections,
        "max-conns-per-host", maxConnectionsPerHost,
        "idle-timeout", idleTimeout,
        "timeout", 0,
        nullptr));

    soup_session_add_feature_by_type(m_soupSession.get(), SOUP_TYPE_CONTENT_SNIFFER);
    soup_session_add_feature_by_type(m_soupSession.get(), SOUP_TYPE_AUTH_NTLM);
    soup_session_add_feature_by_type(m_soupSession.get(), SOUP_TYPE_HSTS_ENFORCER);
    soup_session_add_feature_by_type(m_soupSession.get(), SOUP_TYPE_WEBSOCKET_EXTENSION_MANAGER);

    if (!initialAcceptLanguages().isNull())
        setAcceptLanguages(initialAcceptLanguages());

    if (soup_auth_negotiate_supported() && !m_sessionID.isEphemeral())
        soup_session_add_feature_by_type(m_soupSession.get(), SOUP_TYPE_AUTH_NEGOTIATE);

#if ENABLE(DEVELOPER_MODE)
    // Optionally load a custom path with the TLS CAFile. This is used on the GTK/WPE bundles. See script generate-bundle
    // Don't enable this outside DEVELOPER_MODE because using a non-default TLS database has surprising undesired effects
    // on how certificate verification is performed. See https://webkit.org/b/237107#c14 and git commit 82999879b on glib
    const char* customTLSCAFile = g_getenv("WEBKIT_TLS_CAFILE_PEM");
    if (customTLSCAFile) {
        GUniqueOutPtr<GError> error;
        GRefPtr<GTlsDatabase> customTLSDB = adoptGRef(g_tls_file_database_new(customTLSCAFile, &error.outPtr()));
        if (error)
            WTFLogAlways("Failed to load TLS database \"%s\": %s", customTLSCAFile, error->message);
        else
            soup_session_set_tls_database(m_soupSession.get(), customTLSDB.get());
    }
#endif // ENABLE(DEVELOPER_MODE)

    setupLogger();
}

SoupNetworkSession::~SoupNetworkSession()
{
    soup_session_abort(m_soupSession.get());
}

void SoupNetworkSession::setupLogger()
{
#if !LOG_DISABLED || !RELEASE_LOG_DISABLED
    if (LogNetwork.state != WTFLogChannelState::On || soup_session_get_feature(m_soupSession.get(), SOUP_TYPE_LOGGER))
        return;

    GRefPtr<SoupLogger> logger = adoptGRef(soup_logger_new(SOUP_LOGGER_LOG_BODY));
    soup_session_add_feature(m_soupSession.get(), SOUP_SESSION_FEATURE(logger.get()));
    soup_logger_set_printer(logger.get(), soupLogPrinter, nullptr, nullptr);
#endif
}

void SoupNetworkSession::setCookieJar(SoupCookieJar* jar)
{
    if (SoupCookieJar* currentJar = cookieJar())
        soup_session_remove_feature(m_soupSession.get(), SOUP_SESSION_FEATURE(currentJar));
    soup_session_add_feature(m_soupSession.get(), SOUP_SESSION_FEATURE(jar));
}

SoupCookieJar* SoupNetworkSession::cookieJar() const
{
    return SOUP_COOKIE_JAR(soup_session_get_feature(m_soupSession.get(), SOUP_TYPE_COOKIE_JAR));
}

void SoupNetworkSession::setHSTSPersistentStorage(const String& directory)
{
    if (m_sessionID.isEphemeral())
        return;

    if (!FileSystem::makeAllDirectories(directory)) {
        RELEASE_LOG_ERROR(Network, "Unable to create the HSTS storage directory \"%s\". Using a memory enforcer instead.", directory.utf8());
        return;
    }

    auto storagePath = FileSystem::fileSystemRepresentation(directory);
    auto dbFilename = gBuildFilename(storagePath, "hsts-storage.sqlite");
    GRefPtr<SoupHSTSEnforcer> enforcer = adoptGRef(soup_hsts_enforcer_db_new(dbFilename.utf8()));
    soup_session_remove_feature_by_type(m_soupSession.get(), SOUP_TYPE_HSTS_ENFORCER);
    soup_session_add_feature(m_soupSession.get(), SOUP_SESSION_FEATURE(enforcer.get()));
}

void SoupNetworkSession::getHostNamesWithHSTSCache(HashSet<String>& hostNames)
{
    auto* enforcer = SOUP_HSTS_ENFORCER(soup_session_get_feature(m_soupSession.get(), SOUP_TYPE_HSTS_ENFORCER));
    ASSERT(enforcer);

    GUniquePtr<GList> domains(soup_hsts_enforcer_get_domains(enforcer, FALSE));
    for (GList* iter = domains.get(); iter; iter = iter->next) {
        GUniquePtr<gchar> domain(static_cast<gchar*>(iter->data));
        hostNames.add(String::fromUTF8(domain.get()));
    }
}

void SoupNetworkSession::deleteHSTSCacheForHostNames(const Vector<String>& hostNames)
{
    auto* enforcer = SOUP_HSTS_ENFORCER(soup_session_get_feature(m_soupSession.get(), SOUP_TYPE_HSTS_ENFORCER));
    ASSERT(enforcer);

    for (const auto& hostName : hostNames) {
        GUniquePtr<SoupHSTSPolicy> policy(soup_hsts_policy_new(hostName.utf8().legacyCStringPointer(), SOUP_HSTS_POLICY_MAX_AGE_PAST, FALSE));
        soup_hsts_enforcer_set_policy(enforcer, policy.get());
    }
}

void SoupNetworkSession::clearHSTSCache(WallTime modifiedSince)
{
    auto* enforcer = SOUP_HSTS_ENFORCER(soup_session_get_feature(m_soupSession.get(), SOUP_TYPE_HSTS_ENFORCER));
    ASSERT(enforcer);

    GUniquePtr<GList> policies(soup_hsts_enforcer_get_policies(enforcer, FALSE));
    for (GList* iter = policies.get(); iter != nullptr; iter = iter->next) {
        GUniquePtr<SoupHSTSPolicy> policy(static_cast<SoupHSTSPolicy*>(iter->data));
        auto modified = g_date_time_to_unix(soup_hsts_policy_get_expires(policy.get())) - soup_hsts_policy_get_max_age(policy.get());
        if (modified >= modifiedSince.secondsSinceEpoch().seconds()) {
            GUniquePtr<SoupHSTSPolicy> newPolicy(soup_hsts_policy_new(soup_hsts_policy_get_domain(policy.get()), SOUP_HSTS_POLICY_MAX_AGE_PAST, FALSE));
            soup_hsts_enforcer_set_policy(enforcer, newPolicy.get());
        }
    }
}

static inline bool stringIsNumeric(const std::string_view& str)
{
    return std::all_of(str.cbegin(), str.cend(), [](const auto c) {
        return WTF::isASCIIDigit(c);
    });
}

// Old versions of WebKit created this cache.
void SoupNetworkSession::clearOldSoupCache(const String& cacheDirectory)
{
    auto cachePath = FileSystem::fileSystemRepresentation(cacheDirectory);
    auto cacheFile = gBuildFilename(cachePath, "soup.cache2");
    if (!g_file_test(cacheFile.utf8(), G_FILE_TEST_IS_REGULAR))
        return;

    GUniquePtr<GDir> dir(g_dir_open(cachePath.legacyCStringPointer(), 0, nullptr));
    if (!dir)
        return;

    while (const char* name = g_dir_read_name(dir.get())) {
        const auto nameView = std::string_view(name);
        if (!nameView.starts_with("soup.cache") && !stringIsNumeric(nameView))
            continue;

        auto filename = gBuildFilename(cachePath, name);
        if (g_file_test(filename.utf8(), G_FILE_TEST_IS_REGULAR))
            g_unlink(filename.utf8());
    }
}

void SoupNetworkSession::setProxySettings(const SoupNetworkProxySettings& settings)
{
    m_proxySettings = settings;

    GRefPtr<GProxyResolver> resolver;
    switch (m_proxySettings.mode) {
    case SoupNetworkProxySettings::Mode::Default: {
        GProxyResolver* defaultResolver = g_proxy_resolver_get_default();
        if (defaultResolver == soup_session_get_proxy_resolver(m_soupSession.get()))
            return;
        resolver = defaultResolver;
        break;
    }
    case SoupNetworkProxySettings::Mode::NoProxy:
        // Do nothing in this case, resolver is nullptr so that when set it will disable proxies.
        break;
    case SoupNetworkProxySettings::Mode::Custom:
        resolver = adoptGRef(g_simple_proxy_resolver_new(nullptr, nullptr));
        if (!m_proxySettings.defaultProxyURL.isNull())
            g_simple_proxy_resolver_set_default_proxy(G_SIMPLE_PROXY_RESOLVER(resolver.get()), m_proxySettings.defaultProxyURL.legacyCStringPointer());
        if (!m_proxySettings.ignoreHosts.isEmpty()) {
            auto ignoreHosts = m_proxySettings.ignoreHosts.map([](const UTF8CString& host) {
                return const_cast<char*>(host.legacyCStringPointer());
            });
            ignoreHosts.append(nullptr);
            g_simple_proxy_resolver_set_ignore_hosts(G_SIMPLE_PROXY_RESOLVER(resolver.get()), ignoreHosts.mutableSpan().data());
        }
        for (const auto& iter : m_proxySettings.proxyMap)
            g_simple_proxy_resolver_set_uri_proxy(G_SIMPLE_PROXY_RESOLVER(resolver.get()), iter.key.legacyCStringPointer(), iter.value.legacyCStringPointer());
        break;
    case SoupNetworkProxySettings::Mode::Auto:
        resolver = webkitAutoconfigProxyResolverNew(m_proxySettings.defaultProxyURL);
        break;
    }

    soup_session_set_proxy_resolver(m_soupSession.get(), resolver.get());
    soup_session_abort(m_soupSession.get());
}

static GRefPtr<GInetAddress> inetAddressForInterface(struct ifaddrs* entry)
{
    auto* address = reinterpret_cast<struct sockaddr_in*>(entry->ifa_addr);
    return adoptGRef(g_inet_address_new_from_bytes(reinterpret_cast<const guint8*>(&address->sin_addr), G_SOCKET_FAMILY_IPV4));
}

template<typename MatchFunction>
static GRefPtr<GInetAddress> firstUpIPv4Interface(const MatchFunction& matches)
{
    struct ifaddrs* interfaces = nullptr;
    if (getifaddrs(&interfaces))
        return nullptr;

    GRefPtr<GInetAddress> result;
    for (struct ifaddrs* entry = interfaces; entry; entry = entry->ifa_next) {
        if (!entry->ifa_addr || entry->ifa_addr->sa_family != AF_INET)
            continue;
        if (!(entry->ifa_flags & IFF_UP))
            continue;
        if (!matches(entry))
            continue;
        result = inetAddressForInterface(entry);
        break;
    }

    freeifaddrs(interfaces);
    return result;
}

static GRefPtr<GInetAddress> resolveUplinkSubnet(const CString& addressText, unsigned prefixLength)
{
    struct in_addr subnet;
    if (inet_pton(AF_INET, addressText.data(), &subnet) != 1)
        return nullptr;

    uint32_t subnetBits = ntohl(subnet.s_addr);
    uint32_t mask = prefixLength ? (~uint32_t { 0 } << (32 - prefixLength)) : 0;

    return firstUpIPv4Interface([&](struct ifaddrs* entry) {
        auto* address = reinterpret_cast<struct sockaddr_in*>(entry->ifa_addr);
        return (ntohl(address->sin_addr.s_addr) & mask) == (subnetBits & mask);
    });
}

static GRefPtr<GInetAddress> resolveUplinkInterface(const CString& interfaceName)
{
    return firstUpIPv4Interface([&](struct ifaddrs* entry) {
        return !g_strcmp0(entry->ifa_name, interfaceName.data());
    });
}

// Resolve an uplink specification to the local IPv4 address a connection should
// leave through, matching kodi-pvr-iptvsimple's uplinkAddress semantics. The
// resolution is repeated for every connection so a lease change is followed.
static GRefPtr<GInetAddress> resolveUplinkAddress(const String& uplink)
{
    if (uplink.isEmpty())
        return nullptr;

    size_t slashPosition = uplink.find('/');
    if (slashPosition != notFound) {
        auto prefixLength = parseInteger<unsigned>(StringView(uplink).substring(slashPosition + 1), 10, WTF::ParseIntegerWhitespacePolicy::Disallow);
        if (!prefixLength || *prefixLength > 32)
            return nullptr;
        return resolveUplinkSubnet(uplink.left(slashPosition).utf8(), *prefixLength);
    }

    CString uplinkText = uplink.utf8();
    GRefPtr<GInetAddress> literal = adoptGRef(g_inet_address_new_from_string(uplinkText.data()));
    if (literal) {
        if (g_inet_address_get_family(literal.get()) == G_SOCKET_FAMILY_IPV4)
            return literal;
        return nullptr;
    }

    return resolveUplinkInterface(uplinkText);
}

void SoupNetworkSession::bindConnectionToUplink(GIOStream* connection)
{
    if (m_uplink.isEmpty())
        return;

    if (!G_IS_SOCKET_CONNECTION(connection))
        return;

    GSocket* socket = g_socket_connection_get_socket(G_SOCKET_CONNECTION(connection));
    if (!socket)
        return;

    // A reused SoupMessage can carry the network-event handler more than once, so
    // ignore a socket that already carries a non-wildcard bind of ours.
    GRefPtr<GSocketAddress> boundAddress = adoptGRef(g_socket_get_local_address(socket, nullptr));
    if (boundAddress && G_IS_INET_SOCKET_ADDRESS(boundAddress.get())
        && !g_inet_address_get_is_any(g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(boundAddress.get()))))
        return;

    // The resolver is IPv4 only, so an IPv6 attempt can never match the uplink.
    // Closing the socket fails this attempt and lets happy eyeballs fall back to IPv4.
    if (g_socket_get_family(socket) != G_SOCKET_FAMILY_IPV4) {
        g_socket_close(socket, nullptr);
        return;
    }

    GRefPtr<GInetAddress> localAddress = resolveUplinkAddress(m_uplink);
    if (!localAddress) {
        // The uplink is down: fail the connection instead of leaving through the
        // default route, so the loss stays visible.
        RELEASE_LOG_ERROR(Network, "Uplink \"%s\" could not be resolved; failing connection", m_uplink.utf8().data());
        g_socket_close(socket, nullptr);
        return;
    }

    GRefPtr<GSocketAddress> bindAddress = adoptGRef(g_inet_socket_address_new(localAddress.get(), 0));
    GUniqueOutPtr<GError> error;
    if (!g_socket_bind(socket, bindAddress.get(), FALSE, &error.outPtr())) {
        RELEASE_LOG_ERROR(Network, "Failed to bind connection to uplink \"%s\": %s", m_uplink.utf8().data(), error->message);
        g_socket_close(socket, nullptr);
    }
}

void SoupNetworkSession::setUplink(const String& uplink)
{
    m_uplink = uplink;
    if (m_uplink.isEmpty())
        return;

    g_signal_connect(m_soupSession.get(), "request-queued", G_CALLBACK(+[](SoupSession*, SoupMessage* message, gpointer userData) {
        g_signal_connect(message, "network-event", G_CALLBACK(+[](SoupMessage*, GSocketClientEvent event, GIOStream* connection, gpointer userData) {
            if (event != G_SOCKET_CLIENT_CONNECTING)
                return;
            static_cast<SoupNetworkSession*>(userData)->bindConnectionToUplink(connection);
        }), userData);
    }), this);
}

void SoupNetworkSession::setInitialAcceptLanguages(const UTF8CString& languages)
{
    initialAcceptLanguages() = languages;
}

void SoupNetworkSession::setAcceptLanguages(const UTF8CString& languages)
{
    soup_session_set_accept_language(m_soupSession.get(), languages.legacyCStringPointer());
}

void SoupNetworkSession::setIgnoreTLSErrors(bool ignoreTLSErrors)
{
    m_ignoreTLSErrors = ignoreTLSErrors;
}

static StringView hostForComparison(const URL& requestURL)
{
    StringView host = requestURL.host();

    // If the host component of the URL is an IPv6 address, it will be
    // surrounded by [ ] brackets. We have to remove them because they're part
    // of the WTF::URL's host component and the string representation of the URL,
    // but not part of GUri or SoupURI's host and not part of the host passed to
    // allowSpecificHTTPSCertificateForHost.
    if (host[0] == '[' && host.length() >= 2 && host[host.length() - 1] == ']')
        return host.substring(1, host.length() - 2);

    return host;
}

std::optional<ResourceError> SoupNetworkSession::checkTLSErrors(const URL& requestURL, GTlsCertificate* certificate, GTlsCertificateFlags tlsErrors)
{
    if (m_ignoreTLSErrors || !tlsErrors)
        return std::nullopt;

    auto it = m_allowedCertificates.find<ASCIICaseInsensitiveStringViewHashTranslator>(hostForComparison(requestURL));
    if (it != m_allowedCertificates.end() && it->value.contains(certificate))
        return std::nullopt;

    return ResourceError::tlsError(requestURL, tlsErrors, certificate);
}

void SoupNetworkSession::allowSpecificHTTPSCertificateForHost(const CertificateInfo& certificateInfo, const String& host)
{
    m_allowedCertificates.add(host, HostTLSCertificateSet()).iterator->value.add(certificateInfo.certificate().get());
}

} // namespace WebCore

#endif
