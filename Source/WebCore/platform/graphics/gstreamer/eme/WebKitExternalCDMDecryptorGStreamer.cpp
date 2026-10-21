/* GStreamer external CDM common encryption decryptor
 *
 * Copyright (C) 2020 Metrological
 * Copyright (C) 2020 Igalia S.L
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Suite 500,
 * Boston, MA 02110-1335, USA.
 */

#include "config.h"
#include "WebKitExternalCDMDecryptorGStreamer.h"
#include "WebKitCommonEncryptionDecryptorGStreamer.h"

#if ENABLE(ENCRYPTED_MEDIA) && ENABLE(EXTERNAL_CDM) && USE(GSTREAMER)

#include "CDMExternalCDM.h"
#include "CDMProxyExternalCDM.h"
#include "GStreamerCommon.h"
#include "GStreamerEMEUtilities.h"
#include <wtf/glib/WTFGType.h>

using namespace WebCore;

struct WebKitMediaExternalCDMDecryptPrivate {
    RefPtr<CDMProxyExternalCDM> cdmProxy;
};

static ASCIILiteral protectionSystemId(WebKitMediaCommonEncryptionDecrypt*);
static bool cdmProxyAttached(WebKitMediaCommonEncryptionDecrypt*, const RefPtr<CDMProxy>&);
static DecryptionResult decrypt(WebKitMediaCommonEncryptionDecrypt*, GstBuffer* iv, GstBuffer* keyid, GstBuffer* sample, unsigned subSamplesCount,
    GstBuffer* subSamples);

GST_DEBUG_CATEGORY_STATIC(webkitMediaExternalCDMDecryptDebugCategory);
#define GST_CAT_DEFAULT webkitMediaExternalCDMDecryptDebugCategory

static GstStaticPadTemplate externalCDMSrcTemplate = GST_STATIC_PAD_TEMPLATE("src",
    GST_PAD_SRC,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS(
        "video/webm; "
        "audio/webm; "
        "video/mp4; "
        "audio/mp4; "
        "audio/mpeg; "
        "audio/x-flac; "
        "video/x-h264; "
        "video/x-h265; "
        "video/x-vp9; video/x-vp8; "
        "video/x-av1; "
        "audio/x-opus; audio/x-vorbis"));

WEBKIT_DEFINE_TYPE(WebKitMediaExternalCDMDecrypt, webkit_media_external_cdm_decrypt, WEBKIT_TYPE_MEDIA_CENC_DECRYPT)

static GRefPtr<GstCaps> createSinkPadTemplateCaps()
{
    GRefPtr<GstCaps> caps = adoptGRef(gst_caps_new_empty());

    auto& supportedKeySystems = CDMFactoryExternalCDM::singleton().supportedKeySystems();
    if (supportedKeySystems.isEmpty()) {
        GST_WARNING("no supported key systems in the external CDM, the decryptor cannot decrypt anything");
        return caps;
    }

    for (const auto& mediaType : GStreamerEMEUtilities::s_cencEncryptionMediaTypes) {
        gst_caps_append_structure(caps.get(), gst_structure_new("application/x-cenc", "original-media-type", G_TYPE_STRING,
            mediaType.characters(), nullptr));
    }
    for (const auto& keySystem : supportedKeySystems) {
        for (const auto& mediaType : GStreamerEMEUtilities::s_cencEncryptionMediaTypes) {
            gst_caps_append_structure(caps.get(), gst_structure_new("application/x-cenc", "original-media-type", G_TYPE_STRING,
                mediaType.characters(), "protection-system", G_TYPE_STRING, GStreamerEMEUtilities::keySystemToUuid(keySystem).characters(), nullptr));
        }
    }

    if (supportedKeySystems.contains(GStreamerEMEUtilities::s_ClearKeyKeySystem)) {
        for (const auto& mediaType : GStreamerEMEUtilities::s_webmEncryptionMediaTypes) {
            gst_caps_append_structure(caps.get(), gst_structure_new("application/x-webm-enc", "original-media-type", G_TYPE_STRING,
                mediaType.characters(), nullptr));
        }
    }

    GST_DEBUG("sink pad template caps %" GST_PTR_FORMAT, caps.get());

    return caps;
}

static void webkit_media_external_cdm_decrypt_class_init(WebKitMediaExternalCDMDecryptClass* klass)
{
    GST_DEBUG_CATEGORY_INIT(webkitMediaExternalCDMDecryptDebugCategory, "webkitexternalcdm", 0, "external CDM decrypt");

    GstElementClass* elementClass = GST_ELEMENT_CLASS(klass);
    GRefPtr<GstCaps> gstSinkPadTemplateCaps = createSinkPadTemplateCaps();
    gst_element_class_add_pad_template(elementClass, gst_pad_template_new("sink", GST_PAD_SINK, GST_PAD_ALWAYS, gstSinkPadTemplateCaps.get()));
    gst_element_class_add_pad_template(elementClass, gst_static_pad_template_get(&externalCDMSrcTemplate));

    gst_element_class_set_static_metadata(elementClass, "Decrypt encrypted content using an external CDM", GST_ELEMENT_FACTORY_KLASS_DECRYPTOR,
        "Decrypts encrypted media using an external W3C CDM.", "Igalia");

    WebKitMediaCommonEncryptionDecryptClass* commonClass = WEBKIT_MEDIA_CENC_DECRYPT_CLASS(klass);
    commonClass->protectionSystemId = GST_DEBUG_FUNCPTR(protectionSystemId);
    commonClass->cdmProxyAttached = GST_DEBUG_FUNCPTR(cdmProxyAttached);
    commonClass->decrypt = GST_DEBUG_FUNCPTR(decrypt);
}

static ASCIILiteral protectionSystemId(WebKitMediaCommonEncryptionDecrypt* decryptor)
{
    auto* self = WEBKIT_MEDIA_EXTERNAL_CDM_DECRYPT(decryptor);
    ASSERT(self->priv->cdmProxy);
    return GStreamerEMEUtilities::keySystemToUuid(self->priv->cdmProxy->keySystem());
}

static bool cdmProxyAttached(WebKitMediaCommonEncryptionDecrypt* decryptor, const RefPtr<CDMProxy>& cdmProxy)
{
    auto* self = WEBKIT_MEDIA_EXTERNAL_CDM_DECRYPT(decryptor);
    self->priv->cdmProxy = reinterpret_cast<CDMProxyExternalCDM*>(cdmProxy.get());
    return self->priv->cdmProxy;
}

static DecryptionResult decrypt(WebKitMediaCommonEncryptionDecrypt* decryptor, GstBuffer* ivBuffer, GstBuffer* keyIDBuffer, GstBuffer* buffer, unsigned subsampleCount,
    GstBuffer* subsamplesBuffer)
{
    auto* self = WEBKIT_MEDIA_EXTERNAL_CDM_DECRYPT(decryptor);
    auto* priv = self->priv;

    if (!ivBuffer || !keyIDBuffer || !buffer) {
        GST_ERROR_OBJECT(self, "invalid decrypt() parameter");
        ASSERT_NOT_REACHED();
        return DecryptionResult::Failure;
    }

    if (subsampleCount && !subsamplesBuffer) {
        GST_ERROR_OBJECT(self, "invalid decrypt() subsamples parameter");
        ASSERT_NOT_REACHED();
        return DecryptionResult::Failure;
    }

    GstMappedBuffer mappedIVBuffer(ivBuffer, GST_MAP_READ);
    if (!mappedIVBuffer) {
        GST_ERROR_OBJECT(self, "failed to map IV buffer");
        return DecryptionResult::Failure;
    }

    GstMappedBuffer mappedKeyIdBuffer(keyIDBuffer, GST_MAP_READ);
    if (!mappedKeyIdBuffer) {
        GST_ERROR_OBJECT(self, "failed to map key ID buffer");
        return DecryptionResult::Failure;
    }

    GstMappedBuffer mappedBuffer(buffer, GST_MAP_READWRITE);
    if (!mappedBuffer) {
        GST_ERROR_OBJECT(self, "failed to map data buffer");
        return DecryptionResult::Failure;
    }

    std::optional<GstMappedBuffer> mappedSubsamplesBuffer;
    CDMProxyExternalCDM::cencDecryptContext context = { };
    context.keyID = mappedKeyIdBuffer.data();
    context.keyIDSizeInBytes = mappedKeyIdBuffer.size();
    context.iv = mappedIVBuffer.data();
    context.ivSizeInBytes = mappedIVBuffer.size();
    context.encryptedBuffer = mappedBuffer.data();
    context.encryptedBufferSizeInBytes = mappedBuffer.size();
    context.numSubsamples = subsampleCount;
    if (subsampleCount) {
        mappedSubsamplesBuffer.emplace(subsamplesBuffer, GST_MAP_READ);
        if (!*mappedSubsamplesBuffer) {
            GST_ERROR_OBJECT(self, "failed to map subsamples buffer");
            return DecryptionResult::Failure;
        }
        context.subsamplesBuffer = mappedSubsamplesBuffer->data();
        context.subsamplesBufferSizeInBytes = mappedSubsamplesBuffer->size();
    }
    context.cdmProxyDecryptionClient = webKitMediaCommonEncryptionDecryptGetCDMProxyDecryptionClient(decryptor);

    // The CENC base class parses the per-buffer cipher mode from the protection
    // meta but does not forward it to the subclass, so recover it from the sink
    // caps for the blob-backed key systems that need the scheme in Decrypt().
    // ClearKey ignores the scheme (it is always AES-CTR). cbcs pattern counts
    // are not available through this vfunc, so only the scheme is carried.
    context.encryptionScheme = cdm::EncryptionScheme::kCenc;
    if (auto caps = adoptGRef(gst_pad_get_current_caps(GST_BASE_TRANSFORM_SINK_PAD(GST_BASE_TRANSFORM_CAST(decryptor))))) {
        if (const GstStructure* structure = gst_caps_get_structure(caps.get(), 0)) {
            if (const char* cipherMode = gst_structure_get_string(structure, "cipher-mode")) {
                if (!g_ascii_strcasecmp(cipherMode, "cbcs"))
                    context.encryptionScheme = cdm::EncryptionScheme::kCbcs;
            }
            unsigned cryptByteBlock = 0;
            unsigned skipByteBlock = 0;
            if (gst_structure_get_uint(structure, "crypt_byte_block", &cryptByteBlock))
                context.cryptByteBlock = cryptByteBlock;
            if (gst_structure_get_uint(structure, "skip_byte_block", &skipByteBlock))
                context.skipByteBlock = skipByteBlock;
        }
    }

    return priv->cdmProxy->cencDecrypt(context);
}

#undef GST_CAT_DEFAULT

#endif // ENABLE(ENCRYPTED_MEDIA) && ENABLE(EXTERNAL_CDM) && USE(GSTREAMER)
