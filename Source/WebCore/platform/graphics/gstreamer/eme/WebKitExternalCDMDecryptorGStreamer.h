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
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#pragma once

#if ENABLE(ENCRYPTED_MEDIA) && ENABLE(EXTERNAL_CDM) && USE(GSTREAMER)

#include "CDMProxyExternalCDM.h"
#include "GStreamerCommon.h"
#include "WebKitCommonEncryptionDecryptorGStreamer.h"
#include <optional>

class WebKitExternalCDMDecryptInput {
public:
    bool map(GstElement*, GstBuffer* sample, GstMapFlags, const WebKitMediaCommonEncryptionSampleInfo&);

    WebCore::CDMProxyExternalCDM::cencDecryptContext context { };

private:
    std::optional<WebCore::GstMappedBuffer> m_iv;
    std::optional<WebCore::GstMappedBuffer> m_keyID;
    std::optional<WebCore::GstMappedBuffer> m_sample;
    std::optional<WebCore::GstMappedBuffer> m_subsamples;
};

G_BEGIN_DECLS

#define WEBKIT_TYPE_MEDIA_EXTERNAL_CDM_DECRYPT          (webkit_media_external_cdm_decrypt_get_type())
#define WEBKIT_MEDIA_EXTERNAL_CDM_DECRYPT(obj)          (G_TYPE_CHECK_INSTANCE_CAST((obj), WEBKIT_TYPE_MEDIA_EXTERNAL_CDM_DECRYPT, WebKitMediaExternalCDMDecrypt))
#define WEBKIT_MEDIA_EXTERNAL_CDM_DECRYPT_CLASS(klass)  (G_TYPE_CHECK_CLASS_CAST((klass), WEBKIT_TYPE_MEDIA_EXTERNAL_CDM_DECRYPT, WebKitMediaExternalCDMDecryptClass))
#define WEBKIT_IS_MEDIA_EXTERNAL_CDM_DECRYPT(obj)       (G_TYPE_CHECK_INSTANCE_TYPE((obj), WEBKIT_TYPE_MEDIA_EXTERNAL_CDM_DECRYPT))
#define WEBKIT_IS_MEDIA_EXTERNAL_CDM_DECRYPT_CLASS(obj) (G_TYPE_CHECK_CLASS_TYPE((klass), WEBKIT_TYPE_MEDIA_EXTERNAL_CDM_DECRYPT))

typedef struct _WebKitMediaExternalCDMDecrypt        WebKitMediaExternalCDMDecrypt;
typedef struct _WebKitMediaExternalCDMDecryptClass   WebKitMediaExternalCDMDecryptClass;
struct WebKitMediaExternalCDMDecryptPrivate;

GType webkit_media_external_cdm_decrypt_get_type(void);

struct _WebKitMediaExternalCDMDecrypt {
    WebKitMediaCommonEncryptionDecrypt parent;

    WebKitMediaExternalCDMDecryptPrivate* priv;
};

struct _WebKitMediaExternalCDMDecryptClass {
    WebKitMediaCommonEncryptionDecryptClass parentClass;
};

G_END_DECLS

#endif // ENABLE(ENCRYPTED_MEDIA) && ENABLE(EXTERNAL_CDM) && USE(GSTREAMER)
