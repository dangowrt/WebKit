/* GStreamer video decoder running inside an external CDM
 *
 * Copyright (C) 2026 Daniel Golle <daniel@makrotopia.org>
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

#include <gst/video/gstvideodecoder.h>

G_BEGIN_DECLS

#define WEBKIT_TYPE_EXTERNAL_CDM_VIDEO_DECODER (webkit_external_cdm_video_decoder_get_type())
#define WEBKIT_EXTERNAL_CDM_VIDEO_DECODER(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), WEBKIT_TYPE_EXTERNAL_CDM_VIDEO_DECODER, WebKitExternalCDMVideoDecoder))

typedef struct _WebKitExternalCDMVideoDecoder WebKitExternalCDMVideoDecoder;
typedef struct _WebKitExternalCDMVideoDecoderClass WebKitExternalCDMVideoDecoderClass;
struct WebKitExternalCDMVideoDecoderPrivate;

GType webkit_external_cdm_video_decoder_get_type(void);

struct _WebKitExternalCDMVideoDecoder {
    GstVideoDecoder parent;

    WebKitExternalCDMVideoDecoderPrivate* priv;
};

struct _WebKitExternalCDMVideoDecoderClass {
    GstVideoDecoderClass parentClass;
};

G_END_DECLS

#endif // ENABLE(ENCRYPTED_MEDIA) && ENABLE(EXTERNAL_CDM) && USE(GSTREAMER)
