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

#include "config.h"
#include "WebKitExternalCDMVideoDecoderGStreamer.h"

#if ENABLE(ENCRYPTED_MEDIA) && ENABLE(EXTERNAL_CDM) && USE(GSTREAMER)

#include "CDMProxyExternalCDM.h"
#include "GStreamerCommon.h"
#include "GStreamerEMEUtilities.h"
#include "WebKitCommonEncryptionDecryptorGStreamer.h"
#include "WebKitExternalCDMDecryptorGStreamer.h"
#include <gst/video/video.h>
#include <wtf/Condition.h>
#include <wtf/Lock.h>
#include <wtf/TZoneMallocInlines.h>
#include <wtf/glib/WTFGType.h>

using namespace WebCore;

GST_DEBUG_CATEGORY_STATIC(webkitExternalCDMVideoDecoderDebugCategory);
#define GST_CAT_DEFAULT webkitExternalCDMVideoDecoderDebugCategory

static constexpr std::array<ASCIILiteral, 4> s_decodableMediaTypes = { "video/x-av1"_s, "video/x-vp9"_s, "video/x-vp8"_s, "video/x-h264"_s };
static constexpr std::array<uint8_t, 4> s_annexBStartCode = { 0, 0, 0, 1 };

static GstStaticPadTemplate externalCDMVideoDecoderSrcTemplate = GST_STATIC_PAD_TEMPLATE("src", GST_PAD_SRC, GST_PAD_ALWAYS,
    GST_STATIC_CAPS(GST_VIDEO_CAPS_MAKE("{ I420, I420_10LE, I420_12LE, I422_10LE, I422_12LE, Y444_10LE, Y444_12LE }")));

class ExternalCDMVideoDecoderClient final : public CDMProxyDecryptionClient {
    WTF_MAKE_TZONE_ALLOCATED_INLINE(ExternalCDMVideoDecoderClient);
    WTF_OVERRIDE_DELETE_FOR_CHECKED_PTR(ExternalCDMVideoDecoderClient);
public:
    explicit ExternalCDMVideoDecoderClient(WebKitExternalCDMVideoDecoder* decoder)
        : m_decoder(decoder)
    {
    }

    bool isAborting() final;

private:
    WebKitExternalCDMVideoDecoder* m_decoder;
};

struct CdmBufferDestroyer {
    void operator()(cdm::Buffer* buffer) const { buffer->Destroy(); }
};
using CdmBufferPtr = std::unique_ptr<cdm::Buffer, CdmBufferDestroyer>;

struct WebKitExternalCDMVideoDecoderPrivate {
    Lock lock;
    Condition condition;
    RefPtr<CDMProxyExternalCDM> cdmProxy;
    bool isFlushing { false };
    bool isStopped { true };
    std::unique_ptr<ExternalCDMVideoDecoderClient> client;

    std::shared_ptr<media::CdmAdapter> adapter;
    bool isDecoderInitialized { false };
    cdm::VideoDecoderConfig_3 config { };
    cdm::EncryptionScheme encryptionScheme { cdm::EncryptionScheme::kCenc };
    bool isAvc { false };
    Vector<uint8_t> h264ParameterSets;
    GstVideoCodecState* inputState { nullptr };
    bool canAttachVideoMeta { false };
};

WEBKIT_DEFINE_TYPE(WebKitExternalCDMVideoDecoder, webkit_external_cdm_video_decoder, GST_TYPE_VIDEO_DECODER)

bool ExternalCDMVideoDecoderClient::isAborting()
{
    auto* priv = m_decoder->priv;
    Locker locker { priv->lock };
    return priv->isFlushing || priv->isStopped;
}

static GRefPtr<GstCaps> createSinkPadTemplateCaps()
{
    GRefPtr<GstCaps> caps = adoptGRef(gst_caps_new_empty());

    for (const auto& mediaType : s_decodableMediaTypes) {
        gst_caps_append_structure(caps.get(), gst_structure_new("application/x-cenc", "original-media-type", G_TYPE_STRING, mediaType.characters(),
            "protection-system", G_TYPE_STRING, GStreamerEMEUtilities::s_WidevineUUID.characters(), nullptr));
    }

    return caps;
}

static GstVideoFormat videoFormatFromCdm(cdm::VideoFormat format)
{
    switch (format) {
    case cdm::kYv12:
    case cdm::kI420:
        return GST_VIDEO_FORMAT_I420;
    case cdm::kYUV420P10:
        return GST_VIDEO_FORMAT_I420_10LE;
    case cdm::kYUV420P12:
        return GST_VIDEO_FORMAT_I420_12LE;
    case cdm::kYUV422P10:
        return GST_VIDEO_FORMAT_I422_10LE;
    case cdm::kYUV422P12:
        return GST_VIDEO_FORMAT_I422_12LE;
    case cdm::kYUV444P10:
        return GST_VIDEO_FORMAT_Y444_10LE;
    case cdm::kYUV444P12:
        return GST_VIDEO_FORMAT_Y444_12LE;
    default:
        return GST_VIDEO_FORMAT_UNKNOWN;
    }
}

static cdm::VideoFormat videoFormatFromCaps(const GstStructure* structure)
{
    auto bitDepth = gstStructureGet<unsigned>(structure, "bit-depth-luma"_s).value_or(8);
    auto chromaFormat = gstStructureGetString(structure, "chroma-format"_s);
    bool is444 = chromaFormat == "4:4:4"_s;
    bool is422 = chromaFormat == "4:2:2"_s;

    if (bitDepth == 10)
        return is444 ? cdm::kYUV444P10 : is422 ? cdm::kYUV422P10 : cdm::kYUV420P10;
    if (bitDepth == 12)
        return is444 ? cdm::kYUV444P12 : is422 ? cdm::kYUV422P12 : cdm::kYUV420P12;
    return cdm::kI420;
}

static bool videoCodecFromCaps(const GstStructure* structure, cdm::VideoDecoderConfig_3& config)
{
    auto mediaType = gstStructureGetName(structure);
    auto profile = gstStructureGetString(structure, "profile"_s);

    if (mediaType == "video/x-av1"_s) {
        config.codec = cdm::kCodecAv1;
        config.profile = cdm::kAv1ProfileMain;
        if (profile == "high"_s)
            config.profile = cdm::kAv1ProfileHigh;
        else if (profile == "professional"_s)
            config.profile = cdm::kAv1ProfilePro;
        return true;
    }

    if (mediaType == "video/x-vp9"_s) {
        config.codec = cdm::kCodecVp9;
        config.profile = cdm::kVP9Profile0;
        if (profile == "1"_s)
            config.profile = cdm::kVP9Profile1;
        else if (profile == "2"_s)
            config.profile = cdm::kVP9Profile2;
        else if (profile == "3"_s)
            config.profile = cdm::kVP9Profile3;
        return true;
    }

    if (mediaType == "video/x-h264"_s) {
        config.codec = cdm::kCodecH264;
        config.profile = cdm::kH264ProfileBaseline;
        if (profile == "main"_s)
            config.profile = cdm::kH264ProfileMain;
        else if (profile == "extended"_s)
            config.profile = cdm::kH264ProfileExtended;
        else if (profile == "high"_s)
            config.profile = cdm::kH264ProfileHigh;
        else if (profile == "high-10"_s)
            config.profile = cdm::kH264ProfileHigh10;
        else if (profile == "high-4:2:2"_s)
            config.profile = cdm::kH264ProfileHigh422;
        else if (profile == "high-4:4:4"_s)
            config.profile = cdm::kH264ProfileHigh444Predictive;
        return true;
    }

    if (mediaType == "video/x-vp8"_s) {
        config.codec = cdm::kCodecVp8;
        config.profile = cdm::kProfileNotNeeded;
        return true;
    }

    return false;
}

// The CDM takes H.264 as Annex B with the parameter sets in band, the form Chromium hands it.
static bool h264ParameterSetsFromCodecData(const GstStructure* structure, Vector<uint8_t>& parameterSets)
{
    const GValue* value = gst_structure_get_value(structure, "codec_data");
    GstBuffer* codecData = value ? gst_value_get_buffer(value) : nullptr;
    if (!codecData)
        return false;

    GstMappedBuffer mappedCodecData(codecData, GST_MAP_READ);
    if (!mappedCodecData || mappedCodecData.size() < 6)
        return false;

    auto data = unsafeMakeSpan(mappedCodecData.data(), mappedCodecData.size());
    if ((data[4] & 3) != 3)
        return false;

    size_t offset = 5;
    for (unsigned isPictureParameterSet = 0; isPictureParameterSet < 2; ++isPictureParameterSet) {
        if (offset >= data.size())
            return false;
        unsigned count = isPictureParameterSet ? data[offset] : data[offset] & 0x1f;
        offset++;
        for (unsigned i = 0; i < count; ++i) {
            if (data.size() - offset < 2)
                return false;
            size_t length = (data[offset] << 8) | data[offset + 1];
            offset += 2;
            if (data.size() - offset < length)
                return false;
            parameterSets.append(std::span { s_annexBStartCode });
            parameterSets.append(data.subspan(offset, length));
            offset += length;
        }
    }
    return true;
}

static bool h264SampleToAnnexB(WebKitExternalCDMVideoDecoder* self, bool isKeyFrame, CDMProxyExternalCDM::cencDecryptContext& context,
    Vector<uint8_t>& sample, Vector<uint8_t>& subsamples)
{
    auto* priv = self->priv;
    size_t prefixSize = isKeyFrame ? priv->h264ParameterSets.size() : 0;

    // The NAL lengths are rewritten in place, so they have to be in the clear.
    if (context.isEncrypted() && !context.isSubsampled())
        return false;

    sample.reserveInitialCapacity(prefixSize + context.encryptedBufferSizeInBytes);
    if (prefixSize)
        sample.append(priv->h264ParameterSets.span());
    sample.append(unsafeMakeSpan(context.encryptedBuffer, context.encryptedBufferSizeInBytes));

    for (size_t offset = prefixSize; offset < sample.size();) {
        if (sample.size() - offset < s_annexBStartCode.size())
            return false;
        size_t length = (static_cast<size_t>(sample[offset]) << 24) | (sample[offset + 1] << 16) | (sample[offset + 2] << 8) | sample[offset + 3];
        memcpySpan(sample.mutableSpan().subspan(offset, s_annexBStartCode.size()), std::span { s_annexBStartCode });
        offset += s_annexBStartCode.size();
        if (sample.size() - offset < length)
            return false;
        offset += length;
    }

    context.encryptedBuffer = sample.mutableSpan().data();
    context.encryptedBufferSizeInBytes = sample.size();
    if (!prefixSize || !context.isEncrypted())
        return true;

    subsamples.append(unsafeMakeSpan(context.subsamplesBuffer, context.subsamplesBufferSizeInBytes));
    if (subsamples.size() < 2)
        return false;
    size_t clearBytes = ((subsamples[0] << 8) | subsamples[1]) + prefixSize;
    if (clearBytes > std::numeric_limits<uint16_t>::max())
        return false;
    subsamples[0] = clearBytes >> 8;
    subsamples[1] = clearBytes & 0xff;
    context.subsamplesBuffer = subsamples.span().data();
    return true;
}

static void abortWaits(WebKitExternalCDMVideoDecoder* self)
{
    auto* priv = self->priv;
    RefPtr<CDMProxyExternalCDM> cdmProxy;

    {
        Locker locker { priv->lock };
        priv->condition.notifyAll();
        cdmProxy = priv->cdmProxy;
    }

    if (!cdmProxy)
        return;
    cdmProxy->abortWaitingForKey();
    cdmProxy->abortWaitingForAdapter();
}

static void attachCDMProxyFromContext(WebKitExternalCDMVideoDecoder* self)
{
    auto* priv = self->priv;
    CDMProxy* cdmProxy = webKitMediaCommonEncryptionCDMProxyFromContext(GST_ELEMENT_CAST(self));
    if (!cdmProxy)
        return;

    Locker locker { priv->lock };
    GST_DEBUG_OBJECT(self, "attaching CDMProxy %p", cdmProxy);
    priv->cdmProxy = static_cast<CDMProxyExternalCDM*>(cdmProxy);
    priv->condition.notifyAll();
}

static RefPtr<CDMProxyExternalCDM> waitForCDMProxy(WebKitExternalCDMVideoDecoder* self)
{
    auto* priv = self->priv;

    {
        Locker locker { priv->lock };
        if (priv->cdmProxy)
            return priv->cdmProxy;
    }

    attachCDMProxyFromContext(self);

    Locker locker { priv->lock };
    priv->condition.waitFor(priv->lock, webKitMediaCommonEncryptionMaxSecondsToWaitForCDMProxy, [priv] {
        return priv->cdmProxy || priv->isFlushing || priv->isStopped;
    });
    return priv->cdmProxy;
}

static void deinitializeDecoder(WebKitExternalCDMVideoDecoder* self)
{
    auto* priv = self->priv;

    if (priv->adapter && priv->isDecoderInitialized)
        priv->adapter->DeinitializeDecoder(cdm::kStreamTypeVideo);
    priv->isDecoderInitialized = false;
}

static bool ensureDecoder(WebKitExternalCDMVideoDecoder* self, std::shared_ptr<media::CdmAdapter>&& adapter)
{
    auto* priv = self->priv;

    if (priv->adapter == adapter && priv->isDecoderInitialized)
        return true;

    deinitializeDecoder(self);
    priv->adapter = WTF::move(adapter);

    const auto& config = priv->config;
    cdm::Status status = priv->adapter->InitializeVideoDecoder(config);
    if (status != cdm::kSuccess) {
        GST_ERROR_OBJECT(self, "CDM refused codec %u profile %u format %u %dx%d: status %d", static_cast<unsigned>(config.codec),
            static_cast<unsigned>(config.profile), static_cast<unsigned>(config.format), config.coded_size.width, config.coded_size.height,
            static_cast<int>(status));
        return false;
    }

    GST_DEBUG_OBJECT(self, "CDM decoder initialised for codec %u profile %u format %u %dx%d", static_cast<unsigned>(config.codec),
        static_cast<unsigned>(config.profile), static_cast<unsigned>(config.format), config.coded_size.width, config.coded_size.height);
    priv->isDecoderInitialized = true;
    return true;
}

static bool ensureOutputState(WebKitExternalCDMVideoDecoder* self, GstVideoFormat format, const cdm::Size& size)
{
    auto* decoder = GST_VIDEO_DECODER(self);
    auto* priv = self->priv;

    GstVideoCodecState* current = gst_video_decoder_get_output_state(decoder);
    bool matches = current && GST_VIDEO_INFO_FORMAT(&current->info) == format
        && GST_VIDEO_INFO_WIDTH(&current->info) == size.width && GST_VIDEO_INFO_HEIGHT(&current->info) == size.height;
    if (current)
        gst_video_codec_state_unref(current);
    if (matches)
        return true;

    GST_DEBUG_OBJECT(self, "output %s %dx%d", gst_video_format_to_string(format), size.width, size.height);
    gst_video_codec_state_unref(gst_video_decoder_set_output_state(decoder, format, size.width, size.height, priv->inputState));
    return gst_video_decoder_negotiate(decoder);
}

static GstVideoCodecFrame* takePendingFrame(WebKitExternalCDMVideoDecoder* self, int64_t timestampUs)
{
    auto* decoder = GST_VIDEO_DECODER(self);
    GstVideoCodecFrame* match = nullptr;
    GList* frames = gst_video_decoder_get_frames(decoder);

    for (GList* item = frames; item; item = item->next) {
        auto* frame = static_cast<GstVideoCodecFrame*>(item->data);
        if (GST_CLOCK_TIME_IS_VALID(frame->pts) && static_cast<int64_t>(GST_TIME_AS_USECONDS(frame->pts)) == timestampUs) {
            match = gst_video_codec_frame_ref(frame);
            break;
        }
    }

    // Pictures come out in presentation order, so a frame presented before the match produced none.
    for (GList* item = frames; match && item; item = item->next) {
        auto* frame = static_cast<GstVideoCodecFrame*>(item->data);
        if (frame == match || !GST_CLOCK_TIME_IS_VALID(frame->pts) || frame->pts >= match->pts)
            continue;
        GST_DEBUG_OBJECT(self, "dropping frame %u, the CDM returned no picture for it", frame->system_frame_number);
        gst_video_decoder_drop_frame(decoder, gst_video_codec_frame_ref(frame));
    }

    g_list_free_full(frames, reinterpret_cast<GDestroyNotify>(gst_video_codec_frame_unref));
    return match;
}

static GstBuffer* wrapCdmBuffer(CdmBufferPtr&& cdmBuffer, media::CdmVideoFrame& cdmFrame, GstVideoFormat format)
{
    gsize offsets[GST_VIDEO_MAX_PLANES] = { cdmFrame.PlaneOffset(cdm::kYPlane), cdmFrame.PlaneOffset(cdm::kUPlane), cdmFrame.PlaneOffset(cdm::kVPlane), 0 };
    gint strides[GST_VIDEO_MAX_PLANES] = {
        static_cast<gint>(cdmFrame.Stride(cdm::kYPlane)), static_cast<gint>(cdmFrame.Stride(cdm::kUPlane)), static_cast<gint>(cdmFrame.Stride(cdm::kVPlane)), 0
    };
    auto size = cdmFrame.Size();
    uint8_t* data = cdmBuffer->Data();
    uint32_t capacity = cdmBuffer->Capacity();

    GstBuffer* buffer = gst_buffer_new_wrapped_full(static_cast<GstMemoryFlags>(0), data, capacity, 0, capacity, cdmBuffer.release(), [](gpointer cdmBuffer) {
        static_cast<cdm::Buffer*>(cdmBuffer)->Destroy();
    });
    gst_buffer_add_video_meta_full(buffer, GST_VIDEO_FRAME_FLAG_NONE, format, size.width, size.height, 3, offsets, strides);
    return buffer;
}

static GstFlowReturn copyToOutputBuffer(WebKitExternalCDMVideoDecoder* self, GstVideoCodecFrame* frame, GstBuffer* source)
{
    auto* decoder = GST_VIDEO_DECODER(self);
    GstVideoCodecState* state = gst_video_decoder_get_output_state(decoder);
    GstFlowReturn ret = gst_video_decoder_allocate_output_frame(decoder, frame);
    GstVideoFrame sourceFrame;
    GstVideoFrame outputFrame;

    if (ret != GST_FLOW_OK) {
        gst_video_codec_state_unref(state);
        return ret;
    }

    if (!gst_video_frame_map(&sourceFrame, &state->info, source, GST_MAP_READ)) {
        gst_video_codec_state_unref(state);
        return GST_FLOW_ERROR;
    }

    if (!gst_video_frame_map(&outputFrame, &state->info, frame->output_buffer, GST_MAP_WRITE)) {
        gst_video_frame_unmap(&sourceFrame);
        gst_video_codec_state_unref(state);
        return GST_FLOW_ERROR;
    }

    bool copied = gst_video_frame_copy(&outputFrame, &sourceFrame);
    gst_video_frame_unmap(&outputFrame);
    gst_video_frame_unmap(&sourceFrame);
    gst_video_codec_state_unref(state);
    return copied ? GST_FLOW_OK : GST_FLOW_ERROR;
}

static GstFlowReturn pushDecodedFrame(WebKitExternalCDMVideoDecoder* self, media::CdmVideoFrame& cdmFrame, CdmBufferPtr&& cdmBuffer)
{
    auto* decoder = GST_VIDEO_DECODER(self);
    GstVideoFormat format = videoFormatFromCdm(cdmFrame.Format());
    auto size = cdmFrame.Size();

    if (!cdmBuffer || format == GST_VIDEO_FORMAT_UNKNOWN || size.width <= 0 || size.height <= 0) {
        GST_ELEMENT_ERROR(self, STREAM, DECODE, ("CDM returned an unusable picture"), ("format %u, %dx%d", static_cast<unsigned>(cdmFrame.Format()), size.width, size.height));
        return GST_FLOW_ERROR;
    }

    GstVideoCodecFrame* frame = takePendingFrame(self, cdmFrame.Timestamp());
    if (!frame) {
        GST_DEBUG_OBJECT(self, "no pending frame for timestamp %" G_GINT64_FORMAT "us", cdmFrame.Timestamp());
        return GST_FLOW_OK;
    }

    if (!ensureOutputState(self, format, size)) {
        gst_video_decoder_drop_frame(decoder, frame);
        return GST_FLOW_NOT_NEGOTIATED;
    }

    GstBuffer* buffer = wrapCdmBuffer(WTF::move(cdmBuffer), cdmFrame, format);
    if (self->priv->canAttachVideoMeta) {
        frame->output_buffer = buffer;
        return gst_video_decoder_finish_frame(decoder, frame);
    }

    GstFlowReturn ret = copyToOutputBuffer(self, frame, buffer);
    gst_buffer_unref(buffer);
    if (ret != GST_FLOW_OK) {
        gst_video_decoder_drop_frame(decoder, frame);
        return ret;
    }
    return gst_video_decoder_finish_frame(decoder, frame);
}

static GstFlowReturn decodeFrame(WebKitExternalCDMVideoDecoder* self, const CDMProxyExternalCDM::cencDecryptContext* input)
{
    auto* priv = self->priv;
    media::CdmVideoFrame cdmFrame;

    cdm::Status status = CDMProxyExternalCDM::decryptAndDecodeVideoFrame(*priv->adapter, input, cdmFrame);
    CdmBufferPtr cdmBuffer(cdmFrame.FrameBuffer());
    GstFlowReturn ret = GST_FLOW_OK;

    switch (status) {
    case cdm::kSuccess:
        return pushDecodedFrame(self, cdmFrame, WTF::move(cdmBuffer));
    case cdm::kNeedMoreData:
        return GST_FLOW_OK;
    case cdm::kNoKey:
        GST_ELEMENT_ERROR(self, STREAM, DECRYPT_NOKEY, ("No key found, decryption failed"), (nullptr));
        return GST_FLOW_CUSTOM_ERROR;
    default:
        GST_VIDEO_DECODER_ERROR(self, 1, STREAM, DECODE, ("CDM failed to decrypt and decode a frame"), ("status %d", static_cast<int>(status)), ret);
        return ret;
    }
}

static GstFlowReturn drainOneFrame(WebKitExternalCDMVideoDecoder* self, bool& isDrained)
{
    media::CdmVideoFrame cdmFrame;

    cdm::Status status = CDMProxyExternalCDM::decryptAndDecodeVideoFrame(*self->priv->adapter, nullptr, cdmFrame);
    CdmBufferPtr cdmBuffer(cdmFrame.FrameBuffer());
    isDrained = status != cdm::kSuccess;
    if (isDrained)
        return GST_FLOW_OK;
    return pushDecodedFrame(self, cdmFrame, WTF::move(cdmBuffer));
}

static GstFlowReturn drainFrames(WebKitExternalCDMVideoDecoder* self)
{
    auto* priv = self->priv;
    GstFlowReturn ret = GST_FLOW_OK;
    bool isDrained = false;

    if (!priv->adapter || !priv->isDecoderInitialized)
        return GST_FLOW_OK;

    while (!isDrained && ret == GST_FLOW_OK)
        ret = drainOneFrame(self, isDrained);
    return ret;
}

static GstFlowReturn handleFrame(GstVideoDecoder* decoder, GstVideoCodecFrame* frame)
{
    auto* self = WEBKIT_EXTERNAL_CDM_VIDEO_DECODER(decoder);
    auto* priv = self->priv;

    RefPtr cdmProxy = waitForCDMProxy(self);
    if (!cdmProxy) {
        gst_video_decoder_release_frame(decoder, frame);
        if (priv->client->isAborting())
            return GST_FLOW_FLUSHING;
        GST_ELEMENT_ERROR(self, STREAM, FAILED, ("CDMProxy was not retrieved in time"), (nullptr));
        return GST_FLOW_NOT_SUPPORTED;
    }

    WebKitMediaCommonEncryptionSampleInfo sampleInfo;
    if (auto* protectionMeta = reinterpret_cast<GstProtectionMeta*>(gst_buffer_get_protection_meta(frame->input_buffer))) {
        if (!webKitMediaCommonEncryptionParseProtectionMeta(GST_ELEMENT_CAST(self), protectionMeta, sampleInfo)) {
            gst_video_decoder_release_frame(decoder, frame);
            return GST_FLOW_NOT_SUPPORTED;
        }
    }

    WebKitExternalCDMDecryptInput input;
    if (!input.map(GST_ELEMENT_CAST(self), frame->input_buffer, GST_MAP_READ, sampleInfo)) {
        gst_video_decoder_release_frame(decoder, frame);
        GST_ELEMENT_ERROR(self, STREAM, DECODE, ("Failed to map the input frame"), (nullptr));
        return GST_FLOW_ERROR;
    }
    input.context.cdmProxyDecryptionClient = WeakPtr { *priv->client, EnableWeakPtrThreadingAssertions::No };

    Vector<uint8_t> annexBSample;
    Vector<uint8_t> annexBSubsamples;
    if (priv->isAvc && !h264SampleToAnnexB(self, GST_VIDEO_CODEC_FRAME_IS_SYNC_POINT(frame), input.context, annexBSample, annexBSubsamples)) {
        GstFlowReturn ret = GST_FLOW_OK;
        gst_video_decoder_drop_frame(decoder, frame);
        GST_VIDEO_DECODER_ERROR(self, 1, STREAM, DECODE, ("Malformed H.264 sample"), (nullptr), ret);
        return ret;
    }

    DecryptionResult result;
    auto adapter = cdmProxy->getOrWaitForVideoAdapter(input.context, result);
    if (!adapter) {
        gst_video_decoder_release_frame(decoder, frame);
        if (priv->client->isAborting())
            return GST_FLOW_FLUSHING;
        if (result == DecryptionResult::NoKey) {
            GST_ELEMENT_ERROR(self, STREAM, DECRYPT_NOKEY, ("No key found, decryption failed"), (nullptr));
            return GST_FLOW_CUSTOM_ERROR;
        }
        GST_ELEMENT_ERROR(self, STREAM, DECRYPT, ("No CDM to decode the frame with"), (nullptr));
        return GST_FLOW_ERROR;
    }

    if (!ensureDecoder(self, WTF::move(adapter))) {
        gst_video_decoder_release_frame(decoder, frame);
        GST_ELEMENT_ERROR(self, STREAM, CODEC_NOT_FOUND, ("The CDM cannot decode this stream"), (nullptr));
        return GST_FLOW_NOT_NEGOTIATED;
    }

    gst_video_codec_frame_unref(frame);
    return decodeFrame(self, &input.context);
}

static gboolean setFormat(GstVideoDecoder* decoder, GstVideoCodecState* state)
{
    auto* self = WEBKIT_EXTERNAL_CDM_VIDEO_DECODER(decoder);
    auto* priv = self->priv;
    auto* structure = gst_caps_get_structure(state->caps, 0);
    cdm::VideoDecoderConfig_3 config { };

    if (!videoCodecFromCaps(structure, config)) {
        GST_WARNING_OBJECT(self, "cannot decode %" GST_PTR_FORMAT, state->caps);
        return FALSE;
    }

    config.format = videoFormatFromCaps(structure);
    config.color_space = { 2, 2, 2, cdm::ColorRange::kInvalid };
    config.coded_size = { gstStructureGet<int>(structure, "width"_s).value_or(0), gstStructureGet<int>(structure, "height"_s).value_or(0) };
    config.encryption_scheme = priv->encryptionScheme;

    Vector<uint8_t> h264ParameterSets;
    bool isAvc = config.codec == cdm::kCodecH264 && gstStructureGetString(structure, "stream-format"_s) == "avc"_s;
    if (isAvc && !h264ParameterSetsFromCodecData(structure, h264ParameterSets)) {
        GST_WARNING_OBJECT(self, "unusable avcC in %" GST_PTR_FORMAT, state->caps);
        return FALSE;
    }

    GST_DEBUG_OBJECT(self, "input %" GST_PTR_FORMAT, state->caps);

    if (priv->isDecoderInitialized) {
        drainFrames(self);
        deinitializeDecoder(self);
    }

    priv->config = config;
    priv->isAvc = isAvc;
    priv->h264ParameterSets = WTF::move(h264ParameterSets);
    if (priv->inputState)
        gst_video_codec_state_unref(priv->inputState);
    priv->inputState = gst_video_codec_state_ref(state);
    return TRUE;
}

static gboolean decideAllocation(GstVideoDecoder* decoder, GstQuery* query)
{
    auto* self = WEBKIT_EXTERNAL_CDM_VIDEO_DECODER(decoder);

    self->priv->canAttachVideoMeta = gst_query_find_allocation_meta(query, GST_VIDEO_META_API_TYPE, nullptr);
    GST_DEBUG_OBJECT(self, "downstream %s video meta", self->priv->canAttachVideoMeta ? "supports" : "does not support");
    return GST_VIDEO_DECODER_CLASS(webkit_external_cdm_video_decoder_parent_class)->decide_allocation(decoder, query);
}

static gboolean flush(GstVideoDecoder* decoder)
{
    auto* self = WEBKIT_EXTERNAL_CDM_VIDEO_DECODER(decoder);
    auto* priv = self->priv;

    if (priv->adapter && priv->isDecoderInitialized)
        priv->adapter->ResetDecoder(cdm::kStreamTypeVideo);
    return TRUE;
}

static GstFlowReturn finish(GstVideoDecoder* decoder)
{
    return drainFrames(WEBKIT_EXTERNAL_CDM_VIDEO_DECODER(decoder));
}

static gboolean stop(GstVideoDecoder* decoder)
{
    auto* self = WEBKIT_EXTERNAL_CDM_VIDEO_DECODER(decoder);
    auto* priv = self->priv;

    deinitializeDecoder(self);
    priv->adapter = nullptr;
    if (priv->inputState) {
        gst_video_codec_state_unref(priv->inputState);
        priv->inputState = nullptr;
    }
    return TRUE;
}

// GstVideoDecoder only takes video/ or image/ caps, so it gets the media type the encrypted caps carry.
static GstEvent* decodableCapsEvent(WebKitExternalCDMVideoDecoder* self, GstEvent* event)
{
    GstCaps* caps;
    gst_event_parse_caps(event, &caps);

    GRefPtr<GstCaps> decodableCaps = adoptGRef(gst_caps_copy(caps));
    auto* structure = gst_caps_get_structure(decodableCaps.get(), 0);
    auto cipherMode = gstStructureGetString(structure, "cipher-mode"_s);
    self->priv->encryptionScheme = cipherMode == "cbcs"_s ? cdm::EncryptionScheme::kCbcs : cdm::EncryptionScheme::kCenc;
    webKitMediaCommonEncryptionStripProtection(structure);

    GstEvent* decodableEvent = gst_event_new_caps(decodableCaps.get());
    gst_event_set_seqnum(decodableEvent, gst_event_get_seqnum(event));
    gst_event_unref(event);
    return decodableEvent;
}

static gboolean sinkEvent(GstVideoDecoder* decoder, GstEvent* event)
{
    auto* self = WEBKIT_EXTERNAL_CDM_VIDEO_DECODER(decoder);
    auto* priv = self->priv;

    switch (GST_EVENT_TYPE(event)) {
    case GST_EVENT_CAPS:
        event = decodableCapsEvent(self, event);
        break;
    case GST_EVENT_CUSTOM_DOWNSTREAM_OOB:
        if (gst_event_has_name(event, "attempt-to-decrypt")) {
            attachCDMProxyFromContext(self);
            gst_event_unref(event);
            return TRUE;
        }
        break;
    case GST_EVENT_FLUSH_START: {
        {
            Locker locker { priv->lock };
            priv->isFlushing = true;
        }
        abortWaits(self);
        break;
    }
    case GST_EVENT_FLUSH_STOP: {
        Locker locker { priv->lock };
        priv->isFlushing = false;
        break;
    }
    default:
        break;
    }

    return GST_VIDEO_DECODER_CLASS(webkit_external_cdm_video_decoder_parent_class)->sink_event(decoder, event);
}

static GstStateChangeReturn changeState(GstElement* element, GstStateChange transition)
{
    auto* self = WEBKIT_EXTERNAL_CDM_VIDEO_DECODER(element);
    auto* priv = self->priv;

    switch (transition) {
    case GST_STATE_CHANGE_READY_TO_PAUSED: {
        Locker locker { priv->lock };
        priv->isStopped = false;
        break;
    }
    case GST_STATE_CHANGE_PAUSED_TO_READY: {
        {
            Locker locker { priv->lock };
            priv->isStopped = true;
        }
        abortWaits(self);
        break;
    }
    default:
        break;
    }

    return GST_ELEMENT_CLASS(webkit_external_cdm_video_decoder_parent_class)->change_state(element, transition);
}

static void setContext(GstElement* element, GstContext* context)
{
    GST_ELEMENT_CLASS(webkit_external_cdm_video_decoder_parent_class)->set_context(element, context);

    if (gst_context_has_context_type(context, "drm-cdm-proxy"))
        attachCDMProxyFromContext(WEBKIT_EXTERNAL_CDM_VIDEO_DECODER(element));
}

static void constructed(GObject* object)
{
    G_OBJECT_CLASS(webkit_external_cdm_video_decoder_parent_class)->constructed(object);

    auto* self = WEBKIT_EXTERNAL_CDM_VIDEO_DECODER(object);
    self->priv->client = makeUnique<ExternalCDMVideoDecoderClient>(self);
    gst_video_decoder_set_packetized(GST_VIDEO_DECODER(self), TRUE);
    gst_video_decoder_set_needs_format(GST_VIDEO_DECODER(self), TRUE);
}

static void webkit_external_cdm_video_decoder_class_init(WebKitExternalCDMVideoDecoderClass* klass)
{
    GST_DEBUG_CATEGORY_INIT(webkitExternalCDMVideoDecoderDebugCategory, "webkitexternalcdmvideodec", 0, "external CDM video decoder");

    G_OBJECT_CLASS(klass)->constructed = constructed;

    GstElementClass* elementClass = GST_ELEMENT_CLASS(klass);
    elementClass->change_state = GST_DEBUG_FUNCPTR(changeState);
    elementClass->set_context = GST_DEBUG_FUNCPTR(setContext);

    GRefPtr<GstCaps> sinkCaps = createSinkPadTemplateCaps();
    gst_element_class_add_pad_template(elementClass, gst_pad_template_new("sink", GST_PAD_SINK, GST_PAD_ALWAYS, sinkCaps.get()));
    gst_element_class_add_static_pad_template(elementClass, &externalCDMVideoDecoderSrcTemplate);
    gst_element_class_set_static_metadata(elementClass, "Decrypt and decode video in an external CDM", "Codec/Decoder/Video",
        "Decrypts and decodes encrypted video inside an external W3C CDM.", "Daniel Golle <daniel@makrotopia.org>");

    GstVideoDecoderClass* decoderClass = GST_VIDEO_DECODER_CLASS(klass);
    decoderClass->stop = GST_DEBUG_FUNCPTR(stop);
    decoderClass->set_format = GST_DEBUG_FUNCPTR(setFormat);
    decoderClass->handle_frame = GST_DEBUG_FUNCPTR(handleFrame);
    decoderClass->flush = GST_DEBUG_FUNCPTR(flush);
    decoderClass->finish = GST_DEBUG_FUNCPTR(finish);
    decoderClass->drain = GST_DEBUG_FUNCPTR(finish);
    decoderClass->decide_allocation = GST_DEBUG_FUNCPTR(decideAllocation);
    decoderClass->sink_event = GST_DEBUG_FUNCPTR(sinkEvent);
}

#undef GST_CAT_DEFAULT

#endif // ENABLE(ENCRYPTED_MEDIA) && ENABLE(EXTERNAL_CDM) && USE(GSTREAMER)
