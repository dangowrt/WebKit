/*
 * Copyright (C) 2024 Igalia S.L.
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
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "CoordinatedPlatformLayerBufferDMABuf.h"

#if USE(COORDINATED_GRAPHICS) && USE(TEXTURE_MAPPER) && USE(GBM)
#include "BitmapTexturePool.h"
#include "CoordinatedPlatformLayerBufferExternalOES.h"
#include "CoordinatedPlatformLayerBufferRGB.h"
#include "CoordinatedPlatformLayerBufferYUV.h"
#include "DMABufBuffer.h"
#include "GLContext.h"
#include "GLFence.h"
#include "PlatformDisplay.h"
#include "TextureMapper.h"
#include <drm_fourcc.h>
#include <epoxy/egl.h>
#include <epoxy/gl.h>
#include <wtf/HashMap.h>
#include <wtf/NeverDestroyed.h>
#include <wtf/ThreadSafeRefCounted.h>

namespace WebCore {

std::unique_ptr<CoordinatedPlatformLayerBufferDMABuf> CoordinatedPlatformLayerBufferDMABuf::create(Ref<DMABufBuffer>&& dmabuf, OptionSet<TextureMapperFlags> flags, std::unique_ptr<GLFence>&& fence)
{
    return makeUnique<CoordinatedPlatformLayerBufferDMABuf>(WTF::move(dmabuf), flags, WTF::move(fence));
}

std::unique_ptr<CoordinatedPlatformLayerBufferDMABuf> CoordinatedPlatformLayerBufferDMABuf::create(Ref<DMABufBuffer>&& dmabuf, OptionSet<TextureMapperFlags> flags, UnixFileDescriptor&& fenceFD)
{
    return makeUnique<CoordinatedPlatformLayerBufferDMABuf>(WTF::move(dmabuf), flags, WTF::move(fenceFD));
}

CoordinatedPlatformLayerBufferDMABuf::CoordinatedPlatformLayerBufferDMABuf(Ref<DMABufBuffer>&& dmabuf, OptionSet<TextureMapperFlags> flags, std::unique_ptr<GLFence>&& fence)
    : CoordinatedPlatformLayerBuffer(Type::DMABuf, dmabuf->attributes().size, flags, WTF::move(fence))
    , m_dmabuf(WTF::move(dmabuf))
{
}

CoordinatedPlatformLayerBufferDMABuf::CoordinatedPlatformLayerBufferDMABuf(Ref<DMABufBuffer>&& dmabuf, OptionSet<TextureMapperFlags> flags, UnixFileDescriptor&& fenceFD)
    : CoordinatedPlatformLayerBuffer(Type::DMABuf, dmabuf->attributes().size, flags, nullptr)
    , m_dmabuf(WTF::move(dmabuf))
    , m_fenceFD(WTF::move(fenceFD))
{
}

CoordinatedPlatformLayerBufferDMABuf::~CoordinatedPlatformLayerBufferDMABuf() = default;

static RefPtr<BitmapTexture> importToTexture(const IntSize& textureSize, const DMABufBuffer::Attributes& dmaBufAttributes, OptionSet<BitmapTexture::Flags> textureFlags, std::optional<DMABufBuffer::ColorSpace> colorSpace = std::nullopt, std::optional<DMABufBuffer::SampleRange> sampleRange = std::nullopt)
{
    auto& display = PlatformDisplay::sharedDisplay();
    EGLImage image = EGL_NO_IMAGE;
    if (colorSpace && sampleRange) {
        textureFlags.add(BitmapTexture::Flags::ExternalOESRenderTarget);
#if USE(GSTREAMER)
        image = DMABufBuffer::createEGLImageForQualcommVideoFrame(display.glDisplay(), dmaBufAttributes, *colorSpace, *sampleRange);
#endif
    } else
        image = DMABufBuffer::createEGLImage(display.glDisplay(), dmaBufAttributes);
    if (!image)
        return nullptr;

    auto texture = BitmapTexturePool::singleton().createTextureForImage(image, textureSize, textureFlags);
    display.destroyEGLImage(image);
    return texture;
}

static bool formatIsYUV(uint32_t fourcc)
{
    switch (fourcc) {
    case DRM_FORMAT_YUV420:
    case DRM_FORMAT_YVU420:
    case DRM_FORMAT_NV12:
    case DRM_FORMAT_NV21:
    case DRM_FORMAT_YUV444:
    case DRM_FORMAT_YUV411:
    case DRM_FORMAT_YUV422:
    case DRM_FORMAT_AYUV:
    case DRM_FORMAT_P010:
        return true;
    }

    return false;
}

struct YUVPlaneInfo {
    uint32_t fourcc;
    unsigned index;
    unsigned offset;
    IntSize subsampling;
};

static const HashMap<uint32_t, Vector<YUVPlaneInfo>>& yuvFormatPlaneInfo()
{
    static NeverDestroyed<HashMap<uint32_t, Vector<YUVPlaneInfo>>> yuvFormatsMap = [] {
        HashMap<uint32_t, Vector<YUVPlaneInfo>> map;
        // 1 plane formats.
        map.set(DRM_FORMAT_AYUV, Vector<YUVPlaneInfo> {
            { DRM_FORMAT_ABGR8888, 0, 0, { 1, 1 } },
        });

        // 2 plane formats.
        map.set(DRM_FORMAT_NV12, Vector<YUVPlaneInfo> {
            { DRM_FORMAT_R8, 0, 0, { 1, 1 } },
            { DRM_FORMAT_GR88, 1, 0, { 2, 2 } },
        });
        map.set(DRM_FORMAT_NV21, Vector<YUVPlaneInfo> {
            { DRM_FORMAT_R8, 0, 0, { 1, 1 } },
            { DRM_FORMAT_GR88, 1, 1, { 2, 2 } },
        });
        map.set(DRM_FORMAT_P010, Vector<YUVPlaneInfo> {
            { DRM_FORMAT_R16, 0, 0, { 1, 1 } },
            { DRM_FORMAT_GR1616, 1, 0, { 2, 2 } },
        });

        // 3 plane formats.
        map.set(DRM_FORMAT_YUV420, Vector<YUVPlaneInfo> {
            { DRM_FORMAT_R8, 0, 0, { 1, 1 } },
            { DRM_FORMAT_R8, 1, 0, { 2, 2 } },
            { DRM_FORMAT_R8, 2, 0, { 2, 2 } },
        });
        map.set(DRM_FORMAT_YVU420, Vector<YUVPlaneInfo> {
            { DRM_FORMAT_R8, 0, 0, { 1, 1 } },
            { DRM_FORMAT_R8, 2, 0, { 2, 2 } },
            { DRM_FORMAT_R8, 1, 0, { 2, 2 } },
        });
        map.set(DRM_FORMAT_YUV444, Vector<YUVPlaneInfo> {
            { DRM_FORMAT_R8, 0, 0, { 1, 1 } },
            { DRM_FORMAT_R8, 1, 0, { 1, 1 } },
            { DRM_FORMAT_R8, 2, 0, { 1, 1 } },
        });
        map.set(DRM_FORMAT_YUV411, Vector<YUVPlaneInfo> {
            { DRM_FORMAT_R8, 0, 0, { 1, 1 } },
            { DRM_FORMAT_R8, 1, 0, { 4, 1 } },
            { DRM_FORMAT_R8, 2, 0, { 4, 1 } },
        });
        map.set(DRM_FORMAT_YUV422, Vector<YUVPlaneInfo> {
            { DRM_FORMAT_R8, 0, 0, { 1, 1 } },
            { DRM_FORMAT_R8, 1, 0, { 2, 1 } },
            { DRM_FORMAT_R8, 2, 0, { 2, 1 } },
        });
        return map;
    }();
    return yuvFormatsMap;
}

static CoordinatedPlatformLayerBufferYUV::Format yuvFormatFromDRMFourcc(uint32_t fourcc)
{
    switch (fourcc) {
    case DRM_FORMAT_AYUV:
        return CoordinatedPlatformLayerBufferYUV::Format::AYUV;
    case DRM_FORMAT_NV12:
        return CoordinatedPlatformLayerBufferYUV::Format::NV12;
    case DRM_FORMAT_NV21:
        return CoordinatedPlatformLayerBufferYUV::Format::NV21;
    case DRM_FORMAT_P010:
        return CoordinatedPlatformLayerBufferYUV::Format::P010;
    case DRM_FORMAT_YUV420:
        return CoordinatedPlatformLayerBufferYUV::Format::YUV420;
    case DRM_FORMAT_YVU420:
        return CoordinatedPlatformLayerBufferYUV::Format::YVU420;
    case DRM_FORMAT_YUV444:
        return CoordinatedPlatformLayerBufferYUV::Format::YUV444;
    case DRM_FORMAT_YUV411:
        return CoordinatedPlatformLayerBufferYUV::Format::YUV411;
    case DRM_FORMAT_YUV422:
        return CoordinatedPlatformLayerBufferYUV::Format::YUV422;
    }
    RELEASE_ASSERT_NOT_REACHED();
}

static std::unique_ptr<CoordinatedPlatformLayerBuffer> importYUV(const Ref<DMABufBuffer>& dmabuf, OptionSet<TextureMapperFlags> flags)
{
    OptionSet<BitmapTexture::Flags> textureFlags;
    if (flags.contains(TextureMapperFlags::ShouldBlend))
        textureFlags.add(BitmapTexture::Flags::SupportsAlpha);

    Vector<RefPtr<BitmapTexture>, 4> textures;
    std::array<unsigned, 4> yuvPlane;
    std::array<unsigned, 4> yuvPlaneOffset;

    const auto& attributes = dmabuf->attributes();
    const auto& iter = yuvFormatPlaneInfo().find(attributes.fourcc.value);
    if (iter == yuvFormatPlaneInfo().end())
        return nullptr;

    const auto& planeInfo = iter->value;
    for (unsigned i = 0; i < planeInfo.size(); ++i) {
        const auto& plane = planeInfo[i];
        IntSize adjustedSize { attributes.size.width() / plane.subsampling.width(), attributes.size.height() / plane.subsampling.height() };
        auto planeFds = Vector<UnixFileDescriptor>::from(attributes.fds[i].borrow());
        DMABufBuffer::Attributes planeAttributes { adjustedSize, plane.fourcc, WTF::move(planeFds), { attributes.offsets[i] }, { attributes.strides[i] }, attributes.modifier };
        auto texture = importToTexture(attributes.size, planeAttributes, textureFlags);
        if (!texture)
            return nullptr;
        textures.append(WTF::move(texture));
        yuvPlane[i] = plane.index;
        yuvPlaneOffset[i] = plane.offset;
    }

    if (textures.isEmpty())
        return nullptr;

    auto format = yuvFormatFromDRMFourcc(attributes.fourcc.value);

    CoordinatedPlatformLayerBufferYUV::YuvToRgbColorSpace yuvToRgbColorSpace;
    switch (dmabuf->colorSpace().value_or(DMABufBuffer::ColorSpace::Bt601)) {
    case DMABufBuffer::ColorSpace::Bt601:
        yuvToRgbColorSpace = CoordinatedPlatformLayerBufferYUV::YuvToRgbColorSpace::Bt601;
        break;
    case DMABufBuffer::ColorSpace::Bt709:
        yuvToRgbColorSpace = CoordinatedPlatformLayerBufferYUV::YuvToRgbColorSpace::Bt709;
        break;
    case DMABufBuffer::ColorSpace::Bt2020:
        yuvToRgbColorSpace = CoordinatedPlatformLayerBufferYUV::YuvToRgbColorSpace::Bt2020;
        break;
    case DMABufBuffer::ColorSpace::Smpte240M:
        yuvToRgbColorSpace = CoordinatedPlatformLayerBufferYUV::YuvToRgbColorSpace::Smpte240M;
        break;
    }

    CoordinatedPlatformLayerBufferYUV::TransferFunction transferFunction;
    switch (dmabuf->transferFunction().value_or(DMABufBuffer::TransferFunction::Bt709)) {
    case DMABufBuffer::TransferFunction::Bt709:
        transferFunction = CoordinatedPlatformLayerBufferYUV::TransferFunction::Bt709;
        break;
    case DMABufBuffer::TransferFunction::Pq:
        transferFunction = CoordinatedPlatformLayerBufferYUV::TransferFunction::Pq;
        break;
    }

    unsigned numberOfPlanes = textures.size();
    return CoordinatedPlatformLayerBufferYUV::create(format, numberOfPlanes, WTF::move(textures), WTF::move(yuvPlane), WTF::move(yuvPlaneOffset),
        yuvToRgbColorSpace, transferFunction, attributes.size, flags, nullptr);
}

#if USE(GSTREAMER)
static bool formatSupportsSingleImageImport(const DMABufBuffer::Attributes& attributes)
{
    // Limited to NV12, the format reported and exercised on this path. The gate
    // is per-format so NV21 and P010 can be added once each is verified.
    if (attributes.fourcc.value != DRM_FORMAT_NV12)
        return false;

    // A stable per-display capability: the frame's format and modifier must be
    // one the platform advertises for video. This decides the import path
    // uniformly for every frame of this format, not per frame.
    const auto& formats = PlatformDisplay::sharedDisplay().glDisplay().bufferFormatsForVideo();
    for (const auto& format : formats) {
        if (format.fourcc.value != attributes.fourcc.value)
            continue;
        return format.modifiers.contains(attributes.modifier)
            || format.modifiers.contains(static_cast<uint64_t>(DRM_FORMAT_MOD_INVALID))
            || attributes.modifier == DRM_FORMAT_MOD_INVALID;
    }
    return false;
}

static std::unique_ptr<CoordinatedPlatformLayerBuffer> importSingleImageYUV(const Ref<DMABufBuffer>& dmabuf, OptionSet<TextureMapperFlags> flags)
{
    const auto& attributes = dmabuf->attributes();
    if (!formatSupportsSingleImageImport(attributes))
        return nullptr;

    // The driver converts YUV to RGB from the EGL colour space and sample range
    // hints, so the colour space must be one EGL can express. EGL has no token
    // for SMPTE240M, so leave that to the per-plane path. NARROW matches the
    // limited-range matrices the per-plane shader applies.
    auto colorSpace = dmabuf->colorSpace().value_or(DMABufBuffer::ColorSpace::Bt601);
    if (colorSpace == DMABufBuffer::ColorSpace::Smpte240M)
        return nullptr;

    OptionSet<BitmapTexture::Flags> textureFlags;
    if (flags.contains(TextureMapperFlags::ShouldBlend))
        textureFlags.add(BitmapTexture::Flags::SupportsAlpha);

    auto texture = importToTexture(attributes.size, attributes, textureFlags, colorSpace, DMABufBuffer::SampleRange::Narrow);
    if (!texture)
        return nullptr;

    return CoordinatedPlatformLayerBufferExternalOES::create(texture.releaseNonNull(), flags, nullptr);
}
#endif // USE(GSTREAMER)

std::unique_ptr<CoordinatedPlatformLayerBuffer> CoordinatedPlatformLayerBufferDMABuf::importDMABuf() const
{
    bool importWithHints = m_dmabuf->colorSpace() && m_dmabuf->sampleRange();
    const auto& attributes = m_dmabuf->attributes();
    if (!importWithHints && formatIsYUV(attributes.fourcc.value)) {
#if USE(GSTREAMER)
        // Import an NV12 frame the platform advertises as a single multiplanar
        // image sampled through GL_TEXTURE_EXTERNAL_OES, uniformly for every
        // such frame. A lone per-plane R8/GR88 image is held to a stricter row
        // alignment than a multiplanar NV12 image (64 against 16 bytes on
        // panfrost), which rejects otherwise-valid non-64-aligned strides.
        if (auto buffer = importSingleImageYUV(m_dmabuf, m_flags))
            return buffer;
#endif
        return importYUV(m_dmabuf, m_flags);
    }

    OptionSet<BitmapTexture::Flags> textureFlags;
    if (m_flags.contains(TextureMapperFlags::ShouldBlend))
        textureFlags.add(BitmapTexture::Flags::SupportsAlpha);
    auto texture = importToTexture(attributes.size, attributes, textureFlags, m_dmabuf->colorSpace(), m_dmabuf->sampleRange());
    if (!texture)
        return nullptr;

    if (importWithHints)
        return CoordinatedPlatformLayerBufferExternalOES::create(texture.releaseNonNull(), m_flags, nullptr);
    return CoordinatedPlatformLayerBufferRGB::create(texture.releaseNonNull(), m_flags, nullptr);
}

void CoordinatedPlatformLayerBufferDMABuf::paintToTextureMapper(TextureMapper& textureMapper, const FloatRect& targetRect, const TransformationMatrix& modelViewMatrix, float opacity)
{
    waitForContentsIfNeeded();

    if (m_fenceFD) {
        if (auto fence = GLFence::importFD(PlatformDisplay::sharedDisplay().glDisplay(), WTF::move(m_fenceFD)))
            fence->serverWait();
    }

    if (!m_dmabuf->buffer())
        m_dmabuf->setBuffer(importDMABuf());

    if (auto* buffer = m_dmabuf->buffer())
        buffer->paintToTextureMapper(textureMapper, targetRect, modelViewMatrix, opacity);
}

} // namespace WebCore

#endif // USE(COORDINATED_GRAPHICS) && USE(TEXTURE_MAPPER) && USE(GBM)
