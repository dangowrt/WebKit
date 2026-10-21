/*
 * Copyright (C) 2020 Metrological Group B.V.
 * Copyright (C) 2020 Igalia S.L.
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

#include <wtf/BoxPtr.h>

namespace WebCore {

// Opaque handle to a session living inside an external Chromium CDM. The
// decryptor holds this (by key id, through the shared key store) so it can
// reach the CDM to decrypt; the key bytes never leave the CDM. The full type
// is defined in the GStreamer external-CDM backend, so this header carries only
// what the KeyHandleValueVariant needs, mirroring CDMOpenCDMTypes.h.
class ExternalCdmSession;
void externalCdmSessionDestroy(ExternalCdmSession*);

} // namespace WebCore

namespace WTF {

WTF_DEFINE_BOXPTR_DELETER(WebCore::ExternalCdmSession, WebCore::externalCdmSessionDestroy)

} // namespace WTF

#endif // ENABLE(ENCRYPTED_MEDIA) && ENABLE(EXTERNAL_CDM)
