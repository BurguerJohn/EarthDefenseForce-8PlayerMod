#include "steam_interfaces.h"

#include "logger.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <unordered_map>

namespace steam_capture {
namespace {

using Request = uint32_t;
using Cookie = uint32_t;
using ApiCall = uint64_t;

using CreateRequestFn = Request (*)(void*, int, const char*);
using SetContextFn = bool (*)(void*, Request, uint64_t);
using SetTimeoutFn = bool (*)(void*, Request, uint32_t);
using SetStringPairFn = bool (*)(void*, Request, const char*, const char*);
using SendRequestFn = bool (*)(void*, Request, ApiCall*);
using RequestBoolFn = bool (*)(void*, Request);
using GetHeaderSizeFn = bool (*)(void*, Request, const char*, uint32_t*);
using GetHeaderFn = bool (*)(void*, Request, const char*, uint8_t*, uint32_t);
using GetBodySizeFn = bool (*)(void*, Request, uint32_t*);
using GetBodyFn = bool (*)(void*, Request, uint8_t*, uint32_t);
using GetStreamingFn = bool (*)(void*, Request, uint32_t, uint8_t*, uint32_t);
using GetProgressFn = bool (*)(void*, Request, float*);
using SetRawBodyFn = bool (*)(void*, Request, const char*, uint8_t*, uint32_t);
using CreateCookieFn = Cookie (*)(void*, bool);
using ReleaseCookieFn = bool (*)(void*, Cookie);
using SetCookieFn = bool (*)(void*, Cookie, const char*, const char*, const char*);
using SetCookieContainerFn = bool (*)(void*, Request, Cookie);
using SetRequestStringFn = bool (*)(void*, Request, const char*);
using SetRequestBoolFn = bool (*)(void*, Request, bool);
using WasTimedOutFn = bool (*)(void*, Request, bool*);

CreateRequestFn o_create_request;
SetContextFn o_set_context;
SetTimeoutFn o_set_network_timeout;
SetStringPairFn o_set_header;
SetStringPairFn o_set_parameter;
SendRequestFn o_send_request;
SendRequestFn o_send_streaming;
RequestBoolFn o_defer;
RequestBoolFn o_prioritize;
GetHeaderSizeFn o_get_header_size;
GetHeaderFn o_get_header;
GetBodySizeFn o_get_body_size;
GetBodyFn o_get_body;
GetStreamingFn o_get_streaming;
RequestBoolFn o_release_request;
GetProgressFn o_get_progress;
SetRawBodyFn o_set_raw_body;
CreateCookieFn o_create_cookie;
ReleaseCookieFn o_release_cookie;
SetCookieFn o_set_cookie;
SetCookieContainerFn o_set_cookie_container;
SetRequestStringFn o_set_user_agent;
SetRequestBoolFn o_require_certificate;
SetTimeoutFn o_set_absolute_timeout;
WasTimedOutFn o_was_timed_out;

SRWLOCK g_http_lock = SRWLOCK_INIT;
void* g_http_interface = nullptr;
void* g_http_vtable[25]{};
std::unordered_map<Request, uint32_t>& BodySizes() {
    static auto* map = new std::unordered_map<Request, uint32_t>();
    return *map;
}

std::unordered_map<Request, std::string>& Urls() {
    static auto* map = new std::unordered_map<Request, std::string>();
    return *map;
}

std::string RequestUrl(Request request) {
    std::string value;
    AcquireSRWLockShared(&g_http_lock);
    const auto found = Urls().find(request);
    if (found != Urls().end()) value = found->second;
    ReleaseSRWLockShared(&g_http_lock);
    return value;
}

Request CreateRequest(void* self, int method, const char* url) {
    const Request result = o_create_request(self, method, url);
    AcquireSRWLockExclusive(&g_http_lock);
    if (result) Urls()[result] = url ? url : "";
    ReleaseSRWLockExclusive(&g_http_lock);
    EDF5_CAPTURE_EVENT("steam_http", "create_request",
                   capture::Fields().UInt("request", result).Int("method", method).String("url", url));
    return result;
}

bool SetContext(void* self, Request request, uint64_t context) {
    const bool result = o_set_context(self, request, context);
    EDF5_CAPTURE_EVENT("steam_http", "set_context",
                   capture::Fields().UInt("request", request).String("url", RequestUrl(request))
                       .UInt("context", context).Bool("result", result));
    return result;
}

bool SetNetworkTimeout(void* self, Request request, uint32_t seconds) {
    const bool result = o_set_network_timeout(self, request, seconds);
    EDF5_CAPTURE_EVENT("steam_http", "set_network_timeout",
                   capture::Fields().UInt("request", request).String("url", RequestUrl(request))
                       .UInt("seconds", seconds).Bool("result", result));
    return result;
}

bool SetHeader(void* self, Request request, const char* name, const char* value) {
    const bool result = o_set_header(self, request, name, value);
    EDF5_CAPTURE_EVENT("steam_http", "set_request_header",
                   capture::Fields().UInt("request", request).String("url", RequestUrl(request))
                       .String("name", name).String("value", value).Bool("result", result));
    return result;
}

bool SetParameter(void* self, Request request, const char* name, const char* value) {
    const bool result = o_set_parameter(self, request, name, value);
    EDF5_CAPTURE_EVENT("steam_http", "set_request_parameter",
                   capture::Fields().UInt("request", request).String("url", RequestUrl(request))
                       .String("name", name).String("value", value).Bool("result", result));
    return result;
}

bool SendRequest(void* self, Request request, ApiCall* call) {
    const bool result = o_send_request(self, request, call);
    EDF5_CAPTURE_EVENT("steam_http", "send_request",
                   capture::Fields().String("direction", "out").UInt("request", request)
                       .String("url", RequestUrl(request)).UInt("api_call", call ? *call : 0)
                       .Bool("result", result));
    return result;
}

bool SendStreaming(void* self, Request request, ApiCall* call) {
    const bool result = o_send_streaming(self, request, call);
    EDF5_CAPTURE_EVENT("steam_http", "send_streaming_request",
                   capture::Fields().String("direction", "out").UInt("request", request)
                       .String("url", RequestUrl(request)).UInt("api_call", call ? *call : 0)
                       .Bool("result", result));
    return result;
}

bool Defer(void* self, Request request) {
    const bool result = o_defer(self, request);
    EDF5_CAPTURE_EVENT("steam_http", "defer_request",
                   capture::Fields().UInt("request", request).String("url", RequestUrl(request))
                       .Bool("result", result));
    return result;
}

bool Prioritize(void* self, Request request) {
    const bool result = o_prioritize(self, request);
    EDF5_CAPTURE_EVENT("steam_http", "prioritize_request",
                   capture::Fields().UInt("request", request).String("url", RequestUrl(request))
                       .Bool("result", result));
    return result;
}

bool GetHeaderSize(void* self, Request request, const char* name, uint32_t* size) {
    const bool result = o_get_header_size(self, request, name, size);
    EDF5_CAPTURE_EVENT("steam_http", "get_response_header_size",
                   capture::Fields().UInt("request", request).String("url", RequestUrl(request))
                       .String("name", name).UInt("bytes", result && size ? *size : 0)
                       .Bool("result", result));
    return result;
}

bool GetHeader(void* self, Request request, const char* name, uint8_t* buffer, uint32_t size) {
    const bool result = o_get_header(self, request, name, buffer, size);
    EDF5_CAPTURE_EVENT("steam_http", "get_response_header",
                   capture::Fields().String("direction", "in").UInt("request", request)
                       .String("url", RequestUrl(request)).String("name", name)
                       .UInt("buffer_bytes", size).Bool("result", result),
                   buffer, result ? size : 0);
    return result;
}

bool GetBodySize(void* self, Request request, uint32_t* size) {
    const bool result = o_get_body_size(self, request, size);
    if (result && size) {
        AcquireSRWLockExclusive(&g_http_lock);
        BodySizes()[request] = *size;
        ReleaseSRWLockExclusive(&g_http_lock);
    }
    EDF5_CAPTURE_EVENT("steam_http", "get_response_body_size",
                   capture::Fields().UInt("request", request).String("url", RequestUrl(request))
                       .UInt("bytes", result && size ? *size : 0).Bool("result", result));
    return result;
}

bool GetBody(void* self, Request request, uint8_t* buffer, uint32_t capacity) {
    const bool result = o_get_body(self, request, buffer, capacity);
    uint32_t known_size = capacity;
    bool size_known = false;
    AcquireSRWLockShared(&g_http_lock);
    const auto found = BodySizes().find(request);
    if (found != BodySizes().end()) {
        known_size = std::min(capacity, found->second);
        size_known = true;
    }
    ReleaseSRWLockShared(&g_http_lock);
    EDF5_CAPTURE_EVENT("steam_http", "get_response_body",
                   capture::Fields().String("direction", "in").UInt("request", request)
                       .String("url", RequestUrl(request)).UInt("buffer_bytes", capacity)
                       .UInt("captured_bytes", result ? known_size : 0).Bool("body_size_known", size_known)
                       .Bool("result", result), buffer, result ? known_size : 0);
    return result;
}

bool GetStreaming(void* self, Request request, uint32_t offset, uint8_t* buffer, uint32_t size) {
    const bool result = o_get_streaming(self, request, offset, buffer, size);
    EDF5_CAPTURE_EVENT("steam_http", "get_streaming_response_body",
                   capture::Fields().String("direction", "in").UInt("request", request)
                       .String("url", RequestUrl(request)).UInt("offset", offset)
                       .UInt("requested_bytes", size).Bool("result", result),
                   buffer, result ? size : 0);
    return result;
}

bool ReleaseRequest(void* self, Request request) {
    const std::string url = RequestUrl(request);
    const bool result = o_release_request(self, request);
    EDF5_CAPTURE_EVENT("steam_http", "release_request",
                   capture::Fields().UInt("request", request).String("url", url).Bool("result", result));
    AcquireSRWLockExclusive(&g_http_lock);
    BodySizes().erase(request);
    Urls().erase(request);
    ReleaseSRWLockExclusive(&g_http_lock);
    return result;
}

bool GetProgress(void* self, Request request, float* progress) {
    const bool result = o_get_progress(self, request, progress);
    EDF5_CAPTURE_EVENT("steam_http", "get_download_progress",
                   capture::Fields().UInt("request", request).String("url", RequestUrl(request))
                       .String("progress", result && progress ? std::to_string(*progress) : "")
                       .Bool("result", result));
    return result;
}

bool SetRawBody(void* self, Request request, const char* content_type, uint8_t* body, uint32_t size) {
    const bool result = o_set_raw_body(self, request, content_type, body, size);
    EDF5_CAPTURE_EVENT("steam_http", "set_raw_post_body",
                   capture::Fields().String("direction", "out").UInt("request", request)
                       .String("url", RequestUrl(request)).String("content_type", content_type)
                       .UInt("body_bytes", size).Bool("result", result), body, size);
    return result;
}

Cookie CreateCookie(void* self, bool allow_modify) {
    const Cookie result = o_create_cookie(self, allow_modify);
    EDF5_CAPTURE_EVENT("steam_http", "create_cookie_container",
                   capture::Fields().UInt("cookie_container", result)
                       .Bool("allow_response_modification", allow_modify));
    return result;
}

bool ReleaseCookie(void* self, Cookie cookie) {
    const bool result = o_release_cookie(self, cookie);
    EDF5_CAPTURE_EVENT("steam_http", "release_cookie_container",
                   capture::Fields().UInt("cookie_container", cookie).Bool("result", result));
    return result;
}

bool SetCookie(void* self, Cookie cookie, const char* host, const char* url, const char* value) {
    const bool result = o_set_cookie(self, cookie, host, url, value);
    EDF5_CAPTURE_EVENT("steam_http", "set_cookie",
                   capture::Fields().UInt("cookie_container", cookie).String("host", host)
                       .String("url", url).String("cookie", value).Bool("result", result));
    return result;
}

bool SetCookieContainer(void* self, Request request, Cookie cookie) {
    const bool result = o_set_cookie_container(self, request, cookie);
    EDF5_CAPTURE_EVENT("steam_http", "set_request_cookie_container",
                   capture::Fields().UInt("request", request).String("url", RequestUrl(request))
                       .UInt("cookie_container", cookie).Bool("result", result));
    return result;
}

bool SetUserAgent(void* self, Request request, const char* value) {
    const bool result = o_set_user_agent(self, request, value);
    EDF5_CAPTURE_EVENT("steam_http", "set_user_agent",
                   capture::Fields().UInt("request", request).String("url", RequestUrl(request))
                       .String("user_agent", value).Bool("result", result));
    return result;
}

bool RequireCertificate(void* self, Request request, bool required) {
    const bool result = o_require_certificate(self, request, required);
    EDF5_CAPTURE_EVENT("steam_http", "require_verified_certificate",
                   capture::Fields().UInt("request", request).String("url", RequestUrl(request))
                       .Bool("required", required).Bool("result", result));
    return result;
}

bool SetAbsoluteTimeout(void* self, Request request, uint32_t milliseconds) {
    const bool result = o_set_absolute_timeout(self, request, milliseconds);
    EDF5_CAPTURE_EVENT("steam_http", "set_absolute_timeout",
                   capture::Fields().UInt("request", request).String("url", RequestUrl(request))
                       .UInt("milliseconds", milliseconds).Bool("result", result));
    return result;
}

bool WasTimedOut(void* self, Request request, bool* timed_out) {
    const bool result = o_was_timed_out(self, request, timed_out);
    EDF5_CAPTURE_EVENT("steam_http", "was_timed_out",
                   capture::Fields().UInt("request", request).String("url", RequestUrl(request))
                       .Bool("timed_out", result && timed_out ? *timed_out : false)
                       .Bool("result", result));
    return result;
}

#define INSTALL_SLOT(index, original, replacement, label) \
    original = reinterpret_cast<decltype(original)>(vtable[index]); \
    g_http_vtable[index] = reinterpret_cast<void*>(&replacement); \
    installed += original != nullptr

}  // namespace

void HookHttp(void* interface_pointer) {
    if (!interface_pointer) return;
    AcquireSRWLockExclusive(&g_http_lock);
    if (g_http_interface) {
        ReleaseSRWLockExclusive(&g_http_lock);
        return;
    }
    void** vtable = *reinterpret_cast<void***>(interface_pointer);
    for (unsigned i = 0; i < 25; ++i) g_http_vtable[i] = vtable[i];
    unsigned installed = 0;
    INSTALL_SLOT(0, o_create_request, CreateRequest, "ISteamHTTP002::CreateHTTPRequest");
    INSTALL_SLOT(1, o_set_context, SetContext, "ISteamHTTP002::SetHTTPRequestContextValue");
    INSTALL_SLOT(2, o_set_network_timeout, SetNetworkTimeout, "ISteamHTTP002::SetHTTPRequestNetworkActivityTimeout");
    INSTALL_SLOT(3, o_set_header, SetHeader, "ISteamHTTP002::SetHTTPRequestHeaderValue");
    INSTALL_SLOT(4, o_set_parameter, SetParameter, "ISteamHTTP002::SetHTTPRequestGetOrPostParameter");
    INSTALL_SLOT(5, o_send_request, SendRequest, "ISteamHTTP002::SendHTTPRequest");
    INSTALL_SLOT(6, o_send_streaming, SendStreaming, "ISteamHTTP002::SendHTTPRequestAndStreamResponse");
    INSTALL_SLOT(7, o_defer, Defer, "ISteamHTTP002::DeferHTTPRequest");
    INSTALL_SLOT(8, o_prioritize, Prioritize, "ISteamHTTP002::PrioritizeHTTPRequest");
    INSTALL_SLOT(9, o_get_header_size, GetHeaderSize, "ISteamHTTP002::GetHTTPResponseHeaderSize");
    INSTALL_SLOT(10, o_get_header, GetHeader, "ISteamHTTP002::GetHTTPResponseHeaderValue");
    INSTALL_SLOT(11, o_get_body_size, GetBodySize, "ISteamHTTP002::GetHTTPResponseBodySize");
    INSTALL_SLOT(12, o_get_body, GetBody, "ISteamHTTP002::GetHTTPResponseBodyData");
    INSTALL_SLOT(13, o_get_streaming, GetStreaming, "ISteamHTTP002::GetHTTPStreamingResponseBodyData");
    INSTALL_SLOT(14, o_release_request, ReleaseRequest, "ISteamHTTP002::ReleaseHTTPRequest");
    INSTALL_SLOT(15, o_get_progress, GetProgress, "ISteamHTTP002::GetHTTPDownloadProgressPct");
    INSTALL_SLOT(16, o_set_raw_body, SetRawBody, "ISteamHTTP002::SetHTTPRequestRawPostBody");
    INSTALL_SLOT(17, o_create_cookie, CreateCookie, "ISteamHTTP002::CreateCookieContainer");
    INSTALL_SLOT(18, o_release_cookie, ReleaseCookie, "ISteamHTTP002::ReleaseCookieContainer");
    INSTALL_SLOT(19, o_set_cookie, SetCookie, "ISteamHTTP002::SetCookie");
    INSTALL_SLOT(20, o_set_cookie_container, SetCookieContainer, "ISteamHTTP002::SetHTTPRequestCookieContainer");
    INSTALL_SLOT(21, o_set_user_agent, SetUserAgent, "ISteamHTTP002::SetHTTPRequestUserAgentInfo");
    INSTALL_SLOT(22, o_require_certificate, RequireCertificate, "ISteamHTTP002::SetHTTPRequestRequiresVerifiedCertificate");
    INSTALL_SLOT(23, o_set_absolute_timeout, SetAbsoluteTimeout, "ISteamHTTP002::SetHTTPRequestAbsoluteTimeoutMS");
    INSTALL_SLOT(24, o_was_timed_out, WasTimedOut, "ISteamHTTP002::GetHTTPRequestWasTimedOut");
    InterlockedExchangePointer(reinterpret_cast<PVOID volatile*>(interface_pointer), g_http_vtable);
    g_http_interface = interface_pointer;
    ReleaseSRWLockExclusive(&g_http_lock);
    EDF5_CAPTURE_EVENT("steam", "http_interface_hooked",
                   capture::Fields().String("interface_version", "STEAMHTTP_INTERFACE_VERSION002")
                       .String("interface", capture::HexPointer(interface_pointer))
                       .UInt("hooks_installed", installed).UInt("hooks_expected", 25));
}

}  // namespace steam_capture
