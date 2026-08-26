#include "poc_context.h"

#include <appmodel.h>
#include <roapi.h>
#include <winrt/Windows.ApplicationModel.h>
#include <winrt/base.h>

#include <algorithm>
#include <iterator>
#include <vector>

namespace {

template <std::size_t N>
void CopyString(wchar_t (&destination)[N], const wchar_t* source) {
  if (!source) {
    destination[0] = L'\0';
    return;
  }
  wcsncpy_s(destination, source, _TRUNCATE);
}

void CaptureCurrentProcess(TokenSnapshot& snapshot) {
  ZeroMemory(&snapshot, sizeof(snapshot));
  snapshot.pid = GetCurrentProcessId();
  IsProcessInJob(GetCurrentProcess(), nullptr, &snapshot.is_in_job);
  CopyString(snapshot.command_line, GetCommandLineW());
  GetModuleFileNameW(nullptr, snapshot.image_path,
                     static_cast<DWORD>(std::size(snapshot.image_path)));

  UINT32 length = static_cast<UINT32>(std::size(snapshot.package_family));
  if (GetCurrentPackageFamilyName(&length, snapshot.package_family) !=
      ERROR_SUCCESS) {
    snapshot.package_family[0] = L'\0';
  }

  length = static_cast<UINT32>(std::size(snapshot.package_full_name));
  if (GetCurrentPackageFullName(&length, snapshot.package_full_name) !=
      ERROR_SUCCESS) {
    snapshot.package_full_name[0] = L'\0';
  }

  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
    return;
  }

  snapshot.is_restricted = IsTokenRestricted(token);

  DWORD value = 0;
  DWORD returned = 0;
  if (GetTokenInformation(token, TokenIsAppContainer, &value, sizeof(value),
                          &returned)) {
    snapshot.is_app_container = value;
  }

  TOKEN_ELEVATION elevation{};
  if (GetTokenInformation(token, TokenElevation, &elevation,
                          sizeof(elevation), &returned)) {
    snapshot.is_elevated = elevation.TokenIsElevated;
  }

  GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &returned);
  if (returned) {
    std::vector<BYTE> buffer(returned);
    if (GetTokenInformation(token, TokenIntegrityLevel, buffer.data(),
                            returned, &returned)) {
      const auto label = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buffer.data());
      const auto count = *GetSidSubAuthorityCount(label->Label.Sid);
      snapshot.integrity_rid =
          *GetSidSubAuthority(label->Label.Sid, count - 1);
    }
  }

  CloseHandle(token);
}

}  // namespace

extern "C" __declspec(dllexport) DWORD WINAPI RunPoc(void* raw_context) {
  auto* context = static_cast<LaunchContext*>(raw_context);
  if (!context || context->magic != kPocContextMagic) {
    return ERROR_INVALID_PARAMETER;
  }

  context->call_hresult = E_PENDING;
  context->extended_error = S_OK;
  context->launch_result = -1;
  CaptureCurrentProcess(context->caller);

  const HRESULT initialize_result = RoInitialize(RO_INIT_MULTITHREADED);
  const bool should_uninitialize = SUCCEEDED(initialize_result);
  if (FAILED(initialize_result) && initialize_result != RPC_E_CHANGED_MODE) {
    context->call_hresult = initialize_result;
    return ERROR_SUCCESS;
  }

  try {
    const auto result =
        winrt::Windows::ApplicationModel::FullTrustProcessLauncher::
            LaunchFullTrustProcessForCurrentAppWithArgumentsAsync(
                context->launch_arguments)
                .get();
    context->launch_result =
        static_cast<std::int32_t>(result.LaunchResult());
    context->extended_error = result.ExtendedError().value;
    context->call_hresult = S_OK;
  } catch (const winrt::hresult_error& error) {
    context->call_hresult = error.code().value;
  } catch (...) {
    context->call_hresult = E_FAIL;
  }

  if (should_uninitialize) {
    RoUninitialize();
  }
  return ERROR_SUCCESS;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void*) {
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(instance);
  }
  return TRUE;
}
