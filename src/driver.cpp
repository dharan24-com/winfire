#include "poc_context.h"

#include <appmodel.h>
#include <shobjidl_core.h>
#include <tlhelp32.h>
#include <winternl.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <cwctype>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

class ScopedHandle {
 public:
  explicit ScopedHandle(HANDLE handle = nullptr) : handle_(handle) {}
  ~ScopedHandle() {
    if (handle_ && handle_ != INVALID_HANDLE_VALUE) {
      CloseHandle(handle_);
    }
  }
  ScopedHandle(const ScopedHandle&) = delete;
  ScopedHandle& operator=(const ScopedHandle&) = delete;
  HANDLE get() const { return handle_; }
  explicit operator bool() const {
    return handle_ && handle_ != INVALID_HANDLE_VALUE;
  }

 private:
  HANDLE handle_;
};

class ScopedModule {
 public:
  explicit ScopedModule(HMODULE module = nullptr) : module_(module) {}
  ~ScopedModule() {
    if (module_) {
      FreeLibrary(module_);
    }
  }
  HMODULE get() const { return module_; }

 private:
  HMODULE module_;
};

[[noreturn]] void ThrowWindowsError(const std::string& operation,
                                    DWORD error = GetLastError()) {
  std::ostringstream message;
  message << operation << " failed with Win32 error " << error;
  throw std::runtime_error(message.str());
}

void CheckHresult(HRESULT result, const std::string& operation) {
  if (FAILED(result)) {
    std::ostringstream message;
    message << operation << " failed with HRESULT 0x" << std::hex
            << std::uppercase << static_cast<std::uint32_t>(result);
    throw std::runtime_error(message.str());
  }
}

std::wstring RequireOption(int argc, wchar_t** argv, const wchar_t* option) {
  for (int index = 2; index + 1 < argc; ++index) {
    if (_wcsicmp(argv[index], option) == 0) {
      return argv[index + 1];
    }
  }
  throw std::runtime_error("missing required command-line option");
}

DWORD ParsePid(const std::wstring& value) {
  wchar_t* end = nullptr;
  const auto parsed = wcstoul(value.c_str(), &end, 10);
  if (!end || *end != L'\0' || parsed == 0 || parsed > MAXDWORD) {
    throw std::runtime_error("invalid process id");
  }
  return static_cast<DWORD>(parsed);
}

std::string WideToUtf8(const std::wstring& value) {
  if (value.empty()) {
    return {};
  }
  const int length = WideCharToMultiByte(CP_UTF8, 0, value.data(),
                                         static_cast<int>(value.size()), nullptr,
                                         0, nullptr, nullptr);
  if (length <= 0) {
    ThrowWindowsError("WideCharToMultiByte");
  }
  std::string result(length, '\0');
  WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                      result.data(), length, nullptr, nullptr);
  return result;
}

std::string JsonEscape(const std::wstring& value) {
  const std::string utf8 = WideToUtf8(value);
  std::ostringstream output;
  for (const unsigned char character : utf8) {
    switch (character) {
      case '"':
        output << "\\\"";
        break;
      case '\\':
        output << "\\\\";
        break;
      case '\b':
        output << "\\b";
        break;
      case '\f':
        output << "\\f";
        break;
      case '\n':
        output << "\\n";
        break;
      case '\r':
        output << "\\r";
        break;
      case '\t':
        output << "\\t";
        break;
      default:
        if (character < 0x20) {
          output << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                 << static_cast<unsigned int>(character) << std::dec;
        } else {
          output << character;
        }
    }
  }
  return output.str();
}

std::wstring BaseName(const std::wstring& path) {
  const auto separator = path.find_last_of(L"\\/");
  return separator == std::wstring::npos ? path : path.substr(separator + 1);
}

std::wstring ToLower(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](wchar_t character) { return std::towlower(character); });
  return value;
}

template <std::size_t N>
void CopyString(wchar_t (&destination)[N], const wchar_t* source) {
  wcsncpy_s(destination, source ? source : L"", _TRUNCATE);
}

template <std::size_t N>
void CopyString(wchar_t (&destination)[N], const std::wstring& source) {
  CopyString(destination, source.c_str());
}

std::wstring QueryCommandLine(HANDLE process) {
  using NtQueryInformationProcessFunction = NTSTATUS(NTAPI*)(
      HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
  const auto ntdll = GetModuleHandleW(L"ntdll.dll");
  const auto query = reinterpret_cast<NtQueryInformationProcessFunction>(
      GetProcAddress(ntdll, "NtQueryInformationProcess"));
  if (!query) {
    return {};
  }

  ULONG length = 0;
  query(process, static_cast<PROCESSINFOCLASS>(60), nullptr, 0, &length);
  if (!length) {
    return {};
  }

  std::vector<BYTE> buffer(length + sizeof(wchar_t));
  const NTSTATUS status = query(process, static_cast<PROCESSINFOCLASS>(60),
                                buffer.data(), length, &length);
  if (status < 0) {
    return {};
  }

  const auto command_line = reinterpret_cast<UNICODE_STRING*>(buffer.data());
  if (!command_line->Buffer || !command_line->Length) {
    return {};
  }

  const auto buffer_start = reinterpret_cast<std::uintptr_t>(buffer.data());
  const auto buffer_end = buffer_start + buffer.size();
  const auto string_start =
      reinterpret_cast<std::uintptr_t>(command_line->Buffer);
  const auto string_end = string_start + command_line->Length;
  if (string_start >= buffer_start && string_end <= buffer_end) {
    return std::wstring(command_line->Buffer,
                        command_line->Length / sizeof(wchar_t));
  }

  std::wstring result(command_line->Length / sizeof(wchar_t), L'\0');
  SIZE_T bytes_read = 0;
  if (!ReadProcessMemory(process, command_line->Buffer, result.data(),
                         command_line->Length, &bytes_read)) {
    return {};
  }
  return result;
}

void CaptureToken(HANDLE process, TokenSnapshot& snapshot) {
  HANDLE raw_token = nullptr;
  if (!OpenProcessToken(process, TOKEN_QUERY, &raw_token)) {
    ThrowWindowsError("OpenProcessToken");
  }
  ScopedHandle token(raw_token);
  snapshot.is_restricted = IsTokenRestricted(token.get());

  DWORD returned = 0;
  DWORD value = 0;
  if (GetTokenInformation(token.get(), TokenIsAppContainer, &value,
                          sizeof(value), &returned)) {
    snapshot.is_app_container = value;
  }

  TOKEN_ELEVATION elevation{};
  if (GetTokenInformation(token.get(), TokenElevation, &elevation,
                          sizeof(elevation), &returned)) {
    snapshot.is_elevated = elevation.TokenIsElevated;
  }

  GetTokenInformation(token.get(), TokenIntegrityLevel, nullptr, 0, &returned);
  if (!returned) {
    return;
  }
  std::vector<BYTE> buffer(returned);
  if (!GetTokenInformation(token.get(), TokenIntegrityLevel, buffer.data(),
                           returned, &returned)) {
    ThrowWindowsError("GetTokenInformation(TokenIntegrityLevel)");
  }
  const auto label = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buffer.data());
  const auto count = *GetSidSubAuthorityCount(label->Label.Sid);
  snapshot.integrity_rid = *GetSidSubAuthority(label->Label.Sid, count - 1);
}

TokenSnapshot InspectProcess(DWORD pid, DWORD access) {
  ScopedHandle process(OpenProcess(access, FALSE, pid));
  if (!process) {
    ThrowWindowsError("OpenProcess");
  }

  TokenSnapshot snapshot{};
  snapshot.pid = pid;
  IsProcessInJob(process.get(), nullptr, &snapshot.is_in_job);

  std::vector<wchar_t> image(32768);
  DWORD image_length = static_cast<DWORD>(image.size());
  if (!QueryFullProcessImageNameW(process.get(), 0, image.data(),
                                  &image_length)) {
    ThrowWindowsError("QueryFullProcessImageNameW");
  }
  CopyString(snapshot.image_path,
             std::wstring(image.data(), static_cast<std::size_t>(image_length)));
  CopyString(snapshot.command_line, QueryCommandLine(process.get()));

  UINT32 length = 0;
  LONG result = GetPackageFamilyName(process.get(), &length, nullptr);
  if (result == ERROR_INSUFFICIENT_BUFFER && length) {
    std::vector<wchar_t> package(length);
    if (GetPackageFamilyName(process.get(), &length, package.data()) ==
        ERROR_SUCCESS) {
      CopyString(snapshot.package_family, package.data());
    }
  }

  length = 0;
  result = GetPackageFullName(process.get(), &length, nullptr);
  if (result == ERROR_INSUFFICIENT_BUFFER && length) {
    std::vector<wchar_t> package(length);
    if (GetPackageFullName(process.get(), &length, package.data()) ==
        ERROR_SUCCESS) {
      CopyString(snapshot.package_full_name, package.data());
    }
  }

  CaptureToken(process.get(), snapshot);
  return snapshot;
}

std::uintptr_t FindRemoteModule(DWORD pid, const std::wstring& module_name) {
  for (int attempt = 0; attempt < 10; ++attempt) {
    ScopedHandle snapshot(
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
    if (!snapshot) {
      if (GetLastError() == ERROR_BAD_LENGTH) {
        continue;
      }
      ThrowWindowsError("CreateToolhelp32Snapshot");
    }

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!Module32FirstW(snapshot.get(), &entry)) {
      ThrowWindowsError("Module32FirstW");
    }
    do {
      if (_wcsicmp(entry.szModule, module_name.c_str()) == 0) {
        return reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
      }
    } while (Module32NextW(snapshot.get(), &entry));
    return 0;
  }
  ThrowWindowsError("CreateToolhelp32Snapshot", ERROR_BAD_LENGTH);
}

std::uintptr_t WaitForRemoteModule(DWORD pid,
                                   const std::wstring& module_name) {
  for (int attempt = 0; attempt < 100; ++attempt) {
    const auto address = FindRemoteModule(pid, module_name);
    if (address) {
      return address;
    }
    Sleep(50);
  }
  throw std::runtime_error("injected DLL was not visible in the target process");
}

std::uintptr_t RemoteProcedureAddress(DWORD pid, const wchar_t* module_name,
                                      const char* procedure_name) {
  const auto local_module = GetModuleHandleW(module_name);
  if (!local_module) {
    ThrowWindowsError("GetModuleHandleW");
  }
  const auto local_procedure = GetProcAddress(local_module, procedure_name);
  if (!local_procedure) {
    ThrowWindowsError("GetProcAddress");
  }

  HMODULE containing_module = nullptr;
  if (!GetModuleHandleExW(
          GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
              GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
          reinterpret_cast<LPCWSTR>(local_procedure), &containing_module)) {
    ThrowWindowsError("GetModuleHandleExW");
  }
  wchar_t containing_path[32768]{};
  if (!GetModuleFileNameW(containing_module, containing_path,
                          static_cast<DWORD>(std::size(containing_path)))) {
    ThrowWindowsError("GetModuleFileNameW");
  }

  const auto remote_module = FindRemoteModule(pid, BaseName(containing_path));
  if (!remote_module) {
    throw std::runtime_error("required module not found in target process");
  }
  return remote_module +
         (reinterpret_cast<std::uintptr_t>(local_procedure) -
          reinterpret_cast<std::uintptr_t>(containing_module));
}

std::uintptr_t InjectLibrary(HANDLE process, DWORD pid,
                             const std::wstring& dll_path) {
  const SIZE_T path_size = (dll_path.size() + 1) * sizeof(wchar_t);
  void* remote_path = VirtualAllocEx(process, nullptr, path_size,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!remote_path) {
    ThrowWindowsError("VirtualAllocEx(DLL path)");
  }

  SIZE_T bytes_written = 0;
  if (!WriteProcessMemory(process, remote_path, dll_path.c_str(), path_size,
                          &bytes_written) ||
      bytes_written != path_size) {
    ThrowWindowsError("WriteProcessMemory(DLL path)");
  }

  const auto load_library = RemoteProcedureAddress(
      pid, L"kernel32.dll", "LoadLibraryW");
  ScopedHandle thread(CreateRemoteThread(
      process, nullptr, 0,
      reinterpret_cast<LPTHREAD_START_ROUTINE>(load_library), remote_path, 0,
      nullptr));
  if (!thread) {
    ThrowWindowsError("CreateRemoteThread(LoadLibraryW)");
  }
  if (WaitForSingleObject(thread.get(), 30000) != WAIT_OBJECT_0) {
    throw std::runtime_error("timed out loading the payload DLL");
  }

  VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
  return WaitForRemoteModule(pid, BaseName(dll_path));
}

LaunchContext RunInjectedPoc(DWORD pid, const std::wstring& dll_path,
                             const std::wstring& local_dll_path,
                             const std::wstring& launch_arguments,
                             const std::wstring& background_task_name) {
  const DWORD access = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                       PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION |
                       PROCESS_VM_READ | PROCESS_VM_WRITE;
  ScopedHandle process(OpenProcess(access, FALSE, pid));
  if (!process) {
    ThrowWindowsError("OpenProcess(inject)");
  }

  const auto remote_module = InjectLibrary(process.get(), pid, dll_path);
  ScopedModule local_module(
      LoadLibraryExW(local_dll_path.c_str(), nullptr,
                     DONT_RESOLVE_DLL_REFERENCES));
  if (!local_module.get()) {
    ThrowWindowsError("LoadLibraryExW(payload)");
  }
  const auto local_entry = GetProcAddress(local_module.get(), "RunPoc");
  if (!local_entry) {
    ThrowWindowsError("GetProcAddress(RunPoc)");
  }
  const auto remote_entry =
      remote_module +
      (reinterpret_cast<std::uintptr_t>(local_entry) -
       reinterpret_cast<std::uintptr_t>(local_module.get()));

  LaunchContext context{};
  context.magic = kPocContextMagic;
  context.call_hresult = E_PENDING;
  context.extended_error = E_PENDING;
  context.launch_result = -1;
  context.background_register_hresult = E_PENDING;
  if (launch_arguments.size() >= std::size(context.launch_arguments)) {
    throw std::runtime_error("launch argument string is too long");
  }
  wcsncpy_s(context.launch_arguments, launch_arguments.c_str(), _TRUNCATE);
  if (background_task_name.size() >=
      std::size(context.background_task_name)) {
    throw std::runtime_error("background task name is too long");
  }
  wcsncpy_s(context.background_task_name, background_task_name.c_str(),
            _TRUNCATE);

  void* remote_context = VirtualAllocEx(
      process.get(), nullptr, sizeof(context), MEM_COMMIT | MEM_RESERVE,
      PAGE_READWRITE);
  if (!remote_context) {
    ThrowWindowsError("VirtualAllocEx(context)");
  }

  SIZE_T bytes_written = 0;
  if (!WriteProcessMemory(process.get(), remote_context, &context,
                          sizeof(context), &bytes_written) ||
      bytes_written != sizeof(context)) {
    ThrowWindowsError("WriteProcessMemory(context)");
  }

  ScopedHandle thread(CreateRemoteThread(
      process.get(), nullptr, 0,
      reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_entry), remote_context, 0,
      nullptr));
  if (!thread) {
    ThrowWindowsError("CreateRemoteThread(RunPoc)");
  }
  if (WaitForSingleObject(thread.get(), 120000) != WAIT_OBJECT_0) {
    throw std::runtime_error("timed out waiting for FullTrustProcessLauncher");
  }

  DWORD thread_result = ERROR_GEN_FAILURE;
  GetExitCodeThread(thread.get(), &thread_result);
  if (thread_result != ERROR_SUCCESS) {
    throw std::runtime_error("payload rejected its launch context");
  }

  SIZE_T bytes_read = 0;
  if (!ReadProcessMemory(process.get(), remote_context, &context,
                         sizeof(context), &bytes_read) ||
      bytes_read != sizeof(context)) {
    ThrowWindowsError("ReadProcessMemory(context)");
  }
  VirtualFreeEx(process.get(), remote_context, 0, MEM_RELEASE);

  if (context.magic != kPocContextMagic) {
    throw std::runtime_error("payload returned a corrupt launch context");
  }
  return context;
}

std::string IntegrityName(DWORD integrity_rid) {
  if (integrity_rid < SECURITY_MANDATORY_LOW_RID) {
    return "untrusted";
  }
  if (integrity_rid < SECURITY_MANDATORY_MEDIUM_RID) {
    return "low";
  }
  if (integrity_rid < SECURITY_MANDATORY_HIGH_RID) {
    return "medium";
  }
  if (integrity_rid < SECURITY_MANDATORY_SYSTEM_RID) {
    return "high";
  }
  return "system";
}

void PrintSnapshot(const TokenSnapshot& snapshot) {
  std::cout << "{\"pid\":" << snapshot.pid << ",\"image_path\":\""
            << JsonEscape(snapshot.image_path) << "\",\"command_line\":\""
            << JsonEscape(snapshot.command_line)
            << "\",\"package_family\":\""
            << JsonEscape(snapshot.package_family)
            << "\",\"package_full_name\":\""
            << JsonEscape(snapshot.package_full_name)
            << "\",\"integrity_rid\":" << snapshot.integrity_rid
            << ",\"integrity_name\":\""
            << IntegrityName(snapshot.integrity_rid)
            << "\",\"is_restricted\":"
            << (snapshot.is_restricted ? "true" : "false")
            << ",\"is_app_container\":"
            << (snapshot.is_app_container ? "true" : "false")
            << ",\"is_in_job\":"
            << (snapshot.is_in_job ? "true" : "false")
            << ",\"is_elevated\":"
            << (snapshot.is_elevated ? "true" : "false") << "}";
}

std::string HexHresult(LONG value) {
  std::ostringstream output;
  output << "0x" << std::hex << std::uppercase << std::setw(8)
         << std::setfill('0') << static_cast<std::uint32_t>(value);
  return output.str();
}

void VerifyFirefoxContentProcess(const TokenSnapshot& snapshot,
                                 const std::wstring& expected_family) {
  if (_wcsicmp(BaseName(snapshot.image_path).c_str(), L"firefox.exe") != 0) {
    throw std::runtime_error("target image is not firefox.exe");
  }
  const std::wstring command_line = ToLower(snapshot.command_line);
  if (command_line.find(L"-contentproc") == std::wstring::npos ||
      command_line.find(L"-isforbrowser") == std::wstring::npos) {
    throw std::runtime_error("target is not a Firefox browser content process");
  }
  if (snapshot.package_family[0] != L'\0' &&
      _wcsicmp(snapshot.package_family, expected_family.c_str()) != 0) {
    throw std::runtime_error("target package family does not match the MSIX");
  }
}

void ActivateApplication(const std::wstring& aumid,
                         const std::wstring& arguments) {
  const HRESULT initialize_result =
      CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  if (FAILED(initialize_result) && initialize_result != RPC_E_CHANGED_MODE) {
    CheckHresult(initialize_result, "CoInitializeEx");
  }

  IApplicationActivationManager* raw_manager = nullptr;
  CheckHresult(CoCreateInstance(CLSID_ApplicationActivationManager, nullptr,
                                CLSCTX_INPROC_SERVER,
                                IID_PPV_ARGS(&raw_manager)),
               "CoCreateInstance(ApplicationActivationManager)");
  std::unique_ptr<IApplicationActivationManager,
                  void (*)(IApplicationActivationManager*)>
      manager(raw_manager, [](IApplicationActivationManager* value) {
        value->Release();
      });

  DWORD pid = 0;
  CheckHresult(manager->ActivateApplication(aumid.c_str(), arguments.c_str(),
                                            AO_NONE, &pid),
               "ActivateApplication");
  std::cout << "{\"pid\":" << pid << "}\n";
  manager.reset();

  if (SUCCEEDED(initialize_result)) {
    CoUninitialize();
  }
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
  try {
    if (argc < 2) {
      throw std::runtime_error("expected activate, inspect, or inject mode");
    }

    const std::wstring mode = ToLower(argv[1]);
    if (mode == L"activate") {
      ActivateApplication(RequireOption(argc, argv, L"--aumid"),
                          RequireOption(argc, argv, L"--launch-args"));
      return 0;
    }

    const DWORD pid = ParsePid(RequireOption(argc, argv, L"--pid"));
    if (mode == L"inspect") {
      PrintSnapshot(InspectProcess(pid, PROCESS_QUERY_LIMITED_INFORMATION |
                                           PROCESS_QUERY_INFORMATION |
                                           PROCESS_VM_READ));
      std::cout << "\n";
      return 0;
    }

    if (mode == L"inject") {
      const auto expected_family =
          RequireOption(argc, argv, L"--expected-family");
      const auto before = InspectProcess(
          pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION |
                   PROCESS_VM_READ);
      VerifyFirefoxContentProcess(before, expected_family);

      wchar_t full_dll_path[32768]{};
      if (!GetFullPathNameW(RequireOption(argc, argv, L"--dll").c_str(),
                            static_cast<DWORD>(std::size(full_dll_path)),
                            full_dll_path, nullptr)) {
        ThrowWindowsError("GetFullPathNameW");
      }
      const auto context = RunInjectedPoc(
          pid, full_dll_path, RequireOption(argc, argv, L"--local-dll"),
          RequireOption(argc, argv, L"--launch-args"),
          RequireOption(argc, argv, L"--background-task-name"));

      std::cout << "{\"target_before\":";
      PrintSnapshot(before);
      std::cout << ",\"caller_inside\":";
      PrintSnapshot(context.caller);
      std::cout << ",\"call_hresult\":" << context.call_hresult
                << ",\"call_hresult_hex\":\""
                << HexHresult(context.call_hresult)
                << "\",\"launch_result\":" << context.launch_result
                << ",\"extended_error\":" << context.extended_error
                << ",\"extended_error_hex\":\""
                << HexHresult(context.extended_error)
                << "\",\"background_task_name\":\""
                << JsonEscape(context.background_task_name)
                << "\",\"background_registered\":"
                << (context.background_registered ? "true" : "false")
                << ",\"background_register_hresult\":"
                << context.background_register_hresult
                << ",\"background_register_hresult_hex\":\""
                << HexHresult(context.background_register_hresult) << "\"}\n";
      return 0;
    }

    throw std::runtime_error("unknown mode");
  } catch (const std::exception& error) {
    std::cerr << "{\"harness_error\":\"";
    const std::wstring wide_error(error.what(),
                                  error.what() + strlen(error.what()));
    std::cerr << JsonEscape(wide_error) << "\"}\n";
    return 2;
  }
}
