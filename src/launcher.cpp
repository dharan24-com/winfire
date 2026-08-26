#include <windows.h>

#include <iterator>
#include <stdexcept>
#include <string>

namespace {

std::wstring QuoteArgument(const std::wstring& argument) {
  if (!argument.empty() &&
      argument.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
    return argument;
  }

  std::wstring quoted = L"\"";
  std::size_t backslashes = 0;
  for (const wchar_t character : argument) {
    if (character == L'\\') {
      ++backslashes;
      continue;
    }
    if (character == L'\"') {
      quoted.append(backslashes * 2 + 1, L'\\');
      quoted.push_back(L'\"');
    } else {
      quoted.append(backslashes, L'\\');
      quoted.push_back(character);
    }
    backslashes = 0;
  }
  quoted.append(backslashes * 2, L'\\');
  quoted.push_back(L'\"');
  return quoted;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
  wchar_t launcher_path[32768]{};
  const DWORD launcher_length = GetModuleFileNameW(
      nullptr, launcher_path, static_cast<DWORD>(std::size(launcher_path)));
  if (!launcher_length || launcher_length >= std::size(launcher_path)) {
    return ERROR_BAD_PATHNAME;
  }

  std::wstring directory(launcher_path, launcher_length);
  const auto separator = directory.find_last_of(L"\\/");
  if (separator == std::wstring::npos) {
    return ERROR_BAD_PATHNAME;
  }
  directory.resize(separator);
  const std::wstring firefox_path = directory + L"\\firefox-real.exe";
  const std::wstring payload_path = directory + L"\\renderer_payload.dll";
  if (!SetEnvironmentVariableW(L"MOZ_REPLACE_MALLOC_LIB",
                               payload_path.c_str())) {
    return static_cast<int>(GetLastError());
  }

  std::wstring command_line = QuoteArgument(firefox_path);
  for (int index = 1; index < argc; ++index) {
    command_line.push_back(L' ');
    command_line += QuoteArgument(argv[index]);
  }

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process{};
  if (!CreateProcessW(firefox_path.c_str(), command_line.data(), nullptr,
                      nullptr, FALSE, CREATE_UNICODE_ENVIRONMENT, nullptr,
                      directory.c_str(), &startup, &process)) {
    return static_cast<int>(GetLastError());
  }
  CloseHandle(process.hThread);
  WaitForSingleObject(process.hProcess, INFINITE);
  DWORD exit_code = ERROR_GEN_FAILURE;
  GetExitCodeProcess(process.hProcess, &exit_code);
  CloseHandle(process.hProcess);
  return static_cast<int>(exit_code);
}
