#include <mainchainrpc.h>

#include <chainparams.h>
#include <chainparamsbase.h>
#include <drivechain_bmm.h>
#include <drivechain_peg.h>
#include <drivechain_settings.h>
#include <fs.h>
#include <logging.h>
#include <netbase.h>
#include <pegins.h>
#include <primitives/bitcoin/transaction.h>
#include <primitives/bitcoin/block.h>
#include <primitives/block.h>
#include <script/script.h>
#include <streams.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <rpc/request.h>

#include <support/events.h>

#include <rpc/client.h>

#include <event2/buffer.h>
#include <event2/keyvalq_struct.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <fstream>
#include <functional>
#include <limits>
#include <optional>
#include <set>
#include <vector>

#ifdef WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

/** Reply structure for request_done to fill in */
struct HTTPReply
{
    HTTPReply(): status(0), error(-1) {}

    int status;
    int error;
    std::string body;
};

static constexpr size_t MAX_MAINCHAIN_RPC_RESPONSE_SIZE{16U * 1024U * 1024U};
static constexpr size_t MAX_MAINCHAIN_RPC_HEADER_SIZE{64U * 1024U};

const char *http_errorstring(int code)
{
    switch(code) {
#if LIBEVENT_VERSION_NUMBER >= 0x02010300
    case EVREQ_HTTP_TIMEOUT:
        return "timeout reached";
    case EVREQ_HTTP_EOF:
        return "EOF reached";
    case EVREQ_HTTP_INVALID_HEADER:
        return "error while reading header, or invalid header";
    case EVREQ_HTTP_BUFFER_ERROR:
        return "error encountered while reading or writing";
    case EVREQ_HTTP_REQUEST_CANCEL:
        return "request was canceled";
    case EVREQ_HTTP_DATA_TOO_LONG:
        return "response body is larger than allowed";
#endif
    default:
        return "unknown";
    }
}

static void http_request_done(struct evhttp_request *req, void *ctx)
{
    HTTPReply *reply = static_cast<HTTPReply*>(ctx);

    if (req == NULL) {
        /* If req is NULL, it means an error occurred while connecting: the
         * error code will have been passed to http_error_cb.
         */
        reply->status = 0;
        return;
    }

    reply->status = evhttp_request_get_response_code(req);

    struct evbuffer *buf = evhttp_request_get_input_buffer(req);
    if (buf)
    {
        size_t size = evbuffer_get_length(buf);
        const char *data = (const char*)evbuffer_pullup(buf, size);
        if (data)
            reply->body = std::string(data, size);
        evbuffer_drain(buf, size);
    }
}

#if LIBEVENT_VERSION_NUMBER >= 0x02010300
static void http_error_cb(enum evhttp_request_error err, void *ctx)
{
    HTTPReply *reply = static_cast<HTTPReply*>(ctx);
    reply->error = err;
}
#endif

UniValue CallMainChainRPC(const std::string& strMethod, const UniValue& params)
{
    std::string host = gArgs.GetArg("-mainchainrpchost", DEFAULT_RPCCONNECT);
    int port = gArgs.GetIntArg("-mainchainrpcport", BaseParams().MainchainRPCPort());

    // Bitcoin Core's JSON-RPC protocol carries Basic credentials over HTTP.
    // Never put those credentials on a routable network interface. Operators
    // using a remote parent node must terminate an authenticated TLS tunnel on
    // loopback and point this option at that local endpoint.
    CNetAddr rpc_address;
    if (host != "localhost" &&
        (!LookupHost(host, rpc_address, /*fAllowLookup=*/false) ||
         !rpc_address.IsLocal())) {
        throw std::runtime_error(
            "-mainchainrpchost must be a numeric loopback address or localhost; "
            "use a local authenticated TLS tunnel for a remote parent-chain RPC server");
    }

    // Obtain event base
    raii_event_base base = obtain_event_base();

    // Synchronously look up hostname
    raii_evhttp_connection evcon = obtain_evhttp_connection_base(base.get(), host, port);
    evhttp_connection_set_timeout(evcon.get(), gArgs.GetIntArg("-mainchainrpctimeout", DEFAULT_HTTP_CLIENT_TIMEOUT));
    evhttp_connection_set_max_headers_size(evcon.get(), MAX_MAINCHAIN_RPC_HEADER_SIZE);
    evhttp_connection_set_max_body_size(evcon.get(), MAX_MAINCHAIN_RPC_RESPONSE_SIZE);

    HTTPReply response;
    raii_evhttp_request req = obtain_evhttp_request(http_request_done, (void*)&response);
    if (req == NULL)
        throw std::runtime_error("create http request failed");
#if LIBEVENT_VERSION_NUMBER >= 0x02010300
    evhttp_request_set_error_cb(req.get(), http_error_cb);
#endif

    // Get credentials
    std::string strRPCUserColonPass;
    if (gArgs.GetArg("-mainchainrpcpassword", "") == "") {
        // Try fall back to cookie-based authentication if no password is provided
        if (!GetMainchainAuthCookie(&strRPCUserColonPass)) {
            throw std::runtime_error(strprintf(
                _("Could not locate mainchain RPC credentials. No authentication cookie could be found, and no mainchainrpcpassword is set in the configuration file (%s)").translated,
                    gArgs.GetArg("-conf", BITCOIN_CONF_FILENAME).c_str()));
        }
    } else {
        strRPCUserColonPass = gArgs.GetArg("-mainchainrpcuser", "") + ":" + gArgs.GetArg("-mainchainrpcpassword", "");
    }

    struct evkeyvalq* output_headers = evhttp_request_get_output_headers(req.get());
    assert(output_headers);
    evhttp_add_header(output_headers, "Host", host.c_str());
    evhttp_add_header(output_headers, "Connection", "close");
    evhttp_add_header(output_headers, "Authorization", (std::string("Basic ") + EncodeBase64(strRPCUserColonPass)).c_str());

    // Attach request data
    std::string strRequest = JSONRPCRequestObj(strMethod, params, 1).write() + "\n";
    struct evbuffer* output_buffer = evhttp_request_get_output_buffer(req.get());
    assert(output_buffer);
    evbuffer_add(output_buffer, strRequest.data(), strRequest.size());

    int r = evhttp_make_request(evcon.get(), req.get(), EVHTTP_REQ_POST, "/");
    req.release(); // ownership moved to evcon in above call
    if (r != 0) {
        throw CConnectionFailed("send http request failed");
    }

    event_base_dispatch(base.get());

    if (response.status == 0)
        throw CConnectionFailed(strprintf("couldn't connect to server: %s (code %d)\n(make sure server is running and you are connecting to the correct RPC port)", http_errorstring(response.error), response.error));
    else if (response.status == HTTP_UNAUTHORIZED)
        throw std::runtime_error("incorrect mainchainrpcuser or mainchainrpcpassword (authorization failed)");
    else if (response.status >= 400 && response.status != HTTP_BAD_REQUEST && response.status != HTTP_NOT_FOUND && response.status != HTTP_INTERNAL_SERVER_ERROR)
        throw std::runtime_error(strprintf("server returned HTTP error %d", response.status));
    else if (response.body.empty())
        throw std::runtime_error("no response from server");

    // Parse reply
    UniValue valReply(UniValue::VSTR);
    if (!valReply.read(response.body))
        throw std::runtime_error("couldn't parse reply from server");
    const UniValue& reply = valReply.get_obj();
    if (reply.empty())
        throw std::runtime_error("expected reply to have result, error and id properties");

    return reply;
}

static UniValue CallMainChainRPCChecked(const std::string& method, const UniValue& params)
{
    const UniValue reply = CallMainChainRPC(method, params);
    const UniValue& error = find_value(reply, "error");
    if (!error.isNull()) {
        throw std::runtime_error(strprintf("%s returned error: %s", method, error.write()));
    }
    const UniValue& result = find_value(reply, "result");
    if (result.isNull()) {
        throw std::runtime_error(strprintf("%s returned no result", method));
    }
    return result;
}

#ifdef WIN32
namespace {

std::wstring QuoteWindowsCommandLineArgument(const std::wstring& argument)
{
    if (argument.empty()) return L"\"\"";
    if (argument.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
        return argument;
    }

    std::wstring quoted{L'\"'};
    size_t backslashes{0};
    for (const wchar_t character : argument) {
        if (character == L'\\') {
            ++backslashes;
            continue;
        }
        if (character == L'\"') {
            quoted.append(backslashes * 2 + 1, L'\\');
            quoted.push_back(character);
            backslashes = 0;
            continue;
        }
        quoted.append(backslashes, L'\\');
        backslashes = 0;
        quoted.push_back(character);
    }
    quoted.append(backslashes * 2, L'\\');
    quoted.push_back(L'\"');
    return quoted;
}

std::string WindowsProcessError(const std::string& action)
{
    return strprintf("%s (Windows error %u)", action, GetLastError());
}

std::wstring Utf8ToWindowsString(const std::string& value)
{
    if (value.empty()) return {};
    if (value.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
        throw std::runtime_error("child process argument is too large for Windows");
    }
    const int input_size = static_cast<int>(value.size());
    const int output_size = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), input_size, nullptr, 0);
    if (output_size <= 0) {
        throw std::runtime_error(
            WindowsProcessError("child process argument is not valid UTF-8"));
    }
    std::wstring converted(output_size, L'\0');
    if (MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            value.data(),
            input_size,
            converted.data(),
            output_size) != output_size) {
        throw std::runtime_error(
            WindowsProcessError("failed to convert child process argument"));
    }
    return converted;
}

} // namespace
#endif

BoundedCommandResult RunBoundedCommand(
    const std::vector<std::string>& argv,
    const std::chrono::milliseconds timeout,
    const size_t max_output,
    const std::function<bool()>& should_cancel)
{
    BoundedCommandResult result;
    if (argv.empty() || argv.front().empty()) {
        result.error = "bounded command has no executable";
        return result;
    }
    if (timeout <= std::chrono::milliseconds::zero() || max_output == 0) {
        result.error = "bounded command requires positive timeout and output limit";
        return result;
    }

#ifdef WIN32
    HANDLE output_read{nullptr};
    HANDLE output_write{nullptr};
    HANDLE job{nullptr};
    PROCESS_INFORMATION process{};
    LPPROC_THREAD_ATTRIBUTE_LIST process_attributes{nullptr};
    std::vector<unsigned char> process_attribute_storage;
    const auto close_handle = [](HANDLE& handle) {
        if (handle != nullptr && handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
        handle = nullptr;
    };
    const auto close_all = [&] {
        if (process_attributes != nullptr) {
            DeleteProcThreadAttributeList(process_attributes);
            process_attributes = nullptr;
        }
        close_handle(process.hThread);
        close_handle(process.hProcess);
        close_handle(output_read);
        close_handle(output_write);
        close_handle(job);
    };

    try {
        SECURITY_ATTRIBUTES security{};
        security.nLength = sizeof(security);
        security.bInheritHandle = TRUE;
        if (!CreatePipe(&output_read, &output_write, &security, 0)) {
            result.error = WindowsProcessError("failed to create child output pipe");
            close_all();
            return result;
        }
        if (!SetHandleInformation(output_read, HANDLE_FLAG_INHERIT, 0)) {
            result.error = WindowsProcessError("failed to secure child output pipe");
            close_all();
            return result;
        }

        job = CreateJobObjectW(nullptr, nullptr);
        if (job == nullptr) {
            result.error = WindowsProcessError("failed to create child process job");
            close_all();
            return result;
        }
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limits{};
        job_limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &job_limits,
                sizeof(job_limits))) {
            result.error = WindowsProcessError("failed to secure child process job");
            close_all();
            return result;
        }

        std::wstring command_line;
        for (const std::string& argument : argv) {
            if (!command_line.empty()) command_line.push_back(L' ');
            command_line += QuoteWindowsCommandLineArgument(
                Utf8ToWindowsString(argument));
        }
        if (command_line.size() >= 32767) {
            result.error = "child process command line exceeds the Windows limit";
            close_all();
            return result;
        }
        std::vector<wchar_t> mutable_command_line(
            command_line.begin(), command_line.end());
        mutable_command_line.push_back(L'\0');

        SIZE_T attribute_bytes{0};
        (void)InitializeProcThreadAttributeList(
            nullptr, 1, 0, &attribute_bytes);
        if (attribute_bytes == 0) {
            result.error = WindowsProcessError(
                "failed to size child process handle restrictions");
            close_all();
            return result;
        }
        process_attribute_storage.resize(attribute_bytes);
        process_attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
            process_attribute_storage.data());
        if (!InitializeProcThreadAttributeList(
                process_attributes, 1, 0, &attribute_bytes)) {
            result.error = WindowsProcessError(
                "failed to initialize child process handle restrictions");
            process_attributes = nullptr;
            close_all();
            return result;
        }
        HANDLE inherited_handles[]{output_write};
        if (!UpdateProcThreadAttribute(
                process_attributes,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                inherited_handles,
                sizeof(inherited_handles),
                nullptr,
                nullptr)) {
            result.error = WindowsProcessError(
                "failed to restrict inherited child process handles");
            close_all();
            return result;
        }

        STARTUPINFOEXW startup{};
        startup.StartupInfo.cb = sizeof(startup);
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = INVALID_HANDLE_VALUE;
        startup.StartupInfo.hStdOutput = output_write;
        startup.StartupInfo.hStdError = output_write;
        startup.lpAttributeList = process_attributes;
        const DWORD creation_flags =
            CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT;
        if (!CreateProcessW(
                nullptr,
                mutable_command_line.data(),
                nullptr,
                nullptr,
                TRUE,
                creation_flags,
                nullptr,
                nullptr,
                &startup.StartupInfo,
                &process)) {
            result.error = WindowsProcessError("failed to create child process");
            close_all();
            return result;
        }
        DeleteProcThreadAttributeList(process_attributes);
        process_attributes = nullptr;
        result.started = true;
        close_handle(output_write);

        if (!AssignProcessToJobObject(job, process.hProcess)) {
            result.error = WindowsProcessError("failed to assign child process to bounded job");
            TerminateProcess(process.hProcess, 1);
        } else if (ResumeThread(process.hThread) == static_cast<DWORD>(-1)) {
            result.error = WindowsProcessError("failed to resume child process");
            TerminateJobObject(job, 1);
        }
        close_handle(process.hThread);

        bool terminate_child{!result.error.empty()};
        bool process_exited{false};
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        const auto drain_output = [&] {
            std::array<char, 4096> buffer;
            for (;;) {
                DWORD available{0};
                if (!PeekNamedPipe(
                        output_read, nullptr, 0, nullptr, &available, nullptr)) {
                    if (GetLastError() == ERROR_BROKEN_PIPE) return true;
                    if (result.error.empty()) {
                        result.error = WindowsProcessError("failed reading child output");
                    }
                    return false;
                }
                if (available == 0) return true;

                DWORD count{0};
                const DWORD requested = std::min<DWORD>(
                    available, static_cast<DWORD>(buffer.size()));
                if (!ReadFile(
                        output_read, buffer.data(), requested, &count, nullptr)) {
                    if (GetLastError() == ERROR_BROKEN_PIPE) return true;
                    if (result.error.empty()) {
                        result.error = WindowsProcessError("failed reading child output");
                    }
                    return false;
                }
                const size_t remaining = max_output > result.output.size()
                    ? max_output - result.output.size() : 0;
                const size_t append = std::min<size_t>(remaining, count);
                result.output.append(buffer.data(), append);
                if (append != count) {
                    result.output_truncated = true;
                    return true;
                }
            }
        };

        while (!terminate_child && !process_exited) {
            if (!drain_output()) {
                terminate_child = true;
                break;
            }
            if (result.output_truncated) {
                terminate_child = true;
                break;
            }
            if (should_cancel && should_cancel()) {
                result.cancelled = true;
                terminate_child = true;
                break;
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                result.timed_out = true;
                terminate_child = true;
                break;
            }

            const DWORD wait_result = WaitForSingleObject(process.hProcess, 10);
            if (wait_result == WAIT_OBJECT_0) {
                process_exited = true;
            } else if (wait_result == WAIT_FAILED) {
                result.error = WindowsProcessError("failed waiting for child process");
                terminate_child = true;
            }
        }

        if (terminate_child) {
            if (!TerminateJobObject(job, 1) && result.error.empty()) {
                result.error = WindowsProcessError("failed to terminate child process job");
            }
        }
        const DWORD reap_result = WaitForSingleObject(process.hProcess, INFINITE);
        if (reap_result == WAIT_OBJECT_0) {
            process_exited = true;
        } else if (reap_result == WAIT_FAILED && result.error.empty()) {
            result.error = WindowsProcessError("failed to reap child process");
        }
        if (!result.output_truncated) (void)drain_output();

        DWORD exit_code{0};
        if (!GetExitCodeProcess(process.hProcess, &exit_code)) {
            if (result.error.empty()) {
                result.error = WindowsProcessError("failed to read child exit code");
            }
        } else {
            result.exit_code = static_cast<int>(exit_code);
        }
        result.exited = process_exited;
        close_all();
        return result;
    } catch (const std::exception& error) {
        if (process.hProcess != nullptr) {
            if (job != nullptr) TerminateJobObject(job, 1);
            else TerminateProcess(process.hProcess, 1);
            WaitForSingleObject(process.hProcess, INFINITE);
        }
        result.error = "failed to prepare child process: " + std::string{error.what()};
        close_all();
        return result;
    }
#else
    int output_pipe[2]{-1, -1};
    if (pipe(output_pipe) != 0) {
        result.error = strprintf("failed to create child output pipe (%d)", errno);
        return result;
    }
    const auto close_pipe = [&] {
        if (output_pipe[0] >= 0) close(output_pipe[0]);
        if (output_pipe[1] >= 0) close(output_pipe[1]);
        output_pipe[0] = output_pipe[1] = -1;
    };
    if (fcntl(output_pipe[0], F_SETFD, FD_CLOEXEC) == -1 ||
        fcntl(output_pipe[1], F_SETFD, FD_CLOEXEC) == -1) {
        result.error = strprintf("failed to secure child output pipe (%d)", errno);
        close_pipe();
        return result;
    }

    std::vector<char*> child_argv;
    child_argv.reserve(argv.size() + 1);
    for (const std::string& argument : argv) {
        child_argv.push_back(const_cast<char*>(argument.c_str()));
    }
    child_argv.push_back(nullptr);

    const pid_t child = fork();
    if (child < 0) {
        result.error = strprintf("failed to fork child process (%d)", errno);
        close_pipe();
        return result;
    }
    if (child == 0) {
        setpgid(0, 0);
        close(output_pipe[0]);
        if (dup2(output_pipe[1], STDOUT_FILENO) == -1 ||
            dup2(output_pipe[1], STDERR_FILENO) == -1) {
            _exit(126);
        }
        close(output_pipe[1]);
        execvp(child_argv[0], child_argv.data());
        static constexpr char EXEC_ERROR[] = "execvp failed\n";
        (void)write(STDERR_FILENO, EXEC_ERROR, sizeof(EXEC_ERROR) - 1);
        _exit(127);
    }

    result.started = true;
    close(output_pipe[1]);
    output_pipe[1] = -1;
    (void)setpgid(child, child);
    const int read_flags = fcntl(output_pipe[0], F_GETFL, 0);
    const bool output_nonblocking = read_flags != -1 &&
        fcntl(output_pipe[0], F_SETFL, read_flags | O_NONBLOCK) != -1;
    if (!output_nonblocking) {
        result.error = strprintf("failed to make child output nonblocking (%d)", errno);
    }

    int child_status{0};
    bool child_reaped{false};
    bool output_eof{false};
    const auto reap_nonblocking = [&] {
        if (child_reaped) return;
        for (;;) {
            const pid_t waited = waitpid(child, &child_status, WNOHANG);
            if (waited == child) {
                child_reaped = true;
                return;
            }
            if (waited == 0) return;
            if (waited < 0 && errno == EINTR) continue;
            if (waited < 0 && errno == ECHILD) {
                child_reaped = true;
                return;
            }
            if (waited < 0 && result.error.empty()) {
                result.error = strprintf("failed to reap child process (%d)", errno);
            }
            return;
        }
    };
    const auto drain_output = [&] {
        std::array<char, 4096> buffer;
        for (;;) {
            const ssize_t count = read(output_pipe[0], buffer.data(), buffer.size());
            if (count > 0) {
                const size_t available = max_output > result.output.size()
                    ? max_output - result.output.size() : 0;
                const size_t append = std::min<size_t>(available, static_cast<size_t>(count));
                result.output.append(buffer.data(), append);
                if (append != static_cast<size_t>(count)) {
                    result.output_truncated = true;
                    return true;
                }
                continue;
            }
            if (count == 0) {
                output_eof = true;
                return true;
            }
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
            if (result.error.empty()) {
                result.error = strprintf("failed reading child output (%d)", errno);
            }
            return false;
        }
    };
    const auto signal_group = [&](const int signal_number) {
        (void)kill(-child, signal_number);
        if (!child_reaped) (void)kill(child, signal_number);
    };
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    bool terminate_child{!result.error.empty()};
    while (!terminate_child) {
        if (!drain_output()) {
            terminate_child = true;
            break;
        }
        reap_nonblocking();
        if (result.output_truncated) {
            terminate_child = true;
            break;
        }
        if (should_cancel && should_cancel()) {
            result.cancelled = true;
            terminate_child = true;
            break;
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            result.timed_out = true;
            terminate_child = true;
            break;
        }
        if (child_reaped && output_eof) break;

        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        const int poll_timeout = static_cast<int>(
            std::max<int64_t>(1, std::min<int64_t>(25, remaining.count())));
        pollfd descriptor{output_pipe[0], POLLIN | POLLHUP | POLLERR, 0};
        const int poll_result = poll(&descriptor, 1, poll_timeout);
        if (poll_result < 0 && errno != EINTR) {
            result.error = strprintf("failed polling child output (%d)", errno);
            terminate_child = true;
        }
    }

    if (terminate_child) {
        signal_group(SIGTERM);
        const auto grace_deadline = std::chrono::steady_clock::now() +
            std::chrono::milliseconds{250};
        while (!child_reaped && std::chrono::steady_clock::now() < grace_deadline) {
            reap_nonblocking();
            if (child_reaped) break;
            pollfd descriptor{output_pipe[0], POLLIN | POLLHUP | POLLERR, 0};
            (void)poll(&descriptor, 1, 10);
            if (output_nonblocking) (void)drain_output();
        }
        signal_group(SIGKILL);
    }

    if (!child_reaped) {
        for (;;) {
            const pid_t waited = waitpid(child, &child_status, 0);
            if (waited == child) {
                child_reaped = true;
                break;
            }
            if (waited < 0 && errno == EINTR) continue;
            if (waited < 0 && errno == ECHILD) {
                child_reaped = true;
                break;
            }
            if (waited < 0 && result.error.empty()) {
                result.error = strprintf("failed to reap terminated child (%d)", errno);
            }
            break;
        }
    }
    if (output_nonblocking) (void)drain_output();
    close_pipe();

    result.exited = child_reaped;
    if (child_reaped) {
        if (WIFEXITED(child_status)) {
            result.exit_code = WEXITSTATUS(child_status);
        } else if (WIFSIGNALED(child_status)) {
            result.exit_code = 128 + WTERMSIG(child_status);
        }
    }
    return result;
#endif
}

static std::string ResolveDrivechainBmmGrpcurlPath(const ArgsManager& args)
{
    const std::string configured_path = args.GetArg("-drivechainbmmgrpcurl", "");
    if (!configured_path.empty()) {
        return configured_path;
    }

    const std::vector<fs::path> candidates{
        args.GetDataDirBase().parent_path() / "assets" / "bin" / "grpcurl",
        args.GetDataDirBase().parent_path() / "bin" / "grpcurl",
        fs::PathFromString("/opt/homebrew/bin/grpcurl"),
        fs::PathFromString("/usr/local/bin/grpcurl"),
        fs::PathFromString("/usr/bin/grpcurl"),
    };
    for (const fs::path& candidate : candidates) {
        if (fs::exists(candidate)) {
            return fs::PathToString(candidate);
        }
    }

    return "grpcurl";
}

namespace {

struct DrivechainGrpcTLSConfig {
    std::string address;
    fs::path ca_certificate;
    fs::path client_certificate;
    fs::path client_key;
    std::string authority;
};

fs::path ResolveDrivechainGrpcCredentialPath(
    const ArgsManager& args,
    const std::string& argument,
    const std::string& fallback)
{
    fs::path path = fs::PathFromString(args.GetArg(argument, fallback));
    if (path.is_absolute()) return path;
    return fsbridge::AbsPathJoin(args.GetDataDirNet(), path);
}

DrivechainGrpcTLSConfig GetDrivechainGrpcTLSConfig(const ArgsManager& args)
{
    const std::string shared_address = args.GetArg(
        "-drivechainbmmgrpcaddr", DEFAULT_DRIVECHAIN_GRPC_ENDPOINT);
    const std::string legacy_pegout_address = args.GetArg(
        "-drivechainpegoutenforcer", "");
    return {
        legacy_pegout_address.empty() ? shared_address : legacy_pegout_address,
        ResolveDrivechainGrpcCredentialPath(
            args, "-drivechainbmmgrpcca", "enforcer-tls/ca.pem"),
        ResolveDrivechainGrpcCredentialPath(
            args, "-drivechainbmmgrpccert", "enforcer-tls/elements-client.pem"),
        ResolveDrivechainGrpcCredentialPath(
            args, "-drivechainbmmgrpckey", "enforcer-tls/elements-client-key.pem"),
        args.GetArg("-drivechainbmmgrpcauthority", ""),
    };
}

bool ValidateReadableRegularFile(
    const fs::path& path,
    const bool private_key,
    std::string* error)
{
    if (!fs::exists(path) || !fs::is_regular_file(path)) {
        if (error) {
            *error = strprintf("required %s is not a regular file: %s",
                private_key ? "mTLS client key" : "mTLS certificate",
                fs::PathToString(path));
        }
        return false;
    }
    std::ifstream input(path);
    if (!input.good()) {
        if (error) {
            *error = strprintf("required mTLS credential is not readable: %s",
                fs::PathToString(path));
        }
        return false;
    }
#ifndef WIN32
    struct stat metadata {};
    const std::string native_path = fs::PathToString(path);
    if (lstat(native_path.c_str(), &metadata) != 0 || !S_ISREG(metadata.st_mode)) {
        if (error) {
            *error = strprintf(
                "mTLS credential must be a non-symlink regular file: %s",
                native_path);
        }
        return false;
    }
    if (metadata.st_uid != geteuid()) {
        if (error) {
            *error = strprintf(
                "mTLS credential must be owned by the Elements process user: %s",
                native_path);
        }
        return false;
    }
    const fs::path parent = path.parent_path();
    struct stat parent_metadata {};
    const std::string native_parent = fs::PathToString(parent);
    if (parent.empty() || lstat(native_parent.c_str(), &parent_metadata) != 0 ||
        !S_ISDIR(parent_metadata.st_mode) || parent_metadata.st_uid != geteuid() ||
        (parent_metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        if (error) {
            *error = strprintf(
                "mTLS credential directory must be owned by the Elements process user and deny group/other write access: %s",
                native_parent);
        }
        return false;
    }
    const mode_t forbidden = private_key
        ? (S_IRWXG | S_IRWXO)
        : (S_IWGRP | S_IWOTH);
    if ((metadata.st_mode & forbidden) != 0) {
        if (error) {
            *error = strprintf(
                private_key
                    ? "mTLS client key must deny all group and other access: %s"
                    : "mTLS certificate must deny group and other write access: %s",
                native_path);
        }
        return false;
    }
#endif
    return true;
}

} // namespace

std::string GetDrivechainGrpcAddress(const ArgsManager& args)
{
    return GetDrivechainGrpcTLSConfig(args).address;
}

bool ValidateDrivechainGrpcTLSConfig(const ArgsManager& args, std::string* error)
{
    if (error) error->clear();
    if (args.IsArgSet("-drivechainpegoutenforcer") &&
        args.IsArgSet("-drivechainbmmgrpcaddr") &&
        args.GetArg("-drivechainpegoutenforcer", "") !=
            args.GetArg("-drivechainbmmgrpcaddr", "")) {
        if (error) {
            *error = "-drivechainpegoutenforcer and -drivechainbmmgrpcaddr must name the same authenticated endpoint";
        }
        return false;
    }
    const DrivechainGrpcTLSConfig config = GetDrivechainGrpcTLSConfig(args);
    if (config.address.empty() || config.address.find("://") != std::string::npos) {
        if (error) {
            *error = "-drivechainbmmgrpcaddr must be a host:port endpoint without a URL scheme";
        }
        return false;
    }
    if (config.address.size() > 512 ||
        std::any_of(config.address.begin(), config.address.end(),
            [](const unsigned char c) { return c <= 0x20 || c == 0x7f; })) {
        if (error) {
            *error = "-drivechainbmmgrpcaddr contains whitespace, control characters, or excessive data";
        }
        return false;
    }
    uint16_t port{0};
    std::string host;
    SplitHostPort(config.address, port, host);
    if (host.empty() || host.front() == '-' || port == 0) {
        if (error) {
            *error = "-drivechainbmmgrpcaddr must contain a non-empty host and nonzero port";
        }
        return false;
    }
    if (!config.authority.empty() &&
        std::any_of(config.authority.begin(), config.authority.end(),
            [](const unsigned char c) { return c <= 0x20 || c == 0x7f; })) {
        if (error) {
            *error = "-drivechainbmmgrpcauthority contains whitespace or control characters";
        }
        return false;
    }
    return ValidateReadableRegularFile(config.ca_certificate, false, error) &&
        ValidateReadableRegularFile(config.client_certificate, false, error) &&
        ValidateReadableRegularFile(config.client_key, true, error);
}

BoundedCommandResult RunAuthenticatedDrivechainGrpc(
    const ArgsManager& args,
    const std::string& method,
    const std::string& json_payload,
    const std::chrono::milliseconds timeout,
    const size_t max_output,
    const std::function<bool()>& should_cancel)
{
    BoundedCommandResult failure;
    static const std::set<std::string> ALLOWED_METHODS{
        "cusf.mainchain.v1.WalletService/CreateBmmCriticalDataTransaction",
        "cusf.mainchain.v1.WalletService/BroadcastWithdrawalBundle",
        "cusf.mainchain.v1.ValidatorService/GetChainInfo",
        "cusf.mainchain.v1.ValidatorService/GetChainTip",
        "cusf.mainchain.v1.ValidatorService/GetSidechains",
        "cusf.mainchain.v1.ValidatorService/GetCtip",
        "cusf.mainchain.v1.ValidatorService/GetTwoWayPegData",
    };
    if (ALLOWED_METHODS.count(method) == 0) {
        failure.error = "refusing an unrecognized enforcer gRPC method";
        return failure;
    }
    if (json_payload.empty() || json_payload.size() > (1U << 20)) {
        failure.error = "enforcer gRPC payload must contain 1..1048576 bytes";
        return failure;
    }
    UniValue parsed_payload;
    if (!parsed_payload.read(json_payload) || !parsed_payload.isObject()) {
        failure.error = "enforcer gRPC payload must be one JSON object";
        return failure;
    }
    if (!ValidateDrivechainGrpcTLSConfig(args, &failure.error)) return failure;

    const DrivechainGrpcTLSConfig config = GetDrivechainGrpcTLSConfig(args);
    std::vector<std::string> argv{
        ResolveDrivechainBmmGrpcurlPath(args),
        "-cacert", fs::PathToString(config.ca_certificate),
        "-cert", fs::PathToString(config.client_certificate),
        "-key", fs::PathToString(config.client_key),
    };
    if (!config.authority.empty()) {
        argv.push_back("-authority");
        argv.push_back(config.authority);
    }
    argv.insert(argv.end(), {"-d", json_payload, config.address, method});
    return RunBoundedCommand(argv, timeout, max_output, should_cancel);
}

BoundedCommandResult RunAuthenticatedDrivechainGrpc(
    const std::string& method,
    const std::string& json_payload,
    const std::chrono::milliseconds timeout,
    const size_t max_output,
    const std::function<bool()>& should_cancel)
{
    return RunAuthenticatedDrivechainGrpc(
        gArgs, method, json_payload, timeout, max_output, should_cancel);
}

static const UniValue& FindField(const UniValue& obj, const std::string& lower_camel, const std::string& snake_case)
{
    const UniValue& lower_value = find_value(obj.get_obj(), lower_camel);
    if (!lower_value.isNull()) {
        return lower_value;
    }
    return find_value(obj.get_obj(), snake_case);
}

static bool GetDrivechainGrpcJSON(
    const std::string& method,
    const std::string& request,
    UniValue& response,
    std::string* error)
{
    static constexpr auto TIMEOUT{std::chrono::seconds{60}};
    static constexpr size_t MAX_OUTPUT{16U * 1024U * 1024U};
    const BoundedCommandResult child = RunAuthenticatedDrivechainGrpc(
        "cusf.mainchain.v1.ValidatorService/" + method,
        request,
        std::chrono::duration_cast<std::chrono::milliseconds>(TIMEOUT),
        MAX_OUTPUT);
    if (!child.started || !child.exited || child.exit_code != 0 ||
        child.timed_out || child.cancelled || child.output_truncated ||
        !child.error.empty()) {
        if (error) {
            *error = strprintf(
                "authenticated enforcer request failed: %s%s",
                child.error,
                child.output.empty() ? "" : strprintf(" (%s)", child.output));
        }
        return false;
    }
    if (!response.read(child.output) || !response.isObject()) {
        if (error) *error = "authenticated enforcer returned malformed JSON";
        return false;
    }
    return true;
}

static bool GetDrivechainTwoWayPegDataAtTip(
    const int sidechain_slot,
    const uint256& mainchain_tip,
    UniValue& response,
    std::string* error)
{
    try {
        const std::string request = strprintf(
            "{\"sidechainId\":%d,\"endBlockHash\":{\"hex\":\"%s\"}}",
            sidechain_slot,
            mainchain_tip.GetHex());
        if (!GetDrivechainGrpcJSON("GetTwoWayPegData", request, response, error)) {
            return false;
        }

        size_t block_count{0};
        size_t event_count{0};
        const UniValue& blocks = FindField(response, "blocks", "blocks");
        if (blocks.isArray()) {
            block_count = blocks.size();
            for (const UniValue& block : blocks.getValues()) {
                if (!block.isObject()) continue;
                const UniValue& block_info = FindField(block, "blockInfo", "block_info");
                if (!block_info.isObject()) continue;
                const UniValue& events = FindField(block_info, "events", "events");
                if (events.isArray()) event_count += events.size();
            }
        }
        LogPrintf("GetTwoWayPegData returned %u blocks and %u raw events for sidechain %d\n", block_count, event_count, sidechain_slot);
        return true;
    } catch (const std::exception& e) {
        if (error) {
            *error = e.what();
        }
        return false;
    }
}

bool GetDrivechainTwoWayPegData(const int sidechain_slot, UniValue& response, std::string* error)
{
    try {
        UniValue no_params(UniValue::VARR);
        const uint256 mainchain_tip = uint256S(CallMainChainRPCChecked("getbestblockhash", no_params).get_str());
        return GetDrivechainTwoWayPegDataAtTip(sidechain_slot, mainchain_tip, response, error);
    } catch (const std::exception& e) {
        if (error) {
            *error = e.what();
        }
        return false;
    }
}

static std::string Lowercase(std::string value)
{
    for (char& c : value) c = std::tolower(static_cast<unsigned char>(c));
    return value;
}

static drivechain::DepositIdentity ConfiguredDepositIdentity()
{
    drivechain::DepositIdentity identity;
    identity.sidechain_slot = gArgs.GetIntArg("-drivechainbmmslot", 24);
    identity.sidechain_network = gArgs.GetArg("-drivechainsidechainnetwork", "liquid-signet");
    identity.mainchain_network = gArgs.GetArg("-drivechainmainchainnetwork", "signet");
    identity.mainchain_signet_challenge = Lowercase(gArgs.GetArg(
        "-drivechainmainchainsignetchallenge",
        "00148835832e28c816b7acd8fdb19772ab2199603a56"));
    identity.enforcer_network = gArgs.GetArg("-drivechainenforcernetwork", "NETWORK_SIGNET");
    identity.mainchain_genesis = Params().ParentGenesisBlockHash();
    identity.title = gArgs.GetArg("-drivechainsidechaintitle", "Elements");
    identity.hash_id_1 = Lowercase(gArgs.GetArg(
        "-drivechainsidechainhashid1",
        "5883560531f013b9b27b2f9cfbac4f64ee5062b95ad3e21593a8f6916530b74b"));
    identity.hash_id_2 = Lowercase(gArgs.GetArg(
        "-drivechainsidechainhashid2",
        "b2b7b20f3fbc4baf50e9d39f58661c6168e279d4"));
    return identity;
}

bool VerifyDrivechainDeposit(
    const CTransaction& tx,
    const size_t input_index,
    drivechain::AuthenticatedDeposit* authenticated_out,
    std::string* error)
{
    try {
        if (input_index >= tx.vin.size() || input_index >= tx.witness.vtxinwit.size()) {
            throw std::runtime_error("drivechain deposit input or witness index is out of range");
        }

        CAmount value{0};
        CScript claim_script;
        uint256 mainchain_txid;
        if (!GetDrivechainDepositPeginData(
                tx.witness.vtxinwit[input_index].m_pegin_witness,
                tx.vin[input_index].prevout,
                value,
                claim_script,
                mainchain_txid)) {
            throw std::runtime_error("transaction input is not a valid drivechain deposit witness");
        }

        UniValue no_params(UniValue::VARR);
        const UniValue mainchain_info = CallMainChainRPCChecked("getblockchaininfo", no_params);
        UniValue genesis_params(UniValue::VARR);
        genesis_params.push_back(0);
        const uint256 mainchain_genesis = uint256S(CallMainChainRPCChecked("getblockhash", genesis_params).get_str());
        const uint256 mainchain_tip = uint256S(find_value(mainchain_info.get_obj(), "bestblockhash").get_str());

        UniValue enforcer_chain_info(UniValue::VOBJ);
        UniValue enforcer_tip(UniValue::VOBJ);
        UniValue sidechains(UniValue::VOBJ);
        UniValue ctip(UniValue::VOBJ);
        UniValue two_way_peg_data(UniValue::VOBJ);
        std::string lookup_error;
        if (!GetDrivechainGrpcJSON("GetChainInfo", "{}", enforcer_chain_info, &lookup_error) ||
            !GetDrivechainGrpcJSON("GetChainTip", "{}", enforcer_tip, &lookup_error) ||
            !GetDrivechainGrpcJSON("GetSidechains", "{}", sidechains, &lookup_error)) {
            throw std::runtime_error("unable to obtain enforcer chain identity: " + lookup_error);
        }

        const drivechain::DepositIdentity identity = ConfiguredDepositIdentity();
        const std::string ctip_request = strprintf(
            "{\"sidechainNumber\":%d}",
            identity.sidechain_slot);
        if (!GetDrivechainGrpcJSON("GetCtip", ctip_request, ctip, &lookup_error)) {
            throw std::runtime_error("unable to obtain current CTIP state: " + lookup_error);
        }
        if (!GetDrivechainTwoWayPegDataAtTip(
                identity.sidechain_slot,
                mainchain_tip,
                two_way_peg_data,
                &lookup_error)) {
            throw std::runtime_error("unable to obtain confirmed two-way-peg data: " + lookup_error);
        }

        drivechain::AuthenticatedDeposit authenticated;
        std::string verify_error;
        if (!drivechain::AuthenticateDepositEvidence(
                mainchain_info,
                mainchain_genesis,
                enforcer_chain_info,
                enforcer_tip,
                sidechains,
                two_way_peg_data,
                ctip,
                Params().NetworkIDString(),
                identity,
                tx.vin[input_index].prevout,
                value,
                authenticated,
                verify_error)) {
            throw std::runtime_error(verify_error);
        }

        UniValue block_params(UniValue::VARR);
        block_params.push_back(authenticated.confirmation_block.GetHex());
        block_params.push_back(true);
        const UniValue block_header = CallMainChainRPCChecked("getblockheader", block_params);
        if (!drivechain::VerifyDepositBlockConfirmation(block_header, authenticated, verify_error)) {
            throw std::runtime_error(verify_error);
        }

        UniValue ctip_params(UniValue::VARR);
        ctip_params.push_back(authenticated.current_ctip.hash.GetHex());
        ctip_params.push_back(static_cast<int64_t>(authenticated.current_ctip.n));
        ctip_params.push_back(false);
        const UniValue ctip_txout = CallMainChainRPCChecked("gettxout", ctip_params);
        if (!drivechain::VerifyCurrentCtipOutput(ctip_txout, authenticated, verify_error)) {
            throw std::runtime_error(verify_error);
        }

        if (!drivechain::VerifyDepositTransaction(tx, input_index, authenticated, verify_error)) {
            throw std::runtime_error(verify_error);
        }
        if (authenticated_out) {
            *authenticated_out = std::move(authenticated);
        }
        return true;
    } catch (const std::exception& e) {
        if (error) {
            *error = e.what();
        }
        return false;
    }
}

static bool IsDrivechainCtipScript(const CScript& script, const int sidechain_slot)
{
    if (sidechain_slot < 0 || sidechain_slot > 255) return false;
    CScript::const_iterator cursor = script.begin();
    opcodetype opcode;
    std::vector<unsigned char> data;
    if (!script.GetOp(cursor, opcode, data) || opcode != OP_NOP5) return false;
    if (!script.GetOp(cursor, opcode, data) || opcode > OP_PUSHDATA4 ||
        data.size() != 1 || data[0] != static_cast<unsigned char>(sidechain_slot)) {
        return false;
    }
    if (!script.GetOp(cursor, opcode, data) || opcode != OP_1) return false;
    return cursor == script.end();
}

bool BuildDrivechainDepositEvidence(
    const drivechain::AuthenticatedDeposit& authenticated,
    DrivechainDepositEvidence& evidence,
    std::string* error)
{
    try {
        if (authenticated.sequence_number <= 0 ||
            authenticated.outpoint.hash.IsNull() ||
            authenticated.confirmation_block.IsNull() ||
            authenticated.confirmation_height < 0) {
            throw std::runtime_error("authenticated deposit cannot form a v2 CTIP transition");
        }

        UniValue raw_params(UniValue::VARR);
        raw_params.push_back(authenticated.outpoint.hash.GetHex());
        raw_params.push_back(false);
        raw_params.push_back(authenticated.confirmation_block.GetHex());
        const UniValue raw_result = CallMainChainRPCChecked("getrawtransaction", raw_params);
        if (!raw_result.isStr() || !IsHex(raw_result.get_str())) {
            throw std::runtime_error("getrawtransaction returned malformed deposit transaction hex");
        }
        evidence.deposit_tx = ParseHex(raw_result.get_str());

        Sidechain::Bitcoin::CMutableTransaction deposit_tx;
        {
            CDataStream stream(evidence.deposit_tx, SER_NETWORK, PROTOCOL_VERSION);
            stream >> deposit_tx;
            if (!stream.empty() || deposit_tx.GetHash() != authenticated.outpoint.hash ||
                authenticated.outpoint.n >= deposit_tx.vout.size()) {
                throw std::runtime_error("L1 deposit transaction does not contain the authenticated outpoint");
            }
        }

        UniValue proof_params(UniValue::VARR);
        UniValue proof_txids(UniValue::VARR);
        proof_txids.push_back(authenticated.outpoint.hash.GetHex());
        proof_params.push_back(proof_txids);
        proof_params.push_back(authenticated.confirmation_block.GetHex());
        const UniValue proof_result = CallMainChainRPCChecked("gettxoutproof", proof_params);
        if (!proof_result.isStr() || !IsHex(proof_result.get_str())) {
            throw std::runtime_error("gettxoutproof returned malformed proof hex");
        }
        evidence.txout_proof = ParseHex(proof_result.get_str());

        std::optional<std::vector<unsigned char>> previous_ctip;
        for (const auto& input : deposit_tx.vin) {
            try {
                UniValue previous_params(UniValue::VARR);
                previous_params.push_back(input.prevout.hash.GetHex());
                previous_params.push_back(false);
                const UniValue previous_result = CallMainChainRPCChecked("getrawtransaction", previous_params);
                if (!previous_result.isStr() || !IsHex(previous_result.get_str())) continue;
                const std::vector<unsigned char> previous_bytes = ParseHex(previous_result.get_str());
                Sidechain::Bitcoin::CMutableTransaction previous_tx;
                CDataStream stream(previous_bytes, SER_NETWORK, PROTOCOL_VERSION);
                stream >> previous_tx;
                if (!stream.empty() || input.prevout.n >= previous_tx.vout.size() ||
                    !IsDrivechainCtipScript(
                        previous_tx.vout[input.prevout.n].scriptPubKey,
                        authenticated.sidechain_slot)) {
                    continue;
                }
                if (previous_ctip) {
                    throw std::runtime_error("deposit transaction spends multiple slot CTIP outputs");
                }
                previous_ctip = previous_bytes;
            } catch (const std::runtime_error& exception) {
                if (std::string(exception.what()).find("multiple slot CTIP") != std::string::npos) throw;
            } catch (...) {
            }
        }
        if (!previous_ctip) {
            throw std::runtime_error("deposit transaction's prior CTIP transaction is unavailable");
        }
        evidence.previous_ctip_tx = std::move(*previous_ctip);
        evidence.sequence_number = authenticated.sequence_number;
        evidence.previous_sequence_number = authenticated.sequence_number - 1;

        UniValue chain_info_params(UniValue::VARR);
        const UniValue chain_info = CallMainChainRPCChecked("getblockchaininfo", chain_info_params);
        const int64_t tip_height = find_value(chain_info.get_obj(), "blocks").get_int64();
        if (tip_height < authenticated.confirmation_height ||
            tip_height - authenticated.confirmation_height > 2016) {
            throw std::runtime_error("deposit confirmation is outside the bounded v2 L1 header window");
        }
        evidence.headers.clear();
        for (int64_t height = authenticated.confirmation_height; height <= tip_height; ++height) {
            UniValue hash_params(UniValue::VARR);
            hash_params.push_back(height);
            const UniValue hash_result = CallMainChainRPCChecked("getblockhash", hash_params);
            UniValue header_params(UniValue::VARR);
            header_params.push_back(hash_result.get_str());
            header_params.push_back(false);
            const UniValue header_result = CallMainChainRPCChecked("getblockheader", header_params);
            if (!header_result.isStr() || !IsHex(header_result.get_str())) {
                throw std::runtime_error("getblockheader returned malformed serialized header");
            }
            const std::vector<unsigned char> header_bytes = ParseHex(header_result.get_str());
            Sidechain::Bitcoin::CBlockHeader header;
            CDataStream stream(header_bytes, SER_NETWORK, PROTOCOL_VERSION);
            stream >> header;
            if (!stream.empty()) {
                throw std::runtime_error("serialized L1 header contains trailing data");
            }
            evidence.headers.push_back(header);
        }
        return true;
    } catch (const std::exception& exception) {
        if (error) *error = exception.what();
        return false;
    }
}

bool BuildDrivechainBmmProof(
    const drivechain::BmmL1State& previous_state,
    const int64_t parent_height,
    const uint256& parent_hash,
    const uint256& critical_hash,
    drivechain::BmmProof& proof,
    std::string* error)
{
    try {
        if (parent_height < 0 ||
            static_cast<uint64_t>(parent_height) < previous_state.height ||
            static_cast<uint64_t>(parent_height + 1 - previous_state.height) >
                drivechain::MAX_BMM_PROOF_ENTRIES) {
            throw std::runtime_error("BMM successor is outside the bounded parent-header window");
        }

        UniValue anchor_params(UniValue::VARR);
        anchor_params.push_back(static_cast<int64_t>(previous_state.height));
        const uint256 active_anchor{
            uint256S(CallMainChainRPCChecked("getblockhash", anchor_params).get_str())};
        if (active_anchor != previous_state.block_hash) {
            throw std::runtime_error(strprintf(
                "authenticated BMM anchor %s at height %u is not on the active L1 chain",
                previous_state.block_hash.GetHex(),
                previous_state.height));
        }

        UniValue parent_params(UniValue::VARR);
        parent_params.push_back(parent_height);
        const uint256 active_parent{
            uint256S(CallMainChainRPCChecked("getblockhash", parent_params).get_str())};
        if (active_parent != parent_hash) {
            throw std::runtime_error("sidechain parent commitment is no longer the active L1 block");
        }

        proof = drivechain::BmmProof{};
        proof.previous_state = previous_state;
        for (int64_t height = previous_state.height + 1;
             height <= parent_height + 1;
             ++height) {
            UniValue hash_params(UniValue::VARR);
            hash_params.push_back(height);
            const uint256 block_hash{
                uint256S(CallMainChainRPCChecked("getblockhash", hash_params).get_str())};

            UniValue block_params(UniValue::VARR);
            block_params.push_back(block_hash.GetHex());
            block_params.push_back(1);
            const UniValue block{
                CallMainChainRPCChecked("getblock", block_params)};
            const UniValue& transactions = find_value(block.get_obj(), "tx");
            if (!transactions.isArray() ||
                transactions.empty() ||
                !transactions[0].isStr()) {
                throw std::runtime_error("getblock returned no parent-chain coinbase txid");
            }
            const std::string coinbase_txid = transactions[0].get_str();

            UniValue raw_params(UniValue::VARR);
            raw_params.push_back(coinbase_txid);
            raw_params.push_back(false);
            raw_params.push_back(block_hash.GetHex());
            const UniValue raw{
                CallMainChainRPCChecked("getrawtransaction", raw_params)};
            if (!raw.isStr() || !IsHex(raw.get_str())) {
                throw std::runtime_error("getrawtransaction returned malformed coinbase hex");
            }

            UniValue proof_params(UniValue::VARR);
            UniValue proof_txids(UniValue::VARR);
            proof_txids.push_back(coinbase_txid);
            proof_params.push_back(proof_txids);
            proof_params.push_back(block_hash.GetHex());
            const UniValue merkle{
                CallMainChainRPCChecked("gettxoutproof", proof_params)};
            if (!merkle.isStr() || !IsHex(merkle.get_str())) {
                throw std::runtime_error("gettxoutproof returned malformed coinbase proof hex");
            }
            proof.entries.push_back({
                ParseHex(raw.get_str()),
                ParseHex(merkle.get_str())});
        }

        drivechain::BmmL1State next_state;
        std::string verify_error;
        if (!drivechain::VerifyBmmProofEntries(
                proof,
                critical_hash,
                parent_hash,
                next_state,
                verify_error,
                drivechain::LayerTwoLabsBmmConsensus())) {
            throw std::runtime_error(
                "constructed BMM successor proof failed self-verification: " +
                verify_error);
        }
        return true;
    } catch (const std::exception& exception) {
        if (error) *error = exception.what();
        return false;
    }
}

bool ExtractDrivechainParentHashFromBlock(const CBlock& block, uint256& parent_hash, std::string* error)
{
    if (block.vtx.empty()) {
        if (error) {
            *error = "block has no coinbase transaction";
        }
        return false;
    }

    bool found = false;
    for (const CTxOut& txout : block.vtx[0]->vout) {
        CScript::const_iterator pc = txout.scriptPubKey.begin();
        std::vector<unsigned char> data;
        opcodetype opcode;

        if (!txout.scriptPubKey.GetOp(pc, opcode, data) || opcode != OP_RETURN) {
            continue;
        }
        if (!txout.scriptPubKey.GetOp(pc, opcode, data) || opcode > OP_PUSHDATA4 || data.size() != 32) {
            continue;
        }
        if (pc != txout.scriptPubKey.end()) {
            continue;
        }

        if (found) {
            if (error) {
                *error = "block coinbase contains multiple drivechain parent commitments";
            }
            return false;
        }
        parent_hash = uint256(data);
        found = true;
    }

    if (!found && error) {
        *error = "block coinbase does not contain a drivechain parent commitment";
    }
    return found;
}

bool IsConfirmedBitcoinBlock(const uint256& hash, const int nMinConfirmationDepth, const int nbTxs)
{
    LogPrintf("Checking for confirmed bitcoin block with hash %s, mindepth %d, nbtxs %d\n", hash.ToString().c_str(), nMinConfirmationDepth, nbTxs);
    try {
        UniValue params(UniValue::VARR);
        params.push_back(hash.GetHex());
        UniValue reply = CallMainChainRPC("getblockheader", params);
        UniValue errval = find_value(reply, "error");
        if (!errval.isNull()) {
            LogPrintf("WARNING: Got error reply from bitcoind getblockheader: %s\n", errval.write());
            return false;
        }
        UniValue result = find_value(reply, "result");
        if (!result.isObject()) {
            LogPrintf("ERROR: bitcoind getblockheader result was malformed (not object): %s\n", result.write());
            return false;
        }

        UniValue confirmations = find_value(result.get_obj(), "confirmations");
        if (!confirmations.isNum() || confirmations.get_int64() < nMinConfirmationDepth) {
            LogPrintf("Insufficient confirmations (got %s, need at least %d).\n", confirmations.write(), nMinConfirmationDepth);
            return false;
        }

        // Only perform extra test if nbTxs has been provided (non-zero).
        if (nbTxs != 0) {
            UniValue nTx = find_value(result.get_obj(), "nTx");
            if (!nTx.isNum() || nTx.get_int64() != nbTxs) {
                LogPrintf("ERROR: Invalid number of transactions in merkle block for %s (got %s, need exactly %d)\n",
                        hash.GetHex(), nTx.write(), nbTxs);
                return false;
            }
        }
    } catch (CConnectionFailed&) {
        LogPrintf("WARNING: Lost connection to mainchain daemon RPC; will retry.\n");
        return false;
    } catch (...) {
        LogPrintf("WARNING: Failure connecting to mainchain daemon RPC; will retry.\n");
        return false;
    }
    return true;
}
