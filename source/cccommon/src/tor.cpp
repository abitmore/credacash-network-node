/*
 * CredaCash (TM) cryptocurrency and blockchain
 *
 * Copyright (C) 2015-2025 Creda Foundation, Inc., or its contributors
 *
 * tor.cpp
*/

#include "CCdef.h"
#include "CCboost.hpp"
#include "ccserver/torservice.hpp"
#include "tor.h"
#include "apputil.h"
#include "osutil.h"

static void tor_hidden_service_config(vector<wstring> &params, wstring &service_port_list, const TorService& service, bool external_tor)
{
	if (service.enabled && service.tor_service)
	{
		wstring dir = service.app_data_dir + s2w(service.tor_hostname_subdir);

		if (service.tor_new_hostname && !external_tor)
		{
			delete_file(dir + WIDE(PATH_DELIMITER) + L"private_key");
			delete_file(dir + WIDE(PATH_DELIMITER) + L"hs_ed25519_secret_key");
			delete_file(dir + WIDE(PATH_DELIMITER) + L"hs_ed25519_public_key");
			delete_file(dir + WIDE(PATH_DELIMITER) + L"hostname");
		}

		params.push_back(L"+HiddenServiceDir");
		params.push_back(dir);

		params.push_back(L"HiddenServicePort");
		params.push_back(L"443 " + to_wstring(service.port));

		params.push_back(L"HiddenServiceVersion");
		params.push_back(L"3");

		if (service.tor_auth == 1)
		{
			params.push_back(L"HiddenServiceAuthorizeClient");
			params.push_back(L"basic");
		}

		service_port_list += L" " + to_wstring(service.port);
	}
}

void tor_start(const wstring& process_dir, const wstring& tor_exe, const int tor_port, const wstring& tor_config, const wstring& app_data_dir, bool need_outgoing, vector<TorService*>& services, unsigned tor_control_service_index)
{
	bool external_tor = (tor_exe == L"external");
	bool need_tor = need_outgoing;

	vector<wstring> params;
	wstring service_port_list;

	if (external_tor)
		params.push_back(L"tor");
	else
		params.push_back(tor_exe);

	if (tor_config.length() && tor_config.compare(L"."))
	{
		params.push_back(L"-f");
		params.push_back(tor_config);
	}

	params.push_back(L"DataDirectory");
	params.push_back(app_data_dir + s2w(TOR_SUBDIR));

	params.push_back(L"+SOCKSPort");
	params.push_back(to_wstring(tor_port));

	if (tor_control_service_index < services.size() && services[tor_control_service_index]->enabled)
	{
		need_tor = true;

		params.push_back(L"+ControlPort");
		params.push_back(to_wstring(services[tor_control_service_index]->port));

		params.push_back(L"HashedControlPassword");
		params.push_back(L"16:" + s2w(services[tor_control_service_index]->password_string));
	}

	if (!need_tor)
	{
		BOOST_LOG_TRIVIAL(info) << "No Tor services or outgoing proxy needed";
		return;
	}

	for (auto service : services)
		tor_hidden_service_config(params, service_port_list, *service, external_tor);

	params.push_back(L"+LongLivedPorts");
	params.push_back(L"443" + service_port_list);

	tor_start_process(process_dir, tor_exe, params, external_tor);
}

void tor_start_process(const wstring& process_dir, const wstring& tor_exe, vector<wstring> &params, bool external_tor)
{
	wstring paramline;

	//cerr << "tor_start_process " << w2s(tor_exe) << endl;

	for (auto param : params)
	{
		auto quote = (param.find(L" ") != wstring::npos);
		//BOOST_LOG_TRIVIAL(info) << "tor_start_process quote " << quote << " param " << w2s(param) << endl;
		if (quote) paramline += L'"';
		paramline += param;
		if (quote) paramline += L'"';
		paramline += L' ';
	}

	if (external_tor)
	{
		BOOST_LOG_TRIVIAL(info) << "Tor command line: " << w2s(paramline);
		BOOST_LOG_TRIVIAL(info) << "Skipping Tor launch; Tor must be launched and managed externally";

		return;
	}

#ifdef _WIN32
	BOOST_LOG_TRIVIAL(info) << "Tor process directory: " << w2s(process_dir);
	PROCESS_INFORMATION pi;
#else
	pid_t pid;
#endif

	BOOST_LOG_TRIVIAL(info) << "Tor executable: " << w2s(tor_exe);
	BOOST_LOG_TRIVIAL(info) << "Tor command line: " << w2s(paramline);

	bool tor_running = false;

	while (!g_shutdown || g_is_dll)
	{

#ifdef _WIN32
		STARTUPINFOW si;
		memset(&si, 0, sizeof(si));
		si.cb = sizeof(si);
		si.dwFlags |= STARTF_USESTDHANDLES;
		si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
		si.hStdError = si.hStdOutput;
		si.hStdInput = si.hStdOutput;

		if (! CreateProcessW(tor_exe.c_str(), &paramline[0], NULL, NULL, TRUE,
				CREATE_NO_WINDOW | DEBUG_PROCESS, NULL, process_dir.length() ? process_dir.c_str() : NULL, &si, &pi))
		{
			const char *msg = "Unable to start Tor";

			BOOST_LOG_TRIVIAL(error) << msg << "; error = " << GetLastError();

			{
				lock_guard<mutex> lock(g_cerr_lock);
				check_cerr_newline();
				cerr << "ERROR: " << msg << endl;
			}

			if (g_is_dll)
				return;

			ccsleep(20);
			continue;
		}

		tor_running = true;
		BOOST_LOG_TRIVIAL(info) << "Tor started";

		// Tor processes was created with DEBUG_PROCESS so that it will exit if this process exits
		// this loop (run in a separate thread) handles and ignores all debug events coming from the subprocess

		while (!g_shutdown || g_is_dll)
		{
			DEBUG_EVENT de;

			if (WaitForDebugEvent(&de, 1000))
			{
				ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);

				if (de.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && de.u.CreateProcessInfo.hFile)
					CloseHandle(de.u.CreateProcessInfo.hFile);

				if (de.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && de.u.LoadDll.hFile)
					CloseHandle(de.u.LoadDll.hFile);

				if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT && de.dwProcessId == pi.dwProcessId && !g_shutdown)
				{
					CloseHandle(pi.hProcess);
					CloseHandle(pi.hThread);

					tor_running = false;

					BOOST_LOG_TRIVIAL(error) << "Tor process exited unexpectedly";

					if (g_is_dll)
						return;

					ccsleep(10);

					BOOST_LOG_TRIVIAL(error) << "Attempting to restart Tor...";

					break;
				}
			}
			else if (GetLastError() != ERROR_SEM_TIMEOUT)
			{
				BOOST_LOG_TRIVIAL(debug) << "WaitForDebugEvent error " << GetLastError();
				ccsleep(2);
			}
		}

#else // _WIN32

		vector<string> args;
		vector<char*> argv;

		for (auto param : params)
			args.push_back(w2s(param));

		for (unsigned i = 0; i < args.size(); ++i)
			argv.push_back(&args[i][0]);

		//for (auto arg : argv)
		//	BOOST_LOG_TRIVIAL(debug) << "tor_start_process " << arg;

		argv.push_back(NULL);

		int pipefd[2];
		pipefd[0] = pipefd[1] = -1;
		pipe(pipefd);

		pid = fork();
		
		if (pid == 0)
		{
			// child process:
			if (g_is_dll)
				dup2(pipefd[1], STDOUT_FILENO); // Redirect stdout to pipe write end
			close(pipefd[0]);
			close(pipefd[1]);
			execvp(w2s(tor_exe).c_str(), argv.data());
			BOOST_LOG_TRIVIAL(error) << "tor_spawn exec error " << errno;
			_exit(errno);
		}

		if (pid == -1)
		{
			const char *msg = "Tor process fork error: ";
			BOOST_LOG_TRIVIAL(error) << msg << errno;

			{
				lock_guard<mutex> lock(g_cerr_lock);
				check_cerr_newline();
				cerr << "ERROR: " << msg << errno << endl;
			}

			if (g_is_dll)
				return;

			ccsleep(20);
			continue;
		}

	    close(pipefd[1]);

		tor_running = true;
		BOOST_LOG_TRIVIAL(info) << "Tor started, pid " << pid;

		while (true)
		{
			char buf[32*1024];
			ssize_t nbytes;
			while (g_is_dll && (nbytes = read(pipefd[0], buf, sizeof(buf)-1)) > 0)
			{
				while (nbytes > 0 && (buf[nbytes-1] == ' ' || buf[nbytes-1] == '\t' || buf[nbytes-1] == '\n' || buf[nbytes-1] == '\r'))
					--nbytes;

				buf[nbytes] = 0;

				if (nbytes > 0)
					BOOST_LOG_TRIVIAL(info) << "Tor: " << buf;
			}

			auto rc = waitpid(pid, NULL, WNOHANG);
			if (rc > 0)
			{
				close(pipefd[0]);

				tor_running = false;

				BOOST_LOG_TRIVIAL(error) << "Tor process " << rc << " exited unexpectedly";

				if (g_is_dll)
					return;

				BOOST_LOG_TRIVIAL(error) << "Attempting to restart Tor...";

				break;
			}

			if (ccsleep(1) && !g_is_dll)
				break;
		}
#endif
	}

	//ccsleep(5);	// for testing

	if (tor_running)
	{
		BOOST_LOG_TRIVIAL(info) << "Terminating Tor process";

#ifdef _WIN32
		TerminateProcess(pi.hProcess, 0);
#else
		kill(pid, SIGTERM);
#endif
	}

	BOOST_LOG_TRIVIAL(info) << "Tor monitor thread ending";
}
