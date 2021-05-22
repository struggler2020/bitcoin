// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "db.h"
#include "walletdb.h"
#include "bitcoinrpc.h"
#include "net.h"
#include "init.h"
#include "util.h"
#include "ui_interface.h"
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem/convenience.hpp>
#include <boost/interprocess/sync/file_lock.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <openssl/crypto.h>

#ifndef WIN32
#include <signal.h>
#endif

using namespace std;
using namespace boost;

CWallet* pwalletMain;
CClientUIInterface uiInterface;

//////////////////////////////////////////////////////////////////////////////
//
// Shutdown
//

void ExitTimeout(void* parg)
{
#ifdef WIN32
    Sleep(5000);
    ExitProcess(0);
#endif
}

void StartShutdown()
{
#ifdef QT_GUI
    // ensure we leave the Qt main loop for a clean GUI exit (Shutdown() is called in bitcoin.cpp afterwards)
    uiInterface.QueueShutdown();
#else
    // Without UI, Shutdown() can simply be started in a new thread
    NewThread(Shutdown, NULL);
#endif
}

void Shutdown(void* parg)
{
    static CCriticalSection cs_Shutdown;
    static bool fTaken;

    // Make this thread recognisable as the shutdown thread
    RenameThread("bitcoin-shutoff");

    bool fFirstThread = false;
    {
        TRY_LOCK(cs_Shutdown, lockShutdown);
        if (lockShutdown)
        {
            fFirstThread = !fTaken;
            fTaken = true;
        }
    }
    static bool fExit;
    if (fFirstThread)
    {
        fShutdown = true;
        nTransactionsUpdated++;
        bitdb.Flush(false);
        StopNode();
        bitdb.Flush(true);
        boost::filesystem::remove(GetPidFile());
        UnregisterWallet(pwalletMain);
        delete pwalletMain;
        NewThread(ExitTimeout, NULL);
        Sleep(50);
        printf("Bitcoin exited\n\n");
        fExit = true;
#ifndef QT_GUI
        // ensure non-UI client gets exited here, but let Bitcoin-Qt reach 'return 0;' in bitcoin.cpp
        exit(0);
#endif
    }
    else
    {
        while (!fExit)
            Sleep(500);
        Sleep(100);
        ExitThread(0);
    }
}

void HandleSIGTERM(int)
{
    fRequestShutdown = true;
}

void HandleSIGHUP(int)
{
    fReopenDebugLog = true;
}





//////////////////////////////////////////////////////////////////////////////
//
// Start
//
#if !defined(QT_GUI)
bool AppInit(int argc, char* argv[])
{
    bool fRet = false;
    try
    {
        //
        // Parameters
        //
        // If Qt is used, parameters/bitcoin.conf are parsed in qt/bitcoin.cpp's main()
        ParseParameters(argc, argv);
		//将int argc, char* argv[]传递过去后做初步的处理
        if (!boost::filesystem::is_directory(GetDataDir(false)))
        {
            fprintf(stderr, "Error: Specified directory does not exist\n");
            Shutdown(NULL);
        }
		//创建数据目录
        ReadConfigFile(mapArgs, mapMultiArgs);//读取conf.ini，配置文件里面的内容并存储mapArgs, mapMultiArgs

        if (mapArgs.count("-?") || mapArgs.count("--help"))
        {
            // First part of help message is specific to bitcoind / RPC client
            std::string strUsage = _("Bitcoin version") + " " + FormatFullVersion() + "\n\n" +
                _("Usage:") + "\n" +
                  "  bitcoind [options]                     " + "\n" +
                  "  bitcoind [options] <command> [params]  " + _("Send command to -server or bitcoind") + "\n" +
                  "  bitcoind [options] help                " + _("List commands") + "\n" +
                  "  bitcoind [options] help <command>      " + _("Get help for a command") + "\n";

            strUsage += "\n" + HelpMessage();

            fprintf(stdout, "%s", strUsage.c_str());
            return false;
        }//如何输入的是--help，则显示相关的提示信息。

        // Command-line RPC
        for (int i = 1; i < argc; i++)
            if (!IsSwitchChar(argv[i][0]) && !boost::algorithm::istarts_with(argv[i], "bitcoin:"))
                fCommandLine = true;//不带-符号，我们则认为是需要bitcoind执行cli命令，所以将fCommandLine置位为真

        if (fCommandLine)
        {
            int ret = CommandLineRPC(argc, argv);
            exit(ret);
        }

        fRet = AppInit2();
    }
    catch (std::exception& e) {
        PrintException(&e, "AppInit()");
    } catch (...) {
        PrintException(NULL, "AppInit()");
    }
    if (!fRet)
        Shutdown(NULL);
    return fRet;
}

extern void noui_connect();
int main(int argc, char* argv[])
{
    bool fRet = false;

    // Connect bitcoind signal handlers
    noui_connect();//实现子线程与主线程的消息处理

    fRet = AppInit(argc, argv);

    if (fRet && fDaemon)
        return 0;

    return 1;
}
#endif

bool static InitError(const std::string &str)
{
    uiInterface.ThreadSafeMessageBox(str, _("Bitcoin"), CClientUIInterface::OK | CClientUIInterface::MODAL);
    return false;
}

bool static InitWarning(const std::string &str)
{
    uiInterface.ThreadSafeMessageBox(str, _("Bitcoin"), CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION | CClientUIInterface::MODAL);
    return true;
}


bool static Bind(const CService &addr, bool fError = true) {
    if (IsLimited(addr))
        return false;
    std::string strError;
    if (!BindListenPort(addr, strError)) {
        if (fError)
            return InitError(strError);
        return false;
    }
    return true;
}

// Core-specific options shared between UI and daemon
std::string HelpMessage()
{
    string strUsage = _("Options:") + "\n" +
        "  -?                     " + _("This help message") + "\n" +
        "  -conf=<file>           " + _("Specify configuration file (default: bitcoin.conf)") + "\n" +
        "  -pid=<file>            " + _("Specify pid file (default: bitcoind.pid)") + "\n" +
        "  -gen                   " + _("Generate coins") + "\n" +
        "  -gen=0                 " + _("Don't generate coins") + "\n" +
        "  -datadir=<dir>         " + _("Specify data directory") + "\n" +
        "  -dbcache=<n>           " + _("Set database cache size in megabytes (default: 25)") + "\n" +
        "  -dblogsize=<n>         " + _("Set database disk log size in megabytes (default: 100)") + "\n" +
        "  -timeout=<n>           " + _("Specify connection timeout in milliseconds (default: 5000)") + "\n" +
        "  -proxy=<ip:port>       " + _("Connect through socks proxy") + "\n" +
        "  -socks=<n>             " + _("Select the version of socks proxy to use (4-5, default: 5)") + "\n" +
        "  -tor=<ip:port>         " + _("Use proxy to reach tor hidden services (default: same as -proxy)") + "\n"
        "  -dns                   " + _("Allow DNS lookups for -addnode, -seednode and -connect") + "\n" +
        "  -port=<port>           " + _("Listen for connections on <port> (default: 8333 or testnet: 18333)") + "\n" +
        "  -maxconnections=<n>    " + _("Maintain at most <n> connections to peers (default: 125)") + "\n" +
        "  -addnode=<ip>          " + _("Add a node to connect to and attempt to keep the connection open") + "\n" +
        "  -connect=<ip>          " + _("Connect only to the specified node(s)") + "\n" +
        "  -seednode=<ip>         " + _("Connect to a node to retrieve peer addresses, and disconnect") + "\n" +
        "  -externalip=<ip>       " + _("Specify your own public address") + "\n" +
        "  -onlynet=<net>         " + _("Only connect to nodes in network <net> (IPv4, IPv6 or Tor)") + "\n" +
        "  -discover              " + _("Discover own IP address (default: 1 when listening and no -externalip)") + "\n" +
        "  -irc                   " + _("Find peers using internet relay chat (default: 0)") + "\n" +
        "  -listen                " + _("Accept connections from outside (default: 1 if no -proxy or -connect)") + "\n" +
        "  -bind=<addr>           " + _("Bind to given address. Use [host]:port notation for IPv6") + "\n" +
        "  -dnsseed               " + _("Find peers using DNS lookup (default: 1 unless -connect)") + "\n" +
        "  -banscore=<n>          " + _("Threshold for disconnecting misbehaving peers (default: 100)") + "\n" +
        "  -bantime=<n>           " + _("Number of seconds to keep misbehaving peers from reconnecting (default: 86400)") + "\n" +
        "  -maxreceivebuffer=<n>  " + _("Maximum per-connection receive buffer, <n>*1000 bytes (default: 5000)") + "\n" +
        "  -maxsendbuffer=<n>     " + _("Maximum per-connection send buffer, <n>*1000 bytes (default: 1000)") + "\n" +
#ifdef USE_UPNP
#if USE_UPNP
        "  -upnp                  " + _("Use UPnP to map the listening port (default: 1 when listening)") + "\n" +
#else
        "  -upnp                  " + _("Use UPnP to map the listening port (default: 0)") + "\n" +
#endif
#endif
        "  -detachdb              " + _("Detach block and address databases. Increases shutdown time (default: 0)") + "\n" +
        "  -paytxfee=<amt>        " + _("Fee per KB to add to transactions you send") + "\n" +
#ifdef QT_GUI
        "  -server                " + _("Accept command line and JSON-RPC commands") + "\n" +
#endif
#if !defined(WIN32) && !defined(QT_GUI)
        "  -daemon                " + _("Run in the background as a daemon and accept commands") + "\n" +
#endif
        "  -testnet               " + _("Use the test network") + "\n" +
        "  -debug                 " + _("Output extra debugging information. Implies all other -debug* options") + "\n" +
        "  -debugnet              " + _("Output extra network debugging information") + "\n" +
        "  -logtimestamps         " + _("Prepend debug output with timestamp") + "\n" +
        "  -shrinkdebugfile       " + _("Shrink debug.log file on client startup (default: 1 when no -debug)") + "\n" +
        "  -printtoconsole        " + _("Send trace/debug info to console instead of debug.log file") + "\n" +
#ifdef WIN32
        "  -printtodebugger       " + _("Send trace/debug info to debugger") + "\n" +
#endif
        "  -rpcuser=<user>        " + _("Username for JSON-RPC connections") + "\n" +
        "  -rpcpassword=<pw>      " + _("Password for JSON-RPC connections") + "\n" +
        "  -rpcport=<port>        " + _("Listen for JSON-RPC connections on <port> (default: 8332 or testnet: 18332)") + "\n" +
        "  -rpcallowip=<ip>       " + _("Allow JSON-RPC connections from specified IP address") + "\n" +
        "  -rpcconnect=<ip>       " + _("Send commands to node running on <ip> (default: 127.0.0.1)") + "\n" +
        "  -blocknotify=<cmd>     " + _("Execute command when the best block changes (%s in cmd is replaced by block hash)") + "\n" +
        "  -upgradewallet         " + _("Upgrade wallet to latest format") + "\n" +
        "  -keypool=<n>           " + _("Set key pool size to <n> (default: 100)") + "\n" +
        "  -rescan                " + _("Rescan the block chain for missing wallet transactions") + "\n" +
        "  -salvagewallet         " + _("Attempt to recover private keys from a corrupt wallet.dat") + "\n" +
        "  -checkblocks=<n>       " + _("How many blocks to check at startup (default: 2500, 0 = all)") + "\n" +
        "  -checklevel=<n>        " + _("How thorough the block verification is (0-6, default: 1)") + "\n" +
        "  -loadblock=<file>      " + _("Imports blocks from external blk000?.dat file") + "\n" +

        "\n" + _("Block creation options:") + "\n" +
        "  -blockminsize=<n>      "   + _("Set minimum block size in bytes (default: 0)") + "\n" +
        "  -blockmaxsize=<n>      "   + _("Set maximum block size in bytes (default: 250000)") + "\n" +
        "  -blockprioritysize=<n> "   + _("Set maximum size of high-priority/low-fee transactions in bytes (default: 27000)") + "\n" +

        "\n" + _("SSL options: (see the Bitcoin Wiki for SSL setup instructions)") + "\n" +
        "  -rpcssl                                  " + _("Use OpenSSL (https) for JSON-RPC connections") + "\n" +
        "  -rpcsslcertificatechainfile=<file.cert>  " + _("Server certificate file (default: server.cert)") + "\n" +
        "  -rpcsslprivatekeyfile=<file.pem>         " + _("Server private key (default: server.pem)") + "\n" +
        "  -rpcsslciphers=<ciphers>                 " + _("Acceptable ciphers (default: TLSv1+HIGH:!SSLv2:!aNULL:!eNULL:!AH:!3DES:@STRENGTH)") + "\n";

    return strUsage;
}

/** Initialize bitcoin.
 *  @pre Parameters should be parsed and config file should be read.
 */
bool AppInit2()
//2.3节appinit2 step1到6
{
    // ********************************************************* Step 1: setup
#ifdef _MSC_VER
//_MSC_VER是微软的预编译控制,与区块链无关
    // Turn off Microsoft heap dump noise
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFileA("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0));
#endif
#if _MSC_VER >= 1400
    // Disable confusing "helpful" text message on abort, Ctrl-C
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif

#ifdef WIN32
    // Enable Data Execution Prevention (DEP)
    // Minimum supported OS versions: WinXP SP3, WinVista >= SP1, Win Server 2008
    // A failure is non-critical and needs no further attention!
#ifndef PROCESS_DEP_ENABLE
// We define this here, because GCCs winbase.h limits this to _WIN32_WINNT >= 0x0601 (Windows 7),
// which is not correct. Can be removed, when GCCs winbase.h is fixed!
#define PROCESS_DEP_ENABLE 0x00000001
#endif
    typedef BOOL (WINAPI *PSETPROCDEPPOL)(DWORD);
    PSETPROCDEPPOL setProcDEPPol = (PSETPROCDEPPOL)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "SetProcessDEPPolicy");
    if (setProcDEPPol != NULL) setProcDEPPol(PROCESS_DEP_ENABLE);
#endif
//同上

#ifndef WIN32
    umask(077);

    // Clean shutdown on SIGTERM
    struct sigaction sa;
    sa.sa_handler = HandleSIGTERM;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    // Reopen debug.log on SIGHUP
    struct sigaction sa_hup;
    sa_hup.sa_handler = HandleSIGHUP;
    sigemptyset(&sa_hup.sa_mask);
    sa_hup.sa_flags = 0;
    sigaction(SIGHUP, &sa_hup, NULL);
#endif
//同上

    // ********************************************************* Step 2: parameter interactions
    //这里有很多参数都过时了，所以只是简单的说说意思即可

    fTestNet = GetBoolArg("-testnet");//判断是否为真，很简单
    if (fTestNet) {
        SoftSetBoolArg("-irc", true);//当SoftSetBoolArg为真的时候，通过SoftSetArg赋值
        //上面这俩函数都在这里面广泛的应用，记住即可。
    }

    if (mapArgs.count("-bind")) {
        // when specifying an explicit binding address, you want to listen on it
        // even when -connect or -proxy is specified
        //-bind = <地址>
       //绑定到给定地址并始终听取它。使用[host]：端口表示
        SoftSetBoolArg("-listen", true);
    }

    if (mapArgs.count("-connect") && mapMultiArgs["-connect"].size() > 0) {
		//仅连接到指定的节点
        // when only connecting to trusted nodes, do not seed via DNS, or listen by default
        SoftSetBoolArg("-dnsseed", false);
        SoftSetBoolArg("-listen", false);
    }

    if (mapArgs.count("-proxy")) {
		//通过SOCKS5代理连接
        // to protect privacy, do not listen by default if a proxy server is specified
        SoftSetBoolArg("-listen", false);
    }

    if (!GetBoolArg("-listen", true)) {
		//监听的端口
        // do not map ports or try to retrieve public IP when not listening (pointless)
        SoftSetBoolArg("-upnp", false);
        SoftSetBoolArg("-discover", false);
    }

    if (mapArgs.count("-externalip")) {
        // if an explicit public IP is specified, do not try to find others
        //指定您自己的公共地址
        SoftSetBoolArg("-discover", false);
    }

    if (GetBoolArg("-salvagewallet")) {
        // Rewrite just private keys: rescan to find transactions
        //尝试在启动时从损坏的钱包中恢复交易
        SoftSetBoolArg("-rescan", true);
    }

    // ********************************************************* Step 3: parameter-to-internal-flags

    fDebug = GetBoolArg("-debug");

    // -debug implies fDebug*
    if (fDebug)
        fDebugNet = true;
    else
        fDebugNet = GetBoolArg("-debugnet");
	//是否处于调试状态

    bitdb.SetDetach(GetBoolArg("-detachdb", false));

#if !defined(WIN32) && !defined(QT_GUI)
    fDaemon = GetBoolArg("-daemon");
#else
    fDaemon = false;
#endif

    if (fDaemon)
        fServer = true;
    else
        fServer = GetBoolArg("-server");

    /* force fServer when running without GUI */
#if !defined(QT_GUI)
    fServer = true;
#endif
    fPrintToConsole = GetBoolArg("-printtoconsole");
    fPrintToDebugger = GetBoolArg("-printtodebugger");
    fLogTimestamps = GetBoolArg("-logtimestamps");

    if (mapArgs.count("-timeout"))//毫秒为单位指定连接超时
    {
        int nNewTimeout = GetArg("-timeout", 5000);
        if (nNewTimeout > 0 && nNewTimeout < 600000)
            nConnectTimeout = nNewTimeout;
    }

    // Continue to put "/P2SH/" in the coinbase to monitor
    // BIP16 support.
    // This can be removed eventually...
    const char* pszP2SH = "/P2SH/";
    COINBASE_FLAGS << std::vector<unsigned char>(pszP2SH, pszP2SH+strlen(pszP2SH));
	//P2SH,多重签名，我们将在后面专门一节说一下

    if (mapArgs.count("-paytxfee"))//（以BTC / kB为单位）添加到您发送的交易中
    {
        if (!ParseMoney(mapArgs["-paytxfee"], nTransactionFee))
            return InitError(strprintf(_("Invalid amount for -paytxfee=<amount>: '%s'"), mapArgs["-paytxfee"].c_str()));
        if (nTransactionFee > 0.25 * COIN)
            InitWarning(_("Warning: -paytxfee is set very high! This is the transaction fee you will pay if you send a transaction."));
    }

	//所以我们看到，这部分也是比较零碎的内容，等于是对配置文件的进一步解释

    // ********************************************************* Step 4: application initialization: dir lock, daemonize, pidfile, debug log

    std::string strDataDir = GetDataDir().string();

    // Make sure only a single Bitcoin process is using the data directory.
    boost::filesystem::path pathLockFile = GetDataDir() / ".lock";
    FILE* file = fopen(pathLockFile.string().c_str(), "a"); // empty lock file; created if it doesn't exist.
    if (file) fclose(file);
    static boost::interprocess::file_lock lock(pathLockFile.string().c_str());
    if (!lock.try_lock())
        return InitError(strprintf(_("Cannot obtain a lock on data directory %s.  Bitcoin is probably already running."), strDataDir.c_str()));
	//锁定目录

#if !defined(WIN32) && !defined(QT_GUI)
    if (fDaemon)
		//如果作为守护程序，则建立这个线程
    {
        // Daemonize
        pid_t pid = fork();
        if (pid < 0)
        {
            fprintf(stderr, "Error: fork() returned %d errno %d\n", pid, errno);
            return false;
        }
        if (pid > 0)
        {
            CreatePidFile(GetPidFile(), pid);
            return true;
        }

        pid_t sid = setsid();
        if (sid < 0)
            fprintf(stderr, "Error: setsid() returned %d errno %d\n", sid, errno);
    }
#endif

    if (GetBoolArg("-shrinkdebugfile", !fDebug))
        ShrinkDebugFile();
    printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    printf("Bitcoin version %s (%s)\n", FormatFullVersion().c_str(), CLIENT_DATE.c_str());
    printf("Using OpenSSL version %s\n", SSLeay_version(SSLEAY_VERSION));
    if (!fLogTimestamps)
        printf("Startup time: %s\n", DateTimeStrFormat("%x %H:%M:%S", GetTime()).c_str());
    printf("Default data directory %s\n", GetDefaultDataDir().string().c_str());
    printf("Used data directory %s\n", strDataDir.c_str());
    std::ostringstream strErrors;

    if (fDaemon)
        fprintf(stdout, "Bitcoin server starting\n");
	//打印一系列的调试信息

    int64 nStart;

    // ********************************************************* Step 5: verify database integrity

    uiInterface.InitMessage(_("Verifying database integrity..."));

    if (!bitdb.Open(GetDataDir()))
    {
        string msg = strprintf(_("Error initializing database environment %s!"
                                 " To recover, BACKUP THAT DIRECTORY, then remove"
                                 " everything from it except for wallet.dat."), strDataDir.c_str());
        return InitError(msg);
    }

    if (GetBoolArg("-salvagewallet"))
    {
        // Recover readable keypairs:
        if (!CWalletDB::Recover(bitdb, "wallet.dat", true))//修复钱包，看一下这个函数
            return false;
    }

    if (filesystem::exists(GetDataDir() / "wallet.dat"))
    {
        CDBEnv::VerifyResult r = bitdb.Verify("wallet.dat", CWalletDB::Recover);//验证钱包
        if (r == CDBEnv::RECOVER_OK)
        {
            string msg = strprintf(_("Warning: wallet.dat corrupt, data salvaged!"
                                     " Original wallet.dat saved as wallet.{timestamp}.bak in %s; if"
                                     " your balance or transactions are incorrect you should"
                                     " restore from a backup."), strDataDir.c_str());
            uiInterface.ThreadSafeMessageBox(msg, _("Bitcoin"), CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION | CClientUIInterface::MODAL);
        }
        if (r == CDBEnv::RECOVER_FAIL)
            return InitError(_("wallet.dat corrupt, salvage failed"));
    }

    // ********************************************************* Step 6: network initialization

    int nSocksVersion = GetArg("-socks", 5);

    if (nSocksVersion != 4 && nSocksVersion != 5)
        return InitError(strprintf(_("Unknown -socks proxy version requested: %i"), nSocksVersion));
	//确定版本号

    if (mapArgs.count("-onlynet")) {
        std::set<enum Network> nets;
        BOOST_FOREACH(std::string snet, mapMultiArgs["-onlynet"]) {
            enum Network net = ParseNetwork(snet);
            if (net == NET_UNROUTABLE)
                return InitError(strprintf(_("Unknown network specified in -onlynet: '%s'"), snet.c_str()));
            nets.insert(net);
        }
        for (int n = 0; n < NET_MAX; n++) {
            enum Network net = (enum Network)n;
            if (!nets.count(net))
                SetLimited(net);
        }
    }
	//仅通过net传出连接，不用管这个，很少用

	
#if defined(USE_IPV6)
#if ! USE_IPV6
    else
        SetLimited(NET_IPV6);
#endif
#endif

    CService addrProxy;
    bool fProxy = false;
    if (mapArgs.count("-proxy")) {
        addrProxy = CService(mapArgs["-proxy"], 9050);
        if (!addrProxy.IsValid())
            return InitError(strprintf(_("Invalid -proxy address: '%s'"), mapArgs["-proxy"].c_str()));

        if (!IsLimited(NET_IPV4))
            SetProxy(NET_IPV4, addrProxy, nSocksVersion);
        if (nSocksVersion > 4) {
#ifdef USE_IPV6
            if (!IsLimited(NET_IPV6))
                SetProxy(NET_IPV6, addrProxy, nSocksVersion);
#endif
            SetNameProxy(addrProxy, nSocksVersion);
        }
        fProxy = true;
    }
	//如果用代理服务器，很少用的

    // -tor can override normal proxy, -notor disables tor entirely
    if (!(mapArgs.count("-tor") && mapArgs["-tor"] == "0") && (fProxy || mapArgs.count("-tor"))) {
        CService addrOnion;
        if (!mapArgs.count("-tor"))
            addrOnion = addrProxy;
        else
            addrOnion = CService(mapArgs["-tor"], 9050);
        if (!addrOnion.IsValid())
            return InitError(strprintf(_("Invalid -tor address: '%s'"), mapArgs["-tor"].c_str()));
        SetProxy(NET_TOR, addrOnion, 5);
        SetReachable(NET_TOR);
    }
	//是否用洋葱头，很少用到的

    // see Step 2: parameter interactions for more information about these
    //这些函数的应用和区块链本身关系不大，所以不做说明
    fNoListen = !GetBoolArg("-listen", true);
    fDiscover = GetBoolArg("-discover", true);
    fNameLookup = GetBoolArg("-dns", true);
#ifdef USE_UPNP
    fUseUPnP = GetBoolArg("-upnp", USE_UPNP);
#endif

    bool fBound = false;
    if (!fNoListen)
    {
        std::string strError;
        if (mapArgs.count("-bind")) {
            BOOST_FOREACH(std::string strBind, mapMultiArgs["-bind"]) {
                CService addrBind;
                if (!Lookup(strBind.c_str(), addrBind, GetListenPort(), false))
                    return InitError(strprintf(_("Cannot resolve -bind address: '%s'"), strBind.c_str()));
                fBound |= Bind(addrBind);
            }
        } else {
            struct in_addr inaddr_any;
            inaddr_any.s_addr = INADDR_ANY;
#ifdef USE_IPV6
            if (!IsLimited(NET_IPV6))
                fBound |= Bind(CService(in6addr_any, GetListenPort()), false);
#endif
            if (!IsLimited(NET_IPV4))
                fBound |= Bind(CService(inaddr_any, GetListenPort()), !fBound);
        }
        if (!fBound)
            return InitError(_("Failed to listen on any port. Use -listen=0 if you want this."));
    }

    if (mapArgs.count("-externalip"))
    {
        BOOST_FOREACH(string strAddr, mapMultiArgs["-externalip"]) {
            CService addrLocal(strAddr, GetListenPort(), fNameLookup);
            if (!addrLocal.IsValid())
                return InitError(strprintf(_("Cannot resolve -externalip address: '%s'"), strAddr.c_str()));
            AddLocal(CService(strAddr, GetListenPort(), fNameLookup), LOCAL_MANUAL);
        }
    }

    BOOST_FOREACH(string strDest, mapMultiArgs["-seednode"])
        AddOneShot(strDest);

    // ********************************************************* Step 7: load blockchain
    //读取区块链并进行校验，分第一次启动和第n次启动
    //2.3 step7读取区块链

    if (!bitdb.Open(GetDataDir()))
    {
        string msg = strprintf(_("Error initializing database environment %s!"
                                 " To recover, BACKUP THAT DIRECTORY, then remove"
                                 " everything from it except for wallet.dat."), strDataDir.c_str());
        return InitError(msg);
    }
	//目录判定
	
    if (GetBoolArg("-loadblockindextest"))
    {
        CTxDB txdb("r");
        txdb.LoadBlockIndex();
        PrintBlockTree();
        return false;
    }
	//读取测试链，很少用到

    uiInterface.InitMessage(_("Loading block index..."));
    printf("Loading block index...\n");
    nStart = GetTimeMillis();//返回一个时间
    if (!LoadBlockIndex())
        return InitError(_("Error loading blkindex.dat"));
	//读取区块链索引，整个step7主要就是这个函数
	//我们读完step7后则继续分析这个函数

    // as LoadBlockIndex can take several minutes, it's possible the user
    // requested to kill bitcoin-qt during the last operation. If so, exit.
    // As the program has not fully started yet, Shutdown() is possibly overkill.
    if (fRequestShutdown)
    {
        printf("Shutdown requested. Exiting.\n");
        return false;
    }
	//如果出现关闭信号则关闭
    printf(" block index %15"PRI64d"ms\n", GetTimeMillis() - nStart);

    if (GetBoolArg("-printblockindex") || GetBoolArg("-printblocktree"))
    {
        PrintBlockTree();
        return false;
    }//如何需要打印区块链索引则打印，调试类函数

    if (mapArgs.count("-printblock"))
    {
        string strMatch = mapArgs["-printblock"];
        int nFound = 0;
        for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
        {
            uint256 hash = (*mi).first;
            if (strncmp(hash.ToString().c_str(), strMatch.c_str(), strMatch.size()) == 0)
            {
                CBlockIndex* pindex = (*mi).second;
                CBlock block;
                block.ReadFromDisk(pindex);
                block.BuildMerkleTree();
                block.print();
                printf("\n");
                nFound++;
            }
        }
        if (nFound == 0)
            printf("No blocks matching %s were found\n", strMatch.c_str());
        return false;
    }
	//打印指定的区块在，值得注意的主要是block的几个子函数,主要功能就是查找分解并存储，然后打印。

    // ********************************************************* Step 8: load wallet
    //第二章第5节 appinit2（step8），读取钱包
    //读取钱包
    //本step最大的特点是关键代码不是很长，但涉及到的函数还很多，我们尽量从流程的实现讲起。
    //涉及到的一些交易细节，我们将在交易章来专门说明。

    uiInterface.InitMessage(_("Loading wallet..."));
    printf("Loading wallet...\n");
    nStart = GetTimeMillis();
    bool fFirstRun = true;
    pwalletMain = new CWallet("wallet.dat");
    DBErrors nLoadWalletRet = pwalletMain->LoadWallet(fFirstRun);
	//上面几句话很容易理解，导入一个钱包文件并读取
	//我们一会进一步看这个函数LoadWallet（1）
	
    if (nLoadWalletRet != DB_LOAD_OK)
    {
        if (nLoadWalletRet == DB_CORRUPT)//文件损坏故障
            strErrors << _("Error loading wallet.dat: Wallet corrupted") << "\n";
        else if (nLoadWalletRet == DB_NONCRITICAL_ERROR)
        {
            string msg(_("Warning: error reading wallet.dat! All keys read correctly, but transaction data"
                         " or address book entries might be missing or incorrect."));
			//部分数据错误
            uiInterface.ThreadSafeMessageBox(msg, _("Bitcoin"), CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION | CClientUIInterface::MODAL);
        }
        else if (nLoadWalletRet == DB_TOO_NEW)
            strErrors << _("Error loading wallet.dat: Wallet requires newer version of Bitcoin") << "\n";
		//客户端节点太旧
        else if (nLoadWalletRet == DB_NEED_REWRITE)
        {
            strErrors << _("Wallet needed to be rewritten: restart Bitcoin to complete") << "\n";
            printf("%s", strErrors.str().c_str());
            return InitError(strErrors.str());
			//需要回写
        }
        else
            strErrors << _("Error loading wallet.dat") << "\n";
		//其他错误
    }
	//这个判断语句也很清楚，就是如果读取失败，则判断属于哪种情况，并输出信息
	//这个地方不做深入的解释了

    if (GetBoolArg("-upgradewallet", fFirstRun))
    {
        int nMaxVersion = GetArg("-upgradewallet", 0);
        if (nMaxVersion == 0) // the -upgradewallet without argument case
        {
            printf("Performing wallet upgrade to %i\n", FEATURE_LATEST);
            nMaxVersion = CLIENT_VERSION;
            pwalletMain->SetMinVersion(FEATURE_LATEST); // permanently upgrade the wallet immediately
        }
        else
            printf("Allowing wallet upgrade up to %i\n", nMaxVersion);
        if (nMaxVersion < pwalletMain->GetVersion())
            strErrors << _("Cannot downgrade wallet") << "\n";
        pwalletMain->SetMaxVersion(nMaxVersion);
    }//更新钱包的命令，我们一般不用


	//第一次运行钱包则执行下面几个命令
    if (fFirstRun)
    {
        // Create new keyUser and set as default key
        RandAddSeedPerfmon();
		//建立一对公钥和私钥

        CPubKey newDefaultKey;
        if (!pwalletMain->GetKeyFromPool(newDefaultKey, false))
			//在这个函数中首先调用ReserveKeyFromKeyPool查看密钥储备池中的密钥
            strErrors << _("Cannot initialize keypool") << "\n";
        pwalletMain->SetDefaultKey(newDefaultKey);//设定为缺省的钥匙
        if (!pwalletMain->SetAddressBookName(pwalletMain->vchDefaultKey.GetID(), ""))
            strErrors << _("Cannot write default address") << "\n";
    }//说白了就是新建一个钱包。原理方面更详细的解释，我们将在交易章节专门的进行描述。
    //大家在这里知道这几个函数是用来建立一个新钱包就行

    printf("%s", strErrors.str().c_str());
    printf(" wallet      %15"PRI64d"ms\n", GetTimeMillis() - nStart);

    RegisterWallet(pwalletMain);//注册钱包

    CBlockIndex *pindexRescan = pindexBest;
    if (GetBoolArg("-rescan"))
        pindexRescan = pindexGenesisBlock;
    else
    {
        CWalletDB walletdb("wallet.dat");
        CBlockLocator locator;
        if (walletdb.ReadBestBlock(locator))
            pindexRescan = locator.GetBlockIndex();
    }

	//如果使用了-rescan，则需要重新扫描
    if (pindexBest != pindexRescan)
    {
        uiInterface.InitMessage(_("Rescanning..."));
        printf("Rescanning last %i blocks (from block %i)...\n", pindexBest->nHeight - pindexRescan->nHeight, pindexRescan->nHeight);
        nStart = GetTimeMillis();
        pwalletMain->ScanForWalletTransactions(pindexRescan, true);
        printf(" rescan      %15"PRI64d"ms\n", GetTimeMillis() - nStart);
    }
	//2.6节
    // ********************************************************* Step 9: import blocks
	//这是我搜集的说明，我简单念一下。由于这部分内容和区块链的运行关系不大，所以不做详细解释，大家理解即可。
	//bitcoin Core 0.7以上版本的客戶端支援bootstrap.dat檔案。
	//bootstrap.dat檔案包含了從創世區塊開始的大量的區塊資料，
	//可以通過迅雷等下載軟體先下載好，然後放到Bitcoin Core的資料目錄(即AppData/Roaming/Bitcoin 或者 ~/.bitcoin)下即可。 
	//比特幣專案官方每隔一段時間會把資料檔案打包成bootstrap.dat 檔案，可以在比特幣的專案主頁下載區塊資料檔案的種子檔案。
	//通過這種方式下載區塊不僅可以加快區塊同步速度，還減輕了比特幣的P2P網路的流量負擔。 

    if (mapArgs.count("-loadblock"))
    {
        uiInterface.InitMessage(_("Importing blockchain data file."));

        BOOST_FOREACH(string strFile, mapMultiArgs["-loadblock"])
        {
            FILE *file = fopen(strFile.c_str(), "rb");
            if (file)
                LoadExternalBlockFile(file);
        }
    }

    filesystem::path pathBootstrap = GetDataDir() / "bootstrap.dat";
    if (filesystem::exists(pathBootstrap)) {
        uiInterface.InitMessage(_("Importing bootstrap blockchain data file."));

        FILE *file = fopen(pathBootstrap.string().c_str(), "rb");
        if (file) {
            filesystem::path pathBootstrapOld = GetDataDir() / "bootstrap.dat.old";
            LoadExternalBlockFile(file);//我们简单的分析一下
            RenameOver(pathBootstrap, pathBootstrapOld);
        }
    }

    // ********************************************************* Step 10: load peers
    //peers.dat【v0.7.0 及之后的版本】; addr.dat【v0.7.0 之前的版本】
	//对端 IP 地址数据库（特定的格式）。存储对端信息以便更容易重连。
	//该文件使用比特币指定的文件格式，与任何数据库系统不相关；存储 ip 地址以便更容易重新连接。

    uiInterface.InitMessage(_("Loading addresses..."));
    printf("Loading addresses...\n");
    nStart = GetTimeMillis();

    {
        CAddrDB adb;
		//这里需要注意都是，CAddrDB()
		//adb是一个CaddrDB对象，这个对象读取的是存储在我们本地的peers.dat 。
		//这个文件存储的是本机连接的节点文件。这个文件的的路径就在CAddrDB的构造函数中。
		//CAddrDB::CAddrDB()
		//{
		//	pathAddr = GetDataDir() / "peers.dat";
		//}

		//导入节点的核心代码就adb.Read(addrman)这一句。可以看到这里定义了一个CAddrDB的局部对象。
		//然后调用Read函数读取本地的节点文件的数据，并将数据存储在了addrman这个全局对象中。
		//这个addrman定义在net.h中。

        if (!adb.Read(addrman))//进函数里面看看
            printf("Invalid or missing peers.dat; recreating\n");
    }

    printf("Loaded %i addresses from peers.dat  %"PRI64d"ms\n",
           addrman.size(), GetTimeMillis() - nStart);

    // ********************************************************* Step 11: start node

    if (!CheckDiskSpace())//检查磁盘空间
        return false;

    RandAddSeedPerfmon();
	//同step8

    //// debug print
    //信息调试
    printf("mapBlockIndex.size() = %"PRIszu"\n",   mapBlockIndex.size());
    printf("nBestHeight = %d\n",            nBestHeight);
    printf("setKeyPool.size() = %"PRIszu"\n",      pwalletMain->setKeyPool.size());
    printf("mapWallet.size() = %"PRIszu"\n",       pwalletMain->mapWallet.size());
    printf("mapAddressBook.size() = %"PRIszu"\n",  pwalletMain->mapAddressBook.size());

    if (!NewThread(StartNode, NULL))
		//启动节点线程，这个函数本章不打算介绍了，等下一章将详细介绍
        InitError(_("Error: could not start node"));

    if (fServer)
		//启动rpc线程，这个函数本章不打算介绍了，等api章节章将详细介绍
        NewThread(ThreadRPCServer, NULL);
		//第6.1节正式开始介绍
	

    // ********************************************************* Step 12: finished

    uiInterface.InitMessage(_("Done loading"));
    printf("Done loading\n");
	//当看到这里的时候，整个启动就结束了
	
    if (!strErrors.str().empty())
        return InitError(strErrors.str());

     // Add wallet transactions that aren't already in a block to mapTransactions
    pwalletMain->ReacceptWalletTransactions();
	//在这里，因为时间的关系，我们只需要理解为，把钱包交易中的交易添加到内存池中，即可。

#if !defined(QT_GUI)
    // Loop until process is exit()ed from shutdown() function,
    // called from ThreadRPCServer thread when a "stop" command is received.
    while (1)
        Sleep(5000);
#endif

    return true;
}
