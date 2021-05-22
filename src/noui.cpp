// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "ui_interface.h"
#include "init.h"
#include "bitcoinrpc.h"

#include <string>

static int noui_ThreadSafeMessageBox(const std::string& message, const std::string& caption, int style)
{
    printf("%s: %s\n", caption.c_str(), message.c_str());
    fprintf(stderr, "%s: %s\n", caption.c_str(), message.c_str());
    return 4;
}

static bool noui_ThreadSafeAskFee(int64 nFeeRequired, const std::string& strCaption)
{
    return true;
}

void noui_connect()
{
    // Connect bitcoind signal handlers
    uiInterface.ThreadSafeMessageBox.connect(noui_ThreadSafeMessageBox);
	//消息弹出框信息提示消息
    uiInterface.ThreadSafeAskFee.connect(noui_ThreadSafeAskFee);
	//对用户问题询问的交互提示消息
}
