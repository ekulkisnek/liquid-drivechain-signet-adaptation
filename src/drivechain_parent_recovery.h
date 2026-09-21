// Copyright (c) 2026 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef ELEMENTS_DRIVECHAIN_PARENT_RECOVERY_H
#define ELEMENTS_DRIVECHAIN_PARENT_RECOVERY_H

#include <univalue.h>

#include <chrono>
#include <stdexcept>
#include <string>

namespace drivechain {

inline bool IsPrunedBlockReply(const UniValue& reply)
{
    const auto& error = reply["error"];
    return error.isObject() && error["code"].isNum() &&
        error["code"].getInt<int>() == -1 && error["message"].isStr() &&
        error["message"].get_str() == "Block not available (pruned data)";
}

/** Availability only. The caller must authenticate the returned block bytes.
 * RPC, deadline and wait callbacks allow deterministic testing of recovery.
 * Never allow recovery while holding consensus locks.
 */
template <typename Rpc, typename Check, typename Wait>
UniValue FetchParentBlockBody(const std::string& hash, bool allow_recovery,
                             Rpc&& rpc, Check&& check, Wait&& wait)
{
    auto checked = [&](const std::string& method, const UniValue& params) -> UniValue {
        check();
        const auto reply = rpc(method, params);
        if (!reply["error"].isNull() || reply["result"].isNull())
            throw std::runtime_error(method + " failed during parent block retrieval");
        return reply["result"];
    };
    UniValue block_params(UniValue::VARR);
    block_params.push_back(hash);
    block_params.push_back(0);
    check();
    auto reply = rpc("getblock", block_params);
    if (!IsPrunedBlockReply(reply)) {
        if (!reply["error"].isNull() || reply["result"].isNull())
            throw std::runtime_error("getblock failed: " + reply["error"].write());
        return reply["result"];
    }
    if (!allow_recovery)
        throw std::runtime_error("pruned parent block requires recovery outside consensus locks");

    auto active_height = [&]() {
        UniValue params(UniValue::VARR);
        params.push_back(hash);
        params.push_back(true);
        const UniValue header = checked("getblockheader", params);
        if (!header["hash"].isStr() || header["hash"].get_str() != hash ||
            !header["height"].isNum() || !header["confirmations"].isNum() ||
            header["height"].getInt<int>() < 0 || header["confirmations"].getInt<int>() <= 0)
            throw std::runtime_error("pruned parent block is not active");
        const int height = header["height"].getInt<int>();
        UniValue height_params(UniValue::VARR);
        height_params.push_back(height);
        const auto active = checked("getblockhash", height_params);
        if (!active.isStr() || active.get_str() != hash)
            throw std::runtime_error("parent chain changed during block recovery");
        return height;
    };
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{30};
    const int height = active_height();
    const auto peers = checked("getpeerinfo", UniValue(UniValue::VARR));
    if (!peers.isArray()) throw std::runtime_error("invalid parent peer response");
    bool requested{false};
    for (const auto& peer : peers.getValues()) {
        if (!peer["id"].isNum() || !peer["servicesnames"].isArray()) continue;
        for (const auto& service : peer["servicesnames"].getValues()) {
            if (!service.isStr() || service.get_str() != "NETWORK") continue;
            UniValue params(UniValue::VARR);
            params.push_back(hash);
            params.push_back(peer["id"]);
            checked("getblockfrompeer", params);
            requested = true;
            break;
        }
        if (requested) break;
    }
    if (!requested) throw std::runtime_error("no parent peer offers full block service");
    for (;;) {
        check();
        if (std::chrono::steady_clock::now() >= deadline)
            throw std::runtime_error("parent block recovery timed out");
        reply = rpc("getblock", block_params);
        if (!IsPrunedBlockReply(reply)) {
            if (!reply["error"].isNull() || reply["result"].isNull())
                throw std::runtime_error("getblock failed during parent block recovery");
            if (active_height() != height)
                throw std::runtime_error("parent block height changed during recovery");
            return reply["result"];
        }
        wait();
    }
}
} // namespace drivechain
#endif
