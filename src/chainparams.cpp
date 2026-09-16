// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <chainparams.h>

#include <chainparamsbase.h>
#include <common/args.h>
#include <consensus/params.h>
#include <crypto/sha256.h>
#include <deploymentinfo.h>
#include <issuance.h>
#include <primitives/transaction.h>
#include <logging.h>
#include <tinyformat.h>
#include <util/chaintype.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <cassert>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>
#include <bitcoin-build-config.h> // IWYU pragma: keep

using util::SplitString;

void ReadSigNetArgs(const ArgsManager& args, CChainParams::SigNetOptions& options)
{
    if (!args.GetArgs("-signetseednode").empty()) {
        options.seeds.emplace(args.GetArgs("-signetseednode"));
    }
    if (!args.GetArgs("-signetchallenge").empty()) {
        const auto signet_challenge = args.GetArgs("-signetchallenge");
        if (signet_challenge.size() != 1) {
            throw std::runtime_error("-signetchallenge cannot be multiple values.");
        }
        const auto val{TryParseHex<uint8_t>(signet_challenge[0])};
        if (!val) {
            throw std::runtime_error(strprintf("-signetchallenge must be hex, not '%s'.", signet_challenge[0]));
        }
        options.challenge.emplace(*val);
    }
}

void ReadRegTestArgs(const ArgsManager& args, CChainParams::RegTestOptions& options)
{
    if (auto value = args.GetBoolArg("-fastprune")) options.fastprune = *value;
    if (HasTestOption(args, "bip94")) options.enforce_bip94 = true;

    for (const std::string& arg : args.GetArgs("-testactivationheight")) {
        const auto found{arg.find('@')};
        if (found == std::string::npos) {
            throw std::runtime_error(strprintf("Invalid format (%s) for -testactivationheight=name@height.", arg));
        }

        const auto value{arg.substr(found + 1)};
        int32_t height;
        if (!ParseInt32(value, &height) || height < 0 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Invalid height value (%s) for -testactivationheight=name@height.", arg));
        }

        const auto deployment_name{arg.substr(0, found)};
        if (const auto buried_deployment = GetBuriedDeployment(deployment_name)) {
            options.activation_heights[*buried_deployment] = height;
        } else {
            throw std::runtime_error(strprintf("Invalid name (%s) for -testactivationheight=name@height.", arg));
        }
    }

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams = SplitString(strDeployment, ':');
        if (vDeploymentParams.size() < 3 || 4 < vDeploymentParams.size()) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end[:min_activation_height]");
        }
        CChainParams::VersionBitsParameters vbparams{};
        if (!ParseInt64(vDeploymentParams[1], &vbparams.start_time)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &vbparams.timeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        if (vDeploymentParams.size() >= 4) {
            if (!ParseInt32(vDeploymentParams[3], &vbparams.min_activation_height)) {
                throw std::runtime_error(strprintf("Invalid min_activation_height (%s)", vDeploymentParams[3]));
            }
        } else {
            vbparams.min_activation_height = 0;
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                options.version_bits_parameters[Consensus::DeploymentPos(j)] = vbparams;
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld, min_activation_height=%d\n", vDeploymentParams[0], vbparams.start_time, vbparams.timeout, vbparams.min_activation_height);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<const CChainParams> globalChainParams;

bool HasAlphaPeginOneConfirmationUpgrade(const CChainParams& params)
{
    const auto& consensus = params.GetConsensus();
    // Pin the existing Alpha identity, not just a mutable network name or slot.
    // Keep pegin_min_depth=100 in the historical protocol manifest and genesis.
    return params.NetworkIDString() == CBaseChainParams::ELEMENTS &&
        consensus.elements_mode && consensus.has_parent_chain &&
        consensus.drivechain_slot == 24 &&
        consensus.hashGenesisBlock == uint256S("672af009bd90bfc6527a5a9dda4c83aba0048c15cff3697d07e89a7f96fa5bcd") &&
        params.ParentGenesisBlockHash() == uint256S("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f") &&
        consensus.drivechain_protocol_manifest_hash == uint256S("fbd55822590e0e7a3389c2316171068b2fe7ddbb35c52aa010159bfbd92d09e6") &&
        consensus.pegin_min_depth == 100;
}

uint32_t GetDrivechainPeginConfirmationDepth(const CChainParams& params, const int child_height)
{
    if (child_height >= ALPHA_PEGIN_ONE_CONFIRMATION_HEIGHT &&
        HasAlphaPeginOneConfirmationUpgrade(params)) {
        return 1;
    }
    return params.GetConsensus().pegin_min_depth;
}

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const ChainTypeMeta chain)
{
    if (chain.chain_name == "usdd") {
        throw std::runtime_error("The pre-launch 'usdd' chain identity is unsupported; use -chain=elements");
    }
    switch (chain.chain_type) {
    case ChainType::ELEMENTS:
        return CChainParams::ElementsDrivechain();
    case ChainType::MAIN:
        return CChainParams::Main();
    case ChainType::TESTNET:
        return CChainParams::TestNet();
    case ChainType::TESTNET4:
        return CChainParams::TestNet4();
    case ChainType::SIGNET: {
        auto opts = CChainParams::SigNetOptions{};
        ReadSigNetArgs(args, opts);
        return CChainParams::SigNet(opts);
    }
    case ChainType::REGTEST: {
        // CCustomParams derives from CRegTestParams, so this guard must live at
        // the exact network-selection boundary instead of in the base
        // constructor. Otherwise every custom Elements chain that explicitly
        // enables Elements mode is rejected before its parameters are applied.
        if (args.GetBoolArg("-con_elementsmode", false)) {
            throw std::runtime_error(
                "-con_elementsmode is not supported with -chain=regtest; "
                "use -chain=elementsregtest for Elements/ECX testing");
        }
        for (const std::string& deployment : args.GetArgs("-vbparams")) {
            const auto separator{deployment.find(':')};
            const std::string deployment_name{deployment.substr(0, separator)};
            if (deployment_name == "simplicity") {
                throw std::runtime_error(
                    "the Simplicity deployment is not supported with "
                    "-chain=regtest; use an Elements-mode chain");
            }
            if (deployment_name == "dynafed") {
                throw std::runtime_error(
                    "the dynafed deployment is not supported with "
                    "-chain=regtest; use an Elements-mode chain");
            }
        }
        auto opts = CChainParams::RegTestOptions{};
        ReadRegTestArgs(args, opts);
        return CChainParams::RegTest(opts);
    }
    case ChainType::LIQUID1:
        return CChainParams::LiquidV1(args);
    case ChainType::LIQUID1TEST:
        return CChainParams::LiquidV1Test(args);
    case ChainType::LIQUIDTESTNET: {
        auto opts = CChainParams::RegTestOptions{};
        ReadRegTestArgs(args, opts);
        return CChainParams::LiquidTestNet(chain, args, opts);
    }
    case ChainType::CUSTOM:
        // just log the custom chain and fallthrough to the catch-all for custom params
        LogPrintf("CreateChainParams for custom chain: %s\n", chain.chain_name);
    }

    auto opts = CChainParams::RegTestOptions{};
    ReadRegTestArgs(args, opts);
    return CChainParams::Custom(chain, args, opts);
}

void SelectParams(const ChainTypeMeta chain)
{
    SelectBaseParams(chain);
    globalChainParams = CreateChainParams(gArgs, chain);
}

// ELEMENTS:
// keep the original ChainType constructors, which just call our new ChainTypeMeta constructors
// this helps not to have to change all the other callsites
// in general: don't use these, they're "lossy" for custom chain names
std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const ChainType chain) {
    return CreateChainParams(args, ChainTypeMetaFrom(chain));
}

void SelectParams(const ChainType chain) {
    SelectParams(ChainTypeMetaFrom(chain));
}

std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const std::string& chain)
{
    return CreateChainParams(args, ChainTypeMetaFrom(chain));
}

void SelectParams(const std::string& chain)
{
    SelectParams(ChainTypeMetaFrom(chain));
}
