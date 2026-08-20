// Copyright (c) 2009-2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <assetsdir.h>
#include <bech32.h>
#include <block_proof.h>
#include <core_io.h>
#include <crypto/sha256.h>
#include <deploymentstatus.h>
#include <drivechain_peg.h>
#include <drivechain_settings.h>
#include <dynafed.h>
#include <hash.h>
#include <issuance.h>
#include <interfaces/chain.h>
#include <key_io.h>
#include <mainchainrpc.h>
#include <node/drivechain_withdrawal_bundle.h>
#include <node/drivechain_withdrawal_journal.h>
#include <rpc/rawtransaction_util.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/generic.hpp>
#include <script/pegins.h>
#include <secp256k1.h>
#include <streams.h>
#include <util/fees.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <util/time.h>
#include <wallet/coincontrol.h>
#include <wallet/drivechain_withdrawal.h>
#include <wallet/fees.h>
#include <wallet/receive.h>
#include <wallet/rpc/util.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <chrono>
#include <limits>
#include <optional>

using wallet::BlindDetails;
using wallet::CAddressBookData;
using wallet::CCoinControl;
using wallet::CRecipient;
using wallet::CWallet;
using wallet::CWalletTx;
using wallet::GetMinimumFee;
using wallet::GetWalletForJSONRPCRequest;
using wallet::IssuanceDetails;
using wallet::mapValue_t;
using wallet::LegacyScriptPubKeyMan;

// forward declarations
namespace wallet {
UniValue SendMoney(CWallet& wallet, const CCoinControl &coin_control, std::vector<CRecipient> &recipients, mapValue_t map_value, bool verbose, bool ignore_blind_fail);
RPCHelpMan signrawtransactionwithwallet();
}

// ELEMENTS commands

namespace {
static secp256k1_context *secp256k1_ctx;

//! Drivechain peg-out settings.
//!
//! These were previously read from the process environment with silent
//! defaults, which meant a custody safety property could be switched off by an
//! unrecorded change to a service unit. They are ordinary validated startup
//! arguments now, they are range-checked on every read, and the L1 payout
//! verification they used to gate is no longer optional at all.
static int DrivechainSidechainSlot()
{
    const int64_t slot = gArgs.GetIntArg("-drivechainsidechainslot", DEFAULT_DRIVECHAIN_SIDECHAIN_SLOT);
    if (slot < 0 || slot > 255) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("-drivechainsidechainslot must be a BIP300 slot in [0, 255] (got %d)", slot));
    }
    const int64_t bmm_slot = gArgs.GetIntArg("-drivechainbmmslot", DEFAULT_DRIVECHAIN_SIDECHAIN_SLOT);
    if (slot != bmm_slot) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf(
                "-drivechainsidechainslot (%d) must match -drivechainbmmslot (%d)",
                slot, bmm_slot));
    }
    return static_cast<int>(slot);
}

//! Mainchain fee, in satoshi, reserved out of the withdrawal for the M6 bundle.
//!
//! This used to default to zero, which produces a bundle miners have no reason
//! to include, so a withdrawal could be accepted and then simply never pay out.
//! A positive fee is required and the caller must be able to cover it.
static CAmount DrivechainPegoutMainchainFee(CAmount withdrawal_amount)
{
    const int64_t fee = gArgs.GetIntArg("-drivechainpegoutmainfee", DEFAULT_DRIVECHAIN_PEGOUT_MAIN_FEE_SATS);
    if (fee <= 0) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "-drivechainpegoutmainfee must be a positive satoshi amount; an M6 bundle "
            "with no mainchain fee has no incentive to be mined and can strand the payout");
    }
    if (fee >= withdrawal_amount) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf(
                "withdrawal amount %d does not cover the configured mainchain bundle fee %d",
                withdrawal_amount, fee));
    }
    return static_cast<CAmount>(fee);
}

static void PushLE32(std::vector<unsigned char>& bytes, uint32_t value)
{
    for (int i = 0; i < 4; ++i) {
        bytes.push_back((value >> (8 * i)) & 0xff);
    }
}

static void PushLE64(std::vector<unsigned char>& bytes, uint64_t value)
{
    for (int i = 0; i < 8; ++i) {
        bytes.push_back((value >> (8 * i)) & 0xff);
    }
}

static void PushCompactSize(std::vector<unsigned char>& bytes, uint64_t value)
{
    if (value < 253) {
        bytes.push_back(value);
    } else if (value <= std::numeric_limits<uint16_t>::max()) {
        bytes.push_back(253);
        bytes.push_back(value & 0xff);
        bytes.push_back((value >> 8) & 0xff);
    } else if (value <= std::numeric_limits<uint32_t>::max()) {
        bytes.push_back(254);
        PushLE32(bytes, value);
    } else {
        bytes.push_back(255);
        PushLE64(bytes, value);
    }
}

static void PushBitcoinTxOut(std::vector<unsigned char>& bytes, CAmount amount, const CScript& script_pubkey)
{
    if (amount < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "BIP300 withdrawal output amount cannot be negative");
    }
    PushLE64(bytes, amount);
    PushCompactSize(bytes, script_pubkey.size());
    bytes.insert(bytes.end(), script_pubkey.begin(), script_pubkey.end());
}

static std::vector<unsigned char> ToByteVector(const uint256& value)
{
    return std::vector<unsigned char>(value.begin(), value.end());
}

static uint256 DrivechainInputsCommitment(
    const COutPoint& withdrawal_outpoint,
    uint32_t sidechain_block_height)
{
    std::vector<COutPoint> committed_inputs;
    committed_inputs.push_back(withdrawal_outpoint);
    committed_inputs.emplace_back(uint256::ZERO, sidechain_block_height);
    return SerializeHash(committed_inputs, SER_GETHASH, 0);
}

static CScript BuildDrivechainInputsCommitmentScript(const uint256& commitment)
{
    return CScript() << OP_RETURN << ToByteVector(commitment);
}

static uint256 Sha256(const std::vector<unsigned char>& bytes)
{
    uint256 result;
    CSHA256 hasher;
    if (!bytes.empty()) hasher.Write(bytes.data(), bytes.size());
    hasher.Finalize(result.begin());
    return result;
}

static uint256 TaggedHash(
    const std::string& tag,
    const std::vector<unsigned char>& payload)
{
    const std::vector<unsigned char> tag_bytes(tag.begin(), tag.end());
    const uint256 tag_hash = Sha256(tag_bytes);
    uint256 result;
    CSHA256 hasher;
    hasher.Write(tag_hash.begin(), 32);
    hasher.Write(tag_hash.begin(), 32);
    if (!payload.empty()) hasher.Write(payload.data(), payload.size());
    hasher.Finalize(result.begin());
    return result;
}

static void PushBE32(std::vector<unsigned char>& bytes, uint32_t value)
{
    bytes.push_back((value >> 24) & 0xff);
    bytes.push_back((value >> 16) & 0xff);
    bytes.push_back((value >> 8) & 0xff);
    bytes.push_back(value & 0xff);
}

static uint256 BuildWithdrawalStateAnchor(
    const uint256& child_genesis,
    uint32_t checkpoint_height,
    const uint256& previous_child_hash,
    const uint256& withdrawal_commitment,
    const uint256& exchange_state_root)
{
    if (child_genesis.IsNull() || withdrawal_commitment.IsNull() ||
        exchange_state_root.IsNull()) {
        throw JSONRPCError(
            RPC_MISC_ERROR,
            "Cannot create PXST marker with a null consensus commitment");
    }
    std::vector<unsigned char> payload;
    payload.reserve(134);
    payload.push_back(1);  // PXST interface version
    payload.push_back(24); // LayerTwoLabs BIP300 sidechain slot
    payload.insert(payload.end(), child_genesis.begin(), child_genesis.end());
    PushBE32(payload, checkpoint_height);
    payload.insert(
        payload.end(), previous_child_hash.begin(), previous_child_hash.end());
    payload.insert(
        payload.end(), withdrawal_commitment.begin(), withdrawal_commitment.end());
    payload.insert(
        payload.end(), exchange_state_root.begin(), exchange_state_root.end());
    return TaggedHash("ECX/perps-m6-state/v1", payload);
}

static CScript BuildWithdrawalStateMarkerScript(const uint256& anchor)
{
    std::vector<unsigned char> marker{'P', 'X', 'S', 'T', 1};
    marker.insert(marker.end(), anchor.begin(), anchor.end());
    return CScript() << OP_RETURN << marker;
}


//! Decode a withdrawal destination into the script that will be paid on the
//! parent chain.
//!
//! Every failure path here throws. There is deliberately no fallback that
//! wraps unrecognised text in an OP_RETURN: doing so converted a mistyped or
//! merely non-bech32 address -- an ordinary base58 P2PKH address, for instance
//! -- into a provably unspendable payout, destroying the withdrawal with no
//! warning and no recovery.
//!
//! Decoding is delegated to DecodeParentDestination, which resolves base58
//! prefixes and the bech32 HRP against the configured parent network only. A
//! testnet address on a mainnet parent is rejected rather than paid out.
static CScript BuildDrivechainPayoutScript(const std::string& destination)
{
    if (destination.empty()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Withdrawal destination must not be empty");
    }

    std::string error_msg;
    const CTxDestination parsed = DecodeParentDestination(destination, error_msg);
    if (!IsValidDestination(parsed)) {
        throw JSONRPCError(
            RPC_INVALID_ADDRESS_OR_KEY,
            strprintf(
                "Invalid withdrawal destination for parent network '%s': %s",
                Params().ParentBech32HRP(),
                error_msg.empty() ? "address could not be decoded" : error_msg));
    }

    const CScript payout_script = GetScriptForDestination(parsed);
    if (payout_script.empty()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Withdrawal destination produced an empty payout script");
    }
    // Belt and braces: a destination must never resolve to something provably
    // unspendable, whatever the decoder does in future.
    if (payout_script.IsUnspendable()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Withdrawal destination resolves to an unspendable script");
    }
    return payout_script;
}

static CScript BuildDrivechainWithdrawalBurnScript(const CScript& payout_script)
{
    const uint256 parent_genesis = Params().ParentGenesisBlockHash();
    NullData commitment;
    commitment << std::vector<unsigned char>(
        parent_genesis.begin(), parent_genesis.end());
    commitment << std::vector<unsigned char>(
        payout_script.begin(), payout_script.end());
    const CScript script = GetScriptForDestination(CTxDestination{commitment});
    if (!script.IsPegoutScript(parent_genesis)) {
        throw JSONRPCError(
            RPC_INTERNAL_ERROR,
            "Failed to construct the canonical sidechain withdrawal commitment");
    }
    return script;
}

//! Serialize the M6 withdrawal bundle.
//!
//! The payout script is passed in already decoded and validated rather than
//! being parsed from the destination string here. The caller must validate it
//! before spending anything on the sidechain, and the same script object is
//! then used for both the sidechain peg-out output and this bundle, so the two
//! cannot disagree about where the money is going.
static std::vector<unsigned char> BuildDrivechainWithdrawalBundleBytes(
    CAmount amount,
    CAmount mainchain_fee,
    const CScript& payout_script,
    const COutPoint& withdrawal_outpoint,
    uint32_t sidechain_block_height,
    bool include_witness_marker,
    const uint256& child_genesis,
    const uint256& previous_child_hash,
    const uint256& exchange_state_root)
{
    if (amount <= 0 || !MoneyRange(amount) || mainchain_fee <= 0 ||
        !MoneyRange(mainchain_fee) || mainchain_fee >= amount) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "withdrawal amount and mainchain fee must be in range, with a positive fee less than the amount");
    }

    const uint64_t fee_sats = static_cast<uint64_t>(mainchain_fee);
    std::vector<unsigned char> fee_bytes;
    for (int i = 7; i >= 0; --i) {
        fee_bytes.push_back((fee_sats >> (8 * i)) & 0xff);
    }
    const CScript fee_script = CScript() << OP_RETURN << fee_bytes;
    const uint256 withdrawal_commitment =
        DrivechainInputsCommitment(withdrawal_outpoint, sidechain_block_height);
    const CScript inputs_commitment_script =
        BuildDrivechainInputsCommitmentScript(withdrawal_commitment);
    const uint256 state_anchor = BuildWithdrawalStateAnchor(
        child_genesis,
        sidechain_block_height,
        previous_child_hash,
        withdrawal_commitment,
        exchange_state_root);
    const CScript state_marker_script = BuildWithdrawalStateMarkerScript(state_anchor);

    std::vector<unsigned char> bytes;
    PushLE32(bytes, 2); // nVersion
    if (include_witness_marker) {
        bytes.push_back(0); // segwit marker; disambiguates an inputless tx from a non-witness tx
        bytes.push_back(1); // segwit flag
    }
    PushCompactSize(bytes, 0); // vin
    PushCompactSize(bytes, 4); // vout; append only, output zero is unchanged
    PushBitcoinTxOut(bytes, 0, fee_script);
    PushBitcoinTxOut(bytes, 0, inputs_commitment_script);
    PushBitcoinTxOut(bytes, amount - mainchain_fee, payout_script);
    PushBitcoinTxOut(bytes, 0, state_marker_script);
    PushLE32(bytes, 0); // nLockTime
    return bytes;
}

static wallet::DrivechainWithdrawalBundle BuildDrivechainWithdrawalBundleImpl(
    CAmount amount,
    CAmount mainchain_fee,
    const CScript& payout_script,
    const COutPoint& withdrawal_outpoint,
    uint32_t sidechain_block_height,
    const uint256& child_genesis,
    const uint256& previous_child_hash,
    const uint256& exchange_state_root)
{
    wallet::DrivechainWithdrawalBundle bundle;
    bundle.bytes = BuildDrivechainWithdrawalBundleBytes(
        amount,
        mainchain_fee,
        payout_script,
        withdrawal_outpoint,
        sidechain_block_height,
        true,
        child_genesis,
        previous_child_hash,
        exchange_state_root);
    const std::vector<unsigned char> no_witness_bytes = BuildDrivechainWithdrawalBundleBytes(
        amount,
        mainchain_fee,
        payout_script,
        withdrawal_outpoint,
        sidechain_block_height,
        false,
        child_genesis,
        previous_child_hash,
        exchange_state_root);
    bundle.m6id = Hash(no_witness_bytes);
    return bundle;
}

static UniValue CallMainChainRPCResult(const std::string& method, const UniValue& params)
{
    const UniValue reply = CallMainChainRPC(method, params);
    const UniValue& error = find_value(reply, "error");
    if (!error.isNull()) {
        throw JSONRPCError(RPC_MISC_ERROR, strprintf("mainchain %s returned error: %s", method, error.write()));
    }
    return find_value(reply, "result");
}

static std::string FetchDrivechainWithdrawalBundleEventStatus(
    const int sidechain_id,
    const std::string& m6id_hex,
    std::string& mainchain_tip)
{
    UniValue no_params(UniValue::VARR);
    mainchain_tip = CallMainChainRPCResult("getbestblockhash", no_params).get_str();
    UniValue peg_data;
    std::string error;
    if (!GetDrivechainTwoWayPegData(sidechain_id, peg_data, &error)) {
        throw JSONRPCError(
            RPC_MISC_ERROR,
            "Authenticated withdrawal status lookup failed: " + error);
    }
    if (!IsHex(m6id_hex) || m6id_hex.size() != 64) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Withdrawal bundle id must be 32-byte hex");
    }
    try {
        return drivechain::GetWithdrawalBundleStatus(
            peg_data, sidechain_id, uint256S(m6id_hex));
    } catch (const std::exception& error) {
        throw JSONRPCError(
            RPC_VERIFY_REJECTED,
            "Authenticated withdrawal event data is malformed: " +
                std::string{error.what()});
    }
}

static UniValue VerifyDrivechainWithdrawalBundleEvent(
    const int sidechain_id,
    const std::string& m6id_hex)
{
    std::string mainchain_tip;
    const std::string status = FetchDrivechainWithdrawalBundleEventStatus(
        sidechain_id, m6id_hex, mainchain_tip);

    UniValue verification(UniValue::VOBJ);
    verification.pushKV("mainchain_tip", mainchain_tip);
    verification.pushKV("m6id", m6id_hex);
    verification.pushKV("event_status", status.empty() ? "missing" : status);

    return verification;
}

class DrivechainWithdrawalBundleCreationGuard
{
private:
    bool m_active{false};

public:
    DrivechainWithdrawalBundleCreationGuard()
    {
        uint256 current_bundle_hash;
        bool creation_in_progress{false};
        if (!node::TryBeginDrivechainWithdrawalBundleCreation(current_bundle_hash, creation_in_progress)) {
            if (creation_in_progress) {
                throw JSONRPCError(RPC_WALLET_ERROR, "A drivechain withdrawal bundle is already being created; wait for submitdrivechainwithdrawal to finish before creating another bundle");
            }
            throw JSONRPCError(RPC_WALLET_ERROR, strprintf(
                "A drivechain withdrawal bundle is already active: %s. Wait for it to complete on L1 before creating another bundle",
                current_bundle_hash.GetHex()));
        }
        m_active = true;
    }

    ~DrivechainWithdrawalBundleCreationGuard()
    {
        if (m_active) {
            node::AbortDrivechainWithdrawalBundleCreation();
        }
    }

    void Complete(const uint256& bundle_hash)
    {
        node::CompleteDrivechainWithdrawalBundleCreation(bundle_hash);
        m_active = false;
    }
};

static UniValue BroadcastDrivechainWithdrawalBundle(
    const wallet::DrivechainWithdrawalBundle& bundle)
{
    const int sidechain_id = DrivechainSidechainSlot();

    const std::string tx_base64 = EncodeBase64(MakeUCharSpan(bundle.bytes));
    const std::string tx_hex = HexStr(bundle.bytes);
    const std::string m6id_hex = bundle.m6id.GetHex();

    UniValue payload(UniValue::VOBJ);
    payload.pushKV("sidechainId", sidechain_id);
    payload.pushKV("transaction", tx_base64);

    const BoundedCommandResult child = RunAuthenticatedDrivechainGrpc(
        "cusf.mainchain.v1.WalletService/BroadcastWithdrawalBundle",
        payload.write(),
        std::chrono::seconds{30},
        64U * 1024U);
    if (!child.started || !child.exited || child.exit_code != 0 ||
        child.timed_out || child.cancelled || child.output_truncated ||
        !child.error.empty()) {
        throw JSONRPCError(
            RPC_MISC_ERROR,
            strprintf(
                "Authenticated withdrawal submission failed: %s%s",
                child.error,
                child.output.empty() ? "" : strprintf(" (%s)", child.output)));
    }
    UniValue response;
    if (!response.read(child.output) || !response.isObject()) {
        throw JSONRPCError(
            RPC_PARSE_ERROR,
            "Authenticated enforcer returned a non-JSON withdrawal response");
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("enabled", true);
    result.pushKV("sidechain_id", sidechain_id);
    result.pushKV("enforcer", GetDrivechainGrpcAddress(gArgs));
    result.pushKV("m6id", m6id_hex);
    result.pushKV("withdrawal_bundle_hex", tx_hex);
    result.pushKV("broadcast_response", response);
    return result;
}

class CSecp256k1Init {
public:
    CSecp256k1Init() {
        secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    }
    ~CSecp256k1Init() {
        secp256k1_context_destroy(secp256k1_ctx);
    }
};
static CSecp256k1Init instance_of_csecp256k1;
}

namespace wallet {
DrivechainWithdrawalBundle BuildDrivechainWithdrawalBundle(
    const CAmount amount,
    const CAmount mainchain_fee,
    const CScript& payout_script,
    const COutPoint& withdrawal_outpoint,
    const uint32_t sidechain_block_height,
    const uint256& child_genesis,
    const uint256& previous_child_hash,
    const uint256& exchange_state_root)
{
    return BuildDrivechainWithdrawalBundleImpl(
        amount, mainchain_fee, payout_script, withdrawal_outpoint,
        sidechain_block_height, child_genesis, previous_child_hash,
        exchange_state_root);
}

RPCHelpMan signblock()
{
    return RPCHelpMan{"signblock",
                "\nSigns a block proposal, checking that it would be accepted first. Errors if it cannot sign the block. Note that this call adds the witnessScript to your wallet for signing purposes! This function is intended for QA and testing.\n",
                {
                    {"blockhex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex-encoded block from getnewblockhex"},
                    {"witnessScript", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED_NAMED_ARG, "The hex-encoded witness script. Required for dynamic federation blocks. Argument is \"\" when the block is P2WPKH."},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "pubkey", "signature's pubkey"},
                            {RPCResult::Type::STR_HEX, "sig", "the signature itself"},
                        }},
                    },
                },
                RPCExamples{
                    HelpExampleCli("signblock", "0000002018c6f2f913f9902aeab...5ca501f77be96de63f609010000000000000000015100000000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (!g_signed_blocks) {
        throw JSONRPCError(RPC_MISC_ERROR, "Signed blocks are not active for this network.");
    }

    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    CBlock block;
    if (!DecodeHexBlk(block, request.params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

    LegacyScriptPubKeyMan* spk_man = pwallet->GetLegacyScriptPubKeyMan();
    if (!spk_man) {
        throw JSONRPCError(RPC_WALLET_ERROR, "This type of wallet does not support this command");
    }

    {
        LOCK(cs_main);
        uint256 hash = block.GetHash();
        if (pwallet->chain().hasBlocks(hash, 0, std::nullopt))
            throw JSONRPCError(RPC_VERIFY_ERROR, "already have block");

        CBlockIndex* const pindexPrev = wallet->chain().getTip();
        // TestBlockValidity only supports blocks built on the current Tip
        if (block.hashPrevBlock != pindexPrev->GetBlockHash())
            throw JSONRPCError(RPC_VERIFY_ERROR, "proposal was not based on our best chain");

        BlockValidationState state;
        if (!wallet->chain().testBlockValidity(state, Params(), block, pindexPrev, false, true) || !state.IsValid()) {
            std::string strRejectReason = state.GetRejectReason();
            if (strRejectReason.empty())
                throw JSONRPCError(RPC_VERIFY_ERROR, state.IsInvalid() ? "Block proposal was invalid" : "Error checking block proposal");
            throw JSONRPCError(RPC_VERIFY_ERROR, strRejectReason);
        }
    }

    // Expose SignatureData internals in return value in lieu of "Partially Signed Bitcoin Blocks"
    SignatureData block_sigs;
    if (block.m_dynafed_params.IsNull()) {
        GenericSignScript(*spk_man, block.GetBlockHeader(), block.proof.challenge, block_sigs, SCRIPT_NO_SIGHASH_BYTE /* additional_flags */);
    } else {
        if (request.params[1].isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Signing dynamic blocks requires the witnessScript argument");
        }
        std::vector<unsigned char> witness_bytes(ParseHex(request.params[1].get_str()));
        // Note that we're adding the signblockscript to the wallet so it can actually
        // satisfy witness program scriptpubkeys
        if (!witness_bytes.empty()) {
            spk_man->AddCScript(CScript(witness_bytes.begin(), witness_bytes.end()));
        }
        GenericSignScript(*spk_man, block.GetBlockHeader(), block.m_dynafed_params.m_current.m_signblockscript, block_sigs, SCRIPT_VERIFY_NONE /* additional_flags */);
    }

    // Error if sig data didn't "grow"
    if (!block_sigs.complete && block_sigs.signatures.empty()) {
        throw JSONRPCError(RPC_VERIFY_ERROR, "Could not sign the block.");
    }
    UniValue ret(UniValue::VARR);
    for (const auto& signature : block_sigs.signatures) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("pubkey", HexStr(signature.second.first));
        obj.pushKV("sig", HexStr(signature.second.second));
        ret.push_back(obj);
    }
    return ret;
},
    };
}

RPCHelpMan getpeginaddress()
{
    return RPCHelpMan{"getpeginaddress",
                "\nReturns information needed for claimpegin to move coins to the sidechain.\n"
                "The user should send coins from their Bitcoin wallet to the mainchain_address returned.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "mainchain_address", "mainchain deposit address to send bitcoin to"},
                        {RPCResult::Type::STR_HEX, "claim_script", "claim script committed to by the mainchain address. This may be required in `claimpegin` to retrieve pegged-in funds\n"},
                    },
                },
                RPCExamples{
                    HelpExampleCli("getpeginaddress", "")
            + HelpExampleRpc("getpeginaddress", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    if (pwallet->chain().isInitialBlockDownload()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "This action cannot be completed during initial sync or reindexing.");
    }

    LegacyScriptPubKeyMan* spk_man = pwallet->GetLegacyScriptPubKeyMan();
    if (!spk_man) {
        throw JSONRPCError(RPC_WALLET_ERROR, "This type of wallet does not support this command");
    }

    if (!pwallet->IsLocked()) {
        pwallet->TopUpKeyPool();
    }

    // Use native witness destination
    CTxDestination dest;
    bilingual_str error;
    if (!pwallet->GetNewDestination(OutputType::BECH32, "", dest, error)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, error.original);
    }

    CScript dest_script = GetScriptForDestination(dest);

    // Also add raw scripts to index to recognize later.
    spk_man->AddCScript(dest_script);

    // Get P2CH deposit address on mainchain from most recent fedpegscript.
    const auto& fedpegscripts = GetValidFedpegScripts(pwallet->chain().getTip(), Params().GetConsensus(), true /* nextblock_validation */);
    if (fedpegscripts.empty()) {
        std::string message = "No valid fedpegscripts.";
        if (!g_con_elementsmode) {
            message += " Not running in Elements mode, check your 'chain' param.";
        }
        throw JSONRPCError(RPC_INTERNAL_ERROR, message);
    }
    CTxDestination mainchain_dest(WitnessV0ScriptHash(calculate_contract(fedpegscripts.front().second, dest_script)));
    // P2SH-wrapped is the only valid choice for non-dynafed chains but still an
    // option for dynafed-enabled ones as well
    if (!DeploymentActiveAfter(pwallet->chain().getTip(), Params().GetConsensus(), Consensus::DEPLOYMENT_DYNA_FED) ||
                fedpegscripts.front().first.IsPayToScriptHash()) {
        mainchain_dest = ScriptHash(GetScriptForDestination(mainchain_dest));
    }

    UniValue ret(UniValue::VOBJ);

    ret.pushKV("mainchain_address", EncodeParentDestination(mainchain_dest));
    ret.pushKV("claim_script", HexStr(dest_script));

    PeginMinimum pegin_minimum = Params().GetPeginMinimum();
    if (pegin_minimum.amount > 0) {
        ret.pushKV("pegin_min_amount", FormatMoney(pegin_minimum.amount));
    }
    if (pegin_minimum.height < std::numeric_limits<int>::max()) {
        ret.pushKV("pegin_min_height", pegin_minimum.height);
        ret.pushKV("pegin_min_active", wallet->chain().getTip()->nHeight >= pegin_minimum.height);
    }

    PeginSubsidy pegin_subsidy = Params().GetPeginSubsidy();
    if (pegin_subsidy.threshold > 0) {
        ret.pushKV("pegin_subsidy_threshold", FormatMoney(pegin_subsidy.threshold));
    }
    if (pegin_subsidy.height < std::numeric_limits<int>::max()) {
        ret.pushKV("pegin_subsidy_height", pegin_subsidy.height);
        ret.pushKV("pegin_subsidy_active", wallet->chain().getTip()->nHeight >= pegin_subsidy.height);
    }

    return ret;
},
    };
}

//! Derive BIP32 tweak from master xpub to child pubkey.
bool DerivePubTweak(const std::vector<uint32_t>& vPath, const CPubKey& keyMaster, const ChainCode &ccMaster, std::vector<unsigned char>& tweakSum)
{
    tweakSum.clear();
    tweakSum.resize(32);
    std::vector<unsigned char> tweak;
    CPubKey keyParent = keyMaster;
    CPubKey keyChild;
    ChainCode ccChild;
    ChainCode ccParent = ccMaster;
    for (unsigned int i = 0; i < vPath.size(); i++) {
        if ((vPath[i] >> 31) != 0) {
            return false;
        }
        keyParent.Derive(keyChild, ccChild, vPath[i], ccParent, &tweak);
        CHECK_NONFATAL(tweak.size() == 32);
        ccParent = ccChild;
        keyParent = keyChild;
        if (i == 0) {
            tweakSum = tweak;
        } else {
            bool ret = secp256k1_ec_seckey_tweak_add(secp256k1_ctx, tweakSum.data(), tweak.data());
            if (!ret) {
                return false;
            }
        }
    }
    return true;
}

// For general cryptographic design of peg-out authorization scheme, see: https://github.com/ElementsProject/secp256k1-zkp/blob/secp256k1-zkp/src/modules/whitelist/whitelist.md
RPCHelpMan initpegoutwallet()
{
    return RPCHelpMan{"initpegoutwallet",
                "\nThis call is for Liquid network initialization on the Liquid wallet. The wallet generates a new Liquid pegout authorization key (PAK) and stores it in the Liquid wallet. It then combines this with the `bitcoin_descriptor` to finally create a PAK entry for the network. This allows the user to send Liquid coins directly to a secure offline Bitcoin wallet at the derived path from the bitcoin_descriptor using the `sendtomainchain` command. Losing the Liquid PAK or offline Bitcoin root key will result in the inability to pegout funds, so immediate backup upon initialization is required.\n" +
                wallet::HELP_REQUIRING_PASSPHRASE,
                {
                    {"bitcoin_descriptor", RPCArg::Type::STR, RPCArg::Optional::NO, "The Bitcoin descriptor that includes a single extended pubkey. Must be one of the following: pkh(<xpub>), sh(wpkh(<xpub>)), or wpkh(<xpub>). This is used as the destination chain for the Bitcoin destination wallet. The derivation path from the xpub is given by the descriptor, typically `0/k`, reflecting the external chain of the wallet. DEPRECATED: If a plain xpub is given, pkh(<xpub>) is assumed, with the `0/k` derivation from that xpub. See link for more details on script descriptors: https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md"},
                    {"bip32_counter", RPCArg::Type::NUM , RPCArg::Default{0}, "The `k` in `0/k` to be set as the next address to derive from the `bitcoin_descriptor`. This will be stored in the wallet and incremented on each successful `sendtomainchain` invocation."},
                    {"liquid_pak", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED_NAMED_ARG, "The Liquid wallet pubkey in hex to be used as the Liquid PAK for pegout authorization. The private key must be in the wallet if argument is given. If this argument is not provided one will be generated and stored in the wallet automatically and returned."}
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "pakentry", "PAK entry to be used at network initialization time in the form of: `pak=<bitcoin_pak>:<liquid_pak>`"},
                        {RPCResult::Type::STR_HEX, "liquid_pak", "Liquid PAK pubkey, which is stored in the local Liquid wallet. This can be used in subsequent calls to `initpegoutwallet` to avoid generating a new `liquid_pak`"},
                        {RPCResult::Type::STR, "liquid_pak_address", "corresponding address for `liquid_pak`. Useful for `dumpprivkey` for wallet backup or transfer"},
                        {RPCResult::Type::ARR_FIXED, "address_lookahead", "the three next Bitcoin addresses the wallet will use for `sendtomainchain` based on `bip32_counter`",
                            {RPCResult{RPCResult::Type::STR, "", ""}}},
                    }
                },
                RPCExamples{
                    HelpExampleCli("initpegoutwallet", "sh(wpkh(tpubDAY5hwtonH4NE8zY46ZMFf6B6F3fqMis7cwfNihXXpAg6XzBZNoHAdAzAZx2peoU8nTWFqvUncXwJ9qgE5VxcnUKxdut8F6mptVmKjfiwDQ/0/*))")
            + HelpExampleRpc("initpegoutwallet", "sh(wpkh(tpubDAY5hwtonH4NE8zY46ZMFf6B6F3fqMis7cwfNihXXpAg6XzBZNoHAdAzAZx2peoU8nTWFqvUncXwJ9qgE5VxcnUKxdut8F6mptVmKjfiwDQ/0/*))")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    LOCK(pwallet->cs_wallet);

    LegacyScriptPubKeyMan* spk_man = pwallet->GetLegacyScriptPubKeyMan();
    if (!spk_man) {
        throw JSONRPCError(RPC_WALLET_ERROR, "This type of wallet does not support this command");
    }

    // Check that network cares about PAK
    if (!Params().GetEnforcePak()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "PAK enforcement is not enabled on this network.");
    }

    if (!pwallet->IsLocked())
        pwallet->TopUpKeyPool();

    // Generate a new key that is added to wallet or set from argument
    CPubKey online_pubkey;
    if (request.params.size() < 3) {
        std::string error;
        if (!pwallet->GetOnlinePakKey(online_pubkey, error)) {
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, error);
        }
    } else {
        online_pubkey = CPubKey(ParseHex(request.params[2].get_str()));
        if (!online_pubkey.IsFullyValid()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Error: Given liquid_pak is not valid.");
        }
        if (!spk_man->HaveKey(online_pubkey.GetID())) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Error: liquid_pak could not be found in wallet");
        }
    }

    // Parse offline counter
    int counter = 0;
    if (request.params.size() > 1) {
        counter = request.params[1].get_int();
        if (counter < 0 || counter > 1000000000) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "bip32_counter must be between 0 and 1,000,000,000, inclusive.");
        }
    }

    std::string bitcoin_desc = request.params[0].get_str();
    std::string xpub_str = "";

    // First check for naked xpub, and impute it as pkh(<xpub>/0/*) for backwards compat
    CExtPubKey xpub = DecodeExtPubKey(bitcoin_desc);
    if (xpub.pubkey.IsFullyValid()) {
        bitcoin_desc = "pkh(" + bitcoin_desc + "/0/*)";
    }

    FlatSigningProvider provider;
    std::string error;
    auto desc = Parse(bitcoin_desc, provider, error); // don't require checksum
    if (!desc) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, error);
    } else if (!desc->IsRange()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "bitcoin_descriptor must be a ranged descriptor.");
    }

    // Check if we can actually generate addresses(catches hardened derivation steps etc) before
    // writing to cache
    UniValue address_list(UniValue::VARR);
    for (int i = counter; i < counter+3; i++) {
        std::vector<CScript> scripts;
        if (!desc->Expand(i, provider, scripts, provider)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Could not generate lookahead addresses with descriptor. Are there hardened derivations after the xpub?");
        }
        CTxDestination destination;
        ExtractDestination(scripts[0], destination);
        address_list.push_back(EncodeParentDestination(destination));
    }

    // For our manual pattern matching, we don't want the checksum part.
    auto checksum_char = bitcoin_desc.find('#');
    if (checksum_char != std::string::npos) {
        bitcoin_desc = bitcoin_desc.substr(0, checksum_char);
    }

    // Three acceptable descriptors:
    if (bitcoin_desc.substr(0, 8) ==  "sh(wpkh("
            && bitcoin_desc.substr(bitcoin_desc.size()-2, 2) == "))") {
        xpub_str = bitcoin_desc.substr(8, bitcoin_desc.size()-2);
    } else if (bitcoin_desc.substr(0, 5) ==  "wpkh("
            && bitcoin_desc.substr(bitcoin_desc.size()-1, 1) == ")") {
        xpub_str = bitcoin_desc.substr(5, bitcoin_desc.size()-1);
    } else if (bitcoin_desc.substr(0, 4) == "pkh("
            && bitcoin_desc.substr(bitcoin_desc.size()-1, 1) == ")") {
        xpub_str = bitcoin_desc.substr(4, bitcoin_desc.size()-1);
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "bitcoin_descriptor is not of any type supported: pkh(<xpub>), sh(wpkh(<xpub>)), wpkh(<xpub>), or <xpub>.");
    }

    // Strip off leading key origin
    if (xpub_str.find("]") != std::string::npos) {
        xpub_str = xpub_str.substr(xpub_str.find("]")+1, std::string::npos);
    }

    // Strip off following range
    xpub_str = xpub_str.substr(0, xpub_str.find("/"));

    xpub = DecodeExtPubKey(xpub_str);

    if (!xpub.pubkey.IsFullyValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "bitcoin_descriptor does not contain a valid extended pubkey for this network.");
    }

    // Parse master pubkey
    CPubKey masterpub = xpub.pubkey;
    secp256k1_pubkey masterpub_secp;
    int ret = secp256k1_ec_pubkey_parse(secp256k1_ctx, &masterpub_secp, masterpub.begin(), masterpub.size());
    if (ret != 1) {
        throw JSONRPCError(RPC_WALLET_ERROR, "bitcoin_descriptor could not be parsed.");
    }

    // Store the keys and metadata
    if (!pwallet->SetOnlinePubKey(online_pubkey) ||
            !pwallet->SetOfflineXPubKey(xpub) ||
            !pwallet->SetOfflineCounter(counter) ||
            !pwallet->SetOfflineDescriptor(bitcoin_desc)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Failure to initialize pegout wallet.");
    }

    // Negate the pubkey
    ret = secp256k1_ec_pubkey_negate(secp256k1_ctx, &masterpub_secp);

    std::vector<unsigned char> negatedpubkeybytes;
    negatedpubkeybytes.resize(33);
    size_t len = 33;
    ret = secp256k1_ec_pubkey_serialize(secp256k1_ctx, &negatedpubkeybytes[0], &len, &masterpub_secp, SECP256K1_EC_COMPRESSED);
    CHECK_NONFATAL(ret == 1);
    CHECK_NONFATAL(len == 33);
    CHECK_NONFATAL(negatedpubkeybytes.size() == 33);

    UniValue pak(UniValue::VOBJ);
    pak.pushKV("pakentry", "pak=" + HexStr(negatedpubkeybytes) + ":" + HexStr(online_pubkey));
    pak.pushKV("liquid_pak", HexStr(online_pubkey));
    pak.pushKV("liquid_pak_address", EncodeDestination(PKHash(online_pubkey)));
    pak.pushKV("address_lookahead", address_list);
    return pak;
},
    };
}

RPCHelpMan sendtomainchain_base()
{
    return RPCHelpMan{"sendtomainchain",
                "\nCreates and broadcasts a sidechain withdrawal transaction. After it confirms "
                "in a sidechain block, call submitdrivechainwithdrawal with the returned txid. "
                "Only that second call can build the height-bound BIP300 M6 bundle.\n"
                + wallet::HELP_REQUIRING_PASSPHRASE,
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The destination address on the configured Bitcoin parent network."},
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount being sent to Bitcoin mainchain"},
                    {"subtractfeefromamount", RPCArg::Type::BOOL, RPCArg::Default{false}, "Must be false; the M6 payout is bound to the exact committed burn amount."},
                    {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false}, "If true, return extra information about the transaction."},
                },
                {
                    RPCResult{"if verbose is not set or set to false",
                        RPCResult::Type::STR_HEX, "txid", "Transaction ID of the resulting sidechain transaction",
                    },
                    RPCResult{"if verbose is set to true",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "txid", "The transaction id."},
                            {RPCResult::Type::STR, "fee reason", "The transaction fee reason."},
                            {RPCResult::Type::STR, "withdrawal_status", "waiting_for_sidechain_confirmation"},
                            {RPCResult::Type::STR, "next_rpc", "The follow-up RPC used after confirmation."}
                        },
                    },
                },
                RPCExamples{
                    HelpExampleCli("sendtomainchain", "\"tb1q...\" 0.1")
            + HelpExampleRpc("sendtomainchain", "\"tb1q...\" 0.1")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    LOCK(pwallet->cs_wallet);

    EnsureWalletIsUnlocked(*pwallet);

    const std::string mainchain_destination = request.params[0].get_str();
    const CScript payout_script = BuildDrivechainPayoutScript(mainchain_destination);
    const CScript sidechain_withdrawal_script =
        BuildDrivechainWithdrawalBurnScript(payout_script);
    const CAmount amount = AmountFromValue(request.params[1]);
    if (amount <= 0 || !MoneyRange(amount)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid withdrawal amount");
    }
    if (request.params.size() > 2 && !request.params[2].isNull() &&
        request.params[2].get_bool()) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "subtractfeefromamount is not supported for native drivechain withdrawals");
    }
    const CAmount mainchain_fee = DrivechainPegoutMainchainFee(amount);
    if (DrivechainSidechainSlot() != DEFAULT_DRIVECHAIN_SIDECHAIN_SLOT) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("ECX withdrawals are consensus-bound to BIP300 sidechain slot %d",
                DEFAULT_DRIVECHAIN_SIDECHAIN_SLOT));
    }

    std::vector<CRecipient> recipients{
        {sidechain_withdrawal_script, amount,
         Params().GetConsensus().pegged_asset, CPubKey(), false},
    };

    mapValue_t metadata;
    metadata[DRIVECHAIN_WITHDRAWAL_DESTINATION_KEY] = mainchain_destination;
    metadata[DRIVECHAIN_WITHDRAWAL_AMOUNT_KEY] = ToString(amount);
    metadata[DRIVECHAIN_WITHDRAWAL_MAIN_FEE_KEY] = ToString(mainchain_fee);
    metadata[DRIVECHAIN_WITHDRAWAL_PAYOUT_SCRIPT_KEY] = HexStr(payout_script);
    CCoinControl coin_control;
    coin_control.m_include_unsafe_inputs = true;
    UniValue send_result = SendMoney(
        *pwallet, coin_control, recipients, std::move(metadata),
        /*verbose=*/true, /*ignore_blind_fail=*/true);
    const UniValue& txid = find_value(send_result, "txid");
    if (!txid.isStr()) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            "Created withdrawal transaction has no txid");
    }

    const bool verbose = request.params.size() > 3 &&
        !request.params[3].isNull() && request.params[3].get_bool();
    if (!verbose) return txid.get_str();
    send_result.pushKV(
        "withdrawal_status", "waiting_for_sidechain_confirmation");
    send_result.pushKV("next_rpc", "submitdrivechainwithdrawal");
    send_result.pushKV("mainchain_destination", mainchain_destination);
    send_result.pushKV("mainchain_fee", ValueFromAmount(mainchain_fee));
    return send_result;
},
    };
}

RPCHelpMan submitdrivechainwithdrawal()
{
    return RPCHelpMan{"submitdrivechainwithdrawal",
                "\nBuild and submit the BIP300 M6 bundle for a confirmed sidechain withdrawal.\n"
                "The transaction must have been created by sendtomainchain, must be confirmed in the "
                "active sidechain, and must still contain the exact persisted withdrawal output. The M6 "
                "is bound to that confirmation block's height, parent, and ECX state root.\n",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The confirmed sidechain transaction returned by sendtomainchain."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "txid", "The confirmed sidechain withdrawal transaction."},
                        {RPCResult::Type::NUM, "sidechain_vout", "The exact withdrawal output index."},
                        {RPCResult::Type::NUM, "sidechain_height", "The active confirmation height used by M6."},
                        {RPCResult::Type::STR_HEX, "m6id", "The deterministic withdrawal bundle id."},
                        {RPCResult::Type::STR, "withdrawal_status", "The durable lifecycle state."},
                        {RPCResult::Type::OBJ, "broadcast", /*optional=*/true, "Authenticated enforcer response."},
                    },
                },
                RPCExamples{
                    HelpExampleCli("submitdrivechainwithdrawal", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    const uint256 txid = ParseHashV(request.params[0], "txid");
    CAmount amount{0};
    CAmount mainchain_fee{0};
    std::string destination;
    CScript payout_script;
    uint32_t withdrawal_vout{0};
    uint32_t confirmation_height{0};
    uint256 previous_child_hash;
    uint256 exchange_state_root;

    {
        LOCK(pwallet->cs_wallet);
        const CWalletTx* const wtx = pwallet->GetWalletTx(txid);
        if (wtx == nullptr || !wtx->tx) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Withdrawal transaction is not in this wallet");
        }
        const wallet::TxStateConfirmed* const confirmed =
            wtx->state<wallet::TxStateConfirmed>();
        if (confirmed == nullptr || pwallet->GetTxDepthInMainChain(*wtx) < 1) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                "Withdrawal is not confirmed in the active sidechain; wait for a sidechain block and retry");
        }
        if (confirmed->confirmed_block_height < 0 ||
            static_cast<uint64_t>(confirmed->confirmed_block_height) >
                std::numeric_limits<uint32_t>::max()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Withdrawal confirmation height is invalid");
        }

        bool active{false};
        CBlock confirmation_block;
        if (!pwallet->chain().findBlock(
                confirmed->confirmed_block_hash,
                interfaces::FoundBlock().inActiveChain(active).data(confirmation_block)) ||
            !active || confirmation_block.IsNull()) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                "Withdrawal confirmation block is unavailable or no longer active");
        }
        if (confirmed->position_in_block < 0 ||
            static_cast<size_t>(confirmed->position_in_block) >= confirmation_block.vtx.size() ||
            confirmation_block.vtx[confirmed->position_in_block]->GetHash() != txid) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                "Wallet confirmation metadata does not match the sidechain block");
        }
        if ((static_cast<uint32_t>(confirmation_block.nVersion) &
                CBlockHeader::EXCHANGE_STATE_HF_MASK) == 0 ||
            confirmation_block.hashExchangeStateRoot.IsNull()) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                "Withdrawal confirmation block does not carry a finalized ECX state root");
        }

        const auto metadata = [&](const char* key) -> const std::string& {
            const auto it = wtx->mapValue.find(key);
            if (it == wtx->mapValue.end() || it->second.empty()) {
                throw JSONRPCError(
                    RPC_WALLET_ERROR,
                    strprintf("Withdrawal transaction is missing required wallet metadata '%s'", key));
            }
            return it->second;
        };
        destination = metadata(DRIVECHAIN_WITHDRAWAL_DESTINATION_KEY);
        int64_t parsed_amount{0};
        int64_t parsed_fee{0};
        if (!ParseInt64(metadata(DRIVECHAIN_WITHDRAWAL_AMOUNT_KEY), &parsed_amount) ||
            parsed_amount <= 0 || !MoneyRange(parsed_amount) ||
            !ParseInt64(metadata(DRIVECHAIN_WITHDRAWAL_MAIN_FEE_KEY), &parsed_fee) ||
            parsed_fee <= 0 || parsed_fee >= parsed_amount || !MoneyRange(parsed_fee)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Withdrawal wallet metadata contains an invalid amount or mainchain fee");
        }
        amount = parsed_amount;
        mainchain_fee = parsed_fee;

        const std::string payout_script_hex =
            metadata(DRIVECHAIN_WITHDRAWAL_PAYOUT_SCRIPT_KEY);
        if (!IsHex(payout_script_hex)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Withdrawal payout script metadata is not hex");
        }
        const std::vector<unsigned char> payout_bytes = ParseHex(payout_script_hex);
        payout_script = CScript(payout_bytes.begin(), payout_bytes.end());
        if (payout_script.empty() || payout_script.IsUnspendable() ||
            payout_script != BuildDrivechainPayoutScript(destination)) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                "Withdrawal destination and persisted payout script do not match");
        }

        const CScript burn_script =
            BuildDrivechainWithdrawalBurnScript(payout_script);
        std::optional<uint32_t> matched_vout;
        for (uint32_t vout = 0; vout < wtx->tx->vout.size(); ++vout) {
            const CTxOut& output = wtx->tx->vout[vout];
            if (output.scriptPubKey != burn_script) continue;
            if (!output.nAsset.IsExplicit() ||
                output.nAsset.GetAsset() != Params().GetConsensus().pegged_asset ||
                !output.nValue.IsExplicit() || output.nValue.GetAmount() != amount) {
                throw JSONRPCError(
                    RPC_WALLET_ERROR,
                    "Withdrawal output no longer matches its persisted asset and amount");
            }
            if (matched_vout.has_value()) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Withdrawal transaction contains duplicate matching outputs");
            }
            matched_vout = vout;
        }
        if (!matched_vout.has_value()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Withdrawal transaction does not contain its persisted burn output");
        }

        withdrawal_vout = *matched_vout;
        confirmation_height = static_cast<uint32_t>(confirmed->confirmed_block_height);
        previous_child_hash = confirmation_block.hashPrevBlock;
        exchange_state_root = confirmation_block.hashExchangeStateRoot;
    }

    if (DrivechainSidechainSlot() != DEFAULT_DRIVECHAIN_SIDECHAIN_SLOT) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("ECX withdrawals are consensus-bound to BIP300 sidechain slot %d",
                DEFAULT_DRIVECHAIN_SIDECHAIN_SLOT));
    }

    const COutPoint withdrawal_outpoint(txid, withdrawal_vout);
    const wallet::DrivechainWithdrawalBundle bundle =
        wallet::BuildDrivechainWithdrawalBundle(
            amount,
            mainchain_fee,
            payout_script,
            withdrawal_outpoint,
            confirmation_height,
            Params().GetConsensus().hashGenesisBlock,
            previous_child_hash,
            exchange_state_root);

    node::WithdrawalJournalEntry expected;
    expected.m6id = bundle.m6id;
    expected.sidechain_txid = txid;
    expected.sidechain_vout = withdrawal_vout;
    expected.sidechain_height = confirmation_height;
    expected.amount = amount;
    expected.mainchain_fee = mainchain_fee;
    expected.destination = destination;
    expected.payout_script = payout_script;
    expected.sidechain_slot = DrivechainSidechainSlot();
    expected.created_time = GetTime();
    expected.bundle_bytes = bundle.bytes;

    const fs::path data_dir = gArgs.GetDataDirNet();
    node::WithdrawalJournalEntry journal;
    std::string journal_error;
    const node::WithdrawalJournalReadResult journal_result =
        node::ReadWithdrawalJournal(data_dir, journal, &journal_error);
    if (journal_result == node::WithdrawalJournalReadResult::CORRUPT) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            "Withdrawal journal is corrupt; refusing to submit or replace custody state: " + journal_error);
    }

    const auto same_withdrawal = [&](const node::WithdrawalJournalEntry& entry) {
        return entry.m6id == expected.m6id &&
            entry.sidechain_txid == expected.sidechain_txid &&
            entry.sidechain_vout == expected.sidechain_vout &&
            entry.sidechain_height == expected.sidechain_height &&
            entry.amount == expected.amount &&
            entry.mainchain_fee == expected.mainchain_fee &&
            entry.destination == expected.destination &&
            entry.payout_script == expected.payout_script &&
            entry.sidechain_slot == expected.sidechain_slot &&
            entry.bundle_bytes == expected.bundle_bytes;
    };

    bool replace_settled_journal{false};
    if (journal_result == node::WithdrawalJournalReadResult::OK &&
        !same_withdrawal(journal)) {
        if (journal.GetState() != node::WithdrawalJournalState::SETTLED) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                strprintf(
                    "A different withdrawal is already journalled (m6id %s); recover it before submitting another",
                    journal.m6id.GetHex()));
        }

        const uint256 current = node::GetCurrentDrivechainWithdrawalBundleHash();
        if (current == journal.m6id) {
            node::ClearCurrentDrivechainWithdrawalBundleHash(journal.m6id);
        } else if (!current.IsNull()) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                strprintf(
                    "Settled journal m6id %s conflicts with active bundle %s",
                    journal.m6id.GetHex(), current.GetHex()));
        }
        replace_settled_journal = true;
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", txid.GetHex());
    result.pushKV("sidechain_vout", static_cast<uint64_t>(withdrawal_vout));
    result.pushKV("sidechain_height", static_cast<uint64_t>(confirmation_height));
    result.pushKV("m6id", bundle.m6id.GetHex());
    result.pushKV("mainchain_destination", destination);
    result.pushKV("withdrawal_amount", ValueFromAmount(amount));
    result.pushKV("mainchain_fee", ValueFromAmount(mainchain_fee));
    result.pushKV("payout_amount", ValueFromAmount(amount - mainchain_fee));

    if (journal_result == node::WithdrawalJournalReadResult::OK &&
        same_withdrawal(journal) &&
        journal.GetState() == node::WithdrawalJournalState::SETTLED) {
        const uint256 current = node::GetCurrentDrivechainWithdrawalBundleHash();
        if (current == journal.m6id) {
            node::ClearCurrentDrivechainWithdrawalBundleHash(journal.m6id);
        } else if (!current.IsNull()) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                strprintf(
                    "Settled journal m6id %s conflicts with active bundle %s",
                    journal.m6id.GetHex(), current.GetHex()));
        }
        result.pushKV("withdrawal_status", "settled");
        result.pushKV("journal_retained", true);
        return result;
    }

    const uint256 current_bundle =
        node::GetCurrentDrivechainWithdrawalBundleHash();
    if (!current_bundle.IsNull() && current_bundle != bundle.m6id) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            strprintf("A different withdrawal bundle is active: %s", current_bundle.GetHex()));
    }

    if (journal_result == node::WithdrawalJournalReadResult::OK &&
        journal.GetState() == node::WithdrawalJournalState::BUNDLE_SUBMITTED) {
        if (current_bundle.IsNull()) {
            node::RestoreCurrentDrivechainWithdrawalBundleHash(bundle.m6id);
        }
        result.pushKV("withdrawal_status", "bundle_submitted");
        try {
            result.pushKV(
                "l1_event_verification",
                VerifyDrivechainWithdrawalBundleEvent(
                    DrivechainSidechainSlot(), bundle.m6id.GetHex()));
        } catch (const UniValue& error) {
            result.pushKV("l1_event_verification_error", error.write());
        } catch (const std::exception& error) {
            result.pushKV("l1_event_verification_error", error.what());
        }
        return result;
    }

    std::optional<DrivechainWithdrawalBundleCreationGuard> creation_guard;
    if (current_bundle.IsNull()) {
        creation_guard.emplace();
    }

    if (journal_result == node::WithdrawalJournalReadResult::MISSING ||
        replace_settled_journal) {
        if (!node::WriteWithdrawalJournal(data_dir, expected)) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                "Unable to durably journal the withdrawal; no M6 was submitted");
        }
        journal = expected;
    }

    result.pushKV("broadcast", BroadcastDrivechainWithdrawalBundle(bundle));

    node::WithdrawalJournalEntry submitted = journal;
    submitted.SetState(node::WithdrawalJournalState::BUNDLE_SUBMITTED);
    if (!node::WriteWithdrawalJournal(data_dir, submitted)) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            "M6 was submitted, but the submitted journal state could not be persisted; retry is safe and uses the same M6");
    }
    if (creation_guard.has_value()) {
        creation_guard->Complete(bundle.m6id);
    }

    result.pushKV("withdrawal_status", "bundle_submitted");
    try {
        result.pushKV(
            "l1_event_verification",
            VerifyDrivechainWithdrawalBundleEvent(
                DrivechainSidechainSlot(), bundle.m6id.GetHex()));
    } catch (const UniValue& error) {
        result.pushKV("l1_event_verification_error", error.write());
    } catch (const std::exception& error) {
        result.pushKV("l1_event_verification_error", error.what());
    }
    return result;
},
    };
}

// ELEMENTS: Copied from script/descriptor.cpp

typedef std::vector<uint32_t> KeyPath;

/** Split a string on every instance of sep, returning a vector. */
std::vector<Span<const char>> Split(const Span<const char>& sp, char sep)
{
    std::vector<Span<const char>> ret;
    auto it = sp.begin();
    auto start = it;
    while (it != sp.end()) {
        if (*it == sep) {
            ret.emplace_back(start, it);
            start = it + 1;
        }
        ++it;
    }
    ret.emplace_back(start, it);
    return ret;
}

/** Parse a key path, being passed a split list of elements (the first element is ignored). */
bool ParseKeyPath(const std::vector<Span<const char>>& split, KeyPath& out)
{
    for (size_t i = 1; i < split.size(); ++i) {
        Span<const char> elem = split[i];
        bool hardened = false;
        if (elem.size() > 0 && (elem[elem.size() - 1] == '\'' || elem[elem.size() - 1] == 'h')) {
            elem = elem.first(elem.size() - 1);
            hardened = true;
        }
        uint32_t p;
        if (!ParseUInt32(std::string(elem.begin(), elem.end()), &p) || p > 0x7FFFFFFFUL) return false;
        out.push_back(p | (((uint32_t)hardened) << 31));
    }
    return true;
}

////////////////////////////

RPCHelpMan sendtomainchain_pak()
{
    return RPCHelpMan{"sendtomainchain",
                "\nSends Liquid funds to the Bitcoin mainchain, through the federated withdraw mechanism. The wallet internally generates the returned `bitcoin_address` via `bitcoin_descriptor` and `bip32_counter` previously set in `initpegoutwallet`. The counter will be incremented upon successful send, avoiding address re-use.\n"
                + wallet::HELP_REQUIRING_PASSPHRASE,
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Must be \"\". Only for non-PAK `sendtomainchain` compatibility."},
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount being sent to `bitcoin_address`."},
                    {"subtractfeefromamount", RPCArg::Type::BOOL, RPCArg::Default{false}, "The fee will be deducted from the amount being pegged-out."},
                    {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false}, "If true, return extra information about the transaction."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "bitcoin_address", "destination address on Bitcoin mainchain"},
                        {RPCResult::Type::STR_HEX, "txid", "transaction ID of the resulting Liquid transaction"},
                        {RPCResult::Type::STR, "fee reason", "If verbose is set to true, the Liquid transaction fee reason"},
                        {RPCResult::Type::STR, "bitcoin_descriptor", "xpubkey of the child destination address"},
                        {RPCResult::Type::STR, "bip32_counter", "derivation counter for the `bitcoin_descriptor`"},
                    },
                },
                RPCExamples{
                    HelpExampleCli("sendtomainchain", "\"\" 0.1")
            + HelpExampleRpc("sendtomainchain", "\"\" 0.1")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    LOCK(pwallet->cs_wallet);

    EnsureWalletIsUnlocked(*pwallet);

    if (!request.params[0].get_str().empty()) {
        throw JSONRPCError(RPC_TYPE_ERROR, "`address` argument must be \"\" for PAK-enabled networks as the address is generated automatically.");
    }

    //amount
    CAmount nAmount = AmountFromValue(request.params[1]);
    if (nAmount < 100000)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount for send, must send more than 0.00100000 BTC");

    bool subtract_fee = false;
    if (request.params.size() > 2) {
        subtract_fee = request.params[2].get_bool();
    }

    CPAKList paklist = GetActivePAKList(pwallet->chain().getTip(), Params().GetConsensus());
    if (paklist.IsReject()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Pegout freeze is under effect to aid a pak transition to a new list. Please consult the network operator.");
    }

    // Fetch pegout key data
    int counter = pwallet->offline_counter;
    CExtPubKey& xpub = pwallet->offline_xpub;
    CPubKey& onlinepubkey = pwallet->online_key;

    if (counter < 0) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Pegout authorization for this wallet has not been set. Please call `initpegoutwallet` with the appropriate arguments first.");
    }

    FlatSigningProvider provider;
    std::string error;
    auto descriptor = Parse(pwallet->offline_desc, provider, error);

    LegacyScriptPubKeyMan* spk_man = pwallet->GetLegacyScriptPubKeyMan();
    if (!spk_man) {
        throw JSONRPCError(RPC_WALLET_ERROR, "This type of wallet does not support this command");
    }

    // If descriptor not previously set, generate it
    if (!descriptor) {
        std::string offline_desc = "pkh(" + EncodeExtPubKey(xpub) + "0/*)";
        if (!pwallet->SetOfflineDescriptor(offline_desc)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Couldn't set wallet descriptor for peg-outs.");
        }

        descriptor = Parse(pwallet->offline_desc, provider, error);
        if (!descriptor) {
            throw JSONRPCError(RPC_WALLET_ERROR, "descriptor still null. This is a bug in elementsd.");
        }
    }

    std::string desc_str = pwallet->offline_desc;
    std::string xpub_str = EncodeExtPubKey(xpub);

    // TODO: More properly expose key parsing functionality

    // Strip last parenths(up to 2) and "/*" to let ParseKeyPath do its thing
    desc_str.erase(std::remove(desc_str.begin(), desc_str.end(), ')'), desc_str.end());
    desc_str = desc_str.substr(0, desc_str.size()-2);

    // Since we know there are no key origin data, directly call inner parsing functions
    Span<const char> span(desc_str.data(), desc_str.size());
    auto split = Split(span, '/');
    KeyPath key_path;
    if (!ParseKeyPath(split, key_path)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Stored keypath in descriptor cannot be parsed.");
    }
    key_path.push_back(counter);

    secp256k1_pubkey onlinepubkey_secp;
    if (secp256k1_ec_pubkey_parse(secp256k1_ctx, &onlinepubkey_secp, onlinepubkey.begin(), onlinepubkey.size()) != 1) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Pubkey is invalid");
    }

    // Get index of given online key
    int whitelistindex=-1;
    std::vector<secp256k1_pubkey> pak_online = paklist.OnlineKeys();
    for (unsigned int i=0; i<pak_online.size(); i++) {
        if (memcmp((void *)&pak_online[i], (void *)&onlinepubkey_secp, sizeof(secp256k1_pubkey)) == 0) {
            whitelistindex = i;
            break;
        }
    }
    if (whitelistindex == -1)
        throw JSONRPCError(RPC_WALLET_ERROR, "Given online key is not in Pegout Authorization Key List");

    // Parse master pubkey
    CPubKey masterpub = xpub.pubkey;
    secp256k1_pubkey masterpub_secp;
    int ret = secp256k1_ec_pubkey_parse(secp256k1_ctx, &masterpub_secp, masterpub.begin(), masterpub.size());
    if (ret != 1) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Master pubkey could not be parsed.");
    }

    secp256k1_pubkey btcpub_secp;
    memcpy(&btcpub_secp, &masterpub_secp, sizeof(secp256k1_pubkey));

    // Negate master pubkey
    ret = secp256k1_ec_pubkey_negate(secp256k1_ctx, &masterpub_secp);

    // Make sure negated master pubkey is in PAK list at same index as online_pubkey
    if (memcmp((void *)&paklist.OfflineKeys()[whitelistindex], (void *)&masterpub_secp, sizeof(secp256k1_pubkey)) != 0) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Given bitcoin_descriptor cannot be found in same entry as known liquid_pak");
    }

    // Get online PAK
    CKey masterOnlineKey;
    if (!spk_man->GetKey(onlinepubkey.GetID(), masterOnlineKey))
        throw JSONRPCError(RPC_WALLET_ERROR, "Given online key is in master set but not in wallet");

    // Tweak offline pubkey by tweakSum aka sumkey to get bitcoin key
    std::vector<unsigned char> tweakSum;
    if (!DerivePubTweak(key_path, xpub.pubkey, xpub.chaincode, tweakSum)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Could not create xpub tweak to generate proof.");
    }
    ret = secp256k1_ec_pubkey_tweak_add(secp256k1_ctx, &btcpub_secp, tweakSum.data());
    CHECK_NONFATAL(ret);

    std::vector<unsigned char> btcpubkeybytes;
    btcpubkeybytes.resize(33);
    size_t btclen = 33;
    ret = secp256k1_ec_pubkey_serialize(secp256k1_ctx, &btcpubkeybytes[0], &btclen, &btcpub_secp, SECP256K1_EC_COMPRESSED);
    CHECK_NONFATAL(ret == 1);
    CHECK_NONFATAL(btclen == 33);
    CHECK_NONFATAL(btcpubkeybytes.size() == 33);

    //Create, verify whitelist proof
    secp256k1_whitelist_signature sig;
    if(secp256k1_whitelist_sign(secp256k1_ctx, &sig, &paklist.OnlineKeys()[0], &paklist.OfflineKeys()[0], paklist.size(), &btcpub_secp, masterOnlineKey.begin(), &tweakSum[0], whitelistindex) != 1) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Pegout authorization proof signing failed");
    }

    if (secp256k1_whitelist_verify(secp256k1_ctx, &sig, &paklist.OnlineKeys()[0], &paklist.OfflineKeys()[0], paklist.size(), &btcpub_secp) != 1) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Pegout authorization proof was created and signed but is invalid");
    }

    //Serialize
    const size_t expectedOutputSize = 1 + 32 * (1 + paklist.size());
    CHECK_NONFATAL(1 + 32 * (1 + 256) >= expectedOutputSize);
    unsigned char output[1 + 32 * (1 + 256)];
    size_t outlen = expectedOutputSize;
    secp256k1_whitelist_signature_serialize(secp256k1_ctx, output, &outlen, &sig);
    CHECK_NONFATAL(outlen == expectedOutputSize);
    std::vector<unsigned char> whitelistproof(output, output + expectedOutputSize / sizeof(unsigned char));

    // Derive the end address in mainchain
    std::vector<CScript> scripts;
    if (!descriptor->Expand(counter, provider, scripts, provider)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Could not generate mainchain destination with descriptor. This is a bug.");
    }
    CHECK_NONFATAL(scripts.size() == 1);
    CScript mainchain_script = scripts[0];
    CTxDestination bitcoin_address;
    ExtractDestination(mainchain_script, bitcoin_address);

    uint256 genesisBlockHash = Params().ParentGenesisBlockHash();
    NullData nulldata;
    nulldata << std::vector<unsigned char>(genesisBlockHash.begin(), genesisBlockHash.end());
    nulldata << std::vector<unsigned char>(mainchain_script.begin(), mainchain_script.end());
    nulldata << btcpubkeybytes;
    nulldata << whitelistproof;
    CTxDestination address(nulldata);
    CHECK_NONFATAL(GetScriptForDestination(nulldata).IsPegoutScript(genesisBlockHash));

    std::vector<CRecipient> recipients;
    CRecipient recipient = {GetScriptForDestination(address), nAmount, Params().GetConsensus().pegged_asset, CPubKey(), subtract_fee};
    recipients.push_back(recipient);

    if (!ScriptHasValidPAKProof(GetScriptForDestination(nulldata), Params().ParentGenesisBlockHash(), paklist)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Resulting scriptPubKey is non-standard. Ensure pak=reject is not set");
    }

    bool verbose = request.params[3].isNull() ? false: request.params[3].get_bool();
    mapValue_t mapValue;
    CCoinControl no_coin_control; // This is a deprecated API
    UniValue tx_hash_hex = SendMoney(*pwallet, no_coin_control, recipients, std::move(mapValue), verbose, true /* ignore_blind_fail */);

    pwallet->SetOfflineCounter(counter+1);

    std::stringstream ss;
    ss << counter;

    UniValue obj(UniValue::VOBJ);
    if (!verbose) {
        obj.pushKV("txid", tx_hash_hex);
    } else {
        obj.pushKV("txid", tx_hash_hex["txid"]);
        obj.pushKV("fee_reason", tx_hash_hex["fee_reason"]);
    }
    obj.pushKV("bitcoin_address", EncodeParentDestination(bitcoin_address));
    obj.pushKV("bip32_counter", ss.str());
    obj.pushKV("bitcoin_descriptor", pwallet->offline_desc);
    return obj;
},
    };
}

// BIP300 drivechain peg-out replaces the legacy federated/PAK sendtomainchain paths.
RPCHelpMan sendtomainchain()
{
    return sendtomainchain_base();
}

RPCHelpMan drivechainrecoverwithdrawal()
{
    return RPCHelpMan{"drivechainrecoverwithdrawal",
                "\nInspect, and optionally resubmit, a drivechain withdrawal that is still in flight.\n"
                "\nThe exact M6 is journalled before first submission. A crash or enforcer outage therefore\n"
                "leaves a durable record instead of forcing reconstruction from chain state that may move.\n"
                "This call reports that record and can resubmit the exact same bundle bytes.\n"
                "\nResubmission is idempotent: the M6 identity is fixed by the journal, so retrying cannot\n"
                "create a second, competing bundle.\n",
                {
                    {"resubmit", RPCArg::Type::BOOL, RPCArg::Default{false}, "Resubmit the journalled bundle to the enforcer."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::BOOL, "pending", "whether a withdrawal is in flight"},
                        {RPCResult::Type::STR_HEX, "m6id", /*optional=*/true, "the withdrawal bundle identity"},
                        {RPCResult::Type::STR_HEX, "sidechain_txid", /*optional=*/true, "the sidechain spend"},
                        {RPCResult::Type::NUM, "state", /*optional=*/true, "0 reserved, 1 legacy transition, 2 bundle submitted, 3 settled, 4 failed"},
                        {RPCResult::Type::STR, "destination", /*optional=*/true, "the requested parent-chain destination"},
                        {RPCResult::Type::STR_AMOUNT, "amount", /*optional=*/true, "withdrawal amount"},
                        {RPCResult::Type::STR, "l1_status", /*optional=*/true, "enforcer view of the bundle"},
                        {RPCResult::Type::BOOL, "journal_retained", /*optional=*/true, "whether the durable lifecycle record is retained for restart safety"},
                    },
                },
                RPCExamples{
                    HelpExampleCli("drivechainrecoverwithdrawal", "")
            + HelpExampleCli("drivechainrecoverwithdrawal", "true")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const fs::path data_dir = gArgs.GetDataDirNet();
    node::WithdrawalJournalEntry journal;
    std::string journal_error;
    const node::WithdrawalJournalReadResult journal_result =
        node::ReadWithdrawalJournal(data_dir, journal, &journal_error);

    UniValue result(UniValue::VOBJ);
    if (journal_result == node::WithdrawalJournalReadResult::MISSING) {
        result.pushKV("pending", false);
        return result;
    }
    if (journal_result == node::WithdrawalJournalReadResult::CORRUPT) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            "Withdrawal journal is corrupt; refusing recovery or replacement: " + journal_error);
    }
    if (journal.sidechain_slot != DrivechainSidechainSlot()) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            strprintf(
                "Withdrawal journal belongs to sidechain slot %d, not configured slot %d",
                journal.sidechain_slot, DrivechainSidechainSlot()));
    }

    result.pushKV("pending", journal.GetState() != node::WithdrawalJournalState::SETTLED);
    result.pushKV("m6id", journal.m6id.GetHex());
    result.pushKV("sidechain_txid", journal.sidechain_txid.GetHex());
    result.pushKV("sidechain_vout", static_cast<uint64_t>(journal.sidechain_vout));
    result.pushKV("sidechain_height", static_cast<uint64_t>(journal.sidechain_height));
    result.pushKV("destination", journal.destination);
    result.pushKV("amount", ValueFromAmount(journal.amount));
    result.pushKV("mainchain_fee_sats", journal.mainchain_fee);
    result.pushKV("mainchain_payout_script", HexStr(journal.payout_script));
    result.pushKV("created_time", journal.created_time);
    result.pushKV("journal_retained", true);

    const int sidechain_id = DrivechainSidechainSlot();
    const std::string m6id_hex = journal.m6id.GetHex();

    std::string mainchain_tip;
    std::string l1_status;
    std::string status_error;
    try {
        l1_status = FetchDrivechainWithdrawalBundleEventStatus(
            sidechain_id, m6id_hex, mainchain_tip);
    } catch (const UniValue& error) {
        status_error = error.write();
    } catch (const std::exception& error) {
        status_error = error.what();
    }
    if (!mainchain_tip.empty()) result.pushKV("mainchain_tip", mainchain_tip);
    result.pushKV(
        "l1_status",
        status_error.empty() ? (l1_status.empty() ? "missing" : l1_status) : "unavailable");
    if (!status_error.empty()) result.pushKV("l1_status_error", status_error);

    // SETTLED is terminal even if removing the journal failed after the L1
    // success was persisted. Never let an enforcer outage or an explicit
    // resubmit request turn that durable completion record back into an active
    // bundle.
    if (journal.GetState() == node::WithdrawalJournalState::SETTLED) {
        if (node::GetCurrentDrivechainWithdrawalBundleHash() == journal.m6id) {
            node::ClearCurrentDrivechainWithdrawalBundleHash(journal.m6id);
        }
        result.pushKV("pending", false);
        result.pushKV("state", int{journal.state});
        result.pushKV("resubmitted", false);
        return result;
    }

    if (l1_status == "succeeded") {
        node::WithdrawalJournalEntry settled = journal;
        settled.SetState(node::WithdrawalJournalState::SETTLED);
        if (!node::WriteWithdrawalJournal(data_dir, settled)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Unable to persist the settled withdrawal state");
        }
        if (node::GetCurrentDrivechainWithdrawalBundleHash() == journal.m6id) {
            node::ClearCurrentDrivechainWithdrawalBundleHash(journal.m6id);
        }
        result.pushKV("pending", false);
        result.pushKV("state", int{settled.state});
        return result;
    }

    const bool resubmit = !request.params[0].isNull() && request.params[0].get_bool();
    if (resubmit && !status_error.empty()) {
        throw JSONRPCError(
            RPC_MISC_ERROR,
            "Refusing to resubmit while authenticated L1/enforcer status is unavailable: " +
                status_error);
    }
    if (l1_status == "failed") {
        if (journal.GetState() != node::WithdrawalJournalState::FAILED) {
            journal.SetState(node::WithdrawalJournalState::FAILED);
            if (!node::WriteWithdrawalJournal(data_dir, journal)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Unable to persist the failed withdrawal state");
            }
        }
        if (node::GetCurrentDrivechainWithdrawalBundleHash() == journal.m6id) {
            node::ClearCurrentDrivechainWithdrawalBundleHash(journal.m6id);
        }
        result.pushKV("action_required", "retry with resubmit=true after correcting the L1 rejection cause");
        if (!resubmit) {
            result.pushKV("state", int{journal.state});
            return result;
        }
    }

    if (l1_status == "submitted") {
        if (journal.GetState() != node::WithdrawalJournalState::BUNDLE_SUBMITTED) {
            journal.SetState(node::WithdrawalJournalState::BUNDLE_SUBMITTED);
            if (!node::WriteWithdrawalJournal(data_dir, journal)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Unable to persist the submitted withdrawal state");
            }
        }
        const uint256 current = node::GetCurrentDrivechainWithdrawalBundleHash();
        if (!current.IsNull() && current != journal.m6id) {
            throw JSONRPCError(RPC_WALLET_ERROR, "A different withdrawal bundle is active");
        }
        if (current.IsNull()) node::RestoreCurrentDrivechainWithdrawalBundleHash(journal.m6id);
        result.pushKV("state", int{journal.state});
        result.pushKV("resubmitted", false);
        result.pushKV("note", "the enforcer already holds this bundle; no resubmission was needed");
        return result;
    }

    if (!resubmit) {
        result.pushKV("state", int{journal.state});
        return result;
    }

    const uint256 current = node::GetCurrentDrivechainWithdrawalBundleHash();
    if (!current.IsNull() && current != journal.m6id) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            strprintf("A different withdrawal bundle is active: %s", current.GetHex()));
    }
    std::optional<DrivechainWithdrawalBundleCreationGuard> creation_guard;
    if (current.IsNull()) creation_guard.emplace();

    wallet::DrivechainWithdrawalBundle bundle;
    bundle.bytes = journal.bundle_bytes;
    bundle.m6id = journal.m6id;
    result.pushKV("broadcast", BroadcastDrivechainWithdrawalBundle(bundle));
    result.pushKV("resubmitted", true);

    node::WithdrawalJournalEntry submitted = journal;
    submitted.SetState(node::WithdrawalJournalState::BUNDLE_SUBMITTED);
    if (!node::WriteWithdrawalJournal(data_dir, submitted)) {
        throw JSONRPCError(
            RPC_WALLET_ERROR,
            "M6 was resubmitted, but the submitted journal state could not be persisted; retry remains safe");
    }
    if (creation_guard.has_value()) creation_guard->Complete(journal.m6id);
    result.pushKV("state", int{submitted.state});

    try {
        result.pushKV(
            "l1_event_verification",
            VerifyDrivechainWithdrawalBundleEvent(sidechain_id, m6id_hex));
    } catch (const UniValue& error) {
        result.pushKV("l1_event_verification_error", error.write());
    } catch (const std::exception& error) {
        result.pushKV("l1_event_verification_error", error.what());
    }
    return result;
},
    };
}

extern UniValue signrawtransaction(const JSONRPCRequest& request);

template <typename T_tx_ref, typename T_merkle_block>
static UniValue createrawpegin(const JSONRPCRequest& request, T_tx_ref& txBTCRef, T_merkle_block& merkleBlock)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    LOCK(pwallet->cs_wallet);

    std::vector<unsigned char> txData = ParseHex(request.params[0].get_str());
    std::vector<unsigned char> txOutProofData = ParseHex(request.params[1].get_str());

    std::set<CScript> claim_scripts;
    if (request.params.size() > 2) {
        const std::string claim_script = request.params[2].get_str();
        if (!IsHex(claim_script)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Given claim_script is not hex.");
        }
        // If given manually, no need for it to be a witness script
        std::vector<unsigned char> witnessBytes(ParseHex(claim_script));
        CScript witness_script(witnessBytes.begin(), witnessBytes.end());
        claim_scripts.insert(std::move(witness_script));
    }
    else {
        // Look for known wpkh address in wallet
        for (std::map<CTxDestination, CAddressBookData>::const_iterator iter = pwallet->m_address_book.begin(); iter != pwallet->m_address_book.end(); ++iter) {
            CScript dest_script = GetScriptForDestination(iter->first);
            claim_scripts.insert(std::move(dest_script));
        }
    }

    // Make the tx
    CMutableTransaction mtx;

    // Construct peg-in input
    CreatePegInInput(mtx, 0, txBTCRef, merkleBlock, claim_scripts, txData, txOutProofData, wallet->chain().getTip());

    // Get value for peg-in output
    CAmount value = 0;
    if (!GetAmountFromParentChainPegin(value, *txBTCRef, mtx.vin[0].prevout.n)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Amounts to peg-in must be explicit and asset must be %s", Params().GetConsensus().parent_pegged_asset.GetHex()));
    }

    const PeginMinimum pegin_minimum = Params().GetPeginMinimum();
    if (pwallet->chain().getTip()->nHeight >= pegin_minimum.height && value < pegin_minimum.amount) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Peg-in amount (%d) is lower than the minimum peg-in amount for this chain (%d).", FormatMoney(value), FormatMoney(pegin_minimum.amount)));
    }

    const PeginSubsidy pegin_subsidy = Params().GetPeginSubsidy();
    bool subsidy_required = pwallet->chain().getTip()->nHeight >= pegin_subsidy.height && value < pegin_subsidy.threshold;
    if (subsidy_required && !gArgs.GetBoolArg("-validatepegin", Params().GetConsensus().has_parent_chain) && request.params[3].isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Bitcoin transaction fee rate must be supplied, because validatepegin is off and this peg-in requires a burn subsidy.");
    }

    CAmount fee = 0;
    uint32_t parent_vsize = 0;
    CFeeRate feerate = CFeeRate{0};
    if (gArgs.GetBoolArg("-validatepegin", false) && subsidy_required) {
        std::string txid = txBTCRef->GetHash().ToString();
        std::string blockhash = merkleBlock.header.GetHash().ToString();
        UniValue params(UniValue::VARR);
        params.push_back(txid);
        params.push_back(2);
        params.push_back(blockhash);
        UniValue result = CallMainChainRPC("getrawtransaction", params);
        if (result["error"].isStr()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, result["error"]["message"].get_str());
        } else {
            parent_vsize = result["result"]["vsize"].get_int64();
            if (result["result"]["fee"].isNum()) {
                fee = static_cast<CAmount>(std::round(result["result"]["fee"].get_real() * COIN));
            } else if (result["result"]["fee"].isObject()) {
                std::string asset = Params().GetConsensus().parent_pegged_asset.GetHex();
                if (result["result"]["fee"][asset].isNum()) {
                    fee = static_cast<CAmount>(std::round(result["result"]["fee"][asset].get_real() * COIN));
                } else {
                    throw JSONRPCError(RPC_MISC_ERROR, "No fee result for the parent pegged asset.");
                }
            } else {
                throw JSONRPCError(RPC_MISC_ERROR, "Fee result is not a number or object.");
            }
            // when parent feerate is less than 1 sat/vb, use 1 sat/vb for the calculation
            feerate = std::max(CFeeRate{fee, parent_vsize}, CFeeRate{1000});
        }
    } else if (!request.params[3].isNull()) {
        // manual feerate, specified in sats/vb but CFeeRate takes sats/Kvb
        CAmount satsperk = static_cast<CAmount>(std::round(request.params[3].get_real() * 1000));
        feerate = std::max(CFeeRate{satsperk}, CFeeRate{1000});
    }

    // Manually construct peg-in transaction, sign it, and send it off.
    // Decrement the output value as much as needed given the total vsize to
    // pay the fees.

    if (!pwallet->IsLocked())
        pwallet->TopUpKeyPool();

    // Generate a new key that is added to wallet
    CTxDestination wpkhash;
    bilingual_str error;
    if (!pwallet->GetNewDestination(OutputType::BECH32, "", wpkhash, error)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, error.original);
    }

    // add a wallet output for the peg-in value
    mtx.vout.push_back(CTxOut(Params().GetConsensus().pegged_asset, value, GetScriptForDestination(wpkhash)));
    if (subsidy_required) {
        // add an op_return for the peg-in fee subsidy
        mtx.vout.push_back(CTxOut(Params().GetConsensus().pegged_asset, 0, CScript() << OP_RETURN));
    }
    // add a fee output
    mtx.vout.push_back(CTxOut(Params().GetConsensus().pegged_asset, 0, CScript()));

    // Estimate fee for transaction, decrement fee output (including witness data)
    unsigned int nBytes = GetVirtualTransactionSize(CTransaction(mtx)) + (1 + 1 + 72 + 1 + 33) / WITNESS_SCALE_FACTOR;
    CCoinControl coin_control;
    FeeCalculation feeCalc;
    CAmount nFeeNeeded = GetMinimumFee(*pwallet, nBytes, coin_control, &feeCalc);

    if (nFeeNeeded == CAmount{0} && feeCalc.reason == FeeReason::FALLBACK) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Fee estimation failed. Fallbackfee is disabled. Wait a few blocks or enable -fallbackfee.");
    }

    if (subsidy_required) {
        CHECK_NONFATAL(mtx.vout.size() == 3);

        // calculate the subsidy as the amount required to spend the P2WSH output
        const auto& fedpegscripts = GetValidFedpegScripts(pwallet->chain().getTip(), Params().GetConsensus(), true /* nextblock_validation */);
        int t = 0;
        int n = 0;
        CHECK_NONFATAL(fedpegscripts.size() > 0);
        CHECK_NONFATAL(ParseFedPegQuorum(fedpegscripts[0].second, t, n));

        // P2WSH input is 41 bytes: txid (32) + vout (4) + scriptsig len (1) + sequence (4)
        // the witness to spend is `t` signatures + the script size
        unsigned int weight = WITNESS_SCALE_FACTOR * (32 + 4 + 1 + 4) + (t * 72 + fedpegscripts[0].second.size());
        unsigned int vbytes = (weight + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;

        CAmount subsidy = feerate.GetFee(vbytes);

        CAmount value = mtx.vout[0].nValue.GetAmount() - nFeeNeeded - subsidy;
        mtx.vout[0].nValue = value;
        mtx.vout[1].nValue = subsidy;
        mtx.vout[2].nValue = nFeeNeeded;
        if (IsDust(mtx.vout[0], pwallet->chain().relayDustFee())) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Peg-in transaction would create dust output.");
        }
    } else {
        CHECK_NONFATAL(mtx.vout.size() == 2);
        mtx.vout[0].nValue = mtx.vout[0].nValue.GetAmount() - nFeeNeeded;
        mtx.vout[1].nValue = nFeeNeeded;
    }

    UniValue ret(UniValue::VOBJ);

    // Return hex
    std::string strHex = EncodeHexTx(CTransaction(mtx), RPCSerializationFlags());
    ret.pushKV("hex", strHex);

    // Additional block lee-way to avoid bitcoin block races
    if (gArgs.GetBoolArg("-validatepegin", Params().GetConsensus().has_parent_chain)) {
        unsigned int required_depth = Params().GetConsensus().pegin_min_depth + 2;
        std::vector<uint256> txHashes;
        std::vector<unsigned int> txIndices;
        merkleBlock.txn.ExtractMatches(txHashes, txIndices);
        if (txIndices[0] == 0) {
            required_depth = std::max(required_depth, (unsigned int)COINBASE_MATURITY+2);
        }
        ret.pushKV("mature", IsConfirmedBitcoinBlock(merkleBlock.header.GetHash(), required_depth, merkleBlock.txn.GetNumTransactions()));
    }

    return ret;
}

RPCHelpMan createrawpegin()
{
    return RPCHelpMan{"createrawpegin",
                "\nCreates a raw transaction to claim coins from the main chain by creating a peg-in transaction with the necessary metadata after the corresponding Bitcoin transaction.\n"
                "Note that this call will not sign the transaction.\n"
                "If a transaction is not relayed it may require manual addition to a functionary mempool in order for it to be mined.\n",
                {
                    {"bitcoin_tx", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The raw bitcoin transaction (in hex) depositing bitcoin to the mainchain_address generated by getpeginaddress"},
                    {"txoutproof", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "A rawtxoutproof (in hex) generated by the mainchain daemon's `gettxoutproof` containing a proof of only bitcoin_tx"},
                    {"claim_script", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED_NAMED_ARG, "The witness program generated by getpeginaddress. Only needed if not in wallet."},
                    {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED_NAMED_ARG, "The fee rate of the Bitcoin transaction in sats/vb, only necessary when validatepegin=0."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "hex", "raw transaction data"},
                        {RPCResult::Type::BOOL, "mature", "Whether the peg-in is mature (only included when validating peg-ins)"},
                    },
                },
                RPCExamples{
                    HelpExampleCli("createrawpegin", "\"0200000002b80a99d63ca943d72141750d983a3eeda3a5c5a92aa962884ffb141eb49ffb4f000000006a473044022031ffe1d76decdfbbdb7e2ee6010e865a5134137c261e1921da0348b95a207f9e02203596b065c197e31bcc2f80575154774ac4e80acd7d812c91d93c4ca6a3636f27012102d2130dfbbae9bd27eee126182a39878ac4e117d0850f04db0326981f43447f9efeffffffb80a99d63ca943d72141750d983a3eeda3a5c5a92aa962884ffb141eb49ffb4f010000006b483045022100cf041ce0eb249ae5a6bc33c71c156549c7e5ad877ae39e2e3b9c8f1d81ed35060220472d4e4bcc3b7c8d1b34e467f46d80480959183d743dad73b1ed0e93ec9fd14f012103e73e8b55478ab9c5de22e2a9e73c3e6aca2c2e93cd2bad5dc4436a9a455a5c44feffffff0200e1f5050000000017a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87e86cbe00000000001976a914a25fe72e7139fd3f61936b228d657b2548b3936a88acc0020000\", \"00000020976e918ed537b0f99028648f2a25c0bd4513644fb84d9cbe1108b4df6b8edf6ba715c424110f0934265bf8c5763d9cc9f1675a0f728b35b9bc5875f6806be3d19cd5b159ffff7f2000000000020000000224eab3da09d99407cb79f0089e3257414c4121cb85a320e1fd0f88678b6b798e0713a8d66544b6f631f9b6d281c71633fb91a67619b189a06bab09794d5554a60105\" \"0014058c769ffc7d12c35cddec87384506f536383f9c\"")
            + HelpExampleRpc("createrawpegin", "\"0200000002b80a99d63ca943d72141750d983a3eeda3a5c5a92aa962884ffb141eb49ffb4f000000006a473044022031ffe1d76decdfbbdb7e2ee6010e865a5134137c261e1921da0348b95a207f9e02203596b065c197e31bcc2f80575154774ac4e80acd7d812c91d93c4ca6a3636f27012102d2130dfbbae9bd27eee126182a39878ac4e117d0850f04db0326981f43447f9efeffffffb80a99d63ca943d72141750d983a3eeda3a5c5a92aa962884ffb141eb49ffb4f010000006b483045022100cf041ce0eb249ae5a6bc33c71c156549c7e5ad877ae39e2e3b9c8f1d81ed35060220472d4e4bcc3b7c8d1b34e467f46d80480959183d743dad73b1ed0e93ec9fd14f012103e73e8b55478ab9c5de22e2a9e73c3e6aca2c2e93cd2bad5dc4436a9a455a5c44feffffff0200e1f5050000000017a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87e86cbe00000000001976a914a25fe72e7139fd3f61936b228d657b2548b3936a88acc0020000\", \"00000020976e918ed537b0f99028648f2a25c0bd4513644fb84d9cbe1108b4df6b8edf6ba715c424110f0934265bf8c5763d9cc9f1675a0f728b35b9bc5875f6806be3d19cd5b159ffff7f2000000000020000000224eab3da09d99407cb79f0089e3257414c4121cb85a320e1fd0f88678b6b798e0713a8d66544b6f631f9b6d281c71633fb91a67619b189a06bab09794d5554a60105\", \"0014058c769ffc7d12c35cddec87384506f536383f9c\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    if (!IsHex(request.params[0].get_str()) || !IsHex(request.params[1].get_str())) {
        throw JSONRPCError(RPC_TYPE_ERROR, "the first two arguments must be hex strings");
    }

    UniValue ret(UniValue::VOBJ);
    if (Params().GetConsensus().ParentChainHasPow()) {
        Sidechain::Bitcoin::CTransactionRef txBTCRef;
        Sidechain::Bitcoin::CMerkleBlock merkleBlock;
        ret = createrawpegin(request, txBTCRef, merkleBlock);
        if (!CheckParentProofOfWork(merkleBlock.header.GetHash(), merkleBlock.header.nBits, Params().GetConsensus())) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid tx out proof");
        }
    } else {
        CTransactionRef txBTCRef;
        CMerkleBlock merkleBlock;
        ret = createrawpegin(request, txBTCRef, merkleBlock);
        if (!CheckProofSignedParent(merkleBlock.header, Params().GetConsensus())) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid tx out proof");
        }
    }
    return ret;
},
    };
}

RPCHelpMan claimpegin()
{
    return RPCHelpMan{"claimpegin",
                "\nClaim coins from the main chain by creating a peg-in transaction with the necessary metadata after the corresponding Bitcoin transaction.\n"
                "Note that the transaction will not be relayed unless it is buried at least 102 blocks deep.\n"
                "If a transaction is not relayed it may require manual addition to a functionary mempool in order for it to be mined.\n",
                {
                    {"bitcoin_tx", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The raw bitcoin transaction (in hex) depositing bitcoin to the mainchain_address generated by getpeginaddress"},
                    {"txoutproof", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "A rawtxoutproof (in hex) generated by the mainchain daemon's `gettxoutproof` containing a proof of only bitcoin_tx"},
                    {"claim_script", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED_NAMED_ARG, "The witness program generated by getpeginaddress. Only needed if not in wallet."},
                    {"fee_rate", RPCArg::Type::AMOUNT, RPCArg::Optional::OMITTED_NAMED_ARG, "The fee rate of the Bitcoin transaction in sats/vb, only necessary when validatepegin=0."},
                },
                RPCResult{
                    RPCResult::Type::STR_HEX, "txid", "txid of the resulting sidechain transaction",
                },
                RPCExamples{
                    HelpExampleCli("claimpegin", "\"0200000002b80a99d63ca943d72141750d983a3eeda3a5c5a92aa962884ffb141eb49ffb4f000000006a473044022031ffe1d76decdfbbdb7e2ee6010e865a5134137c261e1921da0348b95a207f9e02203596b065c197e31bcc2f80575154774ac4e80acd7d812c91d93c4ca6a3636f27012102d2130dfbbae9bd27eee126182a39878ac4e117d0850f04db0326981f43447f9efeffffffb80a99d63ca943d72141750d983a3eeda3a5c5a92aa962884ffb141eb49ffb4f010000006b483045022100cf041ce0eb249ae5a6bc33c71c156549c7e5ad877ae39e2e3b9c8f1d81ed35060220472d4e4bcc3b7c8d1b34e467f46d80480959183d743dad73b1ed0e93ec9fd14f012103e73e8b55478ab9c5de22e2a9e73c3e6aca2c2e93cd2bad5dc4436a9a455a5c44feffffff0200e1f5050000000017a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87e86cbe00000000001976a914a25fe72e7139fd3f61936b228d657b2548b3936a88acc0020000\" \"00000020976e918ed537b0f99028648f2a25c0bd4513644fb84d9cbe1108b4df6b8edf6ba715c424110f0934265bf8c5763d9cc9f1675a0f728b35b9bc5875f6806be3d19cd5b159ffff7f2000000000020000000224eab3da09d99407cb79f0089e3257414c4121cb85a320e1fd0f88678b6b798e0713a8d66544b6f631f9b6d281c71633fb91a67619b189a06bab09794d5554a60105\" \"0014058c769ffc7d12c35cddec87384506f536383f9c\"")
            + HelpExampleRpc("claimpegin", "\"0200000002b80a99d63ca943d72141750d983a3eeda3a5c5a92aa962884ffb141eb49ffb4f000000006a473044022031ffe1d76decdfbbdb7e2ee6010e865a5134137c261e1921da0348b95a207f9e02203596b065c197e31bcc2f80575154774ac4e80acd7d812c91d93c4ca6a3636f27012102d2130dfbbae9bd27eee126182a39878ac4e117d0850f04db0326981f43447f9efeffffffb80a99d63ca943d72141750d983a3eeda3a5c5a92aa962884ffb141eb49ffb4f010000006b483045022100cf041ce0eb249ae5a6bc33c71c156549c7e5ad877ae39e2e3b9c8f1d81ed35060220472d4e4bcc3b7c8d1b34e467f46d80480959183d743dad73b1ed0e93ec9fd14f012103e73e8b55478ab9c5de22e2a9e73c3e6aca2c2e93cd2bad5dc4436a9a455a5c44feffffff0200e1f5050000000017a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87e86cbe00000000001976a914a25fe72e7139fd3f61936b228d657b2548b3936a88acc0020000\", \"00000020976e918ed537b0f99028648f2a25c0bd4513644fb84d9cbe1108b4df6b8edf6ba715c424110f0934265bf8c5763d9cc9f1675a0f728b35b9bc5875f6806be3d19cd5b159ffff7f2000000000020000000224eab3da09d99407cb79f0089e3257414c4121cb85a320e1fd0f88678b6b798e0713a8d66544b6f631f9b6d281c71633fb91a67619b189a06bab09794d5554a60105\", \"0014058c769ffc7d12c35cddec87384506f536383f9c\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    CTransactionRef tx_ref;
    CMutableTransaction mtx;

    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    LOCK(pwallet->cs_wallet);

    if (pwallet->chain().isInitialBlockDownload()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Peg-ins cannot be completed during initial sync or reindexing.");
    }

    // NOTE: Making an RPC from within another RPC is not generally a good idea. In particular, it
    //   is necessary to copy the URI, which contains the wallet if one was given; otherwise
    //   multi-wallet support will silently break. The resulting request object is still missing a
    //   bunch of other fields, although they are usually not used by RPC handlers. This is a
    //   brittle hack, and further examples of this pattern should not be introduced.

    // Get raw peg-in transaction
    JSONRPCRequest req;
    req.context = request.context;
    req.URI = request.URI;
    req.params = request.params;
    UniValue ret(createrawpegin().HandleRequest(req));  // See the note above, on why this is a bad idea.

    // Make sure it can be propagated and confirmed
    if (!ret["mature"].isNull() && ret["mature"].get_bool() == false) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Peg-in Bitcoin transaction needs more confirmations to be sent.");
    }

    // Sign it
    JSONRPCRequest req2;
    req2.context = request.context;
    req2.URI = request.URI;
    UniValue varr(UniValue::VARR);
    varr.push_back(ret["hex"]);
    req2.params = varr;
    UniValue result = signrawtransactionwithwallet().HandleRequest(req2);  // See the note above, on why this is a bad idea.

    if (!DecodeHexTx(mtx, result["hex"].get_str(), false, true)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    // To check if it's not double spending an existing peg-in UTXO, we check mempool acceptance.
    const MempoolAcceptResult res = pwallet->chain().testPeginClaimAcceptance(MakeTransactionRef(mtx));
    if (res.m_result_type != MempoolAcceptResult::ResultType::VALID) {
        bilingual_str error = Untranslated(strprintf("Error: The transaction was rejected! Reason given: %s", res.m_state.ToString()));
        throw JSONRPCError(RPC_WALLET_ERROR, error.original);
    }

    // Send it
    mapValue_t mapValue;
    pwallet->CommitTransaction(MakeTransactionRef(mtx), mapValue, {} /* orderForm */);

    return mtx.GetHash().GetHex();
},
    };
}

RPCHelpMan importdrivechaindeposit()
{
    return RPCHelpMan{"importdrivechaindeposit",
                "\nImport a confirmed BIP300/301 drivechain deposit into this Elements wallet.\n"
                "The node independently verifies the exact deposit outpoint, destination, value, CTIP,\n"
                "sidechain identity, mainchain network, and canonical confirmation through the enforcer\n"
                "before broadcasting a sidechain transaction anchored in the UTXO set.\n",
                {
                    {"mainchain_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The mainchain deposit transaction id observed in two-way-peg data."},
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The Elements address to credit."},
                    {"value_sats", RPCArg::Type::NUM, RPCArg::Optional::NO, "The deposit value in satoshis."},
                    {"fee_sats", RPCArg::Type::NUM, RPCArg::Default{1000}, "The sidechain relay fee to subtract from the credited output."},
                    {"mainchain_vout", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Exact mainchain deposit output. If omitted, it is inferred only when authenticated slot data has one unambiguous txid/address/value match."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "txid", "The deterministic wallet credit transaction id."},
                        {RPCResult::Type::STR_HEX, "mainchain_txid", "The mainchain deposit transaction id."},
                        {RPCResult::Type::NUM, "mainchain_vout", "The authenticated mainchain deposit output index."},
                        {RPCResult::Type::STR, "address", "The credited Elements address."},
                        {RPCResult::Type::STR_AMOUNT, "amount", "The credited amount in pegged asset units."},
                        {RPCResult::Type::NUM, "value_sats", "The credited amount in satoshis."},
                        {RPCResult::Type::NUM, "deposit_value_sats", "The deposit input value in satoshis."},
                        {RPCResult::Type::NUM, "fee_sats", "The sidechain relay fee subtracted from the credited output."},
                        {RPCResult::Type::STR_HEX, "hex", "The sidechain transaction hex."},
                        {RPCResult::Type::BOOL, "already_imported", "Whether this sidechain deposit transaction was already known."},
                        {RPCResult::Type::BOOL, "broadcast", "Whether the transaction was broadcast by this call."},
                    },
                },
                RPCExamples{
                    HelpExampleCli("importdrivechaindeposit", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" \"el1qq...\" 100000 1000 2")
            + HelpExampleRpc("importdrivechaindeposit", "\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\", \"el1qq...\", 100000, 1000, 2")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();
    pwallet->BlockUntilSyncedToCurrentChain();

    const std::string mainchain_txid_str = request.params[0].get_str();
    if (!IsHex(mainchain_txid_str) || mainchain_txid_str.size() != 64) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "mainchain_txid must be a 32-byte hex transaction id");
    }

    const std::string address = request.params[1].get_str();
    const CTxDestination dest = DecodeDestination(address);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Elements address");
    }
    {
        LOCK(pwallet->cs_wallet);
        if (!(pwallet->IsMine(dest) & ISMINE_SPENDABLE)) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                "Deposit address is not spendable by this wallet");
        }
    }

    int64_t value_sats{0};
    if (request.params[2].isNum()) {
        value_sats = request.params[2].get_int64();
    } else if (request.params[2].isStr() && ParseInt64(request.params[2].get_str(), &value_sats)) {
        // Allow elements-cli and bridge callers that serialize the satoshi amount as a string.
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "value_sats must be an integer number of satoshis");
    }
    if (value_sats <= 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "value_sats must be greater than zero");
    }
    if (value_sats > std::numeric_limits<CAmount>::max()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "value_sats is too large");
    }
    int64_t fee_sats{1000};
    if (request.params.size() > 3 && !request.params[3].isNull()) {
        if (request.params[3].isNum()) {
            fee_sats = request.params[3].get_int64();
        } else if (request.params[3].isStr() && ParseInt64(request.params[3].get_str(), &fee_sats)) {
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "fee_sats must be an integer number of satoshis");
        }
    }
    if (fee_sats < 0 || fee_sats >= value_sats) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "fee_sats must be non-negative and less than value_sats");
    }
    const CAmount deposit_amount = value_sats;
    const CAmount amount = value_sats - fee_sats;

    const uint256 mainchain_txid = uint256S(mainchain_txid_str);
    uint32_t mainchain_vout{0};
    if (request.params.size() > 4 && !request.params[4].isNull()) {
        int64_t parsed_vout{-1};
        if (request.params[4].isNum()) {
            parsed_vout = request.params[4].get_int64();
        } else if (request.params[4].isStr() &&
                   ParseInt64(request.params[4].get_str(), &parsed_vout)) {
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "mainchain_vout must be a non-negative integer");
        }
        if (parsed_vout < 0 ||
            static_cast<uint64_t>(parsed_vout) > std::numeric_limits<uint32_t>::max()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "mainchain_vout is out of range");
        }
        mainchain_vout = static_cast<uint32_t>(parsed_vout);
    } else {
        UniValue two_way_peg_data;
        std::string lookup_error;
        if (!GetDrivechainTwoWayPegData(
                DrivechainSidechainSlot(), two_way_peg_data, &lookup_error)) {
            throw JSONRPCError(
                RPC_MISC_ERROR,
                "Unable to infer mainchain_vout from authenticated enforcer data: " + lookup_error);
        }

        UniValue events;
        try {
            events = drivechain::NormalizeL1PegEvents(
                two_way_peg_data, DrivechainSidechainSlot());
        } catch (const std::exception& error) {
            throw JSONRPCError(
                RPC_VERIFY_REJECTED,
                "Authenticated deposit event data is malformed: " + std::string{error.what()});
        }

        const std::string address_hex = HexStr(std::vector<unsigned char>(address.begin(), address.end()));
        std::optional<uint32_t> inferred_vout;
        for (const UniValue& event : events.getValues()) {
            if (!event.isObject() || !event["kind"].isStr() ||
                event["kind"].get_str() != "deposit" ||
                !event["mainchain_txid"].isStr() ||
                !IsHex(event["mainchain_txid"].get_str()) ||
                event["mainchain_txid"].get_str().size() != 64 ||
                uint256S(event["mainchain_txid"].get_str()) != mainchain_txid ||
                !event["address_hex"].isStr() ||
                event["address_hex"].get_str() != address_hex ||
                !event["value_sats"].isNum() ||
                event["value_sats"].get_int64() != value_sats ||
                !event["mainchain_vout"].isNum()) {
                continue;
            }
            const int64_t candidate = event["mainchain_vout"].get_int64();
            if (candidate < 0 ||
                static_cast<uint64_t>(candidate) > std::numeric_limits<uint32_t>::max()) {
                throw JSONRPCError(RPC_VERIFY_REJECTED, "Authenticated deposit event has an invalid vout");
            }
            if (inferred_vout.has_value()) {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    "More than one authenticated deposit output matches txid/address/value; specify mainchain_vout explicitly");
            }
            inferred_vout = static_cast<uint32_t>(candidate);
        }
        if (!inferred_vout.has_value()) {
            throw JSONRPCError(
                RPC_VERIFY_REJECTED,
                "No authenticated slot deposit matches the supplied txid, address, and value");
        }
        mainchain_vout = *inferred_vout;
    }

    CMutableTransaction mtx;
    mtx.nVersion = 2;

    CTxIn pegin_input(COutPoint(mainchain_txid, mainchain_vout), CScript(), CTxIn::SEQUENCE_FINAL);
    pegin_input.m_is_pegin = true;
    mtx.vin.push_back(pegin_input);
    mtx.vout.push_back(CTxOut(Params().GetConsensus().pegged_asset, amount, GetScriptForDestination(dest)));
    if (g_con_elementsmode && fee_sats > 0) {
        mtx.vout.push_back(CTxOut(Params().GetConsensus().pegged_asset, fee_sats, CScript()));
    }
    mtx.witness.vtxinwit.resize(1);
    mtx.witness.vtxoutwit.resize(mtx.vout.size());
    mtx.witness.vtxinwit[0].m_pegin_witness = CreateDrivechainDepositPeginWitness(
        deposit_amount,
        Params().GetConsensus().pegged_asset,
        Params().ParentGenesisBlockHash(),
        CScript() << OP_TRUE,
        mainchain_txid);

    CTransactionRef tx_ref = MakeTransactionRef(mtx);
    std::string authentication_error;
    drivechain::AuthenticatedDeposit authenticated;
    if (!VerifyDrivechainDeposit(*tx_ref, 0, &authenticated, &authentication_error)) {
        throw JSONRPCError(
            RPC_VERIFY_REJECTED,
            "Drivechain deposit authentication failed: " + authentication_error);
    }
    DrivechainDepositEvidence evidence;
    if (!BuildDrivechainDepositEvidence(authenticated, evidence, &authentication_error)) {
        throw JSONRPCError(
            RPC_VERIFY_REJECTED,
            "Drivechain deposit evidence construction failed: " + authentication_error);
    }
    mtx.witness.vtxinwit[0].m_pegin_witness = CreateDrivechainDepositPeginWitness(
        deposit_amount,
        Params().GetConsensus().pegged_asset,
        Params().ParentGenesisBlockHash(),
        CScript() << OP_TRUE,
        evidence);
    tx_ref = MakeTransactionRef(mtx);
    const uint256 side_txid = tx_ref->GetHash();
    const std::string tx_hex = EncodeHexTx(*tx_ref);
    bool already_imported;
    bool already_confirmed{false};
    {
        LOCK(pwallet->cs_wallet);
        const CWalletTx* const wallet_tx = pwallet->GetWalletTx(side_txid);
        already_imported = wallet_tx != nullptr;
        already_confirmed = wallet_tx != nullptr &&
            pwallet->GetTxDepthInMainChain(*wallet_tx) > 0;
    }
    bool broadcast = false;

    // A wallet record alone is not evidence that an unconfirmed import is
    // still in the mempool. Always rebroadcast non-confirmed imports so a
    // restart or mempool eviction cannot leave a valid deposit stranded while
    // this RPC misleadingly reports success.
    if (!already_confirmed) {
        std::string err_string;
        if (pwallet->chain().broadcastTransaction(tx_ref, /*max_tx_fee=*/0, /*relay=*/true, err_string)) {
            broadcast = true;
            // Do not make the UI wait for the asynchronous mempool callback
            // before it can display the newly credited output.
            pwallet->transactionAddedToMempool(tx_ref, /*mempool_sequence=*/0);
        } else if (err_string.find("txn-already-in-mempool") != std::string::npos) {
            already_imported = true;
            pwallet->transactionAddedToMempool(tx_ref, /*mempool_sequence=*/0);
        } else if (err_string.find("already in block chain") != std::string::npos ||
                   err_string.find("Transaction already in block chain") != std::string::npos) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                "The authenticated deposit is already confirmed, but this wallet has not indexed it; "
                "run rescanblockchain for the deposit height, then retry importdrivechaindeposit");
        } else {
            throw JSONRPCError(RPC_TRANSACTION_REJECTED, err_string);
        }
    }

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("txid", side_txid.GetHex());
    ret.pushKV("mainchain_txid", mainchain_txid.GetHex());
    ret.pushKV("mainchain_vout", static_cast<uint64_t>(mainchain_vout));
    ret.pushKV("address", address);
    ret.pushKV("amount", ValueFromAmount(amount));
    ret.pushKV("value_sats", value_sats);
    ret.pushKV("deposit_value_sats", deposit_amount);
    ret.pushKV("fee_sats", fee_sats);
    ret.pushKV("hex", tx_hex);
    ret.pushKV("already_imported", already_imported);
    ret.pushKV("broadcast", broadcast);
    return ret;
},
    };
}

// Rewind the outputs to unblinded, and push placeholders for blinding info. Not exported.
void FillBlinds(CWallet* pwallet, CMutableTransaction& tx, std::vector<uint256>& output_value_blinds, std::vector<uint256>& output_asset_blinds, std::vector<CPubKey>& output_pubkeys, std::vector<CKey>& asset_keys, std::vector<CKey>& token_keys) {

    // Resize witness before doing anything
    tx.witness.vtxinwit.resize(tx.vin.size());
    tx.witness.vtxoutwit.resize(tx.vout.size());

    for (size_t nOut = 0; nOut < tx.vout.size(); ++nOut) {
        CTxOut& out = tx.vout[nOut];
        if (out.nValue.IsExplicit()) {
            CPubKey pubkey(out.nNonce.vchCommitment);
            if (!pubkey.IsFullyValid()) {
                output_pubkeys.push_back(CPubKey());
            } else {
                output_pubkeys.push_back(pubkey);
            }
            output_value_blinds.push_back(uint256());
            output_asset_blinds.push_back(uint256());
        } else if (out.nValue.IsCommitment()) {
            CTxOutWitness* ptxoutwit = &tx.witness.vtxoutwit[nOut];
            uint256 blinding_factor;
            uint256 asset_blinding_factor;
            CAsset asset;
            CAmount amount;
            // This can only be used to recover things like change addresses and self-sends.
            if (UnblindConfidentialPair(pwallet->GetBlindingKey(&out.scriptPubKey), out.nValue, out.nAsset, out.nNonce, out.scriptPubKey, ptxoutwit->vchRangeproof, amount, blinding_factor, asset, asset_blinding_factor) != 0) {
                // Wipe out confidential info from output and output witness
                CScript scriptPubKey = tx.vout[nOut].scriptPubKey;
                CTxOut newOut(asset, amount, scriptPubKey);
                tx.vout[nOut] = newOut;
                ptxoutwit->SetNull();

                // Mark for re-blinding with same key that deblinded it
                CPubKey pubkey(pwallet->GetBlindingKey(&out.scriptPubKey).GetPubKey());
                output_pubkeys.push_back(pubkey);
                output_value_blinds.push_back(uint256());
                output_asset_blinds.push_back(uint256());
            } else {
                output_pubkeys.push_back(CPubKey());
                output_value_blinds.push_back(uint256());
                output_asset_blinds.push_back(uint256());
            }
        } else {
            // Null or invalid, do nothing for that output
            output_pubkeys.push_back(CPubKey());
            output_value_blinds.push_back(uint256());
            output_asset_blinds.push_back(uint256());
        }
    }

    // Fill out issuance blinding keys to be used directly as nonce for rangeproof
    for (size_t nIn = 0; nIn < tx.vin.size(); ++nIn) {
        CAssetIssuance& issuance = tx.vin[nIn].assetIssuance;
        if (issuance.IsNull()) {
            asset_keys.push_back(CKey());
            token_keys.push_back(CKey());
            continue;
        }

        // Calculate underlying asset for use as blinding key script
        CAsset asset;
        // New issuance, compute the asset ids
        if (issuance.assetBlindingNonce.IsNull()) {
            uint256 entropy;
            GenerateAssetEntropy(entropy, tx.vin[nIn].prevout, issuance.assetEntropy);
            CalculateAsset(asset, entropy);
        }
        // Re-issuance
        else {
            // TODO Give option to skip blinding when the reissuance token was derived without blinding ability. For now we assume blinded
            // hashAssetIdentifier doubles as the entropy on reissuance
            CalculateAsset(asset, issuance.assetEntropy);
        }

        // Special format for issuance blinding keys, unique for each transaction
        CScript blindingScript = CScript() << OP_RETURN << std::vector<unsigned char>(tx.vin[nIn].prevout.hash.begin(), tx.vin[nIn].prevout.hash.end()) << tx.vin[nIn].prevout.n;

        for (size_t nPseudo = 0; nPseudo < 2; nPseudo++) {
            bool issuance_asset = (nPseudo == 0);
            std::vector<CKey>& issuance_blinding_keys = issuance_asset ? asset_keys : token_keys;
            CConfidentialValue& conf_value = issuance_asset ? issuance.nAmount : issuance.nInflationKeys;
            if (conf_value.IsCommitment()) {
                // Rangeproof must exist
                if (tx.witness.vtxinwit.size() <= nIn) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Transaction issuance is already blinded but has no attached rangeproof.");
                }
                CTxInWitness& txinwit = tx.witness.vtxinwit[nIn];
                std::vector<unsigned char>& vchRangeproof = issuance_asset ? txinwit.vchIssuanceAmountRangeproof : txinwit.vchInflationKeysRangeproof;
                uint256 blinding_factor;
                uint256 asset_blinding_factor;
                CAmount amount;
                if (UnblindConfidentialPair(pwallet->GetBlindingKey(&blindingScript), conf_value, CConfidentialAsset(asset), CConfidentialNonce(), CScript(), vchRangeproof, amount, blinding_factor, asset, asset_blinding_factor) != 0) {
                    // Wipe out confidential info from issuance
                    vchRangeproof.clear();
                    conf_value = CConfidentialValue(amount);
                    // One key blinds both values, single key needed for issuance reveal
                    issuance_blinding_keys.push_back(pwallet->GetBlindingKey(&blindingScript));
                } else {
                    // If  unable to unblind, leave it alone in next blinding step
                    issuance_blinding_keys.push_back(CKey());
                }
            } else if (conf_value.IsExplicit()) {
                // Use wallet to generate blindingkey used directly as nonce
                // as user is not "sending" to anyone.
                // Always assumed we want to blind here.
                // TODO Signal intent for all blinding via API including replacing nonce commitment
                issuance_blinding_keys.push_back(pwallet->GetBlindingKey(&blindingScript));
            } else  {
                // Null or invalid, don't try anything but append an empty key
                issuance_blinding_keys.push_back(CKey());
            }
        }
    }
}

RPCHelpMan blindrawtransaction()
{
    return RPCHelpMan{"blindrawtransaction",
                "\nConvert one or more outputs of a raw transaction into confidential ones using only wallet inputs.\n"
                "Returns the hex-encoded raw transaction.\n"
                "The output keys used can be specified by using a confidential address in createrawtransaction.\n"
                "This call may add an additional 0-value unspendable output in order to balance the blinders.\n",
                {
                    {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "A hex-encoded raw transaction."},
                    {"ignoreblindfail", RPCArg::Type::BOOL , RPCArg::Default{true}, "Return a transaction even when a blinding attempt fails due to number of blinded inputs/outputs."},
                    {"asset_commitments", RPCArg::Type::ARR, RPCArg::Optional::OMITTED_NAMED_ARG, "An array of input asset generators. If provided, this list must be empty, or match the final input commitment list, including ordering, to make a valid surjection proof. This list does not include generators for issuances, as these assets are inherently unblinded.",
                        {
                            {"assetcommitment", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "A hex-encoded asset commitment, one for each input."
            "                        Null commitments must be \"\"."},
                        }
                    },
                    {"blind_issuances", RPCArg::Type::BOOL , RPCArg::Default{true}, "Blind the issuances found in the raw transaction or not. All issuances will be blinded if true."},
                    {"totalblinder", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Ignored for now."},
                },
                RPCResult{
                    RPCResult::Type::STR_HEX, "transaction", "serialized transaction",
                },
                RPCExamples{""},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    std::vector<unsigned char> txData(ParseHexV(request.params[0], "argument 1"));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    CMutableTransaction tx;
    try {
        ssData >> tx;
    } catch (const std::exception &) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    bool ignore_blind_fail = true;
    if (request.params.size() > 1) {
        ignore_blind_fail = request.params[1].get_bool();
    }

    std::vector<std::vector<unsigned char> > auxiliary_generators;
    if (request.params.size() > 2) {
        UniValue assetCommitments = request.params[2].get_array();
        if (assetCommitments.size() != 0 && assetCommitments.size() < tx.vin.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Asset commitment array must have at least as many entries as transaction inputs.");
        }
        for (size_t nIn = 0; nIn < assetCommitments.size(); nIn++) {
            if (assetCommitments[nIn].isStr()) {
                std::string assetcommitment = assetCommitments[nIn].get_str();
                if (IsHex(assetcommitment) && assetcommitment.size() == 66) {
                    auxiliary_generators.push_back(ParseHex(assetcommitment));
                    continue;
                }
            }
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Asset commitments must be a hex encoded string of length 66.");
        }
    }

    bool blind_issuances = request.params[3].isNull() || request.params[3].get_bool();

    LOCK(pwallet->cs_wallet);

    const auto& fedpegscripts = GetValidFedpegScripts(pwallet->chain().getTip(), Params().GetConsensus(), true /* nextblock_validation */);

    std::vector<uint256> input_blinds;
    std::vector<uint256> input_asset_blinds;
    std::vector<CAsset> input_assets;
    std::vector<CAmount> input_amounts;
    int n_blinded_ins = 0;
    for (size_t nIn = 0; nIn < tx.vin.size(); ++nIn) {
        COutPoint prevout = tx.vin[nIn].prevout;

        // Special handling for peg-in inputs: no blinds and explicit amount/asset.
        if (tx.vin[nIn].m_is_pegin) {
            std::string err;
            if (tx.witness.vtxinwit.size() != tx.vin.size() || !IsValidPeginWitness(tx.witness.vtxinwit[nIn].m_pegin_witness, fedpegscripts, prevout, err, false)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Transaction contains invalid peg-in input: %s", err));
            }
            CTxOut pegin_output = GetPeginOutputFromWitness(tx.witness.vtxinwit[nIn].m_pegin_witness);
            input_blinds.push_back(uint256());
            input_asset_blinds.push_back(uint256());
            input_assets.push_back(pegin_output.nAsset.GetAsset());
            input_amounts.push_back(pegin_output.nValue.GetAmount());
            continue;
        }

        std::map<uint256, CWalletTx>::iterator it = pwallet->mapWallet.find(prevout.hash);
        if (it == pwallet->mapWallet.end() || InputIsMine(*pwallet, tx.vin[nIn]) == wallet::ISMINE_NO) {
            // For inputs we don't own, input assetcommitments for the surjection must be supplied.
            if (auxiliary_generators.size() > 0) {
                input_blinds.push_back(uint256());
                input_asset_blinds.push_back(uint256());
                input_assets.push_back(CAsset());
                input_amounts.push_back(-1);
                continue;
            }
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter: transaction spends from non-wallet output and no assetcommitment list was given.");
        }

        if (prevout.n >= it->second.tx->vout.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter: transaction spends non-existing output");
        }
        input_blinds.push_back(it->second.GetOutputAmountBlindingFactor(*pwallet, prevout.n));
        input_asset_blinds.push_back(it->second.GetOutputAssetBlindingFactor(*pwallet, prevout.n));
        input_assets.push_back(it->second.GetOutputAsset(*pwallet, prevout.n));
        input_amounts.push_back(it->second.GetOutputValueOut(*pwallet, prevout.n));
        if (it->second.tx->vout[prevout.n].nValue.IsCommitment()) {
            n_blinded_ins += 1;
        }
    }

    std::vector<uint256> output_blinds;
    std::vector<uint256> output_asset_blinds;
    std::vector<CPubKey> output_pubkeys;
    std::vector<CKey> asset_keys;
    std::vector<CKey> token_keys;
    // This fills out issuance blinding data for you from the wallet itself
    FillBlinds(pwallet, tx, output_blinds, output_asset_blinds, output_pubkeys, asset_keys, token_keys);

    if (!blind_issuances) {
        asset_keys.clear();
        token_keys.clear();
    }

    // How many are we trying to blind?
    int num_pubkeys = 0;
    unsigned int key_index = 0;
    for (unsigned int i = 0; i < output_pubkeys.size(); i++) {
        const CPubKey& key = output_pubkeys[i];
        if (key.IsValid()) {
            num_pubkeys++;
            key_index = i;
        }
    }
    for (const CKey& key : asset_keys) {
        if (key.IsValid()) num_pubkeys++;
    }
    for (const CKey& key : token_keys) {
        if (key.IsValid()) num_pubkeys++;
    }

    if (num_pubkeys == 0 && n_blinded_ins == 0) {
        // Vacuous, just return the transaction
        return EncodeHexTx(CTransaction(tx));
    } else if (n_blinded_ins > 0 && num_pubkeys == 0) {
        // Blinded inputs need to balanced with something to be valid, make a dummy.
        CTxOut newTxOut(tx.vout.back().nAsset.GetAsset(), 0, CScript() << OP_RETURN);
        tx.vout.push_back(newTxOut);
        num_pubkeys++;
        output_pubkeys.push_back(pwallet->GetBlindingPubKey(newTxOut.scriptPubKey));
    } else if (n_blinded_ins == 0 && num_pubkeys == 1) {
        if (ignore_blind_fail) {
            // Just get rid of the ECDH key in the nonce field and return
            tx.vout[key_index].nNonce.SetNull();
            return EncodeHexTx(CTransaction(tx));
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Unable to blind transaction: Add another output to blind in order to complete the blinding.");
        }
    }

    if (BlindTransaction(input_blinds, input_asset_blinds, input_assets, input_amounts, output_blinds, output_asset_blinds, output_pubkeys, asset_keys, token_keys, tx, (auxiliary_generators.size() ? &auxiliary_generators : NULL)) != num_pubkeys) {
        // TODO Have more rich return values, communicating to user what has been blinded
        // User may be ok not blinding something that for instance has no corresponding type on input
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Unable to blind transaction: Are you sure each asset type to blind is represented in the inputs?");
    }

    return EncodeHexTx(CTransaction(tx));
},
    };
}

RPCHelpMan unblindrawtransaction()
{
    return RPCHelpMan{"unblindrawtransaction",
                "\nRecovers unblinded transaction outputs from blinded outputs and issuance inputs when possible using wallet's known blinding keys, and strips related witness data.\n",
                {
                    {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hex string of the raw transaction."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "hex", "unblinded raw transaction"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("unblindrawtransaction", "\"blindedtransactionhex\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    RPCTypeCheck(request.params, {UniValue::VSTR});

    CMutableTransaction tx;
    if (!DecodeHexTx(tx, request.params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");

    std::vector<uint256> output_value_blinds;
    std::vector<uint256> output_asset_blinds;
    std::vector<CPubKey> output_pubkeys;
    std::vector<CKey> asset_keys;
    std::vector<CKey> token_keys;
    FillBlinds(pwallet, tx, output_value_blinds, output_asset_blinds, output_pubkeys, asset_keys, token_keys);

    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", EncodeHexTx(CTransaction(tx)));
    return result;
},
    };
}

static CTransactionRef SendGenerationTransaction(const CScript& asset_script, const CPubKey &asset_pubkey, const CScript& token_script, const CPubKey &token_pubkey, CAmount asset_amount, CAmount token_amount, IssuanceDetails* issuance_details, CWallet* pwallet)
{
    CAsset reissue_token = issuance_details->reissuance_token;
    CAmount curBalance = GetBalance(*pwallet).m_mine_trusted[reissue_token];

    if (!reissue_token.IsNull() && curBalance <= 0) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "No available reissuance tokens in wallet.");
    }

    std::vector<CRecipient> vecSend;
    // Signal outputs to skip "funding" with fixed asset numbers 1, 2, ...
    // We don't know the asset during initial issuance until inputs are chosen
    if (asset_script.size() > 0) {
        vecSend.push_back({asset_script, asset_amount, CAsset(uint256S("1")), asset_pubkey, false});
    }
    if (token_script.size() > 0) {
        CRecipient recipient = {token_script, token_amount, CAsset(uint256S("2")), token_pubkey, false};
        // We need to select the issuance token(s) to spend
        if (!reissue_token.IsNull()) {
            recipient.asset = reissue_token;
            recipient.nAmount = curBalance; // Or 1?
            // If the issuance token *is* the fee asset, subtract fee from this output
            if (reissue_token == ::policyAsset) {
                recipient.fSubtractFeeFromAmount = true;
            }
        }
        vecSend.push_back(recipient);
    }

    CAmount nFeeRequired;
    int nChangePosRet = -1;
    bilingual_str error;
    FeeCalculation fee_calc_out;
    CCoinControl dummy_control;
    BlindDetails blind_details;
    CTransactionRef tx_ref;
    if (!CreateTransaction(*pwallet, vecSend, tx_ref, nFeeRequired, nChangePosRet, error, dummy_control, fee_calc_out, true, &blind_details, issuance_details)) {
        throw JSONRPCError(RPC_WALLET_ERROR, error.original);
    }

    mapValue_t map_value;
    pwallet->CommitTransaction(tx_ref, std::move(map_value), {} /* orderForm */, &blind_details);

    return tx_ref;
}

RPCHelpMan issueasset()
{
    return RPCHelpMan{"issueasset",
                "\nCreate an asset. Must have funds in wallet to do so. Returns asset hex id.\n"
                "For more fine-grained control such as multiple issuances, see `rawissueasset` RPC call.\n",
                {
                    {"assetamount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount of asset to generate. Note that the amount is BTC-like, with 8 decimal places."},
                    {"tokenamount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount of reissuance tokens to generate. Note that the amount is BTC-like, with 8 decimal places. These will allow you to reissue the asset if in wallet using `reissueasset`. These tokens are not consumed during reissuance."},
                    {"blind", RPCArg::Type::BOOL, RPCArg::Default{true}, "Whether to blind the issuances."},
                    {"contract_hash", RPCArg::Type::STR_HEX, RPCArg::Default{"0000...0000"}, "Contract hash that is put into issuance definition. Must be 32 bytes worth in hex string form. This will affect the asset id."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "txid", "Transaction id for issuance"},
                        {RPCResult::Type::NUM, "vin", "The input position of the issuance in the transaction"},
                        {RPCResult::Type::STR_HEX, "entropy", "Entropy of the asset type"},
                        {RPCResult::Type::STR_HEX, "asset", "Asset type for issuance"},
                        {RPCResult::Type::STR_HEX, "token", "Token type for issuance"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("issueasset", "10 0")
            + HelpExampleRpc("issueasset", "10, 0")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    LOCK(pwallet->cs_wallet);

    if (!g_con_elementsmode) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Issuance can only be done on elements-style chains. Note: `-regtest` is Bitcoin's regtest mode, instead try `-chain=<custom chain name>`");
    }

    CAmount nAmount = AmountFromValue(request.params[0], false);
    CAmount nTokens = AmountFromValue(request.params[1], false);
    if (nAmount == 0 && nTokens == 0) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Issuance must have one non-zero component");
    }

    bool blind_issuances = request.params.size() < 3 || request.params[2].get_bool();

    // Check for optional contract to hash into definition
    uint256 contract_hash;
    if (request.params.size() >= 4) {
        contract_hash = ParseHashV(request.params[3], "contract_hash");
    }

    if (!pwallet->IsLocked())
        pwallet->TopUpKeyPool();

    // Generate a new key that is added to wallet
    bilingual_str error;
    CPubKey newKey;
    CTxDestination asset_dest;
    CTxDestination token_dest;
    CPubKey asset_dest_blindpub;
    CPubKey token_dest_blindpub;

    if (nAmount > 0) {
        if (!pwallet->GetNewDestination(OutputType::BECH32, "", asset_dest, error)) {
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, error.original);
        }
        asset_dest_blindpub = pwallet->GetBlindingPubKey(GetScriptForDestination(asset_dest));
    }
    if (nTokens > 0) {
        if (!pwallet->GetNewDestination(OutputType::BECH32, "", token_dest, error)) {
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, error.original);
        }
        token_dest_blindpub = pwallet->GetBlindingPubKey(GetScriptForDestination(token_dest));
    }

    CAsset dummyasset;
    IssuanceDetails issuance_details;
    issuance_details.blind_issuance = blind_issuances;
    issuance_details.contract_hash = contract_hash;
    CTransactionRef tx_ref = SendGenerationTransaction(GetScriptForDestination(asset_dest), asset_dest_blindpub, GetScriptForDestination(token_dest), token_dest_blindpub, nAmount, nTokens, &issuance_details, pwallet);

    // Calculate asset type, assumes first vin is used for issuance
    CAsset asset;
    CAsset token;
    CHECK_NONFATAL(!tx_ref->vin.empty());
    GenerateAssetEntropy(issuance_details.entropy, tx_ref->vin[0].prevout, issuance_details.contract_hash);
    CalculateAsset(asset, issuance_details.entropy);
    CalculateReissuanceToken(token, issuance_details.entropy, blind_issuances);

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("txid", tx_ref->GetHash().GetHex());
    ret.pushKV("vin", 0);
    ret.pushKV("entropy", issuance_details.entropy.GetHex());
    ret.pushKV("asset", asset.GetHex());
    ret.pushKV("token", token.GetHex());
    return ret;
},
    };
}

RPCHelpMan reissueasset()
{
    return RPCHelpMan{"reissueasset",
                "\nCreate more of an already issued asset. Must have reissuance token in wallet to do so. Reissuing does not affect your reissuance token balance, only asset.\n"
                "For more fine-grained control such as reissuing from a multi-signature address cold wallet, see `rawreissueasset` RPC call.\n",
                {
                    {"asset", RPCArg::Type::STR, RPCArg::Optional::NO, "The asset you want to re-issue. The corresponding token must be in your wallet."},
                    {"assetamount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount of additional asset to generate. Note that the amount is BTC-like, with 8 decimal places."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "txid", "transaction id for issuance"},
                        {RPCResult::Type::NUM, "vin", "input position of the issuance in the transaction"},
                    },
                },
                RPCExamples{
                    HelpExampleCli("reissueasset", "<asset> 0")
            + HelpExampleRpc("reissueasset", "<asset>, 0")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    LOCK(pwallet->cs_wallet);

    if (!g_con_elementsmode) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Issuance can only be done on elements-style chains. Note: `-regtest` is Bitcoin's regtest mode, instead try `-chain=<custom chain name>`");
    }

    std::string assetstr = request.params[0].get_str();
    CAsset asset = GetAssetFromString(assetstr);

    CAmount nAmount = AmountFromValue(request.params[1], false);
    if (nAmount <= 0) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Reissuance must create a non-zero amount.");
    }

    if (!pwallet->IsLocked()) {
        pwallet->TopUpKeyPool();
    }

    // Find the entropy and reissuance token in wallet
    IssuanceDetails issuance_details;
    issuance_details.reissuance_asset = asset;
    std::map<uint256, std::pair<CAsset, CAsset> > tokenMap = pwallet->GetReissuanceTokenTypes();
    for (const auto& it : tokenMap) {
        if (it.second.second == asset) {
            issuance_details.entropy = it.first;
            issuance_details.reissuance_token = it.second.first;
        }
        if (it.second.first == asset) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Asset given is a reissuance token type and can not be reissued.");
        }
    }
    if (issuance_details.reissuance_token.IsNull()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Asset reissuance token definition could not be found in wallet.");
    }

    // Add destination for the to-be-created asset
    bilingual_str error;
    CTxDestination asset_dest;
    if (!pwallet->GetNewDestination(OutputType::BECH32, "", asset_dest, error)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, error.original);
    }
    CPubKey asset_dest_blindpub = pwallet->GetBlindingPubKey(GetScriptForDestination(asset_dest));

    // Add destination for tokens we are moving
    CTxDestination token_dest;
    if (!pwallet->GetNewDestination(OutputType::BECH32, "", token_dest, error)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, error.original);
    }
    CPubKey token_dest_blindpub = pwallet->GetBlindingPubKey(GetScriptForDestination(token_dest));

    // Attempt a send.
    CTransactionRef tx_ref = SendGenerationTransaction(GetScriptForDestination(asset_dest), asset_dest_blindpub, GetScriptForDestination(token_dest), token_dest_blindpub, nAmount, -1, &issuance_details, pwallet);
    CHECK_NONFATAL(!tx_ref->vin.empty());

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("txid", tx_ref->GetHash().GetHex());
    for (uint64_t i = 0; i < tx_ref->vin.size(); i++) {
        if (!tx_ref->vin[i].assetIssuance.IsNull()) {
            obj.pushKV("vin", i);
            break;
        }
    }

    return obj;
},
    };
}

RPCHelpMan listissuances()
{
    return RPCHelpMan{"listissuances",
                "\nList all issuances known to the wallet for the given asset, or for all issued assets if none provided.\n",
                {
                    {"asset", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "The asset whose issaunces you wish to list. Accepts either the asset hex or the locally assigned asset label."},
                },
                RPCResult{
                    RPCResult::Type::ARR, "", "List of transaction issuances and information in wallet",
                    {
                        {RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "txid", "Transaction id for issuance"},
                            {RPCResult::Type::STR_HEX, "entropy", "Entropy of the asset type"},
                            {RPCResult::Type::STR_HEX, "asset", "Asset type for issuance if known"},
                            {RPCResult::Type::STR, "assetlabel", "Asset label for issuance if set"},
                            {RPCResult::Type::STR_HEX, "token", "Token type for issuancen"},
                            {RPCResult::Type::NUM, "vin", "The input position of the issuance in the transaction"},
                            {RPCResult::Type::STR_AMOUNT, "assetamount", "The amount of asset issued. Is -1 if blinded and unknown to wallet"},
                            {RPCResult::Type::STR_AMOUNT, "tokenamount", "The reissuance token amount issued. Is -1 if blinded and unknown to wallet"},
                            {RPCResult::Type::BOOL, "isreissuance", "Whether this is a reissuance"},
                            {RPCResult::Type::STR_HEX, "assetblinds", "Blinding factor for asset amounts"},
                            {RPCResult::Type::STR_HEX, "tokenblinds", "Blinding factor for token amounts"},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("listissuances", "<asset>")
            + HelpExampleRpc("listissuances", "<asset>")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (!wallet) return NullUniValue;
    CWallet* const pwallet = wallet.get();

    LOCK(pwallet->cs_wallet);

    std::string assetstr;
    CAsset asset_filter;
    if (request.params.size() > 0) {
        assetstr = request.params[0].get_str();
        asset_filter = GetAssetFromString(assetstr);
    }

    UniValue issuancelist(UniValue::VARR);
    for (const auto& it : pwallet->mapWallet) {
        const CWalletTx* pcoin = &it.second;
        CAsset asset;
        CAsset token;
        uint256 entropy;
        for (uint64_t vinIndex = 0; vinIndex < pcoin->tx->vin.size(); vinIndex++) {
            UniValue item(UniValue::VOBJ);
            const CAssetIssuance& issuance = pcoin->tx->vin[vinIndex].assetIssuance;
            if (issuance.IsNull()) {
                continue;
            }
            if (issuance.assetBlindingNonce.IsNull()) {
                GenerateAssetEntropy(entropy, pcoin->tx->vin[vinIndex].prevout, issuance.assetEntropy);
                CalculateAsset(asset, entropy);
                // Null is considered explicit
                CalculateReissuanceToken(token, entropy, issuance.nAmount.IsCommitment());
                item.pushKV("isreissuance", false);
                item.pushKV("token", token.GetHex());
                CAmount itamount = pcoin->GetIssuanceAmount(*pwallet, vinIndex, true);
                item.pushKV("tokenamount", (itamount == -1 ) ? -1 : ValueFromAmount(itamount));
                item.pushKV("tokenblinds", pcoin->GetIssuanceBlindingFactor(*pwallet, vinIndex, true).GetHex());
                item.pushKV("entropy", entropy.GetHex());
            } else {
                CalculateAsset(asset, issuance.assetEntropy);
                item.pushKV("isreissuance", true);
                item.pushKV("entropy", issuance.assetEntropy.GetHex());
            }
            item.pushKV("txid", pcoin->tx->GetHash().GetHex());
            item.pushKV("vin", vinIndex);
            item.pushKV("asset", asset.GetHex());
            const std::string label = gAssetsDir.GetLabel(asset);
            if (label != "") {
                item.pushKV("assetlabel", label);
            }
            CAmount iaamount = pcoin->GetIssuanceAmount(*pwallet, vinIndex, false);
            item.pushKV("assetamount", (iaamount == -1 ) ? -1 : ValueFromAmount(iaamount));
            item.pushKV("assetblinds", pcoin->GetIssuanceBlindingFactor(*pwallet, vinIndex, false).GetHex());
            if (!asset_filter.IsNull() && asset_filter != asset) {
                continue;
            }
            issuancelist.push_back(item);
        }
    }
    return issuancelist;
},
    };
}

RPCHelpMan destroyamount()
{
    return RPCHelpMan{"destroyamount",
                "\nDestroy an amount of a given asset.\n\n",
                {
                    {"asset", RPCArg::Type::STR, RPCArg::Optional::NO, "Hex asset id or asset label to destroy."},
                    {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "The amount to destroy (8 decimals above the minimal unit)."},
                    {"comment", RPCArg::Type::STR, RPCArg::Optional::OMITTED_NAMED_ARG, "A comment used to store what the transaction is for.\n"
            "                             This is not part of the transaction, just kept in your wallet."},
                    {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false}, "If true, return extra information about the transaction."},
                },
                {
                    RPCResult{"if verbose is not set or set to false",
                        RPCResult::Type::STR_HEX, "transactionid", "the transaction id",
                    },
                    RPCResult{"if verbose is set to true",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::STR_HEX, "transactionid", "the transaction id"},
                            {RPCResult::Type::STR, "fee reason", "The transaction fee reason."},
                        },
                    },
                },
                RPCExamples{
                    HelpExampleCli("destroyamount", "\"bitcoin\" 100")
            + HelpExampleCli("destroyamount", "\"bitcoin\" 100 \"destroy assets\"")
            + HelpExampleRpc("destroyamount", "\"bitcoin\" 100 \"destroy assets\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    LOCK(pwallet->cs_wallet);

    std::string strasset = request.params[0].get_str();
    CAsset asset = GetAssetFromString(strasset);

    CAmount nAmount = AmountFromValue(request.params[1]);
    if (nAmount <= 0) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount to destroy");
    }

    mapValue_t mapValue;
    if (request.params.size() > 2 && !request.params[2].isNull() && !request.params[2].get_str().empty()) {
        mapValue["comment"] = request.params[2].get_str();
    }

    EnsureWalletIsUnlocked(*pwallet);

    bool verbose = request.params[3].isNull() ? false : request.params[3].get_bool();
    NullData nulldata;
    CTxDestination address(nulldata);
    std::vector<CRecipient> recipients;
    CRecipient recipient = {GetScriptForDestination(address), nAmount, asset, CPubKey(), false /* subtract_fee */};
    recipients.push_back(recipient);
    CCoinControl no_coin_control; // This is a deprecated API
    return SendMoney(*pwallet, no_coin_control, recipients, std::move(mapValue), verbose, true /* ignore_blind_fail */);
},
    };
}

// Only used for functionary integration tests
RPCHelpMan generatepegoutproof()
{
    return RPCHelpMan{"generatepegoutproof",
                "\nONLY FOR TESTING: Generates pegout authorization proof for pegout based on the summed privkey and returns in hex. Result should be passed as an argument in `sendtomainchain`. Caution: Whitelist proof-validating mempools will filter incorrect pegoutproofs but aren't consensus enforced!\n",
                {
                    {"sumkey", RPCArg::Type::STR, RPCArg::Optional::NO, "Base58 summed key of Bitcoin and offline key"},
                    {"btcpubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Hex pegout destination Bitcoin pubkey"},
                    {"onlinepubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "hex `online pubkey`"},
                },
                RPCResult{
                    RPCResult::Type::STR_HEX, "pegoutproof", "pegout authorization proof to be passed into sendtomainchain",
                },
                RPCExamples{
                    HelpExampleCli("generatepegoutproof", "\"cQtNrRngdc4RJ9CkuTVKVLyxPFsijiTJySob24xCdKXGohdFhXML\" \"02c611095119e3dc96db428a0e190a3e142237bcd2efa4fb358257497885af3ab6\" \"0390695fff5535780df1e04c1f6c10e7c0a399fa56cfce34bf8108d0a9bc7a437b\"")
            + HelpExampleRpc("generatepegoutproof", "\"cQtNrRngdc4RJ9CkuTVKVLyxPFsijiTJySob24xCdKXGohdFhXML\" \"02c611095119e3dc96db428a0e190a3e142237bcd2efa4fb358257497885af3ab6\" \"0390695fff5535780df1e04c1f6c10e7c0a399fa56cfce34bf8108d0a9bc7a437b\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    LOCK(pwallet->cs_wallet);

    if (!IsHex(request.params[1].get_str()))
        throw JSONRPCError(RPC_TYPE_ERROR, "btcpubkey must be hex string");
    if (!IsHex(request.params[2].get_str()))
        throw JSONRPCError(RPC_TYPE_ERROR, "onlinepubkey must be hex string");

    //Parse private keys

    CKey summedSecret = DecodeSecret(request.params[0].get_str());
    if (!summedSecret.IsValid()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid summed private key encoding");
    }

    std::vector<unsigned char> sumprivkeybytes(summedSecret.begin(), summedSecret.end());
    std::vector<unsigned char> btcpubkeybytes = ParseHex(request.params[1].get_str());
    std::vector<unsigned char> onlinepubkeybytes = ParseHex(request.params[2].get_str());

    //Parse onlinepubkey
    CPubKey onlinepubkey;
    onlinepubkey.Set(onlinepubkeybytes.begin(), onlinepubkeybytes.end());
    if (!onlinepubkey.IsFullyValid())
        throw JSONRPCError(RPC_WALLET_ERROR, "Invalid online pubkey");
    secp256k1_pubkey onlinepubkey_secp;
    if (!secp256k1_ec_pubkey_parse(secp256k1_ctx, &onlinepubkey_secp, &onlinepubkeybytes[0], onlinepubkeybytes.size()))
        throw JSONRPCError(RPC_WALLET_ERROR, "Invalid online pubkey");

    CPAKList paklist = GetActivePAKList(pwallet->chain().getTip(), Params().GetConsensus());
    if (paklist.IsReject()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Pegout freeze is under effect to aid a pak transition to a new list. Please consult the network operator.");
    }

    LegacyScriptPubKeyMan* spk_man = pwallet->GetLegacyScriptPubKeyMan();
    if (!spk_man) {
        throw JSONRPCError(RPC_WALLET_ERROR, "This type of wallet does not support this command");
    }

    //Find PAK online pubkey on PAK list
    int whitelistindex=-1;
    std::vector<secp256k1_pubkey> pak_online = paklist.OnlineKeys();
    for (unsigned int i=0; i<pak_online.size(); i++) {
        if (!memcmp((void *)&pak_online[i], (void *)&onlinepubkey_secp, sizeof(secp256k1_pubkey)))
            whitelistindex = i;
    }
    if (whitelistindex == -1)
        throw JSONRPCError(RPC_WALLET_ERROR, "Given online key is not in Pegout Authorization Key List");

    CKey masterOnlineKey;
    if (!spk_man->GetKey(onlinepubkey.GetID(), masterOnlineKey))
        throw JSONRPCError(RPC_WALLET_ERROR, "Given online key is in master set but not in wallet");

    //Parse own offline pubkey
    secp256k1_pubkey btcpubkey;
    if (secp256k1_ec_pubkey_parse(secp256k1_ctx, &btcpubkey, &btcpubkeybytes[0], btcpubkeybytes.size()) != 1)
        throw JSONRPCError(RPC_WALLET_ERROR, "btcpubkey is invalid pubkey");

    //Create, verify whitelist proof
    secp256k1_whitelist_signature sig;
    if(secp256k1_whitelist_sign(secp256k1_ctx, &sig, &paklist.OnlineKeys()[0], &paklist.OfflineKeys()[0], paklist.size(), &btcpubkey, masterOnlineKey.begin(), &sumprivkeybytes[0], whitelistindex) != 1)
        throw JSONRPCError(RPC_WALLET_ERROR, "Pegout authorization proof signing failed");

    if (secp256k1_whitelist_verify(secp256k1_ctx, &sig, &paklist.OnlineKeys()[0], &paklist.OfflineKeys()[0], paklist.size(), &btcpubkey) != 1)
        throw JSONRPCError(RPC_WALLET_ERROR, "Pegout authorization proof was created and signed but is invalid");

    //Serialize and return as hex
    size_t expectedOutputSize = 1 + 32 * (1 + paklist.size());
    const size_t preSize = expectedOutputSize;
    CHECK_NONFATAL(1 + 32 * (1 + 256) >= expectedOutputSize);
    unsigned char output[1 + 32 * (1 + 256)];
    secp256k1_whitelist_signature_serialize(secp256k1_ctx, output, &expectedOutputSize, &sig);
    CHECK_NONFATAL(expectedOutputSize == preSize);
    std::vector<unsigned char> voutput(output, output + expectedOutputSize / sizeof(output[0]));

    return HexStr(voutput);
},
    };
}

// Only used for functionary integration tests
RPCHelpMan getpegoutkeys()
{
    return RPCHelpMan{"getpegoutkeys",
                "\n(DEPRECATED) Please see `initpegoutwallet` and `sendtomainchain` for best-supported and easiest workflow. This call is for the Liquid network participants' `offline` wallet ONLY. Returns `sumkeys` corresponding to the sum of the Offline PAK and the imported Bitcoin key. The wallet must have the Offline private PAK to succeed. The output will be used in `generatepegoutproof` and `sendtomainchain`. Care is required to keep the bitcoin private key, as well as the `sumkey` safe, as a leak of both results in the leak of your `offlinekey`. Therefore it is recommended to create Bitcoin keys and do Bitcoin transaction signing directly on an offline wallet co-located with your offline Liquid wallet.\n",
                {
                    {"btcprivkey", RPCArg::Type::STR, RPCArg::Optional::NO, "Base58 Bitcoin private key that will be combined with the offline privkey"},
                    {"offlinepubkey", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED_NAMED_ARG, "Hex pubkey of key to combine with btcprivkey. Primarily intended for integration testing."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "sumkey", "Base58-encoded sum key"},
                        {RPCResult::Type::STR_HEX, "btcpubkey", "the bitcoin pubkey that corresponds to the pegout destination Bitcoin address"},
                        {RPCResult::Type::STR, "btcaddress", "Destination Bitcoin address for the funds being pegged out using these keys"},
                    },
                },
                RPCExamples{
                    HelpExampleCli("getpegoutkeys", "")
            + HelpExampleCli("getpegoutkeys", "\"5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF\" \"0389275d512326f7016e014d8625f709c01f23bd0dc16522bf9845a9ee1ef6cbf9\"")
            + HelpExampleRpc("getpegoutkeys", "")
           + HelpExampleRpc("getpegoutkeys", "\"5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF\", \"0389275d512326f7016e014d8625f709c01f23bd0dc16522bf9845a9ee1ef6cbf9\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    LOCK(pwallet->cs_wallet);

    LegacyScriptPubKeyMan* spk_man = pwallet->GetLegacyScriptPubKeyMan();
    if (!spk_man) {
        throw JSONRPCError(RPC_WALLET_ERROR, "This type of wallet does not support this command");
    }

    if (!request.params[1].isStr() || !IsHex(request.params[1].get_str()) || request.params[1].get_str().size() != 66) {
        throw JSONRPCError(RPC_TYPE_ERROR, "offlinepubkey must be hex string of size 66");
    }

    std::vector<unsigned char> offlinepubbytes = ParseHex(request.params[1].get_str());
    CPubKey offline_pub = CPubKey(offlinepubbytes.begin(), offlinepubbytes.end());

    if (!offline_pub.IsFullyValid()) {
        throw JSONRPCError(RPC_TYPE_ERROR, "offlinepubkey is not a valid pubkey");
    }

    CKey pegoutkey;
    if (!spk_man->GetKey(offline_pub.GetID(), pegoutkey))
        throw JSONRPCError(RPC_WALLET_ERROR, "Offline key can not be found in wallet");

    CKey bitcoinkey = DecodeSecret(request.params[0].get_str());
    if (!bitcoinkey.IsValid()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key outside allowed range");
    }

    CPubKey bitcoinpubkey = bitcoinkey.GetPubKey();
    CHECK_NONFATAL(bitcoinkey.VerifyPubKey(bitcoinpubkey));

    std::vector<unsigned char> pegoutkeybytes(pegoutkey.begin(), pegoutkey.end());
    std::vector<unsigned char> pegoutsubkeybytes(bitcoinkey.begin(), bitcoinkey.end());

    if (!secp256k1_ec_seckey_tweak_add(secp256k1_ctx, &pegoutkeybytes[0], &pegoutsubkeybytes[0]))
        throw JSONRPCError(RPC_WALLET_ERROR, "Summed key invalid");

    CKey sumseckey;
    sumseckey.Set(pegoutkeybytes.begin(), pegoutkeybytes.end(), true);

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("sumkey", EncodeSecret(sumseckey));
    ret.pushKV("btcpubkey", HexStr(bitcoinpubkey));
    ret.pushKV("btcaddress", EncodeParentDestination(PKHash(bitcoinpubkey.GetID())));

    return ret;
},
    };
}

// END ELEMENTS commands
//
} // namespace wallet
