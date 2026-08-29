/* Test-only operator-risk ECX catalogue; specification fingerprints only. */
,[ECX_PRIOR_ACTIVE_EXCHANGE_STATE_ROOT_REQUIRED] =
{ .tag = JET
, .jet = simplicity_prior_active_exchange_state_root_required
, .cmr = {{0x0c5ab500u, 0xb3aa0c26u, 0x57d88c32u, 0xd52acb24u, 0xbf9ff2efu, 0x2b948e55u, 0x1052f177u, 0xc250934au}}
, .sourceIx = ty_u
, .targetIx = ty_w256
, .cost = 235 /* milli weight units; nonactivating operator catalogue */
}
,[ECX_PRIOR_ACTIVE_FORCED_INBOX_ROOT_REQUIRED] =
{ .tag = JET
, .jet = simplicity_prior_active_forced_inbox_root_required
, .cmr = {{0x6bac39b5u, 0x27d124fbu, 0xc9ef8b29u, 0xb74fcfb3u, 0x1593b5ccu, 0x901a9e35u, 0x9900d89au, 0xbc9ebfebu}}
, .sourceIx = ty_u
, .targetIx = ty_w256
, .cost = 231 /* milli weight units; nonactivating operator catalogue */
}
,[ECX_PRIOR_ACTIVE_DEPOSIT_INBOX_ROOT_REQUIRED] =
{ .tag = JET
, .jet = simplicity_prior_active_deposit_inbox_root_required
, .cmr = {{0x6f27eefeu, 0x75e280bcu, 0xb1c56175u, 0x42108453u, 0xeea376a7u, 0xfd7a3e31u, 0x64b6a84fu, 0x6ad420a9u}}
, .sourceIx = ty_u
, .targetIx = ty_w256
, .cost = 235 /* milli weight units; nonactivating operator catalogue */
}
,[ECX_PRIOR_ACTIVE_FORCED_PROCESSED_CURSOR_REQUIRED] =
{ .tag = JET
, .jet = simplicity_prior_active_forced_processed_cursor_required
, .cmr = {{0x8586ea41u, 0x6a440270u, 0xa41cddc4u, 0x7d984b8eu, 0x3fc263c1u, 0x9a653cf3u, 0xda4b02dbu, 0x72f8ddb5u}}
, .sourceIx = ty_u
, .targetIx = ty_w64
, .cost = 193 /* milli weight units; nonactivating operator catalogue */
}
,[ECX_PRIOR_ACTIVE_DEPOSIT_PROCESSED_CURSOR_REQUIRED] =
{ .tag = JET
, .jet = simplicity_prior_active_deposit_processed_cursor_required
, .cmr = {{0x56375fdeu, 0x02ea03bdu, 0x14f2dd2au, 0x19a8eed5u, 0x319f2c98u, 0x12937ac3u, 0xf8d4e9dcu, 0x0ea940f9u}}
, .sourceIx = ty_u
, .targetIx = ty_w64
, .cost = 191 /* milli weight units; nonactivating operator catalogue */
}
,[ECX_CURRENT_BMM_PARENT_BLOCK_HASH_REQUIRED] =
{ .tag = JET
, .jet = simplicity_current_bmm_parent_block_hash_required
, .cmr = {{0x78522ee4u, 0xb12802e8u, 0x3c6a369du, 0xc752600eu, 0xef635b7cu, 0xc93c877eu, 0x77bf291du, 0xf6d009cbu}}
, .sourceIx = ty_u
, .targetIx = ty_w256
, .cost = 236 /* milli weight units; nonactivating operator catalogue */
}
,[ECX_CURRENT_BMM_PARENT_HEIGHT_REQUIRED] =
{ .tag = JET
, .jet = simplicity_current_bmm_parent_height_required
, .cmr = {{0x117f2e10u, 0xd293772eu, 0x39df4d49u, 0x95874263u, 0x4a61f008u, 0x39262a67u, 0x34c9f072u, 0xc3108a76u}}
, .sourceIx = ty_u
, .targetIx = ty_w64
, .cost = 195 /* milli weight units; nonactivating operator catalogue */
}
,[ECX_CURRENT_BMM_PARENT_MTP_REQUIRED] =
{ .tag = JET
, .jet = simplicity_current_bmm_parent_mtp_required
, .cmr = {{0x8e17f5d5u, 0xdfbfbd11u, 0x36a1a05bu, 0x8a3bcccdu, 0x063d2e99u, 0xc3d48993u, 0x5b290b15u, 0x1d3b08d1u}}
, .sourceIx = ty_u
, .targetIx = ty_w64
, .cost = 202 /* milli weight units; nonactivating operator catalogue */
}
,[ECX_BOND_V2_CONFIGURATION_HASH_REQUIRED] =
{ .tag = JET
, .jet = simplicity_bond_v2_configuration_hash_required
, .cmr = {{0xb315a967u, 0x8610baabu, 0xe9f73382u, 0xf08b7a06u, 0x145fa124u, 0x3dec4d9au, 0x9477311du, 0xe2acf5b8u}}
, .sourceIx = ty_u
, .targetIx = ty_w256
, .cost = 235 /* milli weight units; nonactivating operator catalogue */
}
,[ECX_BOND_V2_ASSET_ID_REQUIRED] =
{ .tag = JET
, .jet = simplicity_bond_v2_asset_id_required
, .cmr = {{0x5fa2f1efu, 0x55935afdu, 0xbee1da49u, 0x57b6b572u, 0x373de429u, 0x20917ab7u, 0xfb7b7759u, 0x636ac587u}}
, .sourceIx = ty_u
, .targetIx = ty_w256
, .cost = 234 /* milli weight units; nonactivating operator catalogue */
}
,[ECX_BOND_V2_DEPLOYMENT_COMMITMENT_REQUIRED] =
{ .tag = JET
, .jet = simplicity_bond_v2_deployment_commitment_required
, .cmr = {{0xdd7a30f8u, 0xab05ee8fu, 0x6e8bebf8u, 0x5a34a1e4u, 0x08f3817du, 0x8f149663u, 0xea880f34u, 0xf0ae13cbu}}
, .sourceIx = ty_u
, .targetIx = ty_w256
, .cost = 234 /* milli weight units; nonactivating operator catalogue */
}
,[ECX_BOND_V2_TRANSITION_CMR_REQUIRED] =
{ .tag = JET
, .jet = simplicity_bond_v2_transition_cmr_required
, .cmr = {{0x1b566de0u, 0x815028e3u, 0x2c044ee6u, 0x23fb273bu, 0x1c889df2u, 0x2b062cdeu, 0xa0ccb621u, 0x0a3f7305u}}
, .sourceIx = ty_u
, .targetIx = ty_w256
, .cost = 235 /* milli weight units; nonactivating operator catalogue */
}
,[ECX_VERIFY_SP1_GROTH16_SHA256] =
{ .tag = JET
, .jet = simplicity_verify_sp1_groth16_sha256
, .cmr = {{0xd8878f35u, 0xafadf601u, 0x0d8e3102u, 0x6b5c9742u, 0xec938944u, 0xcdd9e6c2u, 0xd66fde33u, 0xca8b5434u}}
, .sourceIx = ty_ecx_pw256w256
, .targetIx = ty_b
, .cost = 842045435 /* milli weight units; nonactivating operator catalogue */
}
,[ECX_VERIFY_SP1_GROTH16_V3_PUBLIC_VALUES_V4_SHA256] =
{ .tag = JET
, .jet = simplicity_verify_sp1_groth16_v3_public_values_v4_sha256
, .cmr = {{0xa52e069cu, 0xf9c1f1dau, 0x6f3fe0c2u, 0x3f893da4u, 0xf59414dcu, 0xec0e3493u, 0x3f05875du, 0xf8f9b5b1u}}
, .sourceIx = ty_ecx_pw256w256
, .targetIx = ty_b
, .cost = 820469462 /* milli weight units; nonactivating operator catalogue */
}
,[ECX_VERIFY_SP1_GROTH16_V4_PUBLIC_VALUES_V5_SHA256] =
{ .tag = JET
, .jet = simplicity_verify_sp1_groth16_v4_public_values_v5_sha256
, .cmr = {{0xfb2aa82du, 0x0500811fu, 0xe750890fu, 0x1441d805u, 0x1b7d09c6u, 0x2365b58bu, 0x7619d699u, 0xc4b6b624u}}
, .sourceIx = ty_ecx_pw256w256
, .targetIx = ty_b
, .cost = 826626612 /* milli weight units; nonactivating operator catalogue */
}
,[ECX_PRIOR_ACTIVE_BOND_INBOX_ROOT_REQUIRED] =
{ .tag = JET
, .jet = simplicity_prior_active_bond_inbox_root_required
, .cmr = {{0xe0f49da0u, 0xa834f48fu, 0xbdee7dfdu, 0x0ff96f56u, 0x675a0f16u, 0x9ac15cf0u, 0x5989c3a3u, 0x5ff10f82u}}
, .sourceIx = ty_u
, .targetIx = ty_w256
, .cost = 233 /* milli weight units; nonactivating operator catalogue */
}
,[ECX_PRIOR_ACTIVE_BOND_INBOX_COUNT_REQUIRED] =
{ .tag = JET
, .jet = simplicity_prior_active_bond_inbox_count_required
, .cmr = {{0x72679a3eu, 0xd747c29eu, 0x4aa870eeu, 0x5c84dfd7u, 0x96c3a342u, 0x381d3c4bu, 0x08d6ab4du, 0xe57bbab9u}}
, .sourceIx = ty_u
, .targetIx = ty_w64
, .cost = 190 /* milli weight units; nonactivating operator catalogue */
}
,[ECX_CURRENT_SIDECHAIN_HEIGHT_REQUIRED] =
{ .tag = JET
, .jet = simplicity_current_sidechain_height_required
, .cmr = {{0x242a810au, 0x64938eeau, 0x9859b32eu, 0x31de786du, 0x7709c0f1u, 0xfc2e7c23u, 0x58646663u, 0x76f77842u}}
, .sourceIx = ty_u
, .targetIx = ty_w64
, .cost = 191 /* milli weight units; nonactivating operator catalogue */
}
,[ECX_BOND_V2_INSURANCE_RESERVE_INPUT_REQUIRED] =
{ .tag = JET
, .jet = simplicity_bond_v2_insurance_reserve_input_required
, .cmr = {{0xd48d4edfu, 0xcb17128cu, 0x2f5da919u, 0xd7dc5727u, 0x108930a2u, 0x86a8acdeu, 0x763038a5u, 0x5e12d1ceu}}
, .sourceIx = ty_w32
, .targetIx = ty_u
, .cost = 200 /* milli weight units; nonactivating operator catalogue */
}
,[ECX_BOND_V2_COLLATERAL_VAULT_INPUT_REQUIRED] =
{ .tag = JET
, .jet = simplicity_bond_v2_collateral_vault_input_required
, .cmr = {{0x377f2458u, 0x4cc215e8u, 0x8771bbaeu, 0xda66046cu, 0xf4812970u, 0x37f6ab80u, 0x58175592u, 0x61b3849cu}}
, .sourceIx = ty_w32
, .targetIx = ty_u
, .cost = 195 /* milli weight units; nonactivating operator catalogue */
}
,[ECX_BOND_V2_INCREMENTAL_ACTIVATION_CMR_REQUIRED] =
{ .tag = JET
, .jet = simplicity_bond_v2_incremental_activation_cmr_required
, .cmr = {{0x547b5f51u, 0x7d8cdef8u, 0xa52db33fu, 0x35334314u, 0xcfa0a5e3u, 0xf8c1d247u, 0x8dcb93acu, 0x96b2544du}}
, .sourceIx = ty_u
, .targetIx = ty_w256
, .cost = 232 /* milli weight units; nonactivating operator catalogue */
}
,[ECX_INCREMENTAL_SUCCESSOR_TRANSITION_CMR_REQUIRED] =
{ .tag = JET
, .jet = simplicity_incremental_successor_transition_cmr_required
, .cmr = {{0x42003f28u, 0x531aeff3u, 0x3225abffu, 0x84d2ea93u, 0x393d43a7u, 0xae9bd9b9u, 0xf12cac79u, 0x89c23e5eu}}
, .sourceIx = ty_u
, .targetIx = ty_w256
, .cost = 231 /* milli weight units; nonactivating operator catalogue */
}
,[ECX_VERIFY_SP1_GROTH16_V5_INCREMENTAL_ACTIVATION_SHA256] =
{ .tag = JET
, .jet = simplicity_verify_sp1_groth16_v5_incremental_activation_sha256
, .cmr = {{0xb9de6209u, 0x0d0b2687u, 0x34a7a7b3u, 0xb361f70du, 0x14aabb04u, 0x08857132u, 0x62b6c3a4u, 0xa2190832u}}
, .sourceIx = ty_ecx_pw256w256
, .targetIx = ty_b
, .cost = 825247407 /* milli weight units; nonactivating operator catalogue */
}
