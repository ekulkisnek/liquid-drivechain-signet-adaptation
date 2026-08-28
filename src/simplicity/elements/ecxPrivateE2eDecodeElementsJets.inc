/* Frozen ECX catalogue; generated. */
case 5:
  code = simplicity_decodeUptoMaxInt(stream);
  if (code < 0) return (simplicity_err)code;
  switch (code) {
    case 1:
      *result = ECX_PRIOR_ACTIVE_EXCHANGE_STATE_ROOT_REQUIRED;
      return SIMPLICITY_NO_ERROR;
    case 2:
      *result = ECX_PRIOR_ACTIVE_FORCED_INBOX_ROOT_REQUIRED;
      return SIMPLICITY_NO_ERROR;
    case 3:
      *result = ECX_PRIOR_ACTIVE_DEPOSIT_INBOX_ROOT_REQUIRED;
      return SIMPLICITY_NO_ERROR;
    case 4:
      *result = ECX_PRIOR_ACTIVE_FORCED_PROCESSED_CURSOR_REQUIRED;
      return SIMPLICITY_NO_ERROR;
    case 5:
      *result = ECX_PRIOR_ACTIVE_DEPOSIT_PROCESSED_CURSOR_REQUIRED;
      return SIMPLICITY_NO_ERROR;
    case 6:
      *result = ECX_CURRENT_BMM_PARENT_BLOCK_HASH_REQUIRED;
      return SIMPLICITY_NO_ERROR;
    case 7:
      *result = ECX_CURRENT_BMM_PARENT_HEIGHT_REQUIRED;
      return SIMPLICITY_NO_ERROR;
    case 8:
      *result = ECX_CURRENT_BMM_PARENT_MTP_REQUIRED;
      return SIMPLICITY_NO_ERROR;
    case 9:
      *result = ECX_VERIFY_SP1_GROTH16_SHA256;
      return SIMPLICITY_NO_ERROR;
  }
  break;
