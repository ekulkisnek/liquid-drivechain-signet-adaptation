#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include "elementsJets.h"

#include <simplicity/elements/env.h>

#include "ops.h"
#include "txEnv.h"
#include "../taptweak.h"
#include "../simplicity_assert.h"

#include <string.h>

#define ECX_SP1_ANNEX_HEADER_LEN ((size_t)79)
#define ECX_SP1_LEGACY_GROTH16_ANNEX_LEN (ECX_SP1_ANNEX_HEADER_LEN + ECX_SP1_GROTH16_PROOF_LEN)
#define ECX_SP1_GROTH16_V4_ANNEX_LEN (ECX_SP1_LEGACY_GROTH16_ANNEX_LEN + ECX_SP1_PUBLIC_VALUES_V4_LEN)
#define ECX_SP1_GROTH16_V5_ANNEX_LEN (ECX_SP1_LEGACY_GROTH16_ANNEX_LEN + ECX_SP1_PUBLIC_VALUES_V5_LEN)
#define ECX_SP1_GROTH16_V5_INCREMENTAL_ACTIVATION_ANNEX_LEN \
  (ECX_SP1_LEGACY_GROTH16_ANNEX_LEN + ECX_SP1_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN)
#define ECX_SP1_GROTH16_V6_INCREMENTAL_SUCCESSOR_ANNEX_LEN \
  (ECX_SP1_LEGACY_GROTH16_ANNEX_LEN + ECX_SP1_INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN)
#define ECX_SP1_KOALA_BEAR_MODULUS UINT32_C(0x7f000001)

/* The interpreter consumes the BIP341 0x50 discriminator before exposing the
 * annex payload to Simplicity. The canonical wire annex is 0x50 || payload. */
static const unsigned char ECX_SP1_ANNEX_MAGIC[7] = {
  'E', 'C', 'X', 'S', 'P', '1', 0x00
};

static uint32_t ecxReadU32Be(const unsigned char input[4]) {
  return ((uint32_t)input[0] << 24) | ((uint32_t)input[1] << 16) |
         ((uint32_t)input[2] << 8) | (uint32_t)input[3];
}

static uint64_t ecxReadU64Be(const unsigned char input[8]) {
  uint64_t result = 0;
  for (size_t i = 0; i < 8; ++i) result = (result << 8) | input[i];
  return result;
}

typedef struct ecxU128 {
  uint64_t high;
  uint64_t low;
} ecxU128;

static ecxU128 ecxReadU128Be(const unsigned char input[16]) {
  return (ecxU128){ecxReadU64Be(input), ecxReadU64Be(input + 8)};
}

static int ecxCmpU128(ecxU128 left, ecxU128 right) {
  if (left.high != right.high) return left.high < right.high ? -1 : 1;
  if (left.low != right.low) return left.low < right.low ? -1 : 1;
  return 0;
}

static bool ecxIsZeroU128(ecxU128 value) {
  return 0 == value.high && 0 == value.low;
}

static bool ecxAddU128(ecxU128 left, ecxU128 right, ecxU128* output) {
  output->low = left.low + right.low;
  const uint64_t carry = output->low < left.low;
  output->high = left.high + right.high;
  if (output->high < left.high) return false;
  const uint64_t beforeCarry = output->high;
  output->high += carry;
  return output->high >= beforeCarry;
}

/* Precondition: left >= right. */
static ecxU128 ecxSubU128(ecxU128 left, ecxU128 right) {
  ecxU128 output;
  const uint64_t borrow = left.low < right.low;
  output.low = left.low - right.low;
  output.high = left.high - right.high - borrow;
  return output;
}

static ecxU128 ecxShrU128(ecxU128 value, unsigned int bits) {
  if (0 == bits) return value;
  if (bits < 64) return (ecxU128){value.high >> bits, (value.low >> bits) | (value.high << (64 - bits))};
  if (bits < 128) return (ecxU128){0, value.high >> (bits - 64)};
  return (ecxU128){0, 0};
}

static bool ecxShl1U128(ecxU128 value, ecxU128* output) {
  if (value.high >> 63) return false;
  output->high = (value.high << 1) | (value.low >> 63);
  output->low = value.low << 1;
  return true;
}

static bool ecxAddSmallU128(ecxU128 value, uint64_t addend, ecxU128* output) {
  return ecxAddU128(value, (ecxU128){0, addend}, output);
}

static bool ecxBitU128(ecxU128 value, unsigned int bit) {
  return bit < 64 ? 0 != ((value.low >> bit) & 1) : 0 != ((value.high >> (bit - 64)) & 1);
}

static void ecxSetBitU128(ecxU128* value, unsigned int bit) {
  if (bit < 64) value->low |= UINT64_C(1) << bit;
  else value->high |= UINT64_C(1) << (bit - 64);
}

static ecxU128 ecxDivU128(ecxU128 dividend, ecxU128 divisor) {
  ecxU128 quotient = {0, 0};
  ecxU128 remainder = {0, 0};
  for (int bit = 127; bit >= 0; --bit) {
    ecxU128 doubled;
    /* remainder < divisor, so overflow is impossible for the only case where
     * the doubled value is retained without immediate subtraction. */
    const bool shifted = ecxShl1U128(remainder, &doubled);
    if (!shifted) {
      doubled.high = (remainder.high << 1) | (remainder.low >> 63);
      doubled.low = remainder.low << 1;
    }
    if (ecxBitU128(dividend, (unsigned int)bit)) {
      doubled.low |= 1;
    }
    remainder = doubled;
    if (!shifted || ecxCmpU128(remainder, divisor) >= 0) {
      remainder = ecxSubU128(remainder, divisor);
      ecxSetBitU128(&quotient, (unsigned int)bit);
    }
  }
  return quotient;
}

/* Exact counterpart of PublicValuesV4's overflow-safe floor(value *
 * multiplier / divisor). */
static bool ecxMulU128U64Div(
  ecxU128 value,
  uint64_t multiplier,
  ecxU128 divisor,
  ecxU128* output
) {
  if (ecxIsZeroU128(divisor)) return false;
  const ecxU128 valueQuotient = ecxDivU128(value, divisor);
  const ecxU128 valueRemainder = ecxSubU128(value, (ecxU128){
    0, 0
  });
  /* Obtain value % divisor without a 256-bit product by the same bitwise
   * division used above. */
  ecxU128 remainderOnly = {0, 0};
  for (int bit = 127; bit >= 0; --bit) {
    ecxU128 doubled;
    const bool shifted = ecxShl1U128(remainderOnly, &doubled);
    if (!shifted) {
      doubled.high = (remainderOnly.high << 1) | (remainderOnly.low >> 63);
      doubled.low = remainderOnly.low << 1;
    }
    if (ecxBitU128(valueRemainder, (unsigned int)bit)) doubled.low |= 1;
    remainderOnly = doubled;
    if (!shifted || ecxCmpU128(remainderOnly, divisor) >= 0) {
      remainderOnly = ecxSubU128(remainderOnly, divisor);
    }
  }

  ecxU128 quotient = {0, 0};
  ecxU128 remainder = {0, 0};
  for (int bit = 63; bit >= 0; --bit) {
    ecxU128 divisorMinusRemainder = ecxSubU128(divisor, remainder);
    ecxU128 nextRemainder;
    uint64_t carry = 0;
    if (ecxCmpU128(remainder, divisorMinusRemainder) >= 0) {
      nextRemainder = ecxSubU128(remainder, divisorMinusRemainder);
      carry = 1;
    } else if (!ecxAddU128(remainder, remainder, &nextRemainder)) {
      return false;
    }
    remainder = nextRemainder;
    if (!ecxShl1U128(quotient, &quotient) || !ecxAddSmallU128(quotient, carry, &quotient)) return false;
    if ((multiplier >> bit) & 1) {
      divisorMinusRemainder = ecxSubU128(divisor, remainderOnly);
      if (ecxCmpU128(remainder, divisorMinusRemainder) >= 0) {
        remainder = ecxSubU128(remainder, divisorMinusRemainder);
        carry = 1;
      } else {
        if (!ecxAddU128(remainder, remainderOnly, &remainder)) return false;
        carry = 0;
      }
      if (!ecxAddU128(quotient, valueQuotient, &quotient) ||
          !ecxAddSmallU128(quotient, carry, &quotient)) return false;
    }
  }
  *output = quotient;
  return true;
}

static bool ecxEqual32(const unsigned char left[32], const unsigned char right[32]) {
  unsigned char difference = 0;
  for (size_t i = 0; i < 32; ++i) difference |= left[i] ^ right[i];
  return 0 == difference;
}

static bool ecxNonzero32(const unsigned char value[32]) {
  unsigned char accumulator = 0;
  for (size_t i = 0; i < 32; ++i) accumulator |= value[i];
  return 0 != accumulator;
}

static bool ecxCanonicalPublicValuesV4(const unsigned char values[ECX_SP1_PUBLIC_VALUES_V4_LEN]) {
  static const size_t requiredHashOffsets[] = {
    0, 36, 68, 100, 132, 164, 196, 244, 276, 308, 340, 372, 404, 436
  };
  const uint64_t parentHeight = ecxReadU64Be(values + 228);
  const uint64_t parentMtp = ecxReadU64Be(values + 236);
  const ecxU128 reserve = ecxReadU128Be(values + 468);
  const uint64_t outstanding = ecxReadU64Be(values + 484);
  const ecxU128 nav = ecxReadU128Be(values + 492);
  const ecxU128 deficit = ecxReadU128Be(values + 508);
  const ecxU128 target = ecxReadU128Be(values + 524);
  const ecxU128 coverage = ecxReadU128Be(values + 540);
  const uint64_t minimumPrice = ecxReadU64Be(values + 557);
  const uint64_t maximumPrice = ecxReadU64Be(values + 565);
  const int32_t fundingRate = (int32_t)ecxReadU32Be(values + 581);
  const uint64_t redemptionHead = ecxReadU64Be(values + 585);
  const uint64_t redemptionTail = ecxReadU64Be(values + 593);
  const uint64_t queued = ecxReadU64Be(values + 601);
  ecxU128 expectedTarget;
  ecxU128 expectedCoverage;
  ecxU128 expectedNav;
  const ecxU128 quarter = ecxShrU128(deficit, 2);
  const uint64_t remainder = deficit.low & 3;

  if (ecxReadU32Be(values + 32) != 4 || values[556] > 2 ||
      minimumPrice == 0 || maximumPrice <= minimumPrice) return false;
  for (size_t i = 0; i < sizeof(requiredHashOffsets) / sizeof(requiredHashOffsets[0]); ++i) {
    if (!ecxNonzero32(values + requiredHashOffsets[i])) return false;
  }
  if (parentHeight == 0 || parentMtp == 0 || reserve.high >> 63 || deficit.high >> 63 ||
      outstanding > UINT64_C(2100000000000000)) return false;
  if (!ecxAddU128(deficit, quarter, &expectedTarget) ||
      !ecxAddSmallU128(expectedTarget, remainder != 0, &expectedTarget) ||
      0 != ecxCmpU128(expectedTarget, target)) return false;
  if (ecxIsZeroU128(deficit)) {
    expectedCoverage = (ecxU128){0, 12500};
  } else if (!ecxMulU128U64Div(reserve, 10000, deficit, &expectedCoverage)) {
    return false;
  }
  if (0 != ecxCmpU128(expectedCoverage, coverage)) return false;
  const uint8_t expectedMode = ecxCmpU128(reserve, target) >= 0 ? 0 :
                               ecxCmpU128(reserve, deficit) >= 0 ? 1 : 2;
  if (values[556] != expectedMode) return false;
  if (outstanding == 0) {
    expectedNav = (ecxU128){0, 0};
  } else if (!ecxMulU128U64Div(reserve, UINT64_C(100000000), (ecxU128){0, outstanding}, &expectedNav)) {
    return false;
  }
  if (0 != ecxCmpU128(expectedNav, nav) || redemptionHead > redemptionTail ||
      queued > outstanding || ((redemptionHead == redemptionTail) != (queued == 0)) ||
      fundingRate < -10000 || fundingRate > 10000) return false;

  return true;
}

/* Canonical PublicValuesV5 is the only statement accepted by the live bond
 * singleton.  The arithmetic prefix deliberately repeats the V4 checks, then
 * validates every additive oracle/availability/inbox/execution projection. */
static bool ecxCanonicalPublicValuesV5(const unsigned char values[ECX_SP1_PUBLIC_VALUES_V5_LEN]) {
  static const size_t requiredHashOffsets[] = {
    0, 36, 68, 100, 132, 164, 196, 244, 276, 308, 340, 372, 404, 436,
    609, 650, 682, 722, 762, 802
  };
  const uint64_t parentHeight = ecxReadU64Be(values + 228);
  const uint64_t parentMtp = ecxReadU64Be(values + 236);
  const ecxU128 reserve = ecxReadU128Be(values + 468);
  const uint64_t outstanding = ecxReadU64Be(values + 484);
  const ecxU128 nav = ecxReadU128Be(values + 492);
  const ecxU128 deficit = ecxReadU128Be(values + 508);
  const ecxU128 target = ecxReadU128Be(values + 524);
  const ecxU128 coverage = ecxReadU128Be(values + 540);
  const uint64_t minimumPrice = ecxReadU64Be(values + 557);
  const uint64_t maximumPrice = ecxReadU64Be(values + 565);
  const int32_t fundingRate = (int32_t)ecxReadU32Be(values + 581);
  const uint64_t redemptionHead = ecxReadU64Be(values + 585);
  const uint64_t redemptionTail = ecxReadU64Be(values + 593);
  const uint64_t queued = ecxReadU64Be(values + 601);
  const uint64_t oracleValidThrough = ecxReadU64Be(values + 641);
  const uint64_t entryCount = ecxReadU64Be(values + 714);
  const uint64_t processedCursor = ecxReadU64Be(values + 754);
  const uint64_t outcomeCount = ecxReadU64Be(values + 794);
  const uint64_t previousExecutionSequence = ecxReadU64Be(values + 834);
  const uint64_t nextExecutionSequence = ecxReadU64Be(values + 842);
  ecxU128 expectedTarget;
  ecxU128 expectedCoverage;
  ecxU128 expectedNav;
  const ecxU128 quarter = ecxShrU128(deficit, 2);
  const uint64_t remainder = deficit.low & 3;

  if (ecxReadU32Be(values + 32) != 5 || values[556] > 2 || values[649] > 3 ||
      minimumPrice == 0 || maximumPrice <= minimumPrice) return false;
  for (size_t i = 0; i < sizeof(requiredHashOffsets) / sizeof(requiredHashOffsets[0]); ++i) {
    if (!ecxNonzero32(values + requiredHashOffsets[i])) return false;
  }
  if (parentHeight == 0 || parentMtp == 0 || oracleValidThrough < parentMtp ||
      reserve.high >> 63 || deficit.high >> 63 ||
      outstanding > UINT64_C(2100000000000000)) return false;
  if (!ecxAddU128(deficit, quarter, &expectedTarget) ||
      !ecxAddSmallU128(expectedTarget, remainder != 0, &expectedTarget) ||
      0 != ecxCmpU128(expectedTarget, target)) return false;
  if (ecxIsZeroU128(deficit)) {
    expectedCoverage = (ecxU128){0, 12500};
  } else if (!ecxMulU128U64Div(reserve, 10000, deficit, &expectedCoverage)) {
    return false;
  }
  if (0 != ecxCmpU128(expectedCoverage, coverage)) return false;
  {
    const uint8_t expectedMode = ecxCmpU128(reserve, target) >= 0 ? 0 :
                                 ecxCmpU128(reserve, deficit) >= 0 ? 1 : 2;
    if (values[556] != expectedMode) return false;
  }
  if (outstanding == 0) {
    expectedNav = (ecxU128){0, 0};
  } else if (!ecxMulU128U64Div(reserve, UINT64_C(100000000), (ecxU128){0, outstanding}, &expectedNav)) {
    return false;
  }
  if (0 != ecxCmpU128(expectedNav, nav) || redemptionHead > redemptionTail ||
      queued > outstanding || ((redemptionHead == redemptionTail) != (queued == 0)) ||
      fundingRate < -10000 || fundingRate > 10000 ||
      processedCursor > entryCount || outcomeCount != processedCursor ||
      (processedCursor == entryCount && !ecxEqual32(values + 682, values + 722)) ||
      nextExecutionSequence < previousExecutionSequence) return false;
  return true;
}

static bool ecxCanonicalIncrementalActivationPublicValues(
  const unsigned char values[ECX_SP1_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN]
) {
  const uint64_t height = NULL == values ? 0 : ecxReadU64Be(values + 324);
  const uint64_t parentMtp = NULL == values ? 0 : ecxReadU64Be(values + 332);
  const uint64_t mark = NULL == values ? 0 : ecxReadU64Be(values + 340);
  const uint64_t lower = NULL == values ? 0 : ecxReadU64Be(values + 348);
  const uint64_t upper = NULL == values ? 0 : ecxReadU64Be(values + 356);
  if (NULL == values || ecxReadU32Be(values) != 1 || 0 == height ||
      0 == parentMtp || 0 == mark || 0 == lower || 0 == upper ||
      lower > mark || mark > upper) return false;
  for (size_t i = 0; i < 10; ++i) {
    if (!ecxNonzero32(values + 4 + 32 * i)) return false;
  }
  /* Finite config, successor config, and predecessor state are independent
   * typed identities; aliasing any of these three is noncanonical. */
  return !ecxEqual32(values + 4, values + 36) &&
         !ecxEqual32(values + 4, values + 100) &&
         !ecxEqual32(values + 36, values + 100);
}

static bool ecxCanonicalIncrementalSuccessorPublicValues(
  const unsigned char values[ECX_SP1_INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN]
) {
  const size_t scalarOffset = 4 + 40 * 32;
  const uint64_t parentHeight = NULL == values ? 0 : ecxReadU64Be(values + scalarOffset);
  const uint64_t parentMtp = NULL == values ? 0 : ecxReadU64Be(values + scalarOffset + 8);
  const uint64_t sidechainHeight = NULL == values ? 0 : ecxReadU64Be(values + scalarOffset + 16);
  const uint64_t mark = NULL == values ? 0 : ecxReadU64Be(values + scalarOffset + 24);
  const uint64_t lower = NULL == values ? 0 : ecxReadU64Be(values + scalarOffset + 32);
  const uint64_t upper = NULL == values ? 0 : ecxReadU64Be(values + scalarOffset + 40);
  const uint64_t issued = NULL == values ? 0 : ecxReadU64Be(values + scalarOffset + 48);
  const uint64_t outstanding = NULL == values ? 0 : ecxReadU64Be(values + scalarOffset + 56);
  const uint64_t inventory = NULL == values ? 0 : ecxReadU64Be(values + scalarOffset + 64);
  const uint64_t queued = NULL == values ? 0 : ecxReadU64Be(values + scalarOffset + 72);
  const uint64_t fundingEpoch = NULL == values ? 0 : ecxReadU64Be(values + scalarOffset + 80);
  const uint64_t oracleValidThrough = NULL == values ? 0 : ecxReadU64Be(values + scalarOffset + 88);
  const size_t wideOffset = scalarOffset + 96 + 16;
  const ecxU128 lowerDeficit = NULL == values ? (ecxU128){0, 0} : ecxReadU128Be(values + wideOffset);
  const ecxU128 upperDeficit = NULL == values ? (ecxU128){0, 0} : ecxReadU128Be(values + wideOffset + 16);
  const ecxU128 fullDeficit = NULL == values ? (ecxU128){0, 0} : ecxReadU128Be(values + wideOffset + 32);
  const ecxU128 target = NULL == values ? (ecxU128){0, 0} : ecxReadU128Be(values + wideOffset + 48);
  const ecxU128 reserve = NULL == values ? (ecxU128){0, 0} : ecxReadU128Be(values + wideOffset + 64);
  const ecxU128 nav = NULL == values ? (ecxU128){0, 0} : ecxReadU128Be(values + wideOffset + 112);
  const ecxU128 coverage = NULL == values ? (ecxU128){0, 0} : ecxReadU128Be(values + wideOffset + 128);
  const ecxU128 redemptionHead = NULL == values ? (ecxU128){0, 0} : ecxReadU128Be(values + wideOffset + 144);
  const ecxU128 redemptionTail = NULL == values ? (ecxU128){0, 0} : ecxReadU128Be(values + wideOffset + 160);
  const ecxU128 inboxEntryCount = NULL == values ? (ecxU128){0, 0} : ecxReadU128Be(values + wideOffset + 176);
  const ecxU128 inboxCursor = NULL == values ? (ecxU128){0, 0} : ecxReadU128Be(values + wideOffset + 192);
  ecxU128 expectedTarget;
  ecxU128 expectedNav;
  ecxU128 expectedCoverage;
  const ecxU128 expectedFull = ecxCmpU128(lowerDeficit, upperDeficit) >= 0
    ? lowerDeficit : upperDeficit;
  const ecxU128 quarter = ecxShrU128(fullDeficit, 2);
  const uint64_t remainder = fullDeficit.low & 3;
  const size_t fundingRateOffset = wideOffset + 14 * 16;
  const int32_t fundingRate = NULL == values ? 0 : (int32_t)ecxReadU32Be(values + fundingRateOffset);
  const size_t modeOffset = fundingRateOffset + 4;

  if (NULL == values || ecxReadU32Be(values) != 23 ||
      parentHeight == 0 || parentMtp == 0 || sidechainHeight == 0 ||
      mark == 0 || lower == 0 || upper == 0 || lower > mark || mark > upper ||
      issued != UINT64_C(2100000000000000) || outstanding > issued ||
      inventory != issued - outstanding || queued > outstanding ||
      (lowerDeficit.high >> 63) || (upperDeficit.high >> 63) ||
      (fullDeficit.high >> 63) || (target.high >> 63) || (reserve.high >> 63) ||
      fundingEpoch != parentMtp / UINT64_C(28800) || oracleValidThrough == 0 ||
      fundingRate < -10000 || fundingRate > 10000 ||
      values[modeOffset] > 2 || values[modeOffset + 1] > 3 ||
      values[modeOffset + 2] > 1) return false;
  for (size_t i = 0; i < 40; ++i) {
    if (!ecxNonzero32(values + 4 + 32 * i)) return false;
  }
  if (0 != ecxCmpU128(fullDeficit, expectedFull) ||
      !ecxAddU128(fullDeficit, quarter, &expectedTarget) ||
      !ecxAddSmallU128(expectedTarget, remainder != 0, &expectedTarget) ||
      0 != ecxCmpU128(expectedTarget, target)) return false;
  if (outstanding == 0) {
    expectedNav = (ecxU128){0, 0};
  } else if (!ecxMulU128U64Div(
      reserve, UINT64_C(100000000), (ecxU128){0, outstanding}, &expectedNav)) {
    return false;
  }
  if (0 != ecxCmpU128(expectedNav, nav)) return false;
  if (ecxIsZeroU128(fullDeficit)) {
    expectedCoverage = (ecxU128){0, 12500};
  } else if (!ecxMulU128U64Div(reserve, 10000, fullDeficit, &expectedCoverage)) {
    return false;
  }
  if (0 != ecxCmpU128(expectedCoverage, coverage) ||
      ecxCmpU128(redemptionHead, redemptionTail) > 0 ||
      (0 == ecxCmpU128(redemptionHead, redemptionTail)) != (queued == 0) ||
      ecxCmpU128(inboxCursor, inboxEntryCount) > 0) return false;
  {
    const uint8_t expectedMode = ecxCmpU128(reserve, target) >= 0 ? 0 :
                                 ecxCmpU128(reserve, fullDeficit) >= 0 ? 1 : 2;
    if (values[modeOffset] != expectedMode) return false;
  }
  return true;
}

static bool ecxSha256(
  unsigned char outputBytes[32],
  const unsigned char* input,
  size_t inputLen
) {
  sha256_midstate output;
  sha256_context context = sha256_init(output.s);
  if (!sha256_uchars(&context, input, inputLen) || !sha256_finalize(&context)) return false;
  sha256_fromMidstate(outputBytes, output.s);
  return true;
}

bool simplicity_elements_parse_sp1_groth16_v2_annex(
  const unsigned char* annex,
  size_t annexLen,
  unsigned char programId[32],
  unsigned char publicValuesSha256[32],
  unsigned char publicValuesV4[ECX_SP1_PUBLIC_VALUES_V4_LEN]
) {
  unsigned char computedHash[32];
  bool nonzeroProgramId = false;
  if (NULL == annex || NULL == programId || NULL == publicValuesSha256 ||
      NULL == publicValuesV4 || annexLen != ECX_SP1_GROTH16_V4_ANNEX_LEN ||
      0 != memcmp(annex, ECX_SP1_ANNEX_MAGIC, sizeof(ECX_SP1_ANNEX_MAGIC)) ||
      annex[7] != 3 || annex[8] != 2 || annex[9] != 1 || annex[10] != 0 ||
      ecxReadU32Be(annex + 75) != ECX_SP1_GROTH16_PROOF_LEN) return false;
  for (size_t i = 0; i < 8; ++i) {
    const uint32_t word = ecxReadU32Be(annex + 11 + 4 * i);
    if (word >= ECX_SP1_KOALA_BEAR_MODULUS) return false;
    nonzeroProgramId = nonzeroProgramId || word != 0;
  }
  if (!nonzeroProgramId ||
      !ecxCanonicalPublicValuesV4(annex + ECX_SP1_LEGACY_GROTH16_ANNEX_LEN) ||
      !ecxSha256(
        computedHash,
        annex + ECX_SP1_LEGACY_GROTH16_ANNEX_LEN,
        ECX_SP1_PUBLIC_VALUES_V4_LEN) ||
      !ecxEqual32(computedHash, annex + 43)) return false;
  memcpy(programId, annex + 11, 32);
  memcpy(publicValuesSha256, annex + 43, 32);
  memcpy(
    publicValuesV4,
    annex + ECX_SP1_LEGACY_GROTH16_ANNEX_LEN,
    ECX_SP1_PUBLIC_VALUES_V4_LEN);
  return true;
}

bool simplicity_elements_parse_sp1_groth16_v4_public_values_v5_annex(
  const unsigned char* annex,
  size_t annexLen,
  unsigned char programId[32],
  unsigned char publicValuesSha256[32],
  unsigned char publicValuesV5[ECX_SP1_PUBLIC_VALUES_V5_LEN]
) {
  unsigned char computedHash[32];
  bool nonzeroProgramId = false;
  if (NULL == annex || NULL == programId || NULL == publicValuesSha256 ||
      NULL == publicValuesV5 || annexLen != ECX_SP1_GROTH16_V5_ANNEX_LEN ||
      0 != memcmp(annex, ECX_SP1_ANNEX_MAGIC, sizeof(ECX_SP1_ANNEX_MAGIC)) ||
      annex[7] != 4 || annex[8] != 2 || annex[9] != 1 || annex[10] != 0 ||
      ecxReadU32Be(annex + 75) != ECX_SP1_GROTH16_PROOF_LEN) return false;
  for (size_t i = 0; i < 8; ++i) {
    const uint32_t word = ecxReadU32Be(annex + 11 + 4 * i);
    if (word >= ECX_SP1_KOALA_BEAR_MODULUS) return false;
    nonzeroProgramId = nonzeroProgramId || word != 0;
  }
  if (!nonzeroProgramId ||
      !ecxCanonicalPublicValuesV5(annex + ECX_SP1_LEGACY_GROTH16_ANNEX_LEN) ||
      !ecxSha256(computedHash, annex + ECX_SP1_LEGACY_GROTH16_ANNEX_LEN,
                 ECX_SP1_PUBLIC_VALUES_V5_LEN) ||
      !ecxEqual32(computedHash, annex + 43)) return false;
  memcpy(programId, annex + 11, 32);
  memcpy(publicValuesSha256, annex + 43, 32);
  memcpy(publicValuesV5, annex + ECX_SP1_LEGACY_GROTH16_ANNEX_LEN,
         ECX_SP1_PUBLIC_VALUES_V5_LEN);
  return true;
}

bool simplicity_elements_parse_sp1_groth16_v5_incremental_activation_annex(
  const unsigned char* annex,
  size_t annexLen,
  unsigned char programId[32],
  unsigned char publicValuesSha256[32],
  unsigned char publicValues[ECX_SP1_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN]
) {
  unsigned char computedHash[32];
  bool nonzeroProgramId = false;
  if (NULL == annex || NULL == programId || NULL == publicValuesSha256 ||
      NULL == publicValues ||
      annexLen != ECX_SP1_GROTH16_V5_INCREMENTAL_ACTIVATION_ANNEX_LEN ||
      0 != memcmp(annex, ECX_SP1_ANNEX_MAGIC, sizeof(ECX_SP1_ANNEX_MAGIC)) ||
      annex[7] != 5 || annex[8] != 2 || annex[9] != 1 || annex[10] != 0 ||
      ecxReadU32Be(annex + 75) != ECX_SP1_GROTH16_PROOF_LEN) return false;
  for (size_t i = 0; i < 8; ++i) {
    const uint32_t word = ecxReadU32Be(annex + 11 + 4 * i);
    if (word >= ECX_SP1_KOALA_BEAR_MODULUS) return false;
    nonzeroProgramId = nonzeroProgramId || word != 0;
  }
  if (!nonzeroProgramId ||
      !ecxCanonicalIncrementalActivationPublicValues(
        annex + ECX_SP1_LEGACY_GROTH16_ANNEX_LEN) ||
      !ecxSha256(computedHash,
        annex + ECX_SP1_LEGACY_GROTH16_ANNEX_LEN,
        ECX_SP1_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN) ||
      !ecxEqual32(computedHash, annex + 43)) return false;
  memcpy(programId, annex + 11, 32);
  memcpy(publicValuesSha256, annex + 43, 32);
  memcpy(publicValues, annex + ECX_SP1_LEGACY_GROTH16_ANNEX_LEN,
         ECX_SP1_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN);
  return true;
}

bool simplicity_elements_parse_sp1_groth16_v6_incremental_successor_annex(
  const unsigned char* annex,
  size_t annexLen,
  unsigned char programId[32],
  unsigned char publicValuesSha256[32],
  unsigned char publicValues[ECX_SP1_INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN]
) {
  unsigned char computedHash[32];
  bool nonzeroProgramId = false;
  if (NULL == annex || NULL == programId || NULL == publicValuesSha256 ||
      NULL == publicValues ||
      annexLen != ECX_SP1_GROTH16_V6_INCREMENTAL_SUCCESSOR_ANNEX_LEN ||
      0 != memcmp(annex, ECX_SP1_ANNEX_MAGIC, sizeof(ECX_SP1_ANNEX_MAGIC)) ||
      annex[7] != 6 || annex[8] != 2 || annex[9] != 1 || annex[10] != 0 ||
      ecxReadU32Be(annex + 75) != ECX_SP1_GROTH16_PROOF_LEN) return false;
  for (size_t i = 0; i < 8; ++i) {
    const uint32_t word = ecxReadU32Be(annex + 11 + 4 * i);
    if (word >= ECX_SP1_KOALA_BEAR_MODULUS) return false;
    nonzeroProgramId = nonzeroProgramId || word != 0;
  }
  if (!nonzeroProgramId ||
      !ecxCanonicalIncrementalSuccessorPublicValues(
        annex + ECX_SP1_LEGACY_GROTH16_ANNEX_LEN) ||
      !ecxSha256(computedHash,
        annex + ECX_SP1_LEGACY_GROTH16_ANNEX_LEN,
        ECX_SP1_INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN) ||
      !ecxEqual32(computedHash, annex + 43)) return false;
  memcpy(programId, annex + 11, 32);
  memcpy(publicValuesSha256, annex + 43, 32);
  memcpy(publicValues, annex + ECX_SP1_LEGACY_GROTH16_ANNEX_LEN,
         ECX_SP1_INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN);
  return true;
}

/* A production build defines HAVE_USDD_SP1_VERIFIER only when it links the
 * pinned Rust verifier ABI and provides this exact-annex accessor.  Ordinary
 * upstream/library builds remain safely unavailable and return False. */
#if defined(HAVE_USDD_SP1_VERIFIER)
#include "../../script/usdd_sp1_verifier_ffi.h"
#endif

/* Read a 256-bit hash value from the 'src' frame, advancing the cursor 256 cells.
 *
 * Precondition: '*src' is a valid read frame for 256 more cells;
 *               NULL != h;
 */
static void readHash(sha256_midstate* h, frameItem *src) {
  read32s(h->s, 8, src);
}

/* Write a 256-bit hash value to the 'dst' frame, advancing the cursor 256 cells.
 *
 * Precondition: '*dst' is a valid write frame for 256 more cells;
 *               NULL != h;
 */
static void writeHash(frameItem* dst, const sha256_midstate* h) {
  write32s(dst, h->s, 8);
}

/* prior_active_exchange_state_root_required : ONE |- TWO^256
 *
 * The generated catalogue entry is intentionally separate from this runtime
 * implementation. Once assigned its reviewed CMR/encoding/cost, the decoder
 * points at this function. Absence is a Simplicity jet failure, not a zero
 * value or witness-controlled fallback.
 */
bool simplicity_prior_active_exchange_state_root_required(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src;
  if (!env->priorActiveExchangeStateRootPresent) return false;
  writeHash(dst, &env->priorActiveExchangeStateRoot);
  return true;
}

bool simplicity_prior_active_forced_inbox_root_required(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src;
  if (!env->priorActiveForcedInboxRootPresent) return false;
  writeHash(dst, &env->priorActiveForcedInboxRoot);
  return true;
}

bool simplicity_prior_active_deposit_inbox_root_required(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src;
  if (!env->priorActiveDepositInboxRootPresent) return false;
  writeHash(dst, &env->priorActiveDepositInboxRoot);
  return true;
}

bool simplicity_prior_active_forced_processed_cursor_required(frameItem* dst, frameItem src, const txEnv* env) {
  (void)src;
  if (!env->priorActiveForcedInboxRootPresent) return false;
  simplicity_write64(dst, env->priorActiveForcedProcessedCursor);
  return true;
}

bool simplicity_prior_active_deposit_processed_cursor_required(frameItem* dst, frameItem src, const txEnv* env) {
  (void)src;
  if (!env->priorActiveDepositInboxRootPresent) return false;
  simplicity_write64(dst, env->priorActiveDepositProcessedCursor);
  return true;
}

/* current_bmm_parent_block_hash_required : ONE |- TWO^256
 * current_bmm_parent_height_required     : ONE |- TWO^64
 * current_bmm_parent_mtp_required        : ONE |- TWO^64
 *
 * "Current" is the BMM state already authenticated at the prior active
 * sidechain tip. It is therefore known while constructing this transaction;
 * the candidate block's future BMM successor is intentionally not exposed.
 */
bool simplicity_current_bmm_parent_block_hash_required(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src;
  if (!env->currentBmmParentPresent) return false;
  writeHash(dst, &env->currentBmmParentBlockHash);
  return true;
}

bool simplicity_current_bmm_parent_height_required(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src;
  if (!env->currentBmmParentPresent) return false;
  simplicity_write64(dst, env->currentBmmParentHeight);
  return true;
}

bool simplicity_current_bmm_parent_mtp_required(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src;
  if (!env->currentBmmParentPresent) return false;
  simplicity_write64(dst, env->currentBmmParentMtp);
  return true;
}

/* Activation-derived V2 identities : ONE |- TWO^256.
 *
 * These values cannot be embedded in the covenant: the configuration digest
 * includes covenant script hashes and the deployment commitment includes the
 * inventory script, while the transition CMR would directly contain itself.
 * The node exposes the tuple atomically only after exact physical deployment
 * and canonical-genesis acceptance. Absence is a jet failure. */
static bool simplicity_bond_v2_identity_required(
  frameItem* dst,
  const sha256_midstate* identity,
  const txEnv* env
) {
  if (!env->bondV2IdentityPresent) return false;
  writeHash(dst, identity);
  return true;
}

bool simplicity_bond_v2_configuration_hash_required(frameItem* dst, frameItem src, const txEnv* env) {
  (void)src;
  return simplicity_bond_v2_identity_required(dst, &env->bondV2ConfigurationHash, env);
}

bool simplicity_bond_v2_asset_id_required(frameItem* dst, frameItem src, const txEnv* env) {
  (void)src;
  return simplicity_bond_v2_identity_required(dst, &env->bondV2AssetId, env);
}

bool simplicity_bond_v2_deployment_commitment_required(frameItem* dst, frameItem src, const txEnv* env) {
  (void)src;
  return simplicity_bond_v2_identity_required(dst, &env->bondV2DeploymentCommitment, env);
}

bool simplicity_bond_v2_transition_cmr_required(frameItem* dst, frameItem src, const txEnv* env) {
  (void)src;
  return simplicity_bond_v2_identity_required(dst, &env->bondV2TransitionCmr, env);
}

static bool simplicity_bond_v2_incremental_activation_identity_required(
  frameItem* dst,
  const sha256_midstate* identity,
  const txEnv* env
) {
  if (!env->bondV2IdentityPresent ||
      !env->bondV2IncrementalActivationIdentityPresent) return false;
  writeHash(dst, identity);
  return true;
}

bool simplicity_bond_v2_incremental_activation_cmr_required(
  frameItem* dst,
  frameItem src,
  const txEnv* env
) {
  (void)src;
  return simplicity_bond_v2_incremental_activation_identity_required(
    dst, &env->bondV2IncrementalActivationCmr, env);
}

bool simplicity_incremental_successor_transition_cmr_required(
  frameItem* dst,
  frameItem src,
  const txEnv* env
) {
  (void)src;
  return simplicity_bond_v2_incremental_activation_identity_required(
    dst, &env->incrementalSuccessorTransitionCmr, env);
}

bool simplicity_prior_active_bond_inbox_root_required(
  frameItem* dst,
  frameItem src,
  const txEnv* env
) {
  (void)src;
  if (!env->bondV2ProjectionPresent) return false;
  writeHash(dst, &env->priorActiveBondInboxRoot);
  return true;
}

bool simplicity_prior_active_bond_inbox_count_required(
  frameItem* dst,
  frameItem src,
  const txEnv* env
) {
  (void)src;
  if (!env->bondV2ProjectionPresent) return false;
  simplicity_write64(dst, env->priorActiveBondInboxCount);
  return true;
}

bool simplicity_current_sidechain_height_required(
  frameItem* dst,
  frameItem src,
  const txEnv* env
) {
  (void)src;
  if (!env->bondV2ProjectionPresent || 0 == env->currentSidechainHeight) return false;
  simplicity_write64(dst, env->currentSidechainHeight);
  return true;
}

bool simplicity_bond_v2_insurance_reserve_input_required(
  frameItem* dst,
  frameItem src,
  const txEnv* env
) {
  const uint_fast32_t inputIndex = simplicity_read32(&src);
  (void)dst;
  if (NULL == env || NULL == env->tx || inputIndex != env->ix ||
      inputIndex < 2 || inputIndex >= env->tx->numInputs ||
      env->tx->input[inputIndex].isPegin ||
      env->tx->input[inputIndex].issuance.type != NO_ISSUANCE ||
      !env->bondV2IdentityPresent) return false;
  return 0 == memcmp(
    env->tx->input[inputIndex].txo.scriptPubKey.s,
    env->bondV2InsuranceReserveScriptSha256.s,
    sizeof(env->bondV2InsuranceReserveScriptSha256.s));
}

bool simplicity_bond_v2_collateral_vault_input_required(
  frameItem* dst,
  frameItem src,
  const txEnv* env
) {
  const uint_fast32_t inputIndex = simplicity_read32(&src);
  (void)dst;
  if (NULL == env || NULL == env->tx || inputIndex != env->ix ||
      inputIndex < 2 || inputIndex >= env->tx->numInputs ||
      env->tx->input[inputIndex].isPegin ||
      env->tx->input[inputIndex].issuance.type != NO_ISSUANCE ||
      !env->bondV2IdentityPresent) return false;
  return 0 == memcmp(
    env->tx->input[inputIndex].txo.scriptPubKey.s,
    env->bondV2CollateralVaultScriptSha256.s,
    sizeof(env->bondV2CollateralVaultScriptSha256.s));
}

/* verify_sp1_groth16_sha256 : TWO^256 * TWO^256 |- TWO
 *
 * The current input's complete annex bytes are copied into the immutable
 * transaction environment. This adapter accepts the legacy ECX annex v2 used
 * by V1, or its additive V4 form carrying the exact canonical 609 public-value
 * bytes after the pinned 356-byte SP1 proof.  The additive form hashes those
 * bytes inside consensus and requires equality with the proof digest before
 * delegating cryptographic verification to the node-supplied frozen backend.
 */
bool simplicity_elements_verify_sp1_groth16_annex_sha256(
  const unsigned char* annex,
  size_t annexLen,
  const unsigned char expectedProgramIdBytes[32],
  const unsigned char expectedPublicValuesHashBytes[32],
  ecx_sp1_groth16_verify_fn verify,
  void* verifyContext,
  bool requirePublicValuesV4
) {
  uint32_t programIdWords[8];
  unsigned char annexProgramIdBytes[32];
  unsigned char encodedPublicValuesHash[32];
  bool carriesPublicValues;
  bool valid = true;

  carriesPublicValues = NULL != annex && annexLen == ECX_SP1_GROTH16_V4_ANNEX_LEN;
  valid = valid && NULL != annex &&
          (annexLen == ECX_SP1_LEGACY_GROTH16_ANNEX_LEN || carriesPublicValues);
  valid = valid && (!requirePublicValuesV4 || carriesPublicValues);
  valid = valid && NULL != expectedProgramIdBytes &&
          NULL != expectedPublicValuesHashBytes && NULL != verify;
  valid = valid && ecxNonzero32(expectedProgramIdBytes);
  if (valid) {
    valid = 0 == memcmp(annex, ECX_SP1_ANNEX_MAGIC, sizeof(ECX_SP1_ANNEX_MAGIC)) &&
            annex[7] == (carriesPublicValues ? 3 : 2) &&
            annex[8] == 2 && annex[9] == 1 && annex[10] == 0 &&
            ecxReadU32Be(annex + 75) == ECX_SP1_GROTH16_PROOF_LEN;
  }
  if (valid) {
    bool nonzeroProgramId = false;
    for (size_t i = 0; i < 8; ++i) {
      const uint32_t word = ecxReadU32Be(annex + 11 + 4 * i);
      if (word >= ECX_SP1_KOALA_BEAR_MODULUS) valid = false;
      programIdWords[i] = word;
      nonzeroProgramId = nonzeroProgramId || 0 != word;
      annexProgramIdBytes[4 * i] = (unsigned char)(word >> 24);
      annexProgramIdBytes[4 * i + 1] = (unsigned char)(word >> 16);
      annexProgramIdBytes[4 * i + 2] = (unsigned char)(word >> 8);
      annexProgramIdBytes[4 * i + 3] = (unsigned char)word;
    }
    valid = valid && nonzeroProgramId;
  }
  if (valid) {
    valid = ecxEqual32(annexProgramIdBytes, expectedProgramIdBytes) &&
            ecxEqual32(annex + 43, expectedPublicValuesHashBytes);
  }
  if (valid && carriesPublicValues) {
    const unsigned char* publicValues = annex + ECX_SP1_LEGACY_GROTH16_ANNEX_LEN;
    valid = ecxCanonicalPublicValuesV4(publicValues) &&
            ecxSha256(encodedPublicValuesHash, publicValues, ECX_SP1_PUBLIC_VALUES_V4_LEN) &&
            ecxEqual32(encodedPublicValuesHash, annex + 43);
  }
  if (valid) {
    valid = verify(
      verifyContext,
      annex + ECX_SP1_ANNEX_HEADER_LEN,
      ECX_SP1_GROTH16_PROOF_LEN,
      programIdWords,
      annex + 43);
  }
  return valid;
}

bool simplicity_elements_verify_sp1_groth16_v4_public_values_v5_annex_sha256(
  const unsigned char* annex,
  size_t annexLen,
  const unsigned char expectedProgramIdBytes[32],
  const unsigned char expectedPublicValuesHashBytes[32],
  ecx_sp1_groth16_verify_fn verify,
  void* verifyContext
) {
  unsigned char programIdBytes[32];
  unsigned char publicValuesHash[32];
  unsigned char publicValues[ECX_SP1_PUBLIC_VALUES_V5_LEN];
  uint32_t programIdWords[8];
  if (NULL == expectedProgramIdBytes || NULL == expectedPublicValuesHashBytes ||
      NULL == verify ||
      !simplicity_elements_parse_sp1_groth16_v4_public_values_v5_annex(
        annex, annexLen, programIdBytes, publicValuesHash, publicValues) ||
      !ecxEqual32(programIdBytes, expectedProgramIdBytes) ||
      !ecxEqual32(publicValuesHash, expectedPublicValuesHashBytes)) return false;
  for (size_t i = 0; i < 8; ++i) {
    programIdWords[i] = ecxReadU32Be(programIdBytes + 4 * i);
  }
  return verify(
    verifyContext,
    annex + ECX_SP1_ANNEX_HEADER_LEN,
    ECX_SP1_GROTH16_PROOF_LEN,
    programIdWords,
    annex + 43);
}

bool simplicity_elements_verify_sp1_groth16_v5_incremental_activation_annex_sha256(
  const unsigned char* annex,
  size_t annexLen,
  const unsigned char expectedProgramIdBytes[32],
  const unsigned char expectedPublicValuesHashBytes[32],
  ecx_sp1_groth16_verify_fn verify,
  void* verifyContext
) {
  unsigned char programIdBytes[32];
  unsigned char publicValuesHash[32];
  unsigned char publicValues[ECX_SP1_INCREMENTAL_ACTIVATION_PUBLIC_VALUES_LEN];
  uint32_t programIdWords[8];
  if (NULL == expectedProgramIdBytes || NULL == expectedPublicValuesHashBytes ||
      NULL == verify ||
      !simplicity_elements_parse_sp1_groth16_v5_incremental_activation_annex(
        annex, annexLen, programIdBytes, publicValuesHash, publicValues) ||
      !ecxEqual32(programIdBytes, expectedProgramIdBytes) ||
      !ecxEqual32(publicValuesHash, expectedPublicValuesHashBytes)) return false;
  for (size_t i = 0; i < 8; ++i) {
    programIdWords[i] = ecxReadU32Be(programIdBytes + 4 * i);
  }
  return verify(
    verifyContext,
    annex + ECX_SP1_ANNEX_HEADER_LEN,
    ECX_SP1_GROTH16_PROOF_LEN,
    programIdWords,
    annex + 43);
}

bool simplicity_elements_verify_sp1_groth16_v6_incremental_successor_annex_sha256(
  const unsigned char* annex,
  size_t annexLen,
  const unsigned char expectedProgramIdBytes[32],
  const unsigned char expectedPublicValuesHashBytes[32],
  ecx_sp1_groth16_verify_fn verify,
  void* verifyContext
) {
  unsigned char programIdBytes[32];
  unsigned char publicValuesHash[32];
  unsigned char publicValues[ECX_SP1_INCREMENTAL_SUCCESSOR_PUBLIC_VALUES_LEN];
  uint32_t programIdWords[8];
  if (NULL == expectedProgramIdBytes || NULL == expectedPublicValuesHashBytes ||
      NULL == verify ||
      !simplicity_elements_parse_sp1_groth16_v6_incremental_successor_annex(
        annex, annexLen, programIdBytes, publicValuesHash, publicValues) ||
      !ecxEqual32(programIdBytes, expectedProgramIdBytes) ||
      !ecxEqual32(publicValuesHash, expectedPublicValuesHashBytes)) return false;
  for (size_t i = 0; i < 8; ++i) {
    programIdWords[i] = ecxReadU32Be(programIdBytes + 4 * i);
  }
  return verify(
    verifyContext,
    annex + ECX_SP1_ANNEX_HEADER_LEN,
    ECX_SP1_GROTH16_PROOF_LEN,
    programIdWords,
    annex + 43);
}

bool simplicity_verify_sp1_groth16_sha256(frameItem* dst, frameItem src, const txEnv* env) {
  sha256_midstate expectedProgramId;
  sha256_midstate expectedPublicValuesHash;
  unsigned char expectedProgramIdBytes[32];
  unsigned char expectedPublicValuesHashBytes[32];
  const sigInput* input;
  bool valid;

  readHash(&expectedProgramId, &src);
  readHash(&expectedPublicValuesHash, &src);
  sha256_fromMidstate(expectedProgramIdBytes, expectedProgramId.s);
  sha256_fromMidstate(expectedPublicValuesHashBytes, expectedPublicValuesHash.s);
  input = &env->tx->input[env->ix];
  valid = simplicity_elements_verify_sp1_groth16_annex_sha256(
    input->annex,
    input->annexLen,
    expectedProgramIdBytes,
    expectedPublicValuesHashBytes,
    env->verifySp1Groth16,
    env->verifySp1Groth16Context,
    false);
  writeBit(dst, valid);
  return true;
}

bool simplicity_verify_sp1_groth16_v3_public_values_v4_sha256(frameItem* dst, frameItem src, const txEnv* env) {
  sha256_midstate expectedProgramId;
  sha256_midstate expectedPublicValuesHash;
  unsigned char expectedProgramIdBytes[32];
  unsigned char expectedPublicValuesHashBytes[32];
  const sigInput* input;
  bool valid;

  readHash(&expectedProgramId, &src);
  readHash(&expectedPublicValuesHash, &src);
  sha256_fromMidstate(expectedProgramIdBytes, expectedProgramId.s);
  sha256_fromMidstate(expectedPublicValuesHashBytes, expectedPublicValuesHash.s);
  input = &env->tx->input[env->ix];
  valid = simplicity_elements_verify_sp1_groth16_annex_sha256(
    input->annex,
    input->annexLen,
    expectedProgramIdBytes,
    expectedPublicValuesHashBytes,
    env->verifySp1Groth16,
    env->verifySp1Groth16Context,
    true);
  writeBit(dst, valid);
  return true;
}

bool simplicity_verify_sp1_groth16_v4_public_values_v5_sha256(frameItem* dst, frameItem src, const txEnv* env) {
  sha256_midstate expectedProgramId;
  sha256_midstate expectedPublicValuesHash;
  unsigned char expectedProgramIdBytes[32];
  unsigned char expectedPublicValuesHashBytes[32];
  const sigInput* input;
  bool valid;

  readHash(&expectedProgramId, &src);
  readHash(&expectedPublicValuesHash, &src);
  sha256_fromMidstate(expectedProgramIdBytes, expectedProgramId.s);
  sha256_fromMidstate(expectedPublicValuesHashBytes, expectedPublicValuesHash.s);
  input = &env->tx->input[env->ix];
  valid = simplicity_elements_verify_sp1_groth16_v4_public_values_v5_annex_sha256(
    input->annex,
    input->annexLen,
    expectedProgramIdBytes,
    expectedPublicValuesHashBytes,
    env->verifySp1Groth16,
    env->verifySp1Groth16Context);
  writeBit(dst, valid);
  return true;
}

bool simplicity_verify_sp1_groth16_v5_incremental_activation_sha256(
  frameItem* dst,
  frameItem src,
  const txEnv* env
) {
  sha256_midstate expectedProgramId;
  sha256_midstate expectedPublicValuesHash;
  unsigned char expectedProgramIdBytes[32];
  unsigned char expectedPublicValuesHashBytes[32];
  const sigInput* input;
  bool valid;

  readHash(&expectedProgramId, &src);
  readHash(&expectedPublicValuesHash, &src);
  sha256_fromMidstate(expectedProgramIdBytes, expectedProgramId.s);
  sha256_fromMidstate(expectedPublicValuesHashBytes, expectedPublicValuesHash.s);
  input = &env->tx->input[env->ix];
  valid = simplicity_elements_verify_sp1_groth16_v5_incremental_activation_annex_sha256(
    input->annex,
    input->annexLen,
    expectedProgramIdBytes,
    expectedPublicValuesHashBytes,
    env->verifySp1Groth16,
    env->verifySp1Groth16Context);
  writeBit(dst, valid);
  return true;
}

bool simplicity_verify_sp1_groth16_v6_incremental_successor_sha256(
  frameItem* dst,
  frameItem src,
  const txEnv* env
) {
  sha256_midstate expectedProgramId;
  sha256_midstate expectedPublicValuesHash;
  unsigned char expectedProgramIdBytes[32];
  unsigned char expectedPublicValuesHashBytes[32];
  const sigInput* input;
  bool valid;

  readHash(&expectedProgramId, &src);
  readHash(&expectedPublicValuesHash, &src);
  sha256_fromMidstate(expectedProgramIdBytes, expectedProgramId.s);
  sha256_fromMidstate(expectedPublicValuesHashBytes, expectedPublicValuesHash.s);
  input = &env->tx->input[env->ix];
  valid = simplicity_elements_verify_sp1_groth16_v6_incremental_successor_annex_sha256(
    input->annex,
    input->annexLen,
    expectedProgramIdBytes,
    expectedPublicValuesHashBytes,
    env->verifySp1Groth16,
    env->verifySp1Groth16Context);
  writeBit(dst, valid);
  return true;
}

/* Write an outpoint value to the 'dst' frame, advancing the cursor 288 cells.
 *
 * Precondition: '*dst' is a valid write frame for 288 more cells;
 *               NULL != op;
 */
static void prevOutpoint(frameItem* dst, const outpoint* op) {
  writeHash(dst, &op->txid);
  simplicity_write32(dst, op->ix);
}

/* Write an confidential asset to the 'dst' frame, advancing the cursor 258 cells.
 *
 * Precondition: '*dst' is a valid write frame for 258 more cells;
 *               NULL != asset;
 */
static void asset(frameItem* dst, const confidential* asset) {
  if (writeBit(dst, EXPLICIT == asset->prefix)) {
    skipBits(dst, 1);
  } else {
    writeBit(dst, ODD_Y == asset->prefix);
  }
  writeHash(dst, &asset->data);
}

/* Write an confidential amount to the 'dst' frame, advancing the cursor 258 cells.
 *
 * Precondition: '*dst' is a valid write frame for 258 more cells;
 *               NULL != amt;
 */
static void amt(frameItem* dst, const confAmount* amt) {
  if (writeBit(dst, EXPLICIT == amt->prefix)) {
    skipBits(dst, 1 + 256 - 64);
    simplicity_write64(dst, amt->explicit);
  } else {
    writeBit(dst, ODD_Y == amt->prefix);
    writeHash(dst, &amt->confidential);
  }
}

/* Write an optional confidential nonce to the 'dst' frame, advancing the cursor 259 cells.
 *
 * Precondition: '*dst' is a valid write frame for 259 more cells;
 *               NULL != nonce;
 */
static void nonce(frameItem* dst, const confidential* nonce) {
  if (writeBit(dst, NONE != nonce->prefix)) {
    if (writeBit(dst, EXPLICIT == nonce->prefix)) {
      skipBits(dst, 1);
    } else {
      writeBit(dst, ODD_Y == nonce->prefix);
    }
    writeHash(dst, &nonce->data);
  } else {
    skipBits(dst, 1+1+256);
  }
}

/* Write an optional 'blindingNonce' from an 'assetIssuance' to the 'dst' frame, advancing the cursor 257 cells.
 *
 * Precondition: '*dst' is a valid write frame for 257 more cells;
 *               NULL != issuance;
 */
static void reissuanceBlinding(frameItem* dst, const assetIssuance* issuance) {
  if (writeBit(dst, REISSUANCE == issuance->type)) {
    writeHash(dst, &issuance->blindingNonce);
  } else {
    skipBits(dst, 256);
  }
}

/* Write an optional 'contractHash' from an 'assetIssuance' to the 'dst' frame, advancing the cursor 257 cells.
 *
 * Precondition: '*dst' is a valid write frame for 257 more cells;
 *               NULL != issuance;
 */
static void newIssuanceContract(frameItem* dst, const assetIssuance* issuance) {
  if (writeBit(dst, NEW_ISSUANCE == issuance->type)) {
    writeHash(dst, &issuance->contractHash);
  } else {
    skipBits(dst, 256);
  }
}

/* Write an optional 'entropy' from an 'assetIssuance' to the 'dst' frame, advancing the cursor 257 cells.
 *
 * Precondition: '*dst' is a valid write frame for 257 more cells;
 *               NULL != issuance;
 */
static void reissuanceEntropy(frameItem* dst, const assetIssuance* issuance) {
  if (writeBit(dst, REISSUANCE == issuance->type)) {
    writeHash(dst, &issuance->entropy);
  } else {
    skipBits(dst, 256);
  }
}

/* Write an optional confidential asset amount from an 'assetIssuance' to the 'dst' frame, advancing the cursor 259 cells.
 *
 * Precondition: '*dst' is a valid write frame for 259 more cells;
 *               NULL != issuance;
 */
static void issuanceAssetAmt(frameItem* dst, const assetIssuance* issuance) {
  if (writeBit(dst, NO_ISSUANCE != issuance->type)) {
    amt(dst, &issuance->assetAmt);
  } else {
    skipBits(dst, 258);
  }
}

/* Write an optional confidential token amount from an 'assetIssuance' to the 'dst' frame, advancing the cursor.
 *
 * Precondition: '*dst' is a valid write frame for 259 more cells;
 *               NULL != issuance;
 */
static void issuanceTokenAmt(frameItem* dst, const assetIssuance* issuance) {
  if (writeBit(dst, NO_ISSUANCE != issuance->type)) {
    amt(dst, NEW_ISSUANCE == issuance->type ? &issuance->tokenAmt : &(confAmount){ .prefix = EXPLICIT, .explicit = 0});
  } else {
    skipBits(dst, 258);
  }
}

static uint_fast32_t lockHeight(const elementsTransaction* tx) {
  return !tx->isFinal && tx->lockTime < 500000000U ? tx->lockTime : 0;
}

static uint_fast32_t lockTime(const elementsTransaction* tx) {
  return !tx->isFinal && 500000000U <= tx->lockTime ? tx->lockTime : 0;
}

static uint_fast16_t obsolete_lockDistance(const elementsTransaction* tx) {
  return 2 <= tx->version ? tx->obsolete_lockDistance : 0;
}

static uint_fast16_t obsolete_lockDuration(const elementsTransaction* tx) {
  return 2 <= tx->version ? tx->obsolete_lockDuration : 0;
}

static bool isFee(const sigOutput* output) {
  /* As specified in https://github.com/ElementsProject/elements/blob/de942511a67c3a3fcbdf002a8ee7e9ba49679b78/src/primitives/transaction.h#L304-L307. */
  return output->emptyScript && EXPLICIT == output->asset.prefix && EXPLICIT == output->amt.prefix;
}

/* Lookup the assetFee from a sorted array of feeOutputs by the given assetid, returning 0 if no entry is found.
 *
 * Precondition: NULL != assetid;
 *               feeOutputs is uniquely sorted by it asset.data.s field, which is to say
 *               for all 0 <= i < j < len,
 *                 0 < memcmp(feeOutputs[j]->asset.data.s, feeOutputs[i]->asset.data.s, sizeof(feeOutputs[i]->asset.data.s));
 */
static uint_fast64_t lookup_fee(const sha256_midstate* assetid, const sigOutput* const * feeOutputs, uint_fast32_t len) {
  /* This loop runs in O(log(len)) time. */
  while(len) {
    int cmp = memcmp(assetid->s, feeOutputs[len/2]->asset.data.s, sizeof(assetid->s));
    if (0 == cmp) return feeOutputs[len/2]->assetFee;
    if (0 < cmp) {
      feeOutputs += len/2 + 1;
      len -= len/2 + 1;
    } else {
      len /= 2;
    }
  }
  return 0;
}

/* version : ONE |- TWO^32 */
bool simplicity_version(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  simplicity_write32(dst, env->tx->version);
  return true;
}

/* lock_time : ONE |- TWO^32 */
bool simplicity_lock_time(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  simplicity_write32(dst, env->tx->lockTime);
  return true;
}

/* input_pegin : TWO^32 |- S (S TWO^256) */
bool simplicity_input_pegin(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numInputs)) {
    if (writeBit(dst, env->tx->input[i].isPegin)) {
      writeHash(dst, &env->tx->input[i].pegin);
    } else {
      skipBits(dst, 256);
    }
  } else {
    skipBits(dst, 257);
  }
  return true;
}

/* input_is_pegin : TWO^32 |- TWO
 *
 * This total predicate is true only for an existing peg-in input.  Invalid
 * indexes and ordinary inputs are false so a fixed controller leaf can admit
 * both the two-input normal form and the three-input refill form without an
 * unexecuted Option branch.
 */
bool simplicity_input_is_pegin(frameItem* dst, frameItem src, const txEnv* env) {
  const uint_fast32_t i = simplicity_read32(&src);
  const bool pegin = env && env->tx && i < env->tx->numInputs
                  && env->tx->input[i].isPegin;
  writeBit(dst, pegin);
  return true;
}

/* fe_is_square_total : TWO^256 |- TWO
 *
 * This is the total predicate corresponding to the tag of fe_square_root.
 * Keeping the tag and discarding the optional square root avoids placing an
 * unreachable CASE branch in fixed-shape controller leaves while preserving
 * exactly the pinned field-normalization semantics.
 */
bool simplicity_fe_is_square_total(frameItem* dst, frameItem src, const txEnv* env) {
  UWORD scratch[ROUND_UWORD(257)] = {0};
  frameItem scratchDst = initWriteFrame(257, scratch + ROUND_UWORD(257));
  frameItem scratchSrc;

  if (!simplicity_fe_square_root(&scratchDst, src, env)) {
    return false;
  }
  scratchSrc = initReadFrame(257, scratch);
  writeBit(dst, readBit(&scratchSrc));
  return true;
}

/* input_prev_outpoint : TWO^32 |- S (TWO^256 * TWO^32) */
bool simplicity_input_prev_outpoint(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numInputs)) {
    prevOutpoint(dst, &env->tx->input[i].prevOutpoint);
  } else {
    skipBits(dst, 288);
  }
  return true;
}

/* input_asset : TWO^32 |- S (Conf TWO^256) */
bool simplicity_input_asset(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numInputs)) {
    asset(dst, &env->tx->input[i].txo.asset);
  } else {
    skipBits(dst, 258);
  }
  return true;
}

/* input_amount : TWO^32 |- S (Conf TWO^256, Conf TWO^64) */
bool simplicity_input_amount(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numInputs)) {
    asset(dst, &env->tx->input[i].txo.asset);
    amt(dst, &env->tx->input[i].txo.amt);
  } else {
    skipBits(dst, 516);
  }
  return true;
}

/* input_script_hash : TWO^32 |- S TWO^256 */
bool simplicity_input_script_hash(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numInputs)) {
    writeHash(dst, &env->tx->input[i].txo.scriptPubKey);
  } else {
    skipBits(dst, 256);
  }
  return true;
}

/* input_sequence : TWO^32 |- S TWO^32 */
bool simplicity_input_sequence(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numInputs)) {
    simplicity_write32(dst, env->tx->input[i].sequence);
  } else {
    skipBits(dst, 32);
  }
  return true;
}

/* reissuance_blinding : TWO^32 |- S (S TWO^256) */
bool simplicity_reissuance_blinding(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numInputs)) {
    reissuanceBlinding(dst, &env->tx->input[i].issuance);
  } else {
    skipBits(dst, 257);
  }
  return true;
}

/* new_issuance_contract : TWO^32 |- S (S TWO^256) */
bool simplicity_new_issuance_contract(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numInputs)) {
    newIssuanceContract(dst, &env->tx->input[i].issuance);
  } else {
    skipBits(dst, 257);
  }
  return true;
}

/* reissuance_entropy : TWO^32 |- S (S TWO^256) */
bool simplicity_reissuance_entropy(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numInputs)) {
    reissuanceEntropy(dst, &env->tx->input[i].issuance);
  } else {
    skipBits(dst, 257);
  }
  return true;
}

/* issuance_asset_amount : TWO^32 |- S (S (Conf TWO^64)) */
bool simplicity_issuance_asset_amount(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numInputs)) {
    issuanceAssetAmt(dst, &env->tx->input[i].issuance);
  } else {
    skipBits(dst, 259);
  }
  return true;
}

/* issuance_token_amount : TWO^32 |- S (S (Conf TWO^64)) */
bool simplicity_issuance_token_amount(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numInputs)) {
    issuanceTokenAmt(dst, &env->tx->input[i].issuance);
  } else {
    skipBits(dst, 259);
  }
  return true;
}

/* issuance_asset_proof : TWO^32 |- S TWO^256 */
bool simplicity_issuance_asset_proof(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numInputs)) {
    writeHash(dst, &env->tx->input[i].issuance.assetRangeProofHash);
  } else {
    skipBits(dst, 256);
  }
  return true;
}

/* issuance_token_proof : TWO^32 |- S TWO^256 */
bool simplicity_issuance_token_proof(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numInputs)) {
    writeHash(dst, &env->tx->input[i].issuance.tokenRangeProofHash);
  } else {
    skipBits(dst, 256);
  }
  return true;
}

/* input_annex_hash : TWO^32 |- S (S (TWO^256)) */
bool simplicity_input_annex_hash(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numInputs)) {
    if (writeBit(dst, env->tx->input[i].hasAnnex)) {
      writeHash(dst, &env->tx->input[i].annexHash);
    } else {
      skipBits(dst, 256);
    }
  } else {
    skipBits(dst, 257);
  }
  return true;
}

/* input_script_sig_hash : TWO^32 |- (S (TWO^256) */
bool simplicity_input_script_sig_hash(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numInputs)) {
    writeHash(dst, &env->tx->input[i].scriptSigHash);
  } else {
    skipBits(dst, 256);
  }
  return true;
}

/* output_asset : TWO^32 |- S (Conf TWO^256) */
bool simplicity_output_asset(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numOutputs)) {
    asset(dst, &env->tx->output[i].asset);
  } else {
    skipBits(dst, 258);
  }
  return true;
}

/* output_amount : TWO^32 |- S (Conf TWO^256, Conf TWO^64) */
bool simplicity_output_amount(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numOutputs)) {
    asset(dst, &env->tx->output[i].asset);
    amt(dst, &env->tx->output[i].amt);
  } else {
    skipBits(dst, 516);
  }
  return true;
}

/* output_nonce : TWO^32 |- S (S (Conf TWO^256)) */
bool simplicity_output_nonce(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numOutputs)) {
    nonce(dst, &env->tx->output[i].nonce);
  } else {
    skipBits(dst, 259);
  }
  return true;
}

/* output_script_hash : TWO^32 |- S TWO^256 */
bool simplicity_output_script_hash(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numOutputs)) {
    writeHash(dst, &env->tx->output[i].scriptPubKey);
  } else {
    skipBits(dst, 256);
  }
  return true;
}

/* output_null_datum : TWO^32 * TWO^32 |- S (S (TWO^2 * TWO^256 + (TWO + TWO^4)))  */
bool simplicity_output_null_datum(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numOutputs && env->tx->output[i].isNullData)) {
    uint_fast32_t j = simplicity_read32(&src);
    if (writeBit(dst, j < env->tx->output[i].pnd.len)) {
      if (writeBit(dst, OP_PUSHDATA4 < env->tx->output[i].pnd.op[j].code)) {
        skipBits(dst, 2 + 256 - 5);
        if (writeBit(dst, OP_1 <= env->tx->output[i].pnd.op[j].code)) {
          switch (env->tx->output[i].pnd.op[j].code) {
            case OP_1 : writeBit(dst, 0); writeBit(dst, 0); writeBit(dst, 0); writeBit(dst, 0); break;
            case OP_2 : writeBit(dst, 0); writeBit(dst, 0); writeBit(dst, 0); writeBit(dst, 1); break;
            case OP_3 : writeBit(dst, 0); writeBit(dst, 0); writeBit(dst, 1); writeBit(dst, 0); break;
            case OP_4 : writeBit(dst, 0); writeBit(dst, 0); writeBit(dst, 1); writeBit(dst, 1); break;
            case OP_5 : writeBit(dst, 0); writeBit(dst, 1); writeBit(dst, 0); writeBit(dst, 0); break;
            case OP_6 : writeBit(dst, 0); writeBit(dst, 1); writeBit(dst, 0); writeBit(dst, 1); break;
            case OP_7 : writeBit(dst, 0); writeBit(dst, 1); writeBit(dst, 1); writeBit(dst, 0); break;
            case OP_8 : writeBit(dst, 0); writeBit(dst, 1); writeBit(dst, 1); writeBit(dst, 1); break;
            case OP_9 : writeBit(dst, 1); writeBit(dst, 0); writeBit(dst, 0); writeBit(dst, 0); break;
            case OP_10: writeBit(dst, 1); writeBit(dst, 0); writeBit(dst, 0); writeBit(dst, 1); break;
            case OP_11: writeBit(dst, 1); writeBit(dst, 0); writeBit(dst, 1); writeBit(dst, 0); break;
            case OP_12: writeBit(dst, 1); writeBit(dst, 0); writeBit(dst, 1); writeBit(dst, 1); break;
            case OP_13: writeBit(dst, 1); writeBit(dst, 1); writeBit(dst, 0); writeBit(dst, 0); break;
            case OP_14: writeBit(dst, 1); writeBit(dst, 1); writeBit(dst, 0); writeBit(dst, 1); break;
            case OP_15: writeBit(dst, 1); writeBit(dst, 1); writeBit(dst, 1); writeBit(dst, 0); break;
            case OP_16: writeBit(dst, 1); writeBit(dst, 1); writeBit(dst, 1); writeBit(dst, 1); break;
            default: SIMPLICITY_UNREACHABLE;
          }
        } else {
          simplicity_debug_assert(OP_RESERVED == env->tx->output[i].pnd.op[j].code ||
                 OP_1NEGATE == env->tx->output[i].pnd.op[j].code);
          skipBits(dst, 3);
          writeBit(dst, OP_RESERVED == env->tx->output[i].pnd.op[j].code);
        }
      } else {
        switch (env->tx->output[i].pnd.op[j].code) {
          case OP_IMMEDIATE: writeBit(dst, 0); writeBit(dst, 0); break;
          case OP_PUSHDATA: writeBit(dst, 0); writeBit(dst, 1); break;
          case OP_PUSHDATA2: writeBit(dst, 1); writeBit(dst, 0); break;
          case OP_PUSHDATA4: writeBit(dst, 1); writeBit(dst, 1); break;
          default: SIMPLICITY_UNREACHABLE;
        }
        writeHash(dst, &env->tx->output[i].pnd.op[j].dataHash);
      }
    } else {
      skipBits(dst, 1 + 2 + 256);
    }
  } else {
    skipBits(dst, 1 + 1 + 2 + 256);
  }
  return true;
}

/* output_is_fee : TWO^32 |- S TWO */
bool simplicity_output_is_fee(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numOutputs)) {
    writeBit(dst, isFee(&env->tx->output[i]));
  } else {
    skipBits(dst, 1);
  }
  return true;
}

/* output_surjection_proof : TWO^32 |- S TWO^256 */
bool simplicity_output_surjection_proof(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numOutputs)) {
    writeHash(dst, &env->tx->output[i].surjectionProofHash);
  } else {
    skipBits(dst, 256);
  }
  return true;
}

/* output_range_proof : TWO^32 |- S TWO^256 */
bool simplicity_output_range_proof(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numOutputs)) {
    writeHash(dst, &env->tx->output[i].rangeProofHash);
  } else {
    skipBits(dst, 256);
  }
  return true;
}

/* total_fee : TWO^256 |- TWO^64 */
bool simplicity_total_fee(frameItem* dst, frameItem src, const txEnv* env) {
  sha256_midstate assetid;
  readHash(&assetid, &src);
  simplicity_write64(dst, lookup_fee(&assetid, env->tx->feeOutputs, env->tx->numFees));
  return true;
}

/* genesis_block_hash : ONE |- TWO^256 */
bool simplicity_genesis_block_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  write32s(dst, env->genesisHash.s, 8);
  return true;
}

/* script_cmr : ONE |- TWO^256 */
bool simplicity_script_cmr(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  write32s(dst, env->taproot->scriptCMR.s, 8);
  return true;
}

/* transaction_id : ONE |- TWO^256 */
bool simplicity_transaction_id(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  write32s(dst, env->tx->txid.s, 8);
  return true;
}

/* current_bmm_parent_mtp : ONE |- S TWO^64 */
bool simplicity_current_bmm_parent_mtp(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src;
  if (writeBit(dst, env->bmmParentMtpPresent)) {
    simplicity_write64(dst, env->bmmParentMtp);
  } else {
    skipBits(dst, 64);
  }
  return true;
}

/* current_bmm_parent_mtp_required : ONE |- TWO^64
 *
 * V11 fixed-shape controller leaves require an authenticated parent MTP.
 * Missing context fails the jet instead of producing an Option branch whose
 * unchosen path would violate mandatory anti-DoS execution coverage. Keep this
 * native implementation separate from the ECX jet above: the latter reads the
 * authenticated prior-active ECX root, not this block's native BMM context.
 */
bool simplicity_native_current_bmm_parent_mtp_required(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src;
  if (!env || !env->bmmParentMtpPresent) {
    return false;
  }
  simplicity_write64(dst, env->bmmParentMtp);
  return true;
}

/* prior_active_bmm_parent_checkpoint_required
 *   : ONE |- TWO^256 * (TWO^64 * (TWO^64 * TWO^256))
 *
 * The 640 result bits are the exact canonical wire bytes:
 * display-hash || height-be || MTP-be || chainwork-be.  The endpoint is one
 * atomic value; missing or malformed transport context fails the jet and the
 * legacy MTP field is never consulted.
 */
bool simplicity_prior_active_bmm_parent_checkpoint_required(
    frameItem* dst, frameItem src, const txEnv* env) {
  (void) src;
  if (!env || !env->priorActiveBmmParentCheckpointPresent
           || !env->priorActiveBmmParentCheckpointValid) {
    return false;
  }
  write8s(dst, env->priorActiveBmmParentCheckpoint, 80);
  return true;
}

/* issuance_is_none : TWO^32 |- TWO
 *
 * This total predicate is true only for an existing input with no issuance.
 * Invalid indexes and every issuance type are false, so a controller cannot
 * hide issuance behind an unexecuted Option branch.
 */
bool simplicity_issuance_is_none(frameItem* dst, frameItem src, const txEnv* env) {
  const uint_fast32_t i = simplicity_read32(&src);
  const bool none = env && env->tx && i < env->tx->numInputs
                 && NO_ISSUANCE == env->tx->input[i].issuance.type;
  writeBit(dst, none);
  return true;
}

/* verify_sp1_compressed_sha256 : TWO^256 * TWO^256 |- TWO
 *
 * Input is (frozen program ID, SHA256(exact canonical journal)).  Only the
 * pinned Rust ABI's ACCEPTED status for the exact current-input annex writes
 * True.  Missing verifier support and every error are explicit False.
 */
bool simplicity_verify_sp1_compressed_sha256(frameItem* dst, frameItem src, const txEnv* env) {
  unsigned char expectedProgramId[32];
  unsigned char expectedPublicValuesSha256[32];
  bool accepted = false;

  read8s(expectedProgramId, sizeof(expectedProgramId), &src);
  read8s(expectedPublicValuesSha256, sizeof(expectedPublicValuesSha256), &src);

#if defined(HAVE_USDD_SP1_VERIFIER)
  if (env && env->tx && usdd_sp1_verifier_abi_version() == USDD_SP1_VERIFIER_ABI_VERSION) {
    rawElementsBuffer annex = {0};
    if (simplicity_elements_getInputFullAnnex(env->tx, (uint32_t)env->ix, &annex) &&
        annex.buf && 0 < annex.len && 0x50 == annex.buf[0]) {
      accepted = USDD_SP1_VERIFIER_ACCEPTED == usdd_sp1_verify_annex(
          USDD_SP1_VERIFIER_ABI_VERSION,
          annex.buf, annex.len,
          expectedProgramId, sizeof(expectedProgramId),
          expectedPublicValuesSha256, sizeof(expectedPublicValuesSha256));
    }
  }
#else
  (void) env;
#endif

  writeBit(dst, accepted);
  return true;
}

/* current_index : ONE |- TWO^32 */
bool simplicity_current_index(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  simplicity_write32(dst, env->ix);
  return true;
}

/* current_pegin : ONE |- S TWO^256 */
bool simplicity_current_pegin(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  if (env->tx->numInputs <= env->ix) return false;
  if (writeBit(dst, env->tx->input[env->ix].isPegin)) {
    writeHash(dst, &env->tx->input[env->ix].pegin);
  } else {
    skipBits(dst, 256);
  }
  return true;
}

/* current_prev_outpoint : ONE |- TWO^256 * TWO^32 */
bool simplicity_current_prev_outpoint(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  if (env->tx->numInputs <= env->ix) return false;
  prevOutpoint(dst, &env->tx->input[env->ix].prevOutpoint);
  return true;
}

/* current_asset : ONE |- Conf TWO^256 */
bool simplicity_current_asset(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  if (env->tx->numInputs <= env->ix) return false;
  asset(dst, &env->tx->input[env->ix].txo.asset);
  return true;
}

/* current_amount : ONE |- (Conf TWO^256, Conf TWO^64) */
bool simplicity_current_amount(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  if (env->tx->numInputs <= env->ix) return false;
  asset(dst, &env->tx->input[env->ix].txo.asset);
  amt(dst, &env->tx->input[env->ix].txo.amt);
  return true;
}

/* current_script_hash : ONE |- TWO^256 */
bool simplicity_current_script_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  if (env->tx->numInputs <= env->ix) return false;
  writeHash(dst, &env->tx->input[env->ix].txo.scriptPubKey);
  return true;
}

/* current_sequence : ONE |- TWO^32 */
bool simplicity_current_sequence(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  if (env->tx->numInputs <= env->ix) return false;
  simplicity_write32(dst, env->tx->input[env->ix].sequence);
  return true;
}

/* current_reissuance_blinding : ONE |- S (Conf TWO^256) */
bool simplicity_current_reissuance_blinding(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  if (env->tx->numInputs <= env->ix) return false;
  reissuanceBlinding(dst, &env->tx->input[env->ix].issuance);
  return true;
}

/* current_new_issuance_contract : ONE |- S (Conf TWO^256) */
bool simplicity_current_new_issuance_contract(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  if (env->tx->numInputs <= env->ix) return false;
  newIssuanceContract(dst, &env->tx->input[env->ix].issuance);
  return true;
}

/* current_reissuance_entropy : ONE |- S (Conf TWO^256) */
bool simplicity_current_reissuance_entropy(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  if (env->tx->numInputs <= env->ix) return false;
  reissuanceEntropy(dst, &env->tx->input[env->ix].issuance);
  return true;
}

/* current_issuance_asset_amount : ONE |- S (Conf TWO^64) */
bool simplicity_current_issuance_asset_amount(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  if (env->tx->numInputs <= env->ix) return false;
  issuanceAssetAmt(dst, &env->tx->input[env->ix].issuance);
  return true;
}

/* current_issuance_token_amount : ONE |- S (Conf TWO^64) */
bool simplicity_current_issuance_token_amount(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  if (env->tx->numInputs <= env->ix) return false;
  issuanceTokenAmt(dst, &env->tx->input[env->ix].issuance);
  return true;
}

/* current_issuance_asset_proof : ONE |- TWO^256 */
bool simplicity_current_issuance_asset_proof(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  if (env->tx->numInputs <= env->ix) return false;
  writeHash(dst, &env->tx->input[env->ix].issuance.assetRangeProofHash);
  return true;
}

/* current_issuance_token_proof : ONE |- TWO^256 */
bool simplicity_current_issuance_token_proof(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  if (env->tx->numInputs <= env->ix) return false;
  writeHash(dst, &env->tx->input[env->ix].issuance.tokenRangeProofHash);
  return true;
}

/* current_script_sig_hash : ONE |- TWO^256 */
bool simplicity_current_script_sig_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  if (env->tx->numInputs <= env->ix) return false;
  writeHash(dst, &env->tx->input[env->ix].scriptSigHash);
  return true;
}

/* current_annex_hash : ONE |- S (TWO^256) */
bool simplicity_current_annex_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  if (env->tx->numInputs <= env->ix) return false;
  if (writeBit(dst, env->tx->input[env->ix].hasAnnex)) {
    writeHash(dst, &env->tx->input[env->ix].annexHash);
  } else {
    skipBits(dst, 256);
  }
  return true;
}

/* tapleaf_version : ONE |- TWO^8 */
bool simplicity_tapleaf_version(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  simplicity_write8(dst, env->taproot->leafVersion);
  return true;
}

/* tappath : TWO^8 |- S (TWO^256) */
bool simplicity_tappath(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast8_t i = simplicity_read8(&src);
  if (writeBit(dst, i < env->taproot->pathLen)) {
    writeHash(dst, &env->taproot->path[i]);
  } else {
    skipBits(dst, 256);
  }
  return true;
}

/* internal_key : ONE |- TWO^256 */
bool simplicity_internal_key(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeHash(dst, &env->taproot->internalKey);
  return true;
}

/* num_inputs : ONE |- TWO^32 */
bool simplicity_num_inputs(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  simplicity_write32(dst, env->tx->numInputs);
  return true;
}

/* num_outputs : ONE |- TWO^32 */
bool simplicity_num_outputs(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  simplicity_write32(dst, env->tx->numOutputs);
  return true;
}

/* tx_is_final : ONE |- TWO */
bool simplicity_tx_is_final(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeBit(dst, env->tx->isFinal);
  return true;
}

/* tx_lock_height : ONE |- TWO^32 */
bool simplicity_tx_lock_height(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  simplicity_write32(dst, lockHeight(env->tx));
  return true;
}

/* tx_lock_time : ONE |- TWO^32 */
bool simplicity_tx_lock_time(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  simplicity_write32(dst, lockTime(env->tx));
  return true;
}

/* tx_lock_distance : ONE |- TWO^16 */
bool simplicity_broken_do_not_use_tx_lock_distance(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  simplicity_write16(dst, obsolete_lockDistance(env->tx));
  return true;
}

/* tx_lock_duration : ONE |- TWO^16 */
bool simplicity_broken_do_not_use_tx_lock_duration(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  simplicity_write16(dst, obsolete_lockDuration(env->tx));
  return true;
}

/* check_lock_height : TWO^32 |- ONE */
bool simplicity_check_lock_height(frameItem* dst, frameItem src, const txEnv* env) {
  (void) dst; // dst is unused;
  uint_fast32_t x = simplicity_read32(&src);
  return x <= lockHeight(env->tx);
}

/* check_lock_time : TWO^32 |- ONE */
bool simplicity_check_lock_time(frameItem* dst, frameItem src, const txEnv* env) {
  (void) dst; // dst is unused;
  uint_fast32_t x = simplicity_read32(&src);
  return x <= lockTime(env->tx);
}

/* check_lock_distance : TWO^16 |- ONE */
bool simplicity_broken_do_not_use_check_lock_distance(frameItem* dst, frameItem src, const txEnv* env) {
  (void) dst; // dst is unused;
  uint_fast16_t x = simplicity_read16(&src);
  return x <= obsolete_lockDistance(env->tx);
}

/* check_lock_duration : TWO^16 |- ONE */
bool simplicity_broken_do_not_use_check_lock_duration(frameItem* dst, frameItem src, const txEnv* env) {
  (void) dst; // dst is unused;
  uint_fast16_t x = simplicity_read16(&src);
  return x <= obsolete_lockDuration(env->tx);
}

/* calculate_issuance_entropy : TWO^256 * TWO^32 * TWO^256 |- TWO^256 */
bool simplicity_calculate_issuance_entropy(frameItem* dst, frameItem src, const txEnv* env) {
  (void) env; // env is unused.
  outpoint op;
  sha256_midstate contract;
  sha256_midstate result;

  read32s(op.txid.s, 8, &src);
  op.ix = simplicity_read32(&src);
  read32s(contract.s, 8, &src);

  result = simplicity_generateIssuanceEntropy(&op, &contract);
  writeHash(dst, &result);
  return true;
}

/* calculate_asset : TWO^256 |- TWO^256 */
bool simplicity_calculate_asset(frameItem* dst, frameItem src, const txEnv* env) {
  (void) env; // env is unused.
  sha256_midstate entropy;
  sha256_midstate result;

  read32s(entropy.s, 8, &src);
  result = simplicity_calculateAsset(&entropy);

  writeHash(dst, &result);
  return true;
}

/* calculate_explicit_token : TWO^256 |- TWO^256 */
bool simplicity_calculate_explicit_token(frameItem* dst, frameItem src, const txEnv* env) {
  (void) env; // env is unused.
  sha256_midstate entropy;
  sha256_midstate result;

  read32s(entropy.s, 8, &src);
  result = simplicity_calculateToken(&entropy, EXPLICIT);

  writeHash(dst, &result);
  return true;
}

/* calculate_confidential_token : TWO^256 |- TWO^256 */
bool simplicity_calculate_confidential_token(frameItem* dst, frameItem src, const txEnv* env) {
  (void) env; // env is unused.
  sha256_midstate entropy;
  sha256_midstate result;

  read32s(entropy.s, 8, &src);
  result = simplicity_calculateToken(&entropy, EVEN_Y /* ODD_Y would also work. */);

  writeHash(dst, &result);
  return true;
}

/* lbtc_asset : ONE |- TWO^256 */
bool simplicity_lbtc_asset(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused.
  (void) env; // env is unused.
  const sha256_midstate lbtc_assetid = {{
    0x6d521c38u, 0xec1ea157u, 0x34ae22b7u, 0xc4606441u, 0x2829c0d0u, 0x579f0a71u, 0x3d1c04edu, 0xe979026fu
  }};

  writeHash(dst, &lbtc_assetid);
  return true;
}

/* build_tapleaf_simplicity : TWO^256 |- TWO^256 */
bool simplicity_build_tapleaf_simplicity(frameItem* dst, frameItem src, const txEnv* env) {
  (void) env; // env is unused.
  sha256_midstate cmr;
  readHash(&cmr, &src);
  sha256_midstate result = simplicity_make_tapleaf(0xbe, &cmr);
  writeHash(dst, &result);
  return true;
}

/* build_tapbranch : TWO^256 * TWO^256 |- TWO^256 */
bool simplicity_build_tapbranch(frameItem* dst, frameItem src, const txEnv* env) {
  (void) env; // env is unused.
  sha256_midstate a, b;
  readHash(&a, &src);
  readHash(&b, &src);

  sha256_midstate result = simplicity_make_tapbranch(&a, &b);
  writeHash(dst, &result);
  return true;
}

/* build_taptweak : PUBKEY * TWO^256 |- PUBKEY */
bool simplicity_build_taptweak(frameItem* dst, frameItem src, const txEnv* env) {
  (void) env; // env is unused.
  static unsigned char taptweak[] = "TapTweak/elements";
  return simplicity_generic_taptweak(dst, &src, taptweak, sizeof(taptweak)-1);
}

/* outpoint_hash : CTX8 * S TWO^256 * TWO^256 * TWO^32 |- CTX8 */
bool simplicity_outpoint_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) env; // env is unused.
  sha256_midstate midstate;
  unsigned char buf[36];
  sha256_context ctx = {.output = midstate.s};

  /* Read a SHA-256 context. */
  if (!simplicity_read_sha256_context(&ctx, &src)) return false;

  /* Read an optional pegin parent chain hash. */
  if (readBit(&src)) {
    /* Read a pegin parent chain hash. */
    read8s(buf, 32, &src);
    sha256_uchar(&ctx, 0x01);
    sha256_uchars(&ctx, buf, 32);
  } else {
    /* No pegin. */
    sha256_uchar(&ctx, 0x00);
    forwardBits(&src, 256);
  }

  /* Read an outpoint (hash and index). */
  read8s(buf, 36, &src);
  sha256_uchars(&ctx, buf, 36);

  return simplicity_write_sha256_context(dst, &ctx);
}

/* asset_amount_hash : CTX8 * Conf TWO^256 * Conf TWO^64 |- CTX8 */
bool simplicity_asset_amount_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) env; // env is unused.
  sha256_midstate midstate;
  unsigned char buf[32];
  sha256_context ctx = {.output = midstate.s};

  /* Read a SHA-256 context. */
  if (!simplicity_read_sha256_context(&ctx, &src)) return false;

  /* Read an asset id prefix. (2 bits) */
  if (readBit(&src)) {
    /* Read an explicit asset id prefix. (1 bit) */
    forwardBits(&src, 1);
    sha256_uchar(&ctx, 0x01);
  } else {
    /* Read an confidential asset id prefix. (1 bit) */
    if (readBit(&src)) {
      sha256_uchar(&ctx, 0x0b);
    } else {
      sha256_uchar(&ctx, 0x0a);
    }
  }
  /* Read an asset id body (both confidential and explicit asset bodies are the same size). (256 bits) */
  read8s(buf, 32, &src);
  sha256_uchars(&ctx, buf, 32);

  /* Read an amount. (258 bits) */
  if (readBit(&src)) {
    /* Read an explicit amount. (257 bits) */
    sha256_uchar(&ctx, 0x01);
    forwardBits(&src, 257-64);
    read8s(buf, 8, &src);
    sha256_uchars(&ctx, buf, 8);
  } else {
    /* Read an confidential amount. (257 bits) */
    if (readBit(&src)) {
      sha256_uchar(&ctx, 0x09);
    } else {
      sha256_uchar(&ctx, 0x08);
    }
    read8s(buf, 32, &src);
    sha256_uchars(&ctx, buf, 32);
  }

  return simplicity_write_sha256_context(dst, &ctx);
}

/* nonce_hash : CTX8 * S (Conf TWO^256) |- CTX8 */
bool simplicity_nonce_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) env; // env is unused.
  sha256_midstate midstate;
  unsigned char buf[32];
  sha256_context ctx = {.output = midstate.s};

  /* Read a SHA-256 context. */
  if (!simplicity_read_sha256_context(&ctx, &src)) return false;

  /* Read an optional nonce. (259 bits) */
  if (readBit(&src)) {
    /* Read a nonce prefix. (2 bits) */
    if (readBit(&src)) {
      /* Read an explicit none prefix. (1 bit) */
      forwardBits(&src, 1);
      sha256_uchar(&ctx, 0x01);
    } else {
      /* Read a confidential none prefix. (1 bit) */
      if (readBit(&src)) {
        sha256_uchar(&ctx, 0x03);
      } else {
        sha256_uchar(&ctx, 0x02);
      }
    }
    /* Read a nonce id body (both confidential and explicit nonce bodies are the same size). (256 bits) */
    read8s(buf, 32, &src);
    sha256_uchars(&ctx, buf, 32);
  } else {
    sha256_uchar(&ctx, 0x00);
  }

  return simplicity_write_sha256_context(dst, &ctx);
}

/* annex_hash : CTX8 * S TWO^256 |- CTX8 */
bool simplicity_annex_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) env; // env is unused.
  sha256_midstate midstate;
  unsigned char buf[32];
  sha256_context ctx = {.output = midstate.s};

  /* Read a SHA-256 context. */
  if (!simplicity_read_sha256_context(&ctx, &src)) return false;

  /* Read an optional hash. (257 bits) */
  if (readBit(&src)) {
    /* Read a hash. (256 bits) */
    read8s(buf, 32, &src);
    sha256_uchar(&ctx, 0x01);
    sha256_uchars(&ctx, buf, 32);
  } else {
    /* No hash. */
    sha256_uchar(&ctx, 0x00);
  }

  return simplicity_write_sha256_context(dst, &ctx);
}

/* issuance : TWO^256 |- S (S TWO) */
bool simplicity_issuance(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numInputs)) {
    const sigInput* input = &env->tx->input[i];
    if (writeBit(dst, NO_ISSUANCE != input->issuance.type)) {
      writeBit(dst, REISSUANCE == input->issuance.type);
    } else {
      skipBits(dst, 1);
    }
  } else {
    skipBits(dst, 2);
  }
  return true;
}

/* issuance_entropy : TWO^256 |- S (S TWO^256) */
bool simplicity_issuance_entropy(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numInputs)) {
    const sigInput* input = &env->tx->input[i];
    if (writeBit(dst, NO_ISSUANCE != input->issuance.type)) {
      writeHash(dst, &input->issuance.entropy);
    } else {
      skipBits(dst, 256);
    }
  } else {
    skipBits(dst, 257);
  }
  return true;
}

/* issuance_asset : TWO^256 |- S (S TWO^256) */
bool simplicity_issuance_asset(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numInputs)) {
    const sigInput* input = &env->tx->input[i];
    if (writeBit(dst, NO_ISSUANCE != input->issuance.type)) {
      writeHash(dst, &input->issuance.assetId);
    } else {
      skipBits(dst, 256);
    }
  } else {
    skipBits(dst, 257);
  }
  return true;
}

/* issuance_token : TWO^256 |- S (S TWO^256) */
bool simplicity_issuance_token(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numInputs)) {
    const sigInput* input = &env->tx->input[i];
    if (writeBit(dst, NO_ISSUANCE != input->issuance.type)) {
      writeHash(dst, &input->issuance.tokenId);
    } else {
      skipBits(dst, 256);
    }
  } else {
    skipBits(dst, 257);
  }
  return true;
}

/* output_amounts_hash : ONE |- TWO^256 */
bool simplicity_output_amounts_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeHash(dst, &env->tx->outputAssetAmountsHash);
  return true;
}

/* output_nonces_hash : ONE |- TWO^256 */
bool simplicity_output_nonces_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeHash(dst, &env->tx->outputNoncesHash);
  return true;
}

/* output_scripts_hash : ONE |- TWO^256 */
bool simplicity_output_scripts_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeHash(dst, &env->tx->outputScriptsHash);
  return true;
}

/* output_range_proofs_hash : ONE |- TWO^256 */
bool simplicity_output_range_proofs_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeHash(dst, &env->tx->outputRangeProofsHash);
  return true;
}

/* output_surjection_proofs_hash : ONE |- TWO^256 */
bool simplicity_output_surjection_proofs_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeHash(dst, &env->tx->outputSurjectionProofsHash);
  return true;
}

/* outputs_hash : ONE |- TWO^256 */
bool simplicity_outputs_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeHash(dst, &env->tx->outputsHash);
  return true;
}

/* output_hash : TWO^32 |- S TWO^256 */
bool simplicity_output_hash(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numOutputs)) {
    const sigOutput* output = &env->tx->output[i];
    sha256_midstate midstate;
    sha256_context ctx = sha256_init(midstate.s);
    simplicity_sha256_confAsset(&ctx, &output->asset);
    simplicity_sha256_confAmt(&ctx, &output->amt);
    simplicity_sha256_confNonce(&ctx, &output->nonce);
    sha256_hash(&ctx, &output->scriptPubKey);
    sha256_hash(&ctx, &output->rangeProofHash);
    sha256_finalize(&ctx);
    writeHash(dst, &midstate);
  } else {
    skipBits(dst, 256);
  }
  return true;
}

/* input_outpoints_hash : ONE |- TWO^256 */
bool simplicity_input_outpoints_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeHash(dst, &env->tx->inputOutpointsHash);
  return true;
}

/* input_amounts_hash : ONE |- TWO^256 */
bool simplicity_input_amounts_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeHash(dst, &env->tx->inputAssetAmountsHash);
  return true;
}

/* input_scripts_hash : ONE |- TWO^256 */
bool simplicity_input_scripts_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeHash(dst, &env->tx->inputScriptsHash);
  return true;
}

/* input_utxos_hash : ONE |- TWO^256 */
bool simplicity_input_utxos_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeHash(dst, &env->tx->inputUTXOsHash);
  return true;
}

/* input_utxo_hash : TWO^32 |- S TWO^256 */
bool simplicity_input_utxo_hash(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numInputs)) {
    const utxo* txo = &env->tx->input[i].txo;
    sha256_midstate midstate;
    sha256_context ctx = sha256_init(midstate.s);
    simplicity_sha256_confAsset(&ctx, &txo->asset);
    simplicity_sha256_confAmt(&ctx, &txo->amt);
    sha256_hash(&ctx, &txo->scriptPubKey);
    sha256_finalize(&ctx);
    writeHash(dst, &midstate);
  } else {
    skipBits(dst, 256);
  }
  return true;
}

/* input_sequences_hash : ONE |- TWO^256 */
bool simplicity_input_sequences_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeHash(dst, &env->tx->inputSequencesHash);
  return true;
}

/* input_annexes_hash : ONE |- TWO^256 */
bool simplicity_input_annexes_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeHash(dst, &env->tx->inputAnnexesHash);
  return true;
}

/* input_script_sigs_hash : ONE |- TWO^256 */
bool simplicity_input_script_sigs_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeHash(dst, &env->tx->inputScriptSigsHash);
  return true;
}

/* inputs_hash : ONE |- TWO^256 */
bool simplicity_inputs_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeHash(dst, &env->tx->inputsHash);
  return true;
}

/* input_hash : TWO^32 |- S TWO^256 */
bool simplicity_input_hash(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numInputs)) {
    const sigInput* input = &env->tx->input[i];
    sha256_midstate midstate;
    sha256_context ctx = sha256_init(midstate.s);
    if (input->isPegin) {
      sha256_uchar(&ctx, 1);
      sha256_hash(&ctx, &input->pegin);
    } else {
      sha256_uchar(&ctx, 0);
    }
    sha256_hash(&ctx, &input->prevOutpoint.txid);
    sha256_u32be(&ctx, input->prevOutpoint.ix);
    sha256_u32be(&ctx, input->sequence);
    if (input->hasAnnex) {
      sha256_uchar(&ctx, 1);
      sha256_hash(&ctx, &input->annexHash);
    } else {
      sha256_uchar(&ctx, 0);
    }
    sha256_finalize(&ctx);
    writeHash(dst, &midstate);
  } else {
    skipBits(dst, 256);
  }
  return true;
}

/* issuance_asset_amounts_hash : ONE |- TWO^256 */
bool simplicity_issuance_asset_amounts_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeHash(dst, &env->tx->issuanceAssetAmountsHash);
  return true;
}

/* issuance_token_amounts_hash : ONE |- TWO^256 */
bool simplicity_issuance_token_amounts_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeHash(dst, &env->tx->issuanceTokenAmountsHash);
  return true;
}

/* issuance_range_proofs_hash : ONE |- TWO^256 */
bool simplicity_issuance_range_proofs_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeHash(dst, &env->tx->issuanceRangeProofsHash);
  return true;
}

/* issuance_blinding_entropy_hash : ONE |- TWO^256 */
bool simplicity_issuance_blinding_entropy_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeHash(dst, &env->tx->issuanceBlindingEntropyHash);
  return true;
}

/* issuances_hash : ONE |- TWO^256 */
bool simplicity_issuances_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeHash(dst, &env->tx->issuancesHash);
  return true;
}

/* issuance_hash : TWO^32 |- S TWO^256 */
bool simplicity_issuance_hash(frameItem* dst, frameItem src, const txEnv* env) {
  uint_fast32_t i = simplicity_read32(&src);
  if (writeBit(dst, i < env->tx->numInputs)) {
    const assetIssuance* issuance = &env->tx->input[i].issuance;
    sha256_midstate midstate;
    sha256_context ctx = sha256_init(midstate.s);
    if (NO_ISSUANCE == issuance->type) {
      sha256_uchar(&ctx, 0);
      sha256_uchar(&ctx, 0);
      sha256_uchar(&ctx, 0);
      sha256_uchar(&ctx, 0);
      sha256_hash(&ctx, &issuance->assetRangeProofHash);
      sha256_hash(&ctx, &issuance->tokenRangeProofHash);
      sha256_uchar(&ctx, 0);
    } else {
      simplicity_sha256_confAsset(&ctx, &(confidential){ .prefix = EXPLICIT, .data = issuance->assetId});
      simplicity_sha256_confAmt(&ctx, &issuance->assetAmt);
      simplicity_sha256_confAsset(&ctx, &(confidential){ .prefix = EXPLICIT, .data = issuance->tokenId});
      simplicity_sha256_confAmt(&ctx, NEW_ISSUANCE == issuance->type
                                         ? &issuance->tokenAmt
                                         : &(confAmount){ .prefix = EXPLICIT, .explicit = 0});
      sha256_hash(&ctx, &issuance->assetRangeProofHash);
      sha256_hash(&ctx, &issuance->tokenRangeProofHash);
      sha256_uchar(&ctx, 1);
      if (NEW_ISSUANCE == issuance->type) {
        sha256_uchars(&ctx, (unsigned char[32]){0}, 32);
        sha256_hash(&ctx, &issuance->contractHash);
      } else {
        sha256_hash(&ctx, &issuance->blindingNonce);
        sha256_hash(&ctx, &issuance->entropy);
      }
    }
    sha256_finalize(&ctx);
    writeHash(dst, &midstate);
  } else {
    skipBits(dst, 256);
  }
  return true;
}

/* tx_hash : ONE |- TWO^256 */
bool simplicity_tx_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeHash(dst, &env->tx->txHash);
  return true;
}

/* tapleaf_hash : ONE |- TWO^256 */
bool simplicity_tapleaf_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeHash(dst, &env->taproot->tapLeafHash);
  return true;
}

/* tappath_hash : ONE |- TWO^256 */
bool simplicity_tappath_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeHash(dst, &env->taproot->tappathHash);
  return true;
}

/* tap_env_hash : ONE |- TWO^256 */
bool simplicity_tap_env_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeHash(dst, &env->taproot->tapEnvHash);
  return true;
}

/* sig_all_hash : ONE |- TWO^256 */
bool simplicity_sig_all_hash(frameItem* dst, frameItem src, const txEnv* env) {
  (void) src; // src is unused;
  writeHash(dst, &env->sigAllHash);
  return true;
}
