/* Keystone Assembler Engine */
/* By Nguyen Anh Quynh, 2016 */

#ifndef KEYSTONE_MSP430_H
#define KEYSTONE_MSP430_H

#ifdef __cplusplus
extern "C" {
#endif

#include "keystone.h"

typedef enum ks_err_asm_msp430 {
    KS_ERR_ASM_MSP430_INVALIDOPERAND = KS_ERR_ASM_ARCH,
    KS_ERR_ASM_MSP430_MISSINGFEATURE,
    KS_ERR_ASM_MSP430_MNEMONICFAIL,
} ks_err_asm_msp430;

#ifdef __cplusplus
}
#endif

#endif
