/* THIS FILE IS GENERATED.  Original: nds32-linux-sid.xml */

#include "defs.h"
#include "osabi.h"
#include "target-descriptions.h"

struct target_desc *tdesc_nds32_linux_sid;
static void
initialize_tdesc_nds32_linux_sid (void)
{
  struct target_desc *result = allocate_target_description ();
  struct tdesc_feature *feature;
  struct tdesc_type *field_type, *type;

  set_tdesc_architecture (result, bfd_scan_arch ("n1h"));

  set_tdesc_osabi (result, osabi_from_tdesc_string ("GNU/Linux"));

  feature = tdesc_create_feature (result, "org.gnu.gdb.nds32.core");
  tdesc_create_reg (feature, "r0", 0, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "r1", 1, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "r2", 2, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "r3", 3, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "r4", 4, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "r5", 5, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "r6", 6, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "r7", 7, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "r8", 8, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "r9", 9, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "r10", 10, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "r11", 11, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "r12", 12, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "r13", 13, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "r14", 14, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "r15", 15, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "r16", 16, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "r17", 17, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "r18", 18, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "r19", 19, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "r20", 20, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "r21", 21, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "r22", 22, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "r23", 23, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "r24", 24, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "r25", 25, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "", 26, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "", 27, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "fp", 28, 1, NULL, 32, "data_ptr");
  tdesc_create_reg (feature, "gp", 29, 1, NULL, 32, "data_ptr");
  tdesc_create_reg (feature, "lp", 30, 1, NULL, 32, "code_ptr");
  tdesc_create_reg (feature, "sp", 31, 1, NULL, 32, "data_ptr");
  tdesc_create_reg (feature, "pc", 32, 1, NULL, 32, "code_ptr");
  tdesc_create_reg (feature, "d0lo", 33, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "d0hi", 34, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "d1lo", 35, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "d1hi", 36, 1, NULL, 32, "int");

  feature = tdesc_create_feature (result, "org.gnu.gdb.nds32.linux");
  tdesc_create_reg (feature, "orig_r0", 37, 1, "system", 32, "int");
  tdesc_create_reg (feature, "fucpr", 38, 1, "system", 32, "int");

  feature = tdesc_create_feature (result, "org.gnu.gdb.nds32.dummy");
  tdesc_create_reg (feature, "", 39, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 40, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 41, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 42, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 43, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 44, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 45, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 46, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 47, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 48, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 49, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 50, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 51, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 52, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 53, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 54, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 55, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 56, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 57, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 58, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 59, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 60, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 61, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 62, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 63, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 64, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 65, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 66, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 67, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 68, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 69, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 70, 1, NULL, 128, "uint128");
  tdesc_create_reg (feature, "", 71, 1, NULL, 128, "uint128");

  tdesc_nds32_linux_sid = result;
}
