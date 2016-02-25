/* THIS FILE IS GENERATED.  -*- buffer-read-only: t -*- vi:set ro:
  Original: nds32.xml */

#include "defs.h"
#include "osabi.h"
#include "target-descriptions.h"

struct target_desc *tdesc_nds32;
static void
initialize_tdesc_nds32 (void)
{
  struct target_desc *result = allocate_target_description ();
  struct tdesc_feature *feature;

  set_tdesc_architecture (result, bfd_scan_arch ("n1h"));

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
  tdesc_create_reg (feature, "r26", 26, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "r27", 27, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "fp", 28, 1, NULL, 32, "data_ptr");
  tdesc_create_reg (feature, "gp", 29, 1, NULL, 32, "data_ptr");
  tdesc_create_reg (feature, "lp", 30, 1, NULL, 32, "code_ptr");
  tdesc_create_reg (feature, "sp", 31, 1, NULL, 32, "data_ptr");
  tdesc_create_reg (feature, "pc", 32, 1, NULL, 32, "code_ptr");
  tdesc_create_reg (feature, "d0lo", 33, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "d0hi", 34, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "d1lo", 35, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "d1hi", 36, 1, NULL, 32, "int");

  feature = tdesc_create_feature (result, "org.gnu.gdb.nds32.fpu");
  tdesc_create_reg (feature, "fd0", 37, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd1", 38, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd2", 39, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd3", 40, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd4", 41, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd5", 42, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd6", 43, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd7", 44, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd8", 45, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd9", 46, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd10", 47, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd11", 48, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd12", 49, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd13", 50, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd14", 51, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd15", 52, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd16", 53, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd17", 54, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd18", 55, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd19", 56, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd20", 57, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd21", 58, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd22", 59, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd23", 60, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd24", 61, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd25", 62, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd26", 63, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd27", 64, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd28", 65, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd29", 66, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd30", 67, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd31", 68, 1, NULL, 64, "ieee_double");

  feature = tdesc_create_feature (result, "org.gnu.gdb.nds32.system");
  tdesc_create_reg (feature, "ir0", 69, 1, "ir", 32, "int");
  tdesc_create_reg (feature, "itb", 70, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "ifc_lp", 71, 1, NULL, 32, "int");

  tdesc_nds32 = result;
}
