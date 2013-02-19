/* THIS FILE IS GENERATED.  Original: nds32-sim.xml */

#include "defs.h"
#include "osabi.h"
#include "target-descriptions.h"

struct target_desc *tdesc_nds32_sim;
static void
initialize_tdesc_nds32_sim (void)
{
  struct target_desc *result = allocate_target_description ();
  struct tdesc_feature *feature;
  struct tdesc_type *field_type, *type;

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
  tdesc_create_reg (feature, "ifc_lp", 37, 1, NULL, 32, "code_ptr");
  tdesc_create_reg (feature, "itb", 38, 1, NULL, 32, "code_ptr");

  feature = tdesc_create_feature (result, "org.gnu.gdb.nds32.system");
  tdesc_create_reg (feature, "ir0", 64, 1, "ir", 32, "data_ptr");

  feature = tdesc_create_feature (result, "org.gnu.gdb.nds32.fpu");
  tdesc_create_reg (feature, "fpcfg", 126, 1, "system", 32, "int");
  tdesc_create_reg (feature, "fpcsr", 127, 1, "system", 32, "int");
  tdesc_create_reg (feature, "fs0", 128, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs1", 129, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs2", 130, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs3", 131, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs4", 132, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs5", 133, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs6", 134, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs7", 135, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs8", 136, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs9", 137, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs10", 138, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs11", 139, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs12", 140, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs13", 141, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs14", 142, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs15", 143, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs16", 144, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs17", 145, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs18", 146, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs19", 147, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs20", 148, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs21", 149, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs22", 150, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs23", 151, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs24", 152, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs25", 153, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs26", 154, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs27", 155, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs28", 156, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs29", 157, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs30", 158, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs31", 159, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fd0", 160, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd1", 161, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd2", 162, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd3", 163, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd4", 164, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd5", 165, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd6", 166, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd7", 167, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd8", 168, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd9", 169, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd10", 170, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd11", 171, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd12", 172, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd13", 173, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd14", 174, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd15", 175, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd16", 176, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd17", 177, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd18", 178, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd19", 179, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd20", 180, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd21", 181, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd22", 182, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd23", 183, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd24", 184, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd25", 185, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd26", 186, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd27", 187, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd28", 188, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd29", 189, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd30", 190, 1, NULL, 64, "ieee_double");
  tdesc_create_reg (feature, "fd31", 191, 1, NULL, 64, "ieee_double");

  tdesc_nds32_sim = result;
}
