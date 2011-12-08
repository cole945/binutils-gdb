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
  tdesc_create_reg (feature, "ifc_lp", 175, 1, NULL, 32, "code_ptr");

  feature = tdesc_create_feature (result, "org.gnu.gdb.nds32.fpu");
  tdesc_create_reg (feature, "fpcfg", 176, 1, "system", 32, "int");
  tdesc_create_reg (feature, "fpcsr", 177, 1, "system", 32, "int");
  tdesc_create_reg (feature, "fs0", 178, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs1", 179, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs2", 180, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs3", 181, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs4", 182, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs5", 183, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs6", 184, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs7", 185, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs8", 186, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs9", 187, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs10", 188, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs11", 189, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs12", 190, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs13", 191, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs14", 192, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs15", 193, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs16", 194, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs17", 195, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs18", 196, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs19", 197, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs20", 198, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs21", 199, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs22", 200, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs23", 201, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs24", 202, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs25", 203, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs26", 204, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs27", 205, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs28", 206, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs29", 207, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs30", 208, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fs31", 209, 1, NULL, 32, "ieee_single");
  tdesc_create_reg (feature, "fd0", 210, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd1", 211, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd2", 212, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd3", 213, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd4", 214, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd5", 215, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd6", 216, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd7", 217, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd8", 218, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd9", 219, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd10", 220, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd11", 221, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd12", 222, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd13", 223, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd14", 224, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd15", 225, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd16", 226, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd17", 227, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd18", 228, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd19", 229, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd20", 230, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd21", 231, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd22", 232, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd23", 233, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd24", 234, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd25", 235, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd26", 236, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd27", 237, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd28", 238, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd29", 239, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd30", 240, 1, NULL, 64, "ieee_single");
  tdesc_create_reg (feature, "fd31", 241, 1, NULL, 64, "ieee_single");

  tdesc_nds32_sim = result;
}
