/* Simulator for NDS32 processors.

   Copyright (C) 2011-2013 Free Software Foundation, Inc.
   Contributed by Andes Technology Corporation.

   This file is part of simulators.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "nds32-pfm.h"
#include "nds32-sim.h"

#include <stdint.h>

/* I put performance monitor definitions here.  */
void
nds32_pfm_ctl (sim_cpu *cpu)
{
  int en, ie, ovf, ks, ku;
  int sel0, sel1, sel2;

  en = CCPU_SR_GET (PFM_CTL, PFM_CTL_EN);
  ie = CCPU_SR_GET (PFM_CTL, PFM_CTL_IE);
  ovf = CCPU_SR_GET (PFM_CTL, PFM_CTL_OVF);
  ks = CCPU_SR_GET (PFM_CTL, PFM_CTL_KS);
  ku = CCPU_SR_GET (PFM_CTL, PFM_CTL_KU);
  sel0 = CCPU_SR_GET (PFM_CTL, PFM_CTL_SEL0);
  sel1 = CCPU_SR_GET (PFM_CTL, PFM_CTL_SEL1);
  sel2 = CCPU_SR_GET (PFM_CTL, PFM_CTL_SEL2);
}

void
nds32_pfm_event (sim_cpu *cpu, int pfm_event)
{
  int sel[3];
  int en, ovf;
  int i;

  en = CCPU_SR_GET (PFM_CTL, PFM_CTL_EN);
  ovf = CCPU_SR_GET (PFM_CTL, PFM_CTL_OVF);

  sel[0] = CCPU_SR_GET (PFM_CTL, PFM_CTL_SEL0);
  sel[1] = CCPU_SR_GET (PFM_CTL, PFM_CTL_SEL1);
  sel[2] = CCPU_SR_GET (PFM_CTL, PFM_CTL_SEL2);

  switch (pfm_event)
    {
    case PFM_CYCLE:
    case PFM_INST:
      for (i = 0; i < 3; i++)
	{
	  if (sel[i] == pfm_event && (en & (1 << i)))
	    {
	      CCPU_SR[SRIDX_PFMC0 + i].u++;
	      if (CCPU_SR[SRIDX_PFMC0 + i].u == 0)
		ovf |= (1 << i);
	    }
	}
      break;
    }

  CCPU_SR_PUT (PFM_CTL, PFM_CTL_OVF, ovf);
}
