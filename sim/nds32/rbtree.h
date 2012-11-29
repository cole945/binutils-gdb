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

#ifndef RBTREE_H
#define RBTREE_H

#include <stdio.h>

enum RB_COLOR
{
  RB_BLACK = 0xabcd,
  RB_RED = 0xdcba,
};

enum RB_ERROR
{
  RBE_PASS,
  RBE_RULE1	= 0x81000000,
  RBE_RULE2	= 0x82000000,
  RBE_RULE3	= 0x84000000,
  RBE_RULE4	= 0x88000000,
  RBE_RULE5	= 0x90000000,
  RBE_CONSIST	= 0xa0000000,
  RBE_MASK	= 0xff000000,
};

typedef struct rbnode *rbnode_t;
typedef struct rbtree *rbtree_t;

typedef int (*rbcmp_ftype) (void *lhs, void *rhs);
typedef void (*rbtrav_ftype) (rbtree_t tree, rbnode_t node, void *arg);

struct rbnode
{
  struct rbnode *parent;
  struct rbnode *left;
  struct rbnode *right;
  enum RB_COLOR color;
  void *key;
};

#define RB_NULL_INIT {NULL, NULL, NULL, RB_BLACK}

struct rbtree
{
  struct rbnode *root;
  rbcmp_ftype rbcmp;
  rbtrav_ftype rbtrav;
};

rbtree_t rbtree_create_tree (rbcmp_ftype fcmp, rbtrav_ftype ftrav);
rbnode_t rbtree_root (rbnode_t node);
int rbtree_bh (rbnode_t node);
void rbtree_destroy_tree (rbtree_t tree);
void rbtree_insert (rbtree_t tree, void *key);
void rbtree_delete_node (rbtree_t tree, rbnode_t node);
void rbtree_delete (rbtree_t tree, void *key);
void rbtree_traverse (rbtree_t tree, void *arg);
void rbtree_traverse_node (rbtree_t tree, rbnode_t node, rbtrav_ftype ftrav,
			   void *arg);
rbnode_t rbtree_find (rbtree_t tree, void *key);
void rbtree_rotate_left (rbtree_t tree, rbnode_t node);
void rbtree_rotate_right (rbtree_t tree, rbnode_t node);
void rbtree_assert (int exp, const char *fmt, ...);
int rbtree_isnull (rbnode_t node);
int rbtree_verify (rbtree_t tree, FILE *fp);
rbnode_t rbtree_minimum (rbnode_t node);
rbnode_t rbtree_maximum (rbnode_t node);
rbnode_t rbtree_successor (rbnode_t node);
rbnode_t rbtree_predecessor (rbnode_t node);

#define RBTREE_ASSERT(exp)	rbtree_assert (exp, #exp "\n")

extern struct rbnode rbnode_null;
#define RB_NULL	(&rbnode_null)

/* extern struct rbnode rbnode_null; */

#endif
