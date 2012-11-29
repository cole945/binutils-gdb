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

#include "rbtree.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <unistd.h>

struct rbnode rbnode_null = RB_NULL_INIT;
static rbnode_t rbnode_allocate_node (void *key);
static void rbtree_insert_fixup (rbtree_t tree, rbnode_t node);
static void rbtree_delete_fixup (rbtree_t tree, rbnode_t node);
static void rbtree_free_node (rbnode_t node);

/* Is an empty red-black tree?  */

int
rbtree_isnull (rbnode_t node)
{
  return (node == RB_NULL);
}

/* Validate the tree.  */

void
rbtree_assert (int exp, const char *fmt, ...)
{
  va_list ap;

  if (exp)
    return;

  va_start (ap, fmt);
  vfprintf (stderr, fmt, ap);
  _exit (1);
  va_end (ap);
}

/* Create and allocate a red-black tree.  */

rbtree_t
rbtree_create_tree (rbcmp_ftype fcmp, rbtrav_ftype ftrav)
{
  rbtree_t tree;

  tree = (rbtree_t) calloc (1, sizeof (*tree));
  tree->root = RB_NULL;
  tree->rbcmp = fcmp;
  tree->rbtrav = ftrav;

  return tree;
}

static void
rbtree_destroy_tree_internal (rbtree_t tree, rbnode_t node)
{
  if (node == RB_NULL)
    return;

  rbtree_destroy_tree_internal (tree, node->left);
  rbtree_destroy_tree_internal (tree, node->right);
  rbtree_free_node (node);
}

/* Destroy and free a red-black tree.  */

void
rbtree_destroy_tree (rbtree_t tree)
{
  rbtree_destroy_tree_internal (tree, tree->root);

  memset (tree, 0, sizeof (*tree));
  free (tree);
}

/* Allocate a tree node.  */

static rbnode_t
rbnode_allocate_node (void *key)
{
  rbnode_t node;
  node = (rbnode_t) calloc (1, sizeof (struct rbnode));
  node->key = key;
  node->left = node->right = RB_NULL;
  node->color = RB_RED;

  return node;
}

/* Free a tree node.  */

static void
rbtree_free_node (rbnode_t node)
{
  memset (node, 0, sizeof (*node));
  free (node);
}

/* Given a tree node, return its root node.  */

rbnode_t
rbtree_root (rbnode_t node)
{
  while (node->parent)
    node = node->parent;

  return node;
}

void
rbtree_rotate_left (rbtree_t tree, rbnode_t node)
{
  rbnode_t p, x, y;

  RBTREE_ASSERT (node->right != RB_NULL);

  x = node;
  y = node->right;
  p = node->parent;

  y->parent = x->parent;

  x->right = y->left;
  y->left->parent = x;
  y->left = x;
  x->parent = y;

  if (p == NULL)
    tree->root = y;
  else if (p->left == x)
    p->left = y;
  else
    p->right = y;
}

void
rbtree_rotate_right (rbtree_t tree, rbnode_t node)
{
  rbnode_t p, x, y;

  RBTREE_ASSERT (node->left != RB_NULL);

  x = node;
  y = node->left;
  p = node->parent;

  y->parent = x->parent;

  x->left = y->right;
  y->right->parent = x;
  y->right = x;
  x->parent = y;

  if (p == NULL)
    tree->root = y;
  else if (p->right == x)
    p->right = y;
  else
    p->left = y;
}

static void
rbtree_insert_fixup (rbtree_t tree, rbnode_t node)
{
  rbnode_t z, y, p, r, t;

  /* -----------------------
		r
	      /   \
    (parent) p    y (uncle)
	    / \
	       z (node)
     ------------------------ */
  z = node;
  while ((p = z->parent) && (r = p->parent) && p->color == RB_RED)
    {
      if (p == r->left)
	{
	  y = r->right;

	  /* case 1 */
	  if (y->color == RB_RED)
	    {
	      p->color = RB_BLACK;
	      y->color = RB_BLACK;
	      r->color = RB_RED;
	      z = r;
	    }
	  else
	    {
	      /* case 2 */
	      if (z == p->right)
		{
		  rbtree_rotate_left (tree, p);
		  z = p;
		  p = z->parent;
		}
	      /* case 3 */
	      rbtree_rotate_right (tree, r);
	      p->color = RB_BLACK;
	      r->color = RB_RED;
	    }
	}
      else
	{
	  y = r->left;

	  /* case 1 */
	  if (y->color == RB_RED)
	    {
	      p->color = RB_BLACK;
	      y->color = RB_BLACK;
	      r->color = RB_RED;
	      z = r;
	    }
	  else
	    {
	      /* case 2 */
	      if (z == p->left)
		{
		  rbtree_rotate_right (tree, p);
		  z = p;
		  p = z->parent;
		}
	      /* case 3 */
	      rbtree_rotate_left (tree, r);
	      p->color = RB_BLACK;
	      r->color = RB_RED;
	    }
	}
    }
  tree->root->color = RB_BLACK;
}

/* Insert a tree node of KEY.  */

void
rbtree_insert (rbtree_t tree, void *key)
{
  int cmp;
  rbnode_t prev = NULL;
  rbnode_t new_node;
  rbnode_t node = tree->root;

  new_node = rbnode_allocate_node (key);

  while (node != RB_NULL)
    {
      cmp = tree->rbcmp (key, node->key);

      prev = node;
      if (cmp < 0) /* less than */
	node = node->left;
      else
	node = node->right;
    }

  if (prev == NULL)
    {
      tree->root = new_node;
      return;
    }

  new_node->parent = prev;
  if (cmp < 0)
    prev->left = new_node;
  else
    prev->right = new_node;

  rbtree_insert_fixup (tree, new_node);
  return;
}

/* Find a tree node of KEY.  */

rbnode_t
rbtree_find (rbtree_t tree, void *key)
{
  int cmp;
  rbnode_t node = tree->root;

  while (node != RB_NULL)
    {
      cmp = tree->rbcmp (key, node->key);

      if (cmp == 0)
	return node;
      else if (cmp < 0)
	node = node->left;
      else
	node = node->right;
    }

  return NULL;
}

static void
rbtree_delete_fixup (rbtree_t tree, rbnode_t node)
{
  /* -----------------------
		 p
	       /   \
	      x     w
	     / \   / \
		  C   E
     ------------------------ */

  rbnode_t x, w;

  x = node;


  while (x != tree->root && x->color == RB_BLACK)
    {
      if (x->parent->left == x)
	{
	  w = x->parent->right;
	  if (w->color == RB_RED)
	    {
	      /* Case 1.  */
	      x->parent->color = RB_RED;
	      w->color = RB_BLACK;
	      rbtree_rotate_left (tree, x->parent);
	    }
	  else if (w->left->color == RB_BLACK
		   && w->right->color == RB_BLACK)
	    {
	      w->color = RB_RED;
	      x = x->parent;
	    }
	  else
	    {
	      if (w->right->color == RB_BLACK)
		{
		  w->left->color = RB_BLACK;
		  w->color = RB_RED;
		  rbtree_rotate_right (tree, w);
		  w = w->parent;
		}
	      w->color = w->parent->color;
	      w->parent->color = RB_BLACK;
	      w->right->color = RB_BLACK;
	      rbtree_rotate_left (tree, w->parent);
	      x = tree->root;
	    }
	}
      else
	{
	  w = x->parent->left;
	  if (w->color == RB_RED)
	    {
	      /* Case 1.  */
	      x->parent->color = RB_RED;
	      w->color = RB_BLACK;
	      rbtree_rotate_right (tree, x->parent);
	    }
	  else if (w->right->color == RB_BLACK
		   && w->left->color == RB_BLACK)
	    {
	      w->color = RB_RED;
	      x = x->parent;
	    }
	  else
	    {
	      if (w->left->color == RB_BLACK)
		{
		  w->right->color = RB_BLACK;
		  w->color = RB_RED;
		  rbtree_rotate_left (tree, w);
		  w = w->parent;
		}
	      w->color = w->parent->color;
	      w->parent->color = RB_BLACK;
	      w->left->color = RB_BLACK;
	      rbtree_rotate_right (tree, w->parent);
	      x = tree->root;
	    }
	}
    }

  x->color = RB_BLACK;
}

void
rbtree_delete_node (rbtree_t tree, rbnode_t node)
{
  /* Case 1. z has no child - just remove it.  */
  /* Case 2. z has only one child - splice out z.  */
  /* case 3. z has two children - splice out its successor y and replce z.  */

  rbnode_t z = node;
  rbnode_t p = NULL;
  rbnode_t x = NULL;
  rbnode_t y = NULL;

  /* z - The node to be deleted.
     y - The node used to replace z.
     x - The child of y to be re-parent.  */

  if (z->left != RB_NULL && z->right != RB_NULL)
    {
      RBTREE_ASSERT (rbtree_minimum (z->right) == rbtree_successor (z));
      y = rbtree_minimum (z->right);
    }
  else
    y = z;

  if (y->left != RB_NULL)
    x = y->left;
  else
    x = y->right;

  /* if (x != RB_NULL) */
    x->parent = y->parent;

  if ((p = y->parent) != NULL)
    {
      if (p->left == y)
	p->left = x;
      else
	p->right = x;

      if (x != RB_NULL)
	x->parent = p;
    }
  else
    {
      tree->root = x;
      x->parent = NULL;
    }

  if (z != y)
    z->key = y->key;

  if (y->color == RB_BLACK)
    rbtree_delete_fixup (tree, x);

  rbtree_free_node (y);
}

void
rbtree_delete (rbtree_t tree, void *key)
{
  rbnode_t node = rbtree_find (tree, key);

  if (node == NULL)
    return;

  rbtree_delete_node (tree, node);
}

/* Black hight of NODE.  */

int
rbtree_bh (rbnode_t node)
{
  int lbh, rbh;

  if (node == RB_NULL)
    return 1;

  lbh = rbtree_bh (node->left);
  rbh = rbtree_bh (node->right);

  RBTREE_ASSERT (lbh == rbh);

  return lbh + (node->color == RB_BLACK ? 1 : 0);
}

/* Traverse the tree and RBTRAV is call for each node with ARG.  */

void
rbtree_traverse_node (rbtree_t tree, rbnode_t node, rbtrav_ftype rbtrav,
		      void *arg)
{
  if (node == RB_NULL)
    return;

  rbtrav (tree, node, arg);
  rbtree_traverse_node (tree, node->left, rbtrav, arg);
  rbtree_traverse_node (tree, node->right, rbtrav, arg);
}

rbnode_t rbtree_minimum (rbnode_t node)
{
  while (node->left != RB_NULL)
    node = node->left;
  return node;
}

rbnode_t rbtree_maximum (rbnode_t node)
{
  while (node->right != RB_NULL)
    node = node->right;
  return node;
}

/* Traverse tree with default RBTRAV callback.  */

void
rbtree_traverse (rbtree_t tree, void *arg)
{
  rbtree_traverse_node (tree, tree->root, tree->rbtrav, arg);
}

rbnode_t
rbtree_successor (rbnode_t node)
{
  if (node->right != RB_NULL)
    return rbtree_minimum (node->right);

  while (node->parent != NULL && node->parent->right == node)
    node = node->parent;
  return node->parent;
}

rbnode_t
rbtree_predecessor (rbnode_t node)
{
  if (node->left != RB_NULL)
    return rbtree_maximum (node->left);

  while (node->parent != NULL && node->parent->left == node)
    node = node->parent;
  return node->parent;
}
