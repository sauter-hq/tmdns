/*
 *
 * llist.h - linked list implementation - prototypes.
 *
 * Part of the tmdns package by Andreas Hofmeister. 
 *
 * Copyright 2000 Benjamin Close <benjsc@hotmail.com>
 *
 * This software is licensed under the terms of the GNU General 
 * Public License (GPL). Please see the file COPYING for details.
 * 
 *
*/
#ifndef __LLIST_H
#define __LLIST_H
 
#include <config.h>

/* list handler */
typedef struct 
{
   struct __ll_entry_t *pHead;
   struct __ll_entry_t *pTail;
}list_t;

/* list element */
typedef struct __ll_entry_t 
{ 
   list_t *list;
   struct __ll_entry_t *pNext;
   struct __ll_entry_t *pPrev;
   void *data;
}ll_entry_t;

/* Constructor, an add method and a destructor */

extern list_t  *ll_new(void);
extern int ll_add(list_t * , void *);
extern void ll_delete(list_t *);

/*... an iterator ... */

extern ll_entry_t *ll_first(const list_t *);
extern ll_entry_t *ll_next(const ll_entry_t *);

/*... element destructor ... */

extern void ll_remove(ll_entry_t *);

/*... move element to front of list ... */

extern void ll_to_front(ll_entry_t *);

/* shorthand for lengthy for iterator thingy */
#define foreach(it,list) \
    for( it = ll_first(list) ; it != NULL; it = ll_next(it) )

#endif
