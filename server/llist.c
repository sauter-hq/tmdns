/*
 * llist.c - linked list implementation
 *
 * Part of the tmdns package by Andreas Hofmeister. 
 *
 * Copyright 2000 Benjamin Close <benjsc@hotmai.com>
 *
 * This software is licensed under the terms of the GNU General 
 * Public License (GPL). Please see the file COPYING for details.
 * 
 *
*/

#include "config.h"
#include <stdlib.h>
#include "llist.h"
#include "debug.h"

/****************************************
  ll_new - create a new list controller

  @return allocated list controller on success, NULL on memory failure
 ***************************************/ 
list_t  *ll_new(void)
{
   list_t *control;
   if((control=(list_t *)malloc(sizeof(list_t)))==NULL)
   {
      debug("No memory for list control\n");
      return NULL;
   }

   control->pHead=NULL;
   control->pTail=NULL;
   return control;
}

/********************************************************
  ll_add - adds an element to the end of the linked list 
  
  @param  control       The controlling structure as created by ll_new
  @param  datatoinsert  A cache entry to be inserted into the linked list 
  @return 0 on success, -1 on errror
 *******************************************************/		  
int ll_add(list_t *control, void *datatoinsert)
{
   ll_entry_t *element;

   if(control==NULL || datatoinsert==NULL)
   {
      debug("ll_add: Invalid parameter passed in\n");
      return -1;
   }

   /* allocate a new element */
   if((element=(ll_entry_t *)malloc(sizeof(ll_entry_t)))==NULL)
   {
      debug("ll_add: out of memory\n");
      return -1;
   }

   element->data=datatoinsert; /* copy across the struct */
   element->pNext=NULL;
   element->list=control;

   /* first element */
   if(control->pHead==NULL) {
      element->pPrev=NULL;
      control->pHead=element;
      control->pTail=element; 
   }

   /* any but first */
   else {
      element->pPrev=control->pTail;
      element->pPrev->pNext = element;
      control->pTail=element;
   }
   return 0;
}

/*********************************************
ll_delete: deletes the linked list controller and any elements it may contain

@param control The controlling linked list structure as created by ll_new
 *********************************************/ 
void ll_delete(list_t *control)
{
   ll_entry_t *element;

   if(control==NULL){
      debug("ll_delete: NULL parameter passed in\n");
      return;
   }

   /* walk through the list freeing the elements */
   while(control->pHead)
   {
      element=control->pHead;
      control->pHead=control->pHead->pNext;
      free(element);
   }

   free(control);
}

/*************************************************
  ll_first - returns the first element of the list 
  
  @param  control The controlling linked list structure as created by ll_new
  @return A pointer to the first entry in the linked list, or NULL on error
 ************************************************/
ll_entry_t *ll_first(const list_t *control)
{
   if(control==NULL){
      debug("ll_entry_t: NULL parameter passed in\n");
      return NULL;
   }

   return control->pHead;
}

/***********************************************
  ll_next - returns the next element in the list
  
  @param  element A list element to be used to obtain the next element
  @return A pointer to the next element or NULL on error
 **********************************************/
ll_entry_t *ll_next(const ll_entry_t *element)
{
   if(element==NULL){
      debug("ll_entry_t: NULL parameter passed in\n");
      return NULL;
   }
      
   return element->pNext;
}

/***********************************************
  ll_remove - removes a single entry from the ll
  
  @param element A pointer to an element in the linked list to be removed
 ***********************************************/ 
void ll_remove(ll_entry_t *element) 
{
   list_t *control;
   
   if(element==NULL){
      debug("ll_remove: NULL parameter passed in\n");
      return;
   }
   
   control=element->list;
   
   /* last element, alter the tail */
   if(element->pNext==NULL) 
      control->pTail=element->pPrev;
   
       /* somewhere in the middle */
   else 
      element->pNext->pPrev=element->pPrev;

   /* first element, alter the head */
   if(element->pPrev==NULL)
      control->pHead=element->pNext;

       /* somewhere in the middle */
   else
      element->pPrev->pNext=element->pNext;

   free(element); 
}

/****************************************************
  ll_to_front moves an entry to the front of the ll
  
  @param element The element to be moved to the front of the linked list
 ***************************************************/ 
void ll_to_front(ll_entry_t *element)
{
   list_t *control;
   
   if(element==NULL){
      debug("ll_to_front: NULL parameter given\n");
      return;
   }
   
   control=element->list;
   
   /* don't do anything if it's already the first element */
   if(control->pHead==element) 
      return;
   
   /* shift the last element to the front */
   if(control->pTail==element){
      element->pPrev->pNext=NULL;
      control->pTail=element->pPrev;
   }

   /* element is in the middle somewhere */
   else {
      element->pPrev->pNext=element->pNext;
      element->pNext->pPrev=element->pPrev;
   }
      
   element->pPrev=NULL;
   element->pNext=control->pHead;
   element->pNext->pPrev = element;
   control->pHead=element;
}

/* eof */

