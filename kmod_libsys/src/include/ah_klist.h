#ifndef _AH_KLIST_H__
#define _AH_KLIST_H__

#ifdef __KERNEL__

/**
 * hlist_first_entry - return the first entry in the list
 * @head:   the head for your list.
 *
 */
#define hlist_first_entry(head)     ((head)->first)


static inline void list_add_after (struct list_head *elem, struct list_head *new)
{
	new->next = elem->next;
	new->prev = elem;
	elem->next->prev = new;
	elem->next = new;

}

static inline void list_add_before (struct list_head *elem, struct list_head *new)
{
	new->next = elem;
	new->prev = elem->prev;
	elem->prev->next = new;
	elem->prev = new;
}

/**
 * list_for_each_entry_continue_reverse  -  iterate over list of given type
 *          continuing after existing point in backwward direction
 * @pos:    the type * to use as a loop counter.
 * @head:   the head for your list.
 * @member: the name of the list_struct within the struct.
 */
#define list_for_each_entry_continue_reverse(pos, head, member)         \
	for (pos = list_entry(pos->member.prev, typeof(*pos), member);  \
		 prefetch(pos->member.prev), &pos->member != (head);    \
		 pos = list_entry(pos->member.prev, typeof(*pos), member))


/**
 * hlist_replace - replace one node in teh linked list with another one
 * @old:   old node that's to be replaced
 * @new:   new node that will replace the old
 */
static inline void hlist_replace (struct hlist_node *old, struct hlist_node *new)
{
	hlist_add_before (new, old);
	hlist_del (old);
}


#else
#warning "don't include kernel headers in userspace"
#endif /* __KERNEL__ */

#endif
