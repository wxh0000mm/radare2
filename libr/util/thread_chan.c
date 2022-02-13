/* radare - LGPL - Copyright 2022 - pancake */
#include <r_util.h>
#include <r_list.h>

R_API void r_th_channel_free(RThreadChannel *tc) {
	if (tc) {
		r_list_free (tc->stack);
		r_th_lock_free (tc->lock);
		free (tc);
	}
}

R_API RThreadChannel *r_th_channel_new(void) {
	RThreadChannel *tc = R_NEW0 (RThreadChannel);
	tc->sem = r_th_sem_new (1);
	r_th_sem_wait (tc->sem); // busy because stack is empty
	tc->lock = r_th_lock_new (true);
	tc->stack = r_list_newf ((RListFree)r_th_channel_message_free);
	return tc;
}

R_API RThreadChannelMessage *r_th_channel_message_new(const ut8 *msg, int len) {
	RThreadChannelMessage *m = R_NEW (RThreadChannelMessage);
	if (m) {
		m->msg = r_mem_dup (msg, len);
		m->len = len;
		m->sem = r_th_sem_new (1);
		r_th_sem_wait (m->sem); // busy because stack is empty
		m->lock = r_th_lock_new (false);
	}
	return m;
}

R_API RThreadChannelMessage *r_th_channel_message_read(RThreadChannel *tc, RThreadChannelMessage *cm) {
	if (cm) {
		r_th_sem_wait (cm->sem);
	}
	return cm;
}

R_API RThreadChannelMessage *r_th_channel_write(RThreadChannel *tc, RThreadChannelMessage *cm) {
	if (!tc || !cm) {
		return NULL;
	}
	r_th_lock_enter (cm->lock);
	RThreadChannelMessage *m = r_th_channel_message_new (cm->msg, cm->len);
	if (m) {
eprintf ("msg new %c", 10);
eprintf ("msg lock enter%c", 10);
		r_th_lock_enter (tc->lock);
eprintf ("msg pushenter%c", 10);
		r_list_push (tc->stack, m);
eprintf ("post the sem to unlock (a)%c", 10);
		r_th_sem_post (tc->sem);
eprintf ("doneunlock (a)%c", 10);
		r_th_lock_leave (tc->lock);
eprintf ("dinfu(a)%c", 10);
		r_th_lock_leave (cm->lock);
eprintf ("jejej(a)%c", 10);
		return m;
	}
	r_th_lock_leave (cm->lock);
	return NULL;
}

R_API void r_th_channel_message_free(RThreadChannelMessage *cm) {
	if (cm) {
		r_th_sem_post (cm->sem);
		r_th_sem_free (cm->sem);
		free (cm->msg);
		r_th_lock_free (cm->lock);
		free (cm);
	}
}

R_API RThreadChannelMessage *r_th_channel_read(RThreadChannel *tc) {
eprintf ("a%c", 10);
	r_th_lock_enter (tc->lock);
eprintf ("c%c", 10);
	RThreadChannelMessage *msg = r_list_pop_head (tc->stack);
if (!msg) {
return NULL;
}
eprintf ("d%c", 10);
eprintf ("i%c", 10);
eprintf ("o%c", 10);
	r_th_lock_enter (msg->lock);
eprintf ("semwait%c", 10);
eprintf ("je%c", 10);
	r_th_sem_post (tc->sem);
	r_th_lock_leave (tc->lock);
//	r_th_sem_wait (msg->sem);
eprintf ("p%c", 10);
	return msg;
}
