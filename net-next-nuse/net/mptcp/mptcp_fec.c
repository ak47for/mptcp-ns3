#include <net/tcp.h>
#include <net/mptcp_fec.h>
#include <net/mptcp.h>

static void print_list_seq(struct sk_buff_head *queue);
static int check_exist_in_queue(struct tcp_sock *tp, struct sk_buff_head *queue, u32 seq );
static void check_exist_fec_skb(struct sk_buff_head *queue);
int check_data_is_ok(char *dec_data, u32 len, struct sk_buff *skb);
static void mptcp_free_fec_skb(struct mptcp_fec_st *fec, struct sk_buff *skb);
void print_data(char *data, u32 len);


int get_fec_st_byptr(struct sk_buff *skb, struct sock *sk, struct mptcp_fec_data *fec_data)
{
	struct mptcp_cb *mpcb = NULL;
	u32 *ptr;

	if(sk)
		mpcb = tcp_sk(sk)->mpcb;

	/*
	*	获取序列号存放在data_seq
	*	ptr指向dss
	*/
	ptr = mptcp_skb_set_data_seq(skb, &fec_data->enc_seq, mpcb);
	ptr++;

	fec_data->max_mss = get_unaligned_be32(ptr) ;
	ptr++;
	fec_data->enc_len = get_unaligned_be16(ptr);
	return 0;
}

struct meta_seq_st{
	u32 seq;
	u32 sub_seq;
	u16 len;
};

int get_meta_seq_byptr(struct sk_buff *skb, struct sock *sk, struct meta_seq_st *meta_seq){
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_cb *mpcb = tp->mpcb;
	u32 *ptr;
	/*
	*	获取序列号存放在data_seq
	*	ptr指向dss
	*/
	ptr = mptcp_skb_set_data_seq(skb, &meta_seq->seq, mpcb);
	ptr++;

	meta_seq->sub_seq = get_unaligned_be32(ptr) + tp->mptcp->rcv_isn;;
	ptr++;
	meta_seq->len = get_unaligned_be16(ptr);
	return 0;
}

static unsigned int tcp_fec_get_next_block(struct sock *sk,
				struct sk_buff **skb,
				struct sk_buff_head *queue, u32 seq,
				unsigned int block_len, unsigned char *block, struct sk_buff **first_skb, int *num)
{
	unsigned int cur_len, offset, num_bytes;
	int err;
	u32 end_seq;

	cur_len = 0;

	if (*skb == NULL) {
		*skb = skb_peek(queue);
		if (*skb == NULL)
			return 0;
	}

	/* move to SKB which stores the next sequence to encode */
	while (*skb) {
		if(!mptcp_fec_is_encoded(*skb)){//!(TCP_SKB_CB(*skb)->fec) ||
			/* If we observe an RST/SYN, we stop here to avoid
			 * handling corner cases
			 */
			if (TCP_SKB_CB(*skb)->tcp_flags &(TCPHDR_RST|TCPHDR_SYN))
				return 0;

			if (!before(seq, TCP_SKB_CB(*skb)->seq) &&
						before(seq, TCP_SKB_CB(*skb)->end_seq))
				break;
		}
		if (*skb == skb_peek_tail(queue)) {
			*skb = NULL;
			break;
		}

		*skb = skb_queue_next(queue, *skb);
	}

	if (*skb == NULL)
		return 0;

	/* copy bytes from SKBs (connected sequences) */
	while (*skb && (cur_len < block_len)) {
		if(!mptcp_fec_is_encoded(*skb)){ //!(TCP_SKB_CB(*skb)->fec) || !(TCP_SKB_CB(*skb)->fec->flags & MPTCP_FEC_ENCODED)
			err = skb_linearize(*skb);
			if (err){
				MPTCP_FEC_DEBUG("linearize is failed err=%d \n", err);
				return err;
			}

			end_seq = TCP_SKB_CB(*skb)->end_seq;
			if (TCP_SKB_CB(*skb)->tcp_flags & TCPHDR_FIN)/*对于FIN包的处理*/
				end_seq--;

			if ((seq >= TCP_SKB_CB(*skb)->seq) && (seq < end_seq)) {
				offset = seq - TCP_SKB_CB(*skb)->seq;/*找到偏移*/
				num_bytes = min(block_len - cur_len, end_seq - seq);
				memcpy(block + cur_len, (*skb)->data + offset,
				       num_bytes);

				cur_len += num_bytes;
				seq += num_bytes;

				if(first_skb != NULL && *first_skb == NULL)
					*first_skb = *skb;

				*num= *num - 1;
				if(*num <= 0)
					break;
			}
		}

		if (*skb == skb_peek_tail(queue) || cur_len >= block_len)
			break;

		*skb = skb_queue_next(queue, *skb);
	}

	return cur_len;
}

/* Allocates an SKB for data we want to send and assigns
 * the necessary options and fields
 */
static struct sk_buff *tcp_fec_make_encoded_pkt(struct sock *sk,
				struct mptcp_fec_data *fec,
				unsigned char *enc_data,
				unsigned int len)
{
	struct sk_buff *skb;
	unsigned char *data;
	unsigned int data_len = 0;

	/* See tcp_make_synack(); 15 probably for tail pointer etc.? */
	/*
	*	只是拷贝做xor的数据，最长不超过block_len
	*	有可能编码长度小于enc_len ?
	*/
	data_len = min(len, fec->enc_len);
	skb = alloc_skb(MAX_TCP_HEADER + 15 + data_len, GFP_ATOMIC);
	if (skb == NULL)
		return NULL;



	/* Reserve space for headers */
	skb_reserve(skb, MAX_TCP_HEADER);

	/* Specify sequence number and FEC struct address in control buffer */
	//fec->flags |= MPTCP_FEC_ENCODED;
	TCP_SKB_CB(skb)->mptcp_flags |= MPTCPHDR_FEC;
	TCP_SKB_CB(skb)->seq = fec->enc_seq;	/*tcp控制块上的seq更新为enc_seq*/
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(skb)->seq+data_len;
	TCP_SKB_CB(skb)->fec = fec;

	/* Enable ACK flag (required for all data packets) */
	TCP_SKB_CB(skb)->tcp_flags = TCPHDR_ACK;

	/* Set GSO parameters */
	skb_shinfo(skb)->gso_segs = 1;
	skb_shinfo(skb)->gso_size = 0;
	skb_shinfo(skb)->gso_type = 0;

	/* Append payload to SKB */
	data = skb_put(skb, data_len);
	memcpy(data, enc_data, data_len);

	skb->ip_summed = CHECKSUM_PARTIAL;

	return skb;
}

int fec_skb_queue_policy(
		struct sock *meta_sk,
		struct sk_buff_head *list,
		struct sk_buff *fec_skb,
		struct sk_buff *start_skb,
		struct sk_buff *end_skb )
{
	//struct sk_buff *tmp;
	/*
	*	目前考虑加入到receive队列，但是   队列是有序的
	*/
	//__skb_queue_after(list, skb, fec_skb);
	if(before(TCP_SKB_CB(fec_skb)->seq, TCP_SKB_CB(start_skb)->seq) ||
		after(TCP_SKB_CB(fec_skb)->seq, TCP_SKB_CB(start_skb)->end_seq))
	{
		MPTCP_FEC_DEBUG("Error !!\n");
		return -1;
	}

	MPTCP_FEC_DEBUG("insert skb-seq=%u \n", TCP_SKB_CB(fec_skb)->seq);
	//__skb_queue_after(list, start_skb, fec_skb);

	if(meta_sk)
		tcp_insert_write_queue_before(fec_skb, meta_sk->sk_send_head, meta_sk);
	else
		skb_queue_head(list, fec_skb);
	return 0;
}

/* Creates FEC packet(s) using XOR encoding
 * (allocates memory for the FEC structs)
 * @first_seq - Sequence number of first byte to be encoded
 * @block_len - Block length (typically MSS)
 * @block_skip - Number of unencoded blocks between two encoded blocks
 * @max_encoded_per_pkt - maximum number of blocks encoded per packet
 *	(0, if unlimited)
 */
static struct sk_buff * tcp_fec_create_xor(struct sock *meta_sk, struct sk_buff_head *list,
				unsigned int block_len,
				unsigned int block_skip,
				unsigned int max_encoded_per_pkt)
{
	struct tcp_sock *tp;
	struct mptcp_cb *mpcb;
	struct sk_buff *skb, *fskb = NULL, *first_skb;
	struct mptcp_fec_data *fec;
	int c_encoded;
	unsigned int next_seq;
	unsigned int i;
	unsigned char *data, *block;
	u16 data_len, offset = 0;
	u32 max_len = 0;


	tp = tcp_sk(meta_sk);
	mpcb = tp->mpcb;
	skb = NULL;

	data = kmalloc(2 * block_len, GFP_ATOMIC);
	if (data == NULL)
		return NULL;

	fec = kmalloc(sizeof(*fec), GFP_ATOMIC);
	if (fec == NULL) {
		kfree(data);
		return NULL;
	}

	memset(data, 0, 2 * block_len);
	memset(fec, 0, sizeof(*fec));
	block = data + block_len;

	fec->enc_seq = mpcb->fec.next_seq;
	next_seq = mpcb->fec.next_seq;
	fec->max_mss = block_len;

	c_encoded = mpcb->fec.fec_mss_num;
	max_len = c_encoded * block_len;
	first_skb = NULL;
	skb = NULL;

	// tcp_sk(meta_sk)->write_seq
	// tcp->snd_nxt
	while ((data_len = tcp_fec_get_next_block(meta_sk, &skb,
				list, next_seq,
				min(block_len, tcp_sk(meta_sk)->write_seq - next_seq),
				block, &first_skb, &c_encoded)))
	{
		if(data_len <= 0)
			break;

		next_seq += data_len;
		fec->enc_len = next_seq - fec->enc_seq;

		for (i = 0; i < data_len; i++)
			data[i] ^= block[i];

		if(TCP_SKB_CB(skb)->end_seq != next_seq){
			continue;
		}

		if(c_encoded <= 0 || fec->enc_len >= max_len)
			break;
	}

	/* create final packet if some data was selected for encoding */
	if (c_encoded <= 0 || fec->enc_len >= max_len) {
		//MPTCP_FEC_DEBUG("Now create a packet... c_encoded=%d enc_seq=%u len=%d \n", c_encoded, fec->enc_seq, next_seq-fec->enc_seq);
		fskb = tcp_fec_make_encoded_pkt(meta_sk, fec, data, block_len);
		if (fskb == NULL) {
			kfree(data);
			kfree(fec);
			MPTCP_FEC_DEBUG("create failed.!!! \n");
			return NULL;
		}
		mpcb->fec.next_seq = next_seq;
	} else {
		data_len = tcp_sk(meta_sk)->write_seq - mpcb->fec.next_seq;
		MPTCP_FEC_DEBUG("c_encoded=%u len=%u(%u) data_len=%u %u    write_seq-fec_seq=%u\n",
			c_encoded,
			fec->enc_len, //data_len
			max_len,
			data_len,	//7140
			data_len/block_len,
			tcp_sk(meta_sk)->write_seq - fec->enc_seq);
		kfree(fec);
	}
	kfree(data);

	return fskb;
}

unsigned int mptcp_get_max_mss(struct sock *meta_sk){
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);  //mptcp_meta_specific

	struct mptcp_cb *mpcb = meta_tp->mpcb;
	struct sock *subsk = NULL;
	unsigned int max=0, cmss;

	mptcp_for_each_sk(mpcb, subsk) {
		cmss = tcp_current_mss(subsk);
		if(cmss > max)
			max = cmss;
	}

	return max;
}

/* Creates one or more FEC packets (can depend on the FEC type used)
 * and puts them in a queue
 * @list: queue head
 */
struct sk_buff * mptcp_fec_create(struct sock *meta_sk, struct sk_buff_head *list)
{
	struct tcp_sock *tp;
	struct mptcp_cb *mpcb;
	unsigned int block_len;
	unsigned int len = 0;
//	int err;

	tp = tcp_sk(meta_sk);
	mpcb = tp->mpcb;

	/* Update the pointer to the first byte to be encoded next
	 * (this only matters when a packet was ACKed before it was
	 * encoded)
	 */
	if (after(tp->snd_una, mpcb->fec.next_seq))
		mpcb->fec.next_seq = tp->snd_una;

	block_len = mptcp_get_max_mss(meta_sk);
	if(block_len <= 0){
		MPTCP_FEC_DEBUG("get mss failed.\n");
		return NULL;
	}
	mpcb->fec.mss = block_len;

	len = tcp_sk(meta_sk)->write_seq - mpcb->fec.next_seq;
	if(block_len >0 && (len/block_len < mpcb->fec.fec_mss_num)){
		return NULL;
	}

	return tcp_fec_create_xor(meta_sk, list,
				block_len,
				0,
				FEC_RCV_QUEUE_LIMIT);
}

/* Since data in the socket's receive queue can get consumed by other parties
 * we need to clone these SKBs until they are no longer required for possible
 * future recoveries. This function is called after the TCP header has been
 * removed from the SKB already. All parameters required for recovery are
 * stored in the SKB's control buffer.
 * @skb - buffer which is moved to the receive queue
 */
int mptcp_fec_update_queue(struct sock *meta_sk, struct sk_buff *skb)
{
	struct tcp_sock *meta_tp;
	struct sk_buff *cskb;
	u32 data_len;
	int extra_bytes, err;
	struct mptcp_fec_st *fec;
	meta_tp = tcp_sk(meta_sk);

	if(!meta_tp->mpcb)
		return 0;

	fec = &meta_tp->mpcb->fec;
	//fec = &tp->mptcp->fec;

	/* clone the SKB and add it to the FEC receive queue
	 * (a simple extra reference to the SKB is not sufficient since
	 * since SKBs can only be queued on one list at a time)
	 */
	cskb = skb_clone(skb, GFP_ATOMIC);
	if (cskb == NULL)
		return -ENOMEM;

	/* linearize the SKB (for easier payload access) */
	err = skb_linearize(cskb);
	if (err)
		return err;

	data_len = skb->len;
	if (!data_len) {
		kfree_skb(cskb);
		return 0;
	}

	skb_queue_tail(&fec->rcv_queue, cskb);
	fec->bytes_rcv_queue += data_len;

	/* check if we can dereference old SKBs (as long as we have enough
	 * data for future recoveries)
	 */
	extra_bytes = fec->bytes_rcv_queue - FEC_RCV_QUEUE_LIMIT;
	while (extra_bytes > 0) {
		cskb = skb_peek(&fec->rcv_queue);
		if (cskb == NULL)
			return -EINVAL;

		data_len = TCP_SKB_CB(cskb)->end_seq - TCP_SKB_CB(cskb)->seq;
		if (data_len > extra_bytes) {
			break;
		} else {
			extra_bytes -= data_len;
			fec->bytes_rcv_queue -= data_len;
			skb_unlink(cskb, &fec->rcv_queue);
			kfree_skb(cskb);
		}
	}

	return 0;
}

static inline int do_merge(struct sock *sk,
	struct sk_buff *to,
	u32 to_len,
	struct sk_buff *from,
	u32 from_len,
	struct mptcp_fec_data *to_mfd,
	struct mptcp_fec_data *from_mfd,
	int is_linked)
{
	bool fragstolen = false;
	int delta;
	int len = 0;
	//struct tcp_skb_cb *ttcb, *ftcb;

	TCP_SKB_CB(from)->seq = TCP_SKB_CB(to)->end_seq;
	TCP_SKB_CB(from)->end_seq = TCP_SKB_CB(from)->seq + from_len;

	if (!skb_cloned(to)){
		len = from->len - tcp_hdrlen(from);
		if ( len <= skb_tailroom(to)) {
			if (len)
				BUG_ON(skb_copy_bits(from, tcp_hdrlen(from), skb_put(to, len), len));

			TCP_SKB_CB(to)->end_seq = TCP_SKB_CB(from)->end_seq;
			TCP_SKB_CB(to)->ack_seq = TCP_SKB_CB(from)->ack_seq;
			TCP_SKB_CB(to)->tcp_flags |= TCP_SKB_CB(from)->tcp_flags;

			kfree_skb(from);
			if(to_mfd->max_mss > TCP_SKB_CB(to)->end_seq - TCP_SKB_CB(to)->seq){
#if 0
				MPTCP_FEC_DEBUG("coalesce: fst-seq=%u len=%u \n",
					to_mfd->enc_seq,
					TCP_SKB_CB(to)->end_seq - TCP_SKB_CB(to)->seq);
#endif
				return 1;
			}

			MPTCP_FEC_DEBUG("coalesce OK : fst-seq=%u len=%u \n",
				to_mfd->enc_seq,
				TCP_SKB_CB(to)->end_seq - TCP_SKB_CB(to)->seq);

			if(to_mfd->enc_seq == 3242403231){
				print_data(to->data+tcp_hdrlen(to), TCP_SKB_CB(to)->end_seq -  TCP_SKB_CB(to)->seq);
			}

			mptcp_fec_skb_enqueue(sk, to);
			mptcp_fec_process(sk, to);
			return 0;
		}
	}
	MPTCP_FEC_DEBUG("coalesce failed fst-seq=%u sec-seq=%u !\n",
		to_mfd->enc_seq,
		from_mfd->enc_seq);
	//if(is_linked)
	//	skb_unlink(to, queue);
	kfree_skb(to);
	kfree_skb(from);

	return -1;
}

int try_to_merge_and_enqueue(struct sock *sk, struct sk_buff_head *queue, struct sk_buff *nskb){
	struct tcp_sock *tp = tcp_sk(sk);
	struct sock *meta_sk = tp->meta_sk;
	struct sk_buff *skb, *tmp;
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct mptcp_fec_st *fec = &(mpcb->fec);
	unsigned long flags;
	struct mptcp_fec_data nskb_mfd, skb_mfd;
	bool fragstolen;
	unsigned int skb_len, nskb_len;
	int ret = 0;

	if( skb_queue_empty(queue) ){
		skb_queue_tail(queue, nskb);
		return 0;
	}

	get_fec_st_byptr(nskb, sk, &nskb_mfd);
	nskb_len = TCP_SKB_CB(nskb)->end_seq - TCP_SKB_CB(nskb)->seq;

	skb_queue_walk_safe(queue, skb, tmp) {
		get_fec_st_byptr(skb, sk, &skb_mfd);
		skb_len = TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq;

		if(nskb_mfd.enc_seq == skb_mfd.enc_seq){
			MPTCP_FEC_DEBUG("Same meta-sequence:%u tcp-seq=%u,%u  skb_len=%u nskb_len=%u !!\n",
				nskb_mfd.enc_seq,
				TCP_SKB_CB(nskb)->seq,
				TCP_SKB_CB(skb)->seq,
				skb_len,
				nskb_len);
			return -1;
		}

		if(nskb_mfd.enc_seq > skb_mfd.enc_seq){//>
			if (nskb_mfd.enc_seq == (skb_mfd.enc_seq+skb_len)){
				skb_unlink(skb, queue);
				if(do_merge(sk, skb, skb_len, nskb, nskb_len, &skb_mfd, &nskb_mfd, 1) <=0)
					return 0;

				/*
				*	condition  >0
				*	try to merge others after it.
				*/
				nskb = skb;
				nskb_len = TCP_SKB_CB(nskb)->end_seq - TCP_SKB_CB(nskb)->seq;

				continue;
			}
		}else{///<
			if ( (nskb_mfd.enc_seq+ nskb_len) == skb_mfd.enc_seq){
				skb_unlink(skb, queue);
				if(do_merge(sk, nskb, nskb_len, skb, skb_len, &nskb_mfd, &skb_mfd, 0) <= 0)
					return 0;
				return try_to_merge_and_enqueue(sk, queue, nskb);
			}
			break;
		}
	}

	spin_lock_irqsave(&queue->lock, flags);
	if(nskb_mfd.enc_seq < skb_mfd.enc_seq )
		__skb_queue_before(queue, skb, nskb);
	else
		__skb_queue_after(queue, skb, nskb);
	spin_unlock_irqrestore(&queue->lock, flags);

	return 0;
}


int mptcp_try_fec_skb_enqueue(struct sock *sk, struct sk_buff *skb){
	struct mptcp_fec_data mfd;
	struct sk_buff *nskb;
	struct sock *meta_sk = tcp_sk(sk)->meta_sk;
	int ret = 0;

	u32 len = (TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq);

	get_fec_st_byptr(skb, sk, &mfd);
	if(mfd.enc_seq+mfd.enc_len < tcp_sk(meta_sk)->rcv_nxt)
		return 0;

	if(tcp_sk(meta_sk)->mpcb->fec.fec_queue.qlen > 5)
		clear_skb_byseq(tcp_sk(sk)->meta_sk, tcp_sk(meta_sk)->rcv_nxt);
	if(mfd.max_mss == len){
		nskb = skb_clone(skb, GFP_ATOMIC);
		if(nskb){
			if((ret = mptcp_fec_skb_enqueue(sk, nskb)) < 0)
				kfree_skb(nskb);
			else
				mptcp_fec_process(sk, nskb);
		}
	}else{
			if(mfd.max_mss > len){
				nskb = skb_copy_expand(skb, 0, (mfd.max_mss - len), GFP_ATOMIC);
				if(nskb){
					if(skb_linearize(nskb) != 0)
						MPTCP_FEC_DEBUG("linearize failed. \n");
					//skb_orphan(nskb);
					try_to_merge_and_enqueue(sk, &(tcp_sk(meta_sk)->mpcb->fec.frag_queue), nskb);
					return 0;
				}
			}else{
				MPTCP_FEC_DEBUG("Error nskb seq=%u len:%u > max_mss(%u) !!! \n", mfd.enc_seq, len, mfd.max_mss);
			}
	}

	return 0;
}

int mptcp_fec_skb_enqueue(struct sock *sk, struct sk_buff *nskb){
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;//, *tmp;
	struct mptcp_cb *mpcb = tcp_sk(tp->meta_sk)->mpcb;
	struct mptcp_fec_st *fec = &(mpcb->fec);
	unsigned long flags;
	struct mptcp_fec_data mfd1, mfd2;

	if( skb_queue_empty(&fec->fec_queue) ){
		skb_queue_tail(&fec->fec_queue, nskb);
		return 0;
	}

	get_fec_st_byptr(nskb, sk, &mfd1);
	skb_queue_walk(&fec->fec_queue, skb) {
		get_fec_st_byptr(skb, sk, &mfd2);
		if(mfd1.enc_seq == mfd2.enc_seq){
			MPTCP_FEC_DEBUG("Same sequence tcp-seq=%u  %u seq=%u seq2=%u !!\n", TCP_SKB_CB(nskb)->seq, TCP_SKB_CB(skb)->seq,
				mfd1.enc_seq, mfd2.enc_seq);
			return -1;
		}
		if(mfd1.enc_seq < mfd2.enc_seq )
			break;
	}

	spin_lock_irqsave(&fec->fec_queue.lock, flags);
	if(mfd1.enc_seq < mfd2.enc_seq )
		__skb_queue_before(&fec->fec_queue, skb, nskb);
	else
		__skb_queue_after(&fec->fec_queue, skb, nskb);
	spin_unlock_irqrestore(&fec->fec_queue.lock, flags);

	return 0;
}

static void clear_rcv_queue_by_scope(struct mptcp_fec_st *fec, u32 start, u32 end){
	struct sk_buff *skb, *next;
	unsigned long flags;

	spin_lock_irqsave(&fec->rcv_queue.lock, flags);
	skb_queue_walk_safe(&fec->rcv_queue, skb, next) {
		if(!after(start, TCP_SKB_CB(skb)->seq) && !after(TCP_SKB_CB(skb)->end_seq, end)){
			fec->bytes_rcv_queue -= skb->len;
			__skb_unlink(skb, &fec->rcv_queue);
			kfree_skb(skb);
		}else if(before(end, TCP_SKB_CB(skb)->seq)){
			break;
		}
	}
	spin_unlock_irqrestore(&fec->rcv_queue.lock, flags);
}

u32 clear_skb_byseq(struct sock *meta_sk, u32 data_seq){

	struct sk_buff *skb, *next;
	struct tcp_sock *meta_tp = tcp_sk(meta_sk);
	struct mptcp_fec_st *fec;
	u32 data_len;
	struct mptcp_fec_data fec_data;
	u32 max_end_seq = 0;
	unsigned long flags;

	if(!meta_tp->mpcb)
		return 0 ;
	fec = &(meta_tp->mpcb->fec);

	//MPTCP_FEC_DEBUG("fec-qlen=%u rcv_queue.len=%u frag-qlen=%u .\n", fec->fec_queue.qlen, fec->rcv_queue.qlen, fec->frag_queue.qlen);
	if(!skb_queue_empty(&fec->frag_queue)){
		spin_lock_irqsave(&fec->frag_queue.lock, flags);
		skb_queue_walk_safe(&fec->frag_queue, skb, next){
			get_fec_st_byptr(skb, NULL, &fec_data);
			if(!after(fec_data.enc_seq+fec_data.enc_len, data_seq)){//<=
				max_end_seq = fec_data.enc_seq+fec_data.enc_len;
				__skb_unlink(skb, &fec->frag_queue);
				kfree_skb(skb);
			}else{
				break;
			}
		}
		spin_unlock_irqrestore(&fec->frag_queue.lock, flags);
	}

	if(!skb_queue_empty(&fec->fec_queue)){
		spin_lock_irqsave(&fec->fec_queue.lock, flags);
		skb_queue_walk_safe(&fec->fec_queue, skb, next){
			get_fec_st_byptr(skb, NULL, &fec_data);
			if(!after(fec_data.enc_seq+fec_data.enc_len, data_seq)){//<=
				if(max_end_seq < fec_data.enc_seq+fec_data.enc_len)
					max_end_seq = fec_data.enc_seq+fec_data.enc_len;
				__skb_unlink(skb, &fec->fec_queue);
				kfree_skb(skb);
			}else{
				break;
			}
		}
		spin_unlock_irqrestore(&fec->fec_queue.lock, flags);
	}

	if(max_end_seq == 0){
		if(skb_queue_empty(&fec->fec_queue))
			return max_end_seq;
		skb = skb_peek(&fec->fec_queue);
		get_fec_st_byptr(skb, NULL, &fec_data);
		if(fec_data.enc_seq < data_seq)
			max_end_seq = fec_data.enc_seq;
		else
			return max_end_seq;
	}

	spin_lock_irqsave(&fec->rcv_queue.lock, flags);
	skb_queue_walk_safe(&fec->rcv_queue, skb, next) {
		if(!after(TCP_SKB_CB(skb)->end_seq, max_end_seq)){
			data_len = TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq;
			fec->bytes_rcv_queue -= data_len;
			__skb_unlink(skb, &fec->rcv_queue);
			kfree_skb(skb);
		}else{
			break;
		}
	}
	spin_unlock_irqrestore(&fec->rcv_queue.lock, flags);

	return max_end_seq;
}

void clear_all_fec_queue(struct mptcp_cb *mpcb){
	struct sk_buff *skb, *next;

	MPTCP_FEC_DEBUG("fec_queue len=%u \n", mpcb->fec.fec_queue.qlen);
	skb_queue_walk_safe(&mpcb->fec.fec_queue, skb, next){
		skb_unlink(skb, &mpcb->fec.fec_queue);
		kfree_skb(skb);
	}

	MPTCP_FEC_DEBUG("rcv_queue len=%u \n", mpcb->fec.rcv_queue.qlen);
	skb_queue_walk_safe(&mpcb->fec.rcv_queue, skb, next){
		skb_unlink(skb, &mpcb->fec.rcv_queue);
		kfree_skb(skb);
	}

	MPTCP_FEC_DEBUG("frag_queue len=%u \n", mpcb->fec.frag_queue.qlen);
	skb_queue_walk_safe(&mpcb->fec.frag_queue, skb, next){
		skb_unlink(skb, &mpcb->fec.frag_queue);
		kfree_skb(skb);
	}
}

bool fec_skb_try_coalesce(struct sock *sk, struct sk_buff *to, struct sk_buff *from,
		      bool *fragstolen){
	int delta;

	*fragstolen = false;

	if (!skb_try_coalesce(to, from, fragstolen, &delta))
		return false;

	atomic_add(delta, &sk->sk_rmem_alloc);
	sk_mem_charge(sk, delta);
	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPRCVCOALESCE);
	TCP_SKB_CB(to)->end_seq = TCP_SKB_CB(from)->end_seq;
	TCP_SKB_CB(to)->ack_seq = TCP_SKB_CB(from)->ack_seq;
	TCP_SKB_CB(to)->tcp_flags |= TCP_SKB_CB(from)->tcp_flags;
	return true;
}

unsigned char *tcp_fec_update_decoded_option(struct sk_buff *skb)
{
	struct tcphdr *th;
	unsigned char *ptr;
	int length;

	th = tcp_hdr(skb);
	ptr = (unsigned char *) (th + 1);
	length = (th->doff * 4) - sizeof(struct tcphdr);

	while (length > 0) {
		int opcode = *ptr++;
		int opsize;

		switch (opcode) {
		case TCPOPT_EOL:
			return NULL;
		case TCPOPT_NOP:
			length--;
			continue;
		default:
			opsize = *ptr++;
			if (opsize < 2 || opsize > length)
				return NULL;

			MPTCP_FEC_DEBUG(" opcode=%d  ------>>> \n", opcode);
			if (opcode == TCPOPT_MPTCP)
				return (ptr-2);


			ptr += opsize - 2;
			length -= opsize;
		}
	}

	return NULL;
}


static struct sk_buff *mptcp_fec_make_decoded_pkt(struct sock *sk,
				const struct sk_buff *skb,
				unsigned char *dec_data,
				u32 seq, unsigned int len)
{
	struct tcp_sock *tp;
	struct sk_buff *nskb;
	struct mp_dss *dss;
	unsigned char *ptr;
	char *old_data_ptr;
	struct tcphdr *th;

	tp = tcp_sk(sk);
	nskb = skb_copy(skb, GFP_ATOMIC);
	if (nskb == NULL){
		MPTCP_FEC_DEBUG("ERROR - skb_copy\n");
		return NULL;
	}

	if (tcp_is_sack(tp)) {
		int i;
		for (i = 0; i < tp->rx_opt.num_sacks; i++) {
			if (before(tp->selective_acks[i].start_seq,
				   seq + len) &&
				   !before(tp->selective_acks[i].end_seq,
				   seq + len)) {
				len = tp->selective_acks[i].start_seq - seq;
				break;
			}
		}
	}

	/* trim data section to fit recovered sequence if necessary */
	if (len < (TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq))
		skb_trim(nskb, len + tcp_hdrlen(nskb));

	/* fix the sequence numbers */
	th = tcp_hdr(skb);
	th->seq = htonl(seq);
	th->ack_seq = htonl(tp->snd_una);
	TCP_SKB_CB(nskb)->seq = seq;
	TCP_SKB_CB(nskb)->end_seq = seq + len;
	TCP_SKB_CB(nskb)->fec = NULL;
	TCP_SKB_CB(nskb)->mptcp_flags = MPTCPHDR_REC_OK;

	tcp_hdr(skb)->doff = sizeof(struct tcphdr)/4;
	*(((__be16 *)th) + 6)	= htons(((sizeof(struct tcphdr) >> 2) << 12) |
					TCP_SKB_CB(nskb)->tcp_flags); //

	/* replace SKB payload with recovered data */
	memcpy(nskb->data + tcp_hdrlen(nskb), dec_data, len);

	/* packets used for recovery had their checksums checked already */
	nskb->ip_summed = CHECKSUM_UNNECESSARY;

	////
	if(check_data_is_ok(dec_data, len, nskb)){
		MPTCP_FEC_DEBUG("FEC-RANGE(%u ~ %u) \n", TCP_SKB_CB(skb)->fec->enc_seq, TCP_SKB_CB(skb)->fec->enc_seq+TCP_SKB_CB(skb)->fec->enc_len);
	}

	return nskb;
}


/*
*	<0 :    error happened .
*	0  :	OK
*	>0 : 	recovery ok
*/
static int mptcp_fec_recover(struct sock *sk, const struct sk_buff *skb,
		unsigned char *data, u32 seq, int len)
{
	struct sk_buff *rskb;
	struct tcp_sock *meta_tp;
	struct sock *meta_sk = tcp_sk(sk)->meta_sk;

	meta_tp = tcp_sk(meta_sk);
	/* Check if we received some tail of the recovered sequence already
	 * by looking at the current SACK blocks (we don't want to recover
	 * more data than necessary to prevent DSACKS)
	 */
	if (tcp_is_sack(meta_tp)) {
		int i;
		for (i = 0; i < meta_tp->rx_opt.num_sacks; i++) {
			if (before(meta_tp->selective_acks[i].start_seq,
				   seq + len) &&
			   !before(meta_tp->selective_acks[i].end_seq,
				   seq + len)) {
				len = meta_tp->selective_acks[i].start_seq - seq;
				break;
			}
		}
	}

	/* We might have prematurely asked for a recovery in the case where the
	 * whole recovery sequence is already covered by SACKs
	 */
	if (len <= 0)
		return 0;

	/* Create decoded packet and forward to reception routine */
	rskb = mptcp_fec_make_decoded_pkt(meta_sk, skb, data, seq, len);
	if (rskb == NULL)
		return -EINVAL;

	if(TCP_SKB_CB(rskb)->seq == meta_tp->rcv_nxt){
		bool fragstolen;
		int eaten = -1;

		MPTCP_FEC_DEBUG("ENTER->REV %p %u qlen=%u \n", rskb, TCP_SKB_CB(rskb)->seq, tcp_sk(meta_sk)->mpcb->fec.fec_queue.qlen);
		eaten = tcp_queue_rcv(meta_sk, rskb, 0, &fragstolen);
		meta_tp->rcv_nxt = TCP_SKB_CB(rskb)->end_seq;
		if (!skb_queue_empty(&meta_tp->out_of_order_queue)) {
			/*	如果packet并非顺序到达,
			*	那么它将通过tcp_ofo_queue()
			*	把packet压入乱序队列(out of order queue).
			*/
			mptcp_ofo_queue(meta_sk);
		}
		if (eaten > 0)
			kfree_skb_partial(rskb, fragstolen);
		meta_sk->sk_data_ready(meta_sk);
	}else{
		//print_list_seq(&meta_tp->out_of_order_queue);
		mptcp_add_meta_ofo_queue(meta_sk, rskb, sk);
		MPTCP_FEC_DEBUG("ENTER->OFO %p %u   enc(%u ~ %u)\n",
			rskb,
			TCP_SKB_CB(rskb)->seq,
			TCP_SKB_CB(skb)->fec->enc_seq,
			TCP_SKB_CB(skb)->fec->enc_seq + TCP_SKB_CB(skb)->fec->enc_len);
		//print_list_seq(&meta_tp->out_of_order_queue);
	}

	return 1;
}


/*
*	<0 :    error happened .
*	0  :	OK
*	>0 : 	recovery ok
*/
static int mptcp_fec_process_xor(struct sock *sk,
			struct sk_buff *skb,
			unsigned int block_skip)
{
	struct sk_buff *pskb;
	//struct tcp_sock *tp;
	struct tcp_sock *meta_tp;
//	struct tcphdr *th;
	u32 next_seq, end_seq, rec_seq;
	unsigned char *data, *block;
	unsigned int i, offset, data_len, block_len, rec_len;
	bool seen_loss;
	int ret;
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
	struct sk_buff_head *start_queue;
	int coded = INT_MAX;

	pskb = NULL;
	//tp = tcp_sk(sk);
	meta_tp = tcp_sk(tcp_sk(sk)->meta_sk);

	next_seq = tcb->fec->enc_seq;
	end_seq = tcb->fec->enc_seq + tcb->fec->enc_len;
	block_len = tcb->fec->max_mss;

	if(block_len != (TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq)){
		MPTCP_FEC_DEBUG("max_mss=%u seq=%u len=%u \n",
			block_len,
			next_seq,
			TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq);
		return -1;
	}

	if(!after(meta_tp->rcv_nxt, next_seq))
		start_queue = &meta_tp->out_of_order_queue;
	else
		start_queue = &meta_tp->mpcb->fec.rcv_queue;

	seen_loss = false;
	offset = 0;

	data = kmalloc(2 * block_len, GFP_ATOMIC);
	if (data == NULL)
		return -ENOMEM;

	block = data + block_len;
	memcpy(data, skb->data + tcp_hdrlen(skb), block_len);

	while ((data_len = tcp_fec_get_next_block(sk, &pskb,
				start_queue, next_seq,
				min(block_len, end_seq - next_seq),
				block, NULL, &coded)))
	{
#if 0
		if(tcb->fec->enc_seq == 3240711943){
			MPTCP_FEC_DEBUG("(%u ~%u )next_seq:%u end_seq=%u data_len=%u offset=%u pskb=%p \n",
				tcb->fec->enc_seq,
				tcb->fec->enc_seq + tcb->fec->enc_len,
				next_seq,
				end_seq,
				data_len,
				offset,
				pskb);
			if(pskb){
				MPTCP_FEC_DEBUG("PSKB seq:%u \n", TCP_SKB_CB(pskb)->seq);
				print_data(pskb->data, data_len);
			}
		}
#endif
		next_seq += data_len;

		/* XOR with existing payload */
		for (i = 0; i < data_len; i++)
			data[i] ^= block[i];

		/* we could no read a whole MSS block, which means we
		 * reached the end of the queue or end of range which the
		 * FEC packet covers
		 */
		if (data_len < block_len)
			break;

		/* skip unencoded blocks if there is more data encoded */
		if (end_seq - next_seq > 0)
			next_seq += block_len * block_skip;
	}

	/* check if all encoded bytes were already received */
	if (next_seq == end_seq) {
		kfree(data);
		MPTCP_FEC_DEBUG("ALL Data is received! %p %u\n", skb, tcb->fec->enc_seq);
		//MPTCP_FLAG_SET(skb, MPTCPHDR_REC_OK);
		mptcp_free_fec_skb(&meta_tp->mpcb->fec, skb);
		return 1;
	}

	/*需要恢复的部分*/
	rec_seq = next_seq;
	rec_len = min(block_len, end_seq - rec_seq);
	offset  = data_len;
	/*
	*	如果正好剩一块需要恢复的数据
	*	则 跳转到 recover进行恢复
	*/
	if ((rec_seq + rec_len) == end_seq)
		goto recover;

	/*
	*	考虑当block_skip==0的情况
	*	跳过1个block_len, 下面查找out_of_order_queue队列，继续找后面的skb
	*	跳过1个block_len的意思是，上面顺序的查找完，说明下一个就是丢失的skb
	*	所以，下面要进行out_of_order_queue继续查找后面没有丢失的skb
	*	如果最后只是一块丢失，就能恢复。
	*/
	next_seq += block_len * (block_skip + 1);

	if(start_queue != &meta_tp->out_of_order_queue)
		pskb = NULL;

	/* read a possibly partial (smaller than MSS) block to fill up the
	 * previously unfilled block and achieve alignment again
	 */
	data_len = tcp_fec_get_next_block(sk, &pskb, &meta_tp->out_of_order_queue,
				next_seq, block_len - offset, block, NULL, &coded);

	next_seq += data_len;

	/* check if we could not read as much data as requested */
	if ((next_seq != end_seq) && (data_len < (block_len - offset)))
		goto clean;

	/* XOR with existing payload */
	for (i = 0; i < data_len; i++)
		data[i+offset] ^= block[i];

	/* skip unencoded blocks if there is more data encoded */
	if (end_seq - next_seq > 0)
		next_seq += block_len * block_skip;

	/* read all necessary blocks to finish decoding */
	while ((data_len = tcp_fec_get_next_block(sk, &pskb,
				&meta_tp->out_of_order_queue, next_seq,
				min(block_len, end_seq - next_seq),
				block, NULL, &coded))) {

		next_seq += data_len;

		/* XOR with existing payload */
		for (i = 0; i < data_len; i++)
			data[i] ^= block[i];

		/* we could not read a whole MSS block, which means we reached
		 * the end of the queue or end of range which the FEC packet
		 * covers
		 */
		if (data_len < block_len)
			break;

		/* skip unencoded blocks if there is more data encoded */
		if (end_seq - next_seq > 0)
			next_seq += block_len * block_skip;
	}
	/*
	* 暂时不能恢复，需要缓存该skb
	*/
	if (next_seq != end_seq){

		goto clean;
	}

recover:
	/* create and process recovered packets */
	for (i = 0; i < rec_len; i++)
		block[i] = data[(offset + i) % block_len];

	/* for debug .*/
	//check_exist_fec_skb(&meta_tp->out_of_order_queue);
	//check_exist_fec_skb(&meta_tp->mpcb->fec.rcv_queue);
	ret = mptcp_fec_recover(sk, skb, block, rec_seq, rec_len);
	if(ret > 0)
		mptcp_free_fec_skb(&meta_tp->mpcb->fec, skb);


	kfree(data);
	return ret;
clean:
    kfree(data);
    return 0;
}

static void mptcp_free_fec_skb(struct mptcp_fec_st *fec, struct sk_buff *skb){
	clear_rcv_queue_by_scope(fec, TCP_SKB_CB(skb)->fec->enc_seq, TCP_SKB_CB(skb)->fec->enc_len);
	skb_unlink(skb, &fec->fec_queue);
	kfree(skb);
}

/*
*	>0 : recover successful
*	0  : do nothing.
*	<0 : failure, jrop it.
*/
int mptcp_fec_process(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp;
	struct tcp_sock *meta_tp;
	struct sock *meta_sk;

	int recovery_status;//, err;
	u32 end_seq;
	struct mptcp_fec_data fec_data;
	//int ret = 0;
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
	//struct mptcp_fec_st *fec = &(mptcp_meta_sk(sk)->mptcp->fec);

	tp = tcp_sk(sk);
	meta_sk = mptcp_meta_sk(sk);
	meta_tp = tcp_sk(meta_sk);
	recovery_status = 0;

	if(mptcp_recover_is_ok(skb)){
		MPTCP_FEC_DEBUG("RECOVERD SKB :%u is HERE !! \n", TCP_SKB_CB(skb)->seq);
		return 0;
	}

	if(!mptcp_fec_is_encoded(skb)){
		MPTCP_FEC_DEBUG("ERROR \n");
		return -1;
	}

	get_fec_st_byptr(skb, sk, &fec_data);
	TCP_SKB_CB(skb)->fec = &fec_data;
	end_seq = fec_data.enc_seq + fec_data.enc_len;

	if (!after(end_seq, meta_tp->rcv_nxt)){
		//MPTCP_FEC_DEBUG("seq:%u have been received \n", end_seq);
		mptcp_free_fec_skb(&tcp_sk(meta_sk)->mpcb->fec, skb);
		return 1;
	}

	if(after(fec_data.enc_seq, meta_tp->rcv_nxt))
		return 0;


	if(skb_linearize(skb))
	{
		MPTCP_FEC_DEBUG("ERROR \n");
		return -1;
	}

	return mptcp_fec_process_xor(sk, skb, 0);
}


int mptcp_fec_process_queue(struct sock *sk){
	struct sk_buff *skb, *next;
	struct sock *meta_sk = tcp_sk(sk)->meta_sk;
	struct mptcp_fec_st *fec = &(tcp_sk(meta_sk)->mpcb->fec);

	if(!fec)
		return 0;

	//MPTCP_FEC_DEBUG("fec_queue qlen=%d \n", fec->fec_queue.qlen);
	if(!skb_queue_empty(&fec->fec_queue)){
		skb_queue_walk_safe(&fec->fec_queue, skb, next){
			mptcp_fec_process(sk, skb);
		}
		//clear_skb_byseq(meta_sk, tcp_sk(meta_sk)->rcv_nxt);
	}
	//MPTCP_FEC_DEBUG("fec_queue qlen=%d \n", fec->fec_queue.qlen);
	return 0;
}

int mptcp_init_fec(struct mptcp_fec_st *fec, u32 write_seq){
	if(!fec)
		return 0;

	MPTCP_FEC_DEBUG("--->>>>FEC INIT !!\n");
	memset(fec, 0, sizeof(*fec));
	fec->fec_mss_num = DEFAULT_MSS_NUM;

	skb_queue_head_init(&fec->fec_queue);
	skb_queue_head_init(&fec->rcv_queue);
	skb_queue_head_init(&fec->frag_queue);
	skb_queue_head_init(&fec->snd_fec_queue);
	fec->next_seq = write_seq;
	return 0;
}

void free_fec_skb(struct sock *meta_sk, struct sk_buff *skb){

	skb_unlink(skb, &(tcp_sk(meta_sk)->mpcb->fec.snd_fec_queue));
	if(TCP_SKB_CB(skb)->fec)
		kfree(TCP_SKB_CB(skb)->fec);

	TCP_SKB_CB(skb)->fec = NULL;
	kfree_skb(skb);
}

void skb_queue_fec(struct mptcp_cb *mpcb, struct sk_buff *skb, struct sk_buff *new){
	unsigned long flags;

	spin_lock_irqsave(&mpcb->fec.snd_fec_queue.lock, flags);
	if(skb)
		__skb_queue_after(&mpcb->fec.snd_fec_queue, skb, new);
	else
		__skb_queue_tail(&mpcb->fec.snd_fec_queue, new);
	spin_unlock_irqrestore(&mpcb->fec.snd_fec_queue.lock, flags);
}

struct sk_buff *peek_skb_frm_snd_fec_queue(struct sock *meta_sk, struct mptcp_cb *mpcb){
	struct sk_buff *skb = NULL;

	if(!skb_queue_empty(&mpcb->fec.snd_fec_queue)){
		skb = skb_peek(&mpcb->fec.snd_fec_queue);
		if(TCP_SKB_CB(skb)->seq < tcp_sk(meta_sk)->snd_nxt){
			if((TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq) != TCP_SKB_CB(skb)->fec->max_mss ){
				MPTCP_FEC_DEBUG(" seq:%u W:%u %u    \n", TCP_SKB_CB(skb)->seq, (TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq), TCP_SKB_CB(skb)->fec->max_mss);
				return skb;
			}

			if(mpcb->fec.freq++%(mpcb->fec.fec_mss_num*2) == 0){
				MPTCP_FEC_DEBUG(" seq:%u W:%u %u    \n", TCP_SKB_CB(skb)->seq, (TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq), TCP_SKB_CB(skb)->fec->max_mss);
				return skb;
			}
		}else if((TCP_SKB_CB(skb)->fec->enc_seq +
				TCP_SKB_CB(skb)->fec->enc_len) <= tcp_sk(meta_sk)->snd_una){
			MPTCP_FEC_DEBUG("we should free this skb->seq=%u  snd_una=%u \n", TCP_SKB_CB(skb)->seq, tcp_sk(meta_sk)->snd_una);
			free_fec_skb(meta_sk, skb);
		}
	}
	return NULL;
}

static void print_list_seq(struct sk_buff_head *queue){
	struct sk_buff *skb = NULL;

	skb = skb_peek(queue);
	MPTCP_FEC_DEBUG("-------------OFO INFO --------------\n");
		/* move to SKB which stores the next sequence to encode */
	while (skb) {

		if(mptcp_recover_is_ok(skb))
			printk("##");
		MPTCP_FEC_DEBUG("OFO %p:%u \n", skb, TCP_SKB_CB(skb)->seq);

		if(skb == skb_peek_tail(queue))
			break;
		/* 继续找下一个	*/
		skb = skb_queue_next(queue, skb);

	}
	MPTCP_FEC_DEBUG("-------------OFO END --------------\n");
}

static int check_exist_in_queue(struct tcp_sock *tp, struct sk_buff_head *queue, u32 seq ){
	struct sk_buff *skb = NULL;

	skb = skb_peek(queue);
	/* move to SKB which stores the next sequence to encode */
	while (skb) {
		if(TCP_SKB_CB(skb)->seq == seq){
			MPTCP_FEC_DEBUG("^^^^^^^FIND IT !!! %p:%u  rcv_nxt=%u \n", skb, TCP_SKB_CB(skb)->seq, tp->rcv_nxt);
			return 1;
		}

		if(skb == skb_peek_tail(queue))
			break;
		/* 继续找下一个	*/
		skb = skb_queue_next(queue, skb);
	}
	return 0;
}

static void check_exist_fec_skb(struct sk_buff_head *queue){

	struct sk_buff *skb = NULL;

	skb = skb_peek(queue);

	while (skb) {
		if(mptcp_fec_is_encoded(skb))
			MPTCP_FEC_DEBUG("*****OFO-FIND ENC-SKB !!! %p:%u \n", skb, TCP_SKB_CB(skb)->seq);


		if(skb == skb_peek_tail(queue))
			break;
		/* 继续找下一个	*/
		skb = skb_queue_next(queue, skb);
	}
}


int check_data_is_ok(char *dec_data, u32 len, struct sk_buff *skb){
	int i = 0;

	for(i=0; i<len; i++){
		if(dec_data[i] != 'A'){
			if(skb)
				MPTCP_FEC_DEBUG("*******************FATAL-ERROR   REC is not good. %p %u index=%d\n", skb, TCP_SKB_CB(skb)->seq, i);
			break;
		}
	}

#if 0
	if(i<len){
		print_data(dec_data, len);
		return 1;
	}
#endif

	return 0;
}

void print_data(char *data, u32 len){
	int i = 0;
	for(i=0; i<len; i++){
		printk("%x", data[i]);
	}
	printk("\n");
}


