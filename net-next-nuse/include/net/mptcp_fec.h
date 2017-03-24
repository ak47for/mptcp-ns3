#ifndef MPTCP_FEC_HEADER_
#define MPTCP_FEC_HEADER_

#define FEC_RCV_QUEUE_LIMIT 131072		//128k
#define DEFAULT_MSS_NUM 5	//5*mss
#define MPTCP_FEC_NUM_TYPES 5

#define MPTCP_FEC_DEBUG(FMT, args...) \
	do{ if(1) printk("%-25s():%-5d "FMT"", __FUNCTION__, __LINE__, ##args); }while(0)

struct mptcp_fec_st{
	//u8 type;
	//u8 flags;
	u32 next_seq;
	u16 fec_mss_num;	//do fec skb's number.
	u32 freq;			//frequence.
	u32 mss;	/**/
	u32 bytes_rcv_queue;

	struct sk_buff_head snd_fec_queue;
	struct sk_buff_head rcv_queue;
	struct sk_buff_head fec_queue;
	struct sk_buff_head frag_queue;
};
struct mptcp_fec_data {
	//u8	type;
	//u8	flags;

	u32	enc_seq;	/* Sequence number of first encoded byte */
	u32	enc_len;	/* Encoding length			 */
	u32 max_mss;	/**/
};

extern u32 clear_skb_byseq(struct sock *meta_sk, u32 data_seq);
extern int mptcp_fec_update_queue(struct sock *meta_sk, struct sk_buff *skb);
extern int mptcp_fec_process_queue(struct sock *meta_sk);
extern int mptcp_fec_process(struct sock *sk, struct sk_buff *skb);
extern int mptcp_init_fec(struct mptcp_fec_st *fec, u32 write_seq);
extern struct sk_buff * mptcp_fec_create(struct sock *meta_sk, struct sk_buff_head *list);
extern int mptcp_fec_skb_enqueue(struct sock *sk, struct sk_buff *nskb);
extern int mptcp_try_fec_skb_enqueue(struct sock *sk, struct sk_buff *nskb);
extern void clear_all_fec_queue(struct mptcp_cb *mpcb);
extern struct sk_buff *peek_skb_frm_snd_fec_queue(struct sock *meta_sk, struct mptcp_cb *mpcb);
extern void skb_queue_fec(struct mptcp_cb *mpcb, struct sk_buff *skb, struct sk_buff *new);
extern void free_fec_skb(struct sock *meta_sk, struct sk_buff *skb);

extern void print_data(char *data, u32 len);
extern int check_data_is_ok(char *dec_data, u32 len, struct sk_buff *skb);

static inline bool mptcp_fec_is_enabled(const struct tcp_sock *tp)
{
	return unlikely(tp->mptcp_fec_type > 0);
}

#endif

