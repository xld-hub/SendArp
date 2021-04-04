#ifndef  __TCPPACKETHEAD_H__
#define   __TCPPACKETHEAD_H__


// 以太网协议格式的定义
typedef struct ether_header {
	unsigned char ether_dhost[6];		// 目标MAC地址
	unsigned char ether_shost[6];		// 源MAC地址
	unsigned short ether_type;			// 以太网类型
}ether_header;

// 用户保存4字节的IP地址
typedef struct ip_address {
	unsigned char byte1;
	unsigned char byte2;
	unsigned char byte3;
	unsigned char byte4;
}ip_address;

// 用于保存IPV4的首部
typedef struct ip_header {
	unsigned char version_hlen;		// 首部长度 版本
	unsigned char tos;					// 服务质量
	unsigned short tlen;				// 总长度
	unsigned short identification;		// 身份识别
	unsigned short flags_offset;		// 标识 分组偏移
	unsigned char ttl;					// 生命周期
	unsigned char proto;				// 协议类型
	unsigned short checksum;			// 包头测验码
	unsigned int saddr;				// 源IP地址
	unsigned int daddr;				// 目的IP地址
}ip_header;

// 用于保存TCP首部
typedef struct tcp_header {
	unsigned short sport;
	unsigned short dport;
	unsigned int sequence;				// 序列码
	unsigned int ack;					// 回复码
	unsigned char hdrLen;				// 首部长度保留字
	unsigned char flags;				// 标志
	unsigned short windows;			// 窗口大小
	unsigned short checksum;			// 校验和
	unsigned short urgent_pointer;		// 紧急指针
}tcp_header;

// 用于保存UDP的首部
typedef struct udp_header {
	unsigned short sport;				// 源端口
	unsigned short dport;				// 目标端口
	unsigned short datalen;			// UDP数据长度
	unsigned short checksum;			// 校验和
}udp_header;

// 用于保存ICMP的首部
typedef struct icmp_header {
	unsigned char type;				// ICMP类型
	unsigned char code;				// 代码
	unsigned short checksum;			// 校验和
	unsigned short identification;		// 标识
	unsigned short sequence;			// 序列号
	unsigned long timestamp;			// 时间戳
}icmp_header;

// 用于保存ARP的首部
typedef struct arp_header {
	unsigned short hardware_type;					// 格式化的硬件地址
	unsigned short protocol_type;					// 协议地址格式
	unsigned char hardware_length;					// 硬件地址长度
	unsigned char protocol_length;					// 协议地址长度
	unsigned short operation_code;					// 操作码
	unsigned char source_ethernet_address[6];		// 发送者硬件地址
	unsigned char source_ip_address[4];			// 发送者协议地址
	unsigned char destination_ethernet_address[6];	// 目的方硬件地址
	unsigned char destination_ip_address[4];		// 目的方协议地址
}arp_header;


#endif