#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include<iostream>
#include "pcap.h"
#include<time.h>
#include <conio.h> 

using namespace std;


//定义4字节长的IP地址
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

//定义Mac地址
struct mac_header
{
	u_char arp_tha[6];//目标mac地址
	u_char arp_sha[6];//发送者mac地址
};

//定义互联网协议第4版数据报头部格式
typedef struct ip_header
{
	u_char	ver_ihl;		// 4字节的IP协议版本+4字节的IP数据报头部
	u_char	tos;			// 定义服务类型字段 
	u_short tlen;			// 总长度
	u_short identification; // 定义16位的标识
	u_short flags_fo;		/* 定义3位的标志用以指出该IP数据报后面是否还有分段，
							也就是这个字段时分段标志和13位的段偏移
							*/
	u_char	ttl;			// 定义生存时间，即IP数据报在网络中传输的有效期
	u_char	proto;			// 定义协议类型（如TCP、UDP等）
	u_short crc;			// 定义16位的CRC校验和
	ip_address	saddr;		// 报文发送方的IPv4地址
	ip_address	daddr;		// 报文接收方的IPv4地址
	u_int	op_pad;			// 选项，选项字段支持各种选项，提供扩展余地
}ip_header;

//定义UDP协议头部结构
typedef struct udp_header
{
	u_short sport;			// 16位源端口号
	u_short dport;			// 16位目的端口号
	u_short len;			// 16位UDP长度
	u_short crc;			// 16位UDP校验和
}udp_header;

int Mac_Check(int mac1[7], int mac2[7])
{
	int temp = 1;
	for (int i = 0; i < 6; i++)
	{
		if (mac1[i] != mac2[i]) { temp = 0; break; }
	}
	return temp;
}

//数据包处理程序
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	ip_header *ih;
	udp_header *uh;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;

	/*
	* unused parameter
	*/
	(VOID)(param);

	//将时间戳转换为可读格式
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	//获取当前年月日
	time_t tt = time(NULL);
	tm* t = localtime(&tt);
	int year = t->tm_year + 1900;
	int month = t->tm_mon + 1;
	int day = t->tm_mday;

	//输出时间
	cout << "时间：" << year << "-" << month << "-" << day << " " << timestr << endl;
	//输出帧长度
	cout << "帧长度：" << header->len << endl;
	//当流量超过1024时，发出警告
	if (header->len > 1024)cout << "警告：流量超过1024。" << endl;

	//输出源Mac地址和目标Mac地址
	mac_header* mh;
	mh = (struct mac_header*)(pkt_data);
	u_int8_t* arp_tha = mh->arp_tha;
	u_int8_t* arp_sha = mh->arp_sha;

	int macR[1000][7];  //用于记录源mac信息
	int macS[1000][7];  //用于记录目标mac信息
	int macSSum = 0;
	int macRSum = 0;

	int mactempR[7];
	int mactempS[7];
	for (int i = 0; i < 6; i++)
	{
		mactempR[i] = arp_tha[i];
		mactempS[i] = arp_sha[i];
	}
	mactempR[6] = header->len;
	mactempS[6] = header->len;
	int mr = 0; int ms = 0;
	for (int i = 0; i < macSSum; i++)
	{
		if (Mac_Check(mactempS, macS[i])) { macS[i][6] = macS[i][6] + mactempS[6]; ms = 1; break; }
	}
	for (int i = 0; i < macRSum; i++)
	{
		if (Mac_Check(mactempR, macR[i])) { macR[i][6] = macR[i][6] + mactempR[6]; mr = 1; break; }
	}
	if (!ms) {
		for (int i = 0; i < 7; i++)
			macS[macSSum][i] = mactempS[i];
		macSSum++;
	}
	if (!mr) {
		for (int i = 0; i < 7; i++)
			macR[macRSum][i] = mactempR[i];
		macRSum++;
	}
	cout << "源Mac地址 -> 目标Mac地址：";
	printf("%02x-%02x-%02x-%02x-%02x-%02x -> %02x-%02x-%02x-%02x-%02x-%02x",
		*arp_sha, *(arp_sha + 1), *(arp_sha + 2), *(arp_sha + 3), *(arp_sha + 4), *(arp_sha + 5),
		*arp_tha, *(arp_tha + 1), *(arp_tha + 2), *(arp_tha + 3), *(arp_tha + 4), *(arp_tha + 5));
	cout << endl;

	/* retireve the position of the ip header */
	ih = (ip_header *)(pkt_data +
		14); //length of ethernet header

			 /* retireve the position of the udp header */
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header *)((u_char*)ih + ip_len);

	/* convert from network byte order to host byte order */
	sport = ntohs(uh->sport);
	dport = ntohs(uh->dport);

	//源IP地址->目标Mac地址
	cout << "源IP地址 -> 目标IP地址：";
	printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		sport,
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4,
		dport);
	cout << endl;

}

#define FROM_NIC
int main()
{
	pcap_if_t *alldevs;//指向网络设备的指针
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];//错误缓冲区
	u_int netmask;
	char packet_filter[] = "ip and udp";
	struct bpf_program fcode;


	/* 如果pcap_findalldevs返回值为-1，则表明查找网络设备出错，并把错误信息
	输入到errbuf里输出*/
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "查找网卡出错: %s\n", errbuf);
		exit(1);
	}

	//输出所有网卡
	cout << "所有网络设备如下：" << endl;
	for (d = alldevs; d; d = d->next)
	{
		i++;
		cout << i << ". 网卡名：" << d->name;
		if (d->description)
			cout << "网卡描述：" << "(" << d->description << ")" << endl;
		else
			cout << "没有可用的描述" << endl;
	}

	if (i == 0)
	{
		printf("\n没有找到网卡，请确认是否安装了WinPcap\n");
		return -1;
	}

	cout << endl << "请输入你要监听的网卡序号(1—" << i << ")：";
	cin >> inum;

	//检验输入的网卡序号是否越界
	if (inum < 1 || inum > i)
	{
		cout << "输入的序号应该大于0,小于" << i + 1;

		//释放接口列表
		pcap_freealldevs(alldevs);
		return -1;
	}

	//跳转到所选择的适配器
	for (d = alldevs, i = 0; i< inum - 1;d = d->next, i++);

	//打开所选择的适配器
	//pcap_open_live()函数用于获取包抓捕句柄
	//参数1：指定网络接口设备名
	//参数2：指定单包最大捕捉字节数
	//参数3：指定网络接口进入混杂模式
	//参数4：指定毫秒级读超时
	//参数5：调用失败返回NULL时将失败原因存到错误缓冲区中
	if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		//释放接口列表
		pcap_freealldevs(alldevs);
		return -1;
	}

	//检查链接层，只检查是否支持以太网(为了简化)
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		//释放接口列表
		pcap_freealldevs(alldevs);
		return -1;
	}

	//设置掩码
	if (d->addresses != NULL)
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else netmask = 0xffffff;


	//编译筛选器
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		//释放接口列表
		pcap_freealldevs(alldevs);
		return -1;
	}

	//设置筛选器
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		//释放接口列表
		pcap_freealldevs(alldevs);
		return -1;
	}

	cout << endl << "正在监听" << d->description << "..." << endl;

	//释放网卡列表
	pcap_freealldevs(alldevs);

	//开始抓取信息
	pcap_loop(adhandle, 0, packet_handler, NULL);

#ifdef From_NIC

/* Open the capture file */
if ((adhandle = pcap_open_offline("C:\\Users\\HP\\Desktop\\大二下\\计网\\实验\\实验3\\dns.pcap",			// name of the device
	errbuf					// error buffer
)) == NULL)
{
	fprintf(stderr, "\nUnable to open the file %s.\n");
	return -1;
}

/* read and dispatch packets until EOF is reached */
pcap_loop(adhandle, 0, packet_handler, NULL);

pcap_close(adhandle);
#endif

	return 0;
}