#define _CRT_SECURE_NO_WARNINGS
#define HAVE_REMOTE
#include <pcap.h>
#include <Packet32.h>
#include <ntddndis.h>
#include <time.h>
#include <stdio.h>
#include<iostream>
#pragma comment(lib, "Packet")
#pragma comment(lib, "wpcap")
#pragma comment(lib, "WS2_32")

using namespace std;

u_char USER[20];//用户名
u_char PASS[20];//密码

//定义TCP首部
typedef struct tcp_header
{
	u_short sport;//源程序的端口号
	u_short dsport;//目的程序的端口号
	u_int seq;//序列号 SN
	u_int ack_num;//确认号
	u_char ihl; //Internet 头部长度
	u_char frame;
	u_short wsize;//窗口大小
	u_short crc; //check sum
	u_short urg;
}tcp_header;

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
	u_char saddr[4];        // 报文发送方的IPv4地址
	u_char daddr[4];        // 报文接收方的IPv4地址
	u_int	op_pad;			// 选项，选项字段支持各种选项，提供扩展余地
}ip_header;

//以太网的帧格式(Mac地址)
typedef struct mac_header {
	u_char dest_addr[6];
	u_char src_addr[6];
	u_char type[2];
} mac_header;

void output(ip_header * ih, mac_header* mh, const struct pcap_pkthdr *header, char user[], bool is)
{
	//如果用户名为空，就不输出
	if (user[0] == '\0')
		return;

	char timestr[46];
	struct tm *ltime;
	time_t local_tv_sec;

	/*将时间戳转换成可识别的格式 */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", ltime);


	/*
	输出到控制台
	*/
	printf("%s,", timestr);//时间

						   // 从登录后 ftp服务器 给客户机返回的信息提取目标地址（FTP服务器地址）和源地址（客户机地址）
	printf("%02X-%02X-%02X-%02X-%02X-%02X,",
		mh->dest_addr[0],
		mh->dest_addr[1],
		mh->dest_addr[2],
		mh->dest_addr[3],
		mh->dest_addr[4],
		mh->dest_addr[5]);//客户机地址
	printf("%d.%d.%d.%d,",
		ih->daddr[0],
		ih->daddr[1],
		ih->daddr[2],
		ih->daddr[3]);//客户机IP

	printf("%02X-%02X-%02X-%02X-%02X-%02X,",
		mh->src_addr[0],
		mh->src_addr[1],
		mh->src_addr[2],
		mh->src_addr[3],
		mh->src_addr[4],
		mh->src_addr[5]);//FTP服务器MAC
	printf("%d.%d.%d.%d,",
		ih->saddr[0],
		ih->saddr[1],
		ih->saddr[2],
		ih->saddr[3]);//FTP服务器IP
	//输出到文件
	/*
	输出到文件
	*/
	FILE* fp = fopen("log.csv", "a+");
	fprintf(fp, "%s,", timestr);//时间

	fprintf(fp, "%02X-%02X-%02X-%02X-%02X-%02X,",
		mh->dest_addr[0],
		mh->dest_addr[1],
		mh->dest_addr[2],
		mh->dest_addr[3],
		mh->dest_addr[4],
		mh->dest_addr[5]);//客户机地址
	fprintf(fp, "%d.%d.%d.%d,",
		ih->daddr[0],
		ih->daddr[1],
		ih->daddr[2],
		ih->daddr[3]);//客户机IP

	fprintf(fp, "%02X-%02X-%02X-%02X-%02X-%02X,",
		mh->src_addr[0],
		mh->src_addr[1],
		mh->src_addr[2],
		mh->src_addr[3],
		mh->src_addr[4],
		mh->src_addr[5]);//FTP服务器MAC
	fprintf(fp, "%d.%d.%d.%d,",
		ih->saddr[0],
		ih->saddr[1],
		ih->saddr[2],
		ih->saddr[3]);//FTP服务器IP

	fprintf(fp, "%s,%s,", USER, PASS);//账号密码

	if (is) {
		fprintf(fp, "SUCCEED\n");
	}
	else {
		fprintf(fp, "FAILED\n");
	}
	fclose(fp);
}

//回调函数，数据包处理程序，每收到一个数据包时就会被lipcap调用
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	ip_header * ih;
	mac_header* mh;
	u_int i = 0;

	int length = sizeof(mac_header) + sizeof(ip_header);
	mh = (mac_header*)pkt_data;
	ih = (ip_header *)(pkt_data + 14); 

	int name = 0;//记录用户名的首字符在pkt_data的那个位置
	int pass = 0;//记录密码的首字符在pkt_data的那个位置
	int tmp;//记录密码和用户名的位置，之后用于记录是否登陆成功的字符串的位置
	//获取用户名和密码
	for (int i = 0; i<ih->tlen; i++) 
	{
		//用户名的前面会有"USER "这五个字符，在pkt_data里遍历，找到这五个字符后，
		//第六个字符就是密码开始的位置
		if (*(pkt_data + i) == 'U'&&*(pkt_data + i + 1) == 'S'&&*(pkt_data + i + 2) == 'E'&&*(pkt_data + i + 3) == 'R') 
		{
			name = i + 5;
			int j = 0;
			//到回车和换行为止，前面的内容就是我们需要的用户名
			while (!(*(pkt_data + name) == 13 && *(pkt_data + name + 1) == 10))
			{
				USER[j] = *(pkt_data + name);
				j++;
				++name;
			}
			USER[j] = '\0';
			break;

		}


		//与用户名相似，密码的前面会有"PASS "五个字符，找到这五个字符后
		//，第六个字符就是密码开始的位置
		if (*(pkt_data + i) == 'P' && *(pkt_data + i + 1) == 'A' && *(pkt_data + i + 2) == 'S' && *(pkt_data + i + 3) == 'S') 
		{
			pass = i + 5;
			tmp = pass;
			int k = 0;
			//到回车和换行为止，前面的内容就是我们需要的密码
			while (!(*(pkt_data + pass) == 13 && *(pkt_data + pass + 1) == 10)) 
			{
				PASS[k] = *(pkt_data + pass);
				k++;
				++pass;

			}
			PASS[k] = '\0';

			//获取了用户名和密码后，再获取是否成功登陆的信息
			for (;; tmp++) 
			{
				if (*(pkt_data + tmp) == '2'&&*(pkt_data + tmp + 1) == '3'&&*(pkt_data + tmp + 2) == '0') 
				{
					//输出除用户名，密码和登陆状态以外的信息
					output(ih, mh, header, (char *)USER, true);
					//输出用户名
					cout << endl << "用户名为：";
					for (int p = 0;p < 20;p++)
					{
						if (USER[p] != '\0')cout << USER[p];
						else break;
					}
					//输出密码
					cout << endl << "密码为：";
					for (int p = 0;p < 20;p++)
					{
						if (PASS[p] != '\0')cout << PASS[p];
						else break;
					}
					cout << endl << "登陆状态为：SUCCEED" << endl;
					break;
				}
				else if (*(pkt_data + tmp) == '5'&&*(pkt_data + tmp + 1) == '3'&&*(pkt_data + tmp + 2) == '0') 
				{
					//输出除用户名，密码和登陆状态以外的信息
					output(ih, mh, header, (char *)USER, false);
					//输出用户名
					cout << endl << "用户名为：";
					for (int p = 0;p < 20;p++)
					{
						if (USER[p] != '\0')cout << USER[p];
						else break;
					}
					//输出密码
					cout << endl << "密码为：";
					for (int p = 0;p < 20;p++)
					{
						if (PASS[p] != '\0')cout << PASS[p];
						else break;
					}
					cout << endl << "登陆状态为：FAILED" << endl;
					break;
				}
			}
			break;
		}
	}
}

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;


	/*
	过滤的规则，在设置过滤器是过滤掉非FTP包
	*/
	char packet_filter[] = "tcp port ftp";//ftp的端口是21


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



	//编译过滤器，过滤掉非FTP数据包
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//设置过滤器
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	cout << endl << "正在监听" << d->description << "..." << endl;

	//释放网卡列表
	pcap_freealldevs(alldevs);

	//开始抓取信息
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}

