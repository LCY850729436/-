#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include<iostream>
#include "pcap.h"
#include<time.h>
#include <conio.h> 

using namespace std;


//����4�ֽڳ���IP��ַ
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

//����Mac��ַ
struct mac_header
{
	u_char arp_tha[6];//Ŀ��mac��ַ
	u_char arp_sha[6];//������mac��ַ
};

//���廥����Э���4�����ݱ�ͷ����ʽ
typedef struct ip_header
{
	u_char	ver_ihl;		// 4�ֽڵ�IPЭ��汾+4�ֽڵ�IP���ݱ�ͷ��
	u_char	tos;			// ������������ֶ� 
	u_short tlen;			// �ܳ���
	u_short identification; // ����16λ�ı�ʶ
	u_short flags_fo;		/* ����3λ�ı�־����ָ����IP���ݱ������Ƿ��зֶΣ�
							Ҳ��������ֶ�ʱ�ֶα�־��13λ�Ķ�ƫ��
							*/
	u_char	ttl;			// ��������ʱ�䣬��IP���ݱ��������д������Ч��
	u_char	proto;			// ����Э�����ͣ���TCP��UDP�ȣ�
	u_short crc;			// ����16λ��CRCУ���
	ip_address	saddr;		// ���ķ��ͷ���IPv4��ַ
	ip_address	daddr;		// ���Ľ��շ���IPv4��ַ
	u_int	op_pad;			// ѡ�ѡ���ֶ�֧�ָ���ѡ��ṩ��չ���
}ip_header;

//����UDPЭ��ͷ���ṹ
typedef struct udp_header
{
	u_short sport;			// 16λԴ�˿ں�
	u_short dport;			// 16λĿ�Ķ˿ں�
	u_short len;			// 16λUDP����
	u_short crc;			// 16λUDPУ���
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

//���ݰ��������
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

	//��ʱ���ת��Ϊ�ɶ���ʽ
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	//��ȡ��ǰ������
	time_t tt = time(NULL);
	tm* t = localtime(&tt);
	int year = t->tm_year + 1900;
	int month = t->tm_mon + 1;
	int day = t->tm_mday;

	//���ʱ��
	cout << "ʱ�䣺" << year << "-" << month << "-" << day << " " << timestr << endl;
	//���֡����
	cout << "֡���ȣ�" << header->len << endl;
	//����������1024ʱ����������
	if (header->len > 1024)cout << "���棺��������1024��" << endl;

	//���ԴMac��ַ��Ŀ��Mac��ַ
	mac_header* mh;
	mh = (struct mac_header*)(pkt_data);
	u_int8_t* arp_tha = mh->arp_tha;
	u_int8_t* arp_sha = mh->arp_sha;

	int macR[1000][7];  //���ڼ�¼Դmac��Ϣ
	int macS[1000][7];  //���ڼ�¼Ŀ��mac��Ϣ
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
	cout << "ԴMac��ַ -> Ŀ��Mac��ַ��";
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

	//ԴIP��ַ->Ŀ��Mac��ַ
	cout << "ԴIP��ַ -> Ŀ��IP��ַ��";
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
	pcap_if_t *alldevs;//ָ�������豸��ָ��
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];//���󻺳���
	u_int netmask;
	char packet_filter[] = "ip and udp";
	struct bpf_program fcode;


	/* ���pcap_findalldevs����ֵΪ-1����������������豸�������Ѵ�����Ϣ
	���뵽errbuf�����*/
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "������������: %s\n", errbuf);
		exit(1);
	}

	//�����������
	cout << "���������豸���£�" << endl;
	for (d = alldevs; d; d = d->next)
	{
		i++;
		cout << i << ". ��������" << d->name;
		if (d->description)
			cout << "����������" << "(" << d->description << ")" << endl;
		else
			cout << "û�п��õ�����" << endl;
	}

	if (i == 0)
	{
		printf("\nû���ҵ���������ȷ���Ƿ�װ��WinPcap\n");
		return -1;
	}

	cout << endl << "��������Ҫ�������������(1��" << i << ")��";
	cin >> inum;

	//�����������������Ƿ�Խ��
	if (inum < 1 || inum > i)
	{
		cout << "��������Ӧ�ô���0,С��" << i + 1;

		//�ͷŽӿ��б�
		pcap_freealldevs(alldevs);
		return -1;
	}

	//��ת����ѡ���������
	for (d = alldevs, i = 0; i< inum - 1;d = d->next, i++);

	//����ѡ���������
	//pcap_open_live()�������ڻ�ȡ��ץ�����
	//����1��ָ������ӿ��豸��
	//����2��ָ���������׽�ֽ���
	//����3��ָ������ӿڽ������ģʽ
	//����4��ָ�����뼶����ʱ
	//����5������ʧ�ܷ���NULLʱ��ʧ��ԭ��浽���󻺳�����
	if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		//�ͷŽӿ��б�
		pcap_freealldevs(alldevs);
		return -1;
	}

	//������Ӳ㣬ֻ����Ƿ�֧����̫��(Ϊ�˼�)
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		//�ͷŽӿ��б�
		pcap_freealldevs(alldevs);
		return -1;
	}

	//��������
	if (d->addresses != NULL)
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else netmask = 0xffffff;


	//����ɸѡ��
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		//�ͷŽӿ��б�
		pcap_freealldevs(alldevs);
		return -1;
	}

	//����ɸѡ��
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		//�ͷŽӿ��б�
		pcap_freealldevs(alldevs);
		return -1;
	}

	cout << endl << "���ڼ���" << d->description << "..." << endl;

	//�ͷ������б�
	pcap_freealldevs(alldevs);

	//��ʼץȡ��Ϣ
	pcap_loop(adhandle, 0, packet_handler, NULL);

#ifdef From_NIC

/* Open the capture file */
if ((adhandle = pcap_open_offline("C:\\Users\\HP\\Desktop\\�����\\����\\ʵ��\\ʵ��3\\dns.pcap",			// name of the device
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