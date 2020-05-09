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

u_char USER[20];//�û���
u_char PASS[20];//����

//����TCP�ײ�
typedef struct tcp_header
{
	u_short sport;//Դ����Ķ˿ں�
	u_short dsport;//Ŀ�ĳ���Ķ˿ں�
	u_int seq;//���к� SN
	u_int ack_num;//ȷ�Ϻ�
	u_char ihl; //Internet ͷ������
	u_char frame;
	u_short wsize;//���ڴ�С
	u_short crc; //check sum
	u_short urg;
}tcp_header;

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
	u_char saddr[4];        // ���ķ��ͷ���IPv4��ַ
	u_char daddr[4];        // ���Ľ��շ���IPv4��ַ
	u_int	op_pad;			// ѡ�ѡ���ֶ�֧�ָ���ѡ��ṩ��չ���
}ip_header;

//��̫����֡��ʽ(Mac��ַ)
typedef struct mac_header {
	u_char dest_addr[6];
	u_char src_addr[6];
	u_char type[2];
} mac_header;

void output(ip_header * ih, mac_header* mh, const struct pcap_pkthdr *header, char user[], bool is)
{
	//����û���Ϊ�գ��Ͳ����
	if (user[0] == '\0')
		return;

	char timestr[46];
	struct tm *ltime;
	time_t local_tv_sec;

	/*��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", ltime);


	/*
	���������̨
	*/
	printf("%s,", timestr);//ʱ��

						   // �ӵ�¼�� ftp������ ���ͻ������ص���Ϣ��ȡĿ���ַ��FTP��������ַ����Դ��ַ���ͻ�����ַ��
	printf("%02X-%02X-%02X-%02X-%02X-%02X,",
		mh->dest_addr[0],
		mh->dest_addr[1],
		mh->dest_addr[2],
		mh->dest_addr[3],
		mh->dest_addr[4],
		mh->dest_addr[5]);//�ͻ�����ַ
	printf("%d.%d.%d.%d,",
		ih->daddr[0],
		ih->daddr[1],
		ih->daddr[2],
		ih->daddr[3]);//�ͻ���IP

	printf("%02X-%02X-%02X-%02X-%02X-%02X,",
		mh->src_addr[0],
		mh->src_addr[1],
		mh->src_addr[2],
		mh->src_addr[3],
		mh->src_addr[4],
		mh->src_addr[5]);//FTP������MAC
	printf("%d.%d.%d.%d,",
		ih->saddr[0],
		ih->saddr[1],
		ih->saddr[2],
		ih->saddr[3]);//FTP������IP
	//������ļ�
	/*
	������ļ�
	*/
	FILE* fp = fopen("log.csv", "a+");
	fprintf(fp, "%s,", timestr);//ʱ��

	fprintf(fp, "%02X-%02X-%02X-%02X-%02X-%02X,",
		mh->dest_addr[0],
		mh->dest_addr[1],
		mh->dest_addr[2],
		mh->dest_addr[3],
		mh->dest_addr[4],
		mh->dest_addr[5]);//�ͻ�����ַ
	fprintf(fp, "%d.%d.%d.%d,",
		ih->daddr[0],
		ih->daddr[1],
		ih->daddr[2],
		ih->daddr[3]);//�ͻ���IP

	fprintf(fp, "%02X-%02X-%02X-%02X-%02X-%02X,",
		mh->src_addr[0],
		mh->src_addr[1],
		mh->src_addr[2],
		mh->src_addr[3],
		mh->src_addr[4],
		mh->src_addr[5]);//FTP������MAC
	fprintf(fp, "%d.%d.%d.%d,",
		ih->saddr[0],
		ih->saddr[1],
		ih->saddr[2],
		ih->saddr[3]);//FTP������IP

	fprintf(fp, "%s,%s,", USER, PASS);//�˺�����

	if (is) {
		fprintf(fp, "SUCCEED\n");
	}
	else {
		fprintf(fp, "FAILED\n");
	}
	fclose(fp);
}

//�ص����������ݰ��������ÿ�յ�һ�����ݰ�ʱ�ͻᱻlipcap����
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	ip_header * ih;
	mac_header* mh;
	u_int i = 0;

	int length = sizeof(mac_header) + sizeof(ip_header);
	mh = (mac_header*)pkt_data;
	ih = (ip_header *)(pkt_data + 14); 

	int name = 0;//��¼�û��������ַ���pkt_data���Ǹ�λ��
	int pass = 0;//��¼��������ַ���pkt_data���Ǹ�λ��
	int tmp;//��¼������û�����λ�ã�֮�����ڼ�¼�Ƿ��½�ɹ����ַ�����λ��
	//��ȡ�û���������
	for (int i = 0; i<ih->tlen; i++) 
	{
		//�û�����ǰ�����"USER "������ַ�����pkt_data��������ҵ�������ַ���
		//�������ַ��������뿪ʼ��λ��
		if (*(pkt_data + i) == 'U'&&*(pkt_data + i + 1) == 'S'&&*(pkt_data + i + 2) == 'E'&&*(pkt_data + i + 3) == 'R') 
		{
			name = i + 5;
			int j = 0;
			//���س��ͻ���Ϊֹ��ǰ������ݾ���������Ҫ���û���
			while (!(*(pkt_data + name) == 13 && *(pkt_data + name + 1) == 10))
			{
				USER[j] = *(pkt_data + name);
				j++;
				++name;
			}
			USER[j] = '\0';
			break;

		}


		//���û������ƣ������ǰ�����"PASS "����ַ����ҵ�������ַ���
		//���������ַ��������뿪ʼ��λ��
		if (*(pkt_data + i) == 'P' && *(pkt_data + i + 1) == 'A' && *(pkt_data + i + 2) == 'S' && *(pkt_data + i + 3) == 'S') 
		{
			pass = i + 5;
			tmp = pass;
			int k = 0;
			//���س��ͻ���Ϊֹ��ǰ������ݾ���������Ҫ������
			while (!(*(pkt_data + pass) == 13 && *(pkt_data + pass + 1) == 10)) 
			{
				PASS[k] = *(pkt_data + pass);
				k++;
				++pass;

			}
			PASS[k] = '\0';

			//��ȡ���û�����������ٻ�ȡ�Ƿ�ɹ���½����Ϣ
			for (;; tmp++) 
			{
				if (*(pkt_data + tmp) == '2'&&*(pkt_data + tmp + 1) == '3'&&*(pkt_data + tmp + 2) == '0') 
				{
					//������û���������͵�½״̬�������Ϣ
					output(ih, mh, header, (char *)USER, true);
					//����û���
					cout << endl << "�û���Ϊ��";
					for (int p = 0;p < 20;p++)
					{
						if (USER[p] != '\0')cout << USER[p];
						else break;
					}
					//�������
					cout << endl << "����Ϊ��";
					for (int p = 0;p < 20;p++)
					{
						if (PASS[p] != '\0')cout << PASS[p];
						else break;
					}
					cout << endl << "��½״̬Ϊ��SUCCEED" << endl;
					break;
				}
				else if (*(pkt_data + tmp) == '5'&&*(pkt_data + tmp + 1) == '3'&&*(pkt_data + tmp + 2) == '0') 
				{
					//������û���������͵�½״̬�������Ϣ
					output(ih, mh, header, (char *)USER, false);
					//����û���
					cout << endl << "�û���Ϊ��";
					for (int p = 0;p < 20;p++)
					{
						if (USER[p] != '\0')cout << USER[p];
						else break;
					}
					//�������
					cout << endl << "����Ϊ��";
					for (int p = 0;p < 20;p++)
					{
						if (PASS[p] != '\0')cout << PASS[p];
						else break;
					}
					cout << endl << "��½״̬Ϊ��FAILED" << endl;
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
	���˵Ĺ��������ù������ǹ��˵���FTP��
	*/
	char packet_filter[] = "tcp port ftp";//ftp�Ķ˿���21


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



	//��������������˵���FTP���ݰ�
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//���ù�����
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return -1;
	}

	cout << endl << "���ڼ���" << d->description << "..." << endl;

	//�ͷ������б�
	pcap_freealldevs(alldevs);

	//��ʼץȡ��Ϣ
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}

