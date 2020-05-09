using System;
using System.IO.Ports;
using System.Threading;

public class Program
{
    static bool Continue;
    static SerialPort Port;


    public static void Main()
    {
        string name;
        string message;
        StringComparer stringComparer = StringComparer.OrdinalIgnoreCase;
        Thread readThread = new Thread(Read);
        Port = new SerialPort();

        //将所有端口属性定义为默认属性
        Port.PortName = "COM2";
        Port.BaudRate = 9600;
        Port.Parity = Parity.None;
        Port.DataBits = 8;
        Port.StopBits = StopBits.One;
        Port.Handshake = Handshake.None;

        //设置超时时间
        Port.ReadTimeout = 500;
        Port.WriteTimeout = 500;

        Port.Open();
        Continue = true;
        readThread.Start();

        //用户自定义昵称
        Console.Write("请输入你的昵称：");
        name = Console.ReadLine();

        Console.WriteLine("手动输入quit退出(小写)");

        while (Continue)
        {
            message = Console.ReadLine();
            if (stringComparer.Equals("quit", message)) Continue = false;
            else
            {
                System.DateTime currentTime = new System.DateTime();
                currentTime = System.DateTime.Now;
                string strTime = currentTime.ToString();
                message = "[SENT " + strTime + "] " + message;//发送信息
                Console.WriteLine(message);//在控制台输出发送的信息
                Port.WriteLine(String.Format("{0}", message));
            }
        }


        readThread.Join();
        Port.Close();
    }
    //接收并输出接收信息
    public static void Read()
    {
        while (Continue)
        {
            try
            {
                string message = Port.ReadLine();
                System.DateTime currentTime = new System.DateTime();
                currentTime = System.DateTime.Now;
                string strTime = currentTime.ToString();
                message = "[REVC " + strTime + "] " + message;//接收串口信息
                Console.WriteLine(message);//在控制台输出接收的信息
            }
            catch (TimeoutException) { }
        }
    }


}