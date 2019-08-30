using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace 端口转发
{
    public partial class Form1 : Form
    {
        private string publickey = string.Empty;
        private string privatekey = string.Empty;
        private static Dictionary<string, object> LanguageConfigs { get; set; }
        private static Dictionary<string, string> Languages { get; set; }
        public Form1()
        {
            InitializeComponent();
            try
            {
                LanguageConfigs = JsonConvert.DeserializeObject<Dictionary<string, object>>(File.ReadAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "languages.json")));
                if (!LanguageConfigs.ContainsKey("languages"))
                    throw new Exception("lll");
            }
            catch {
                LanguageConfigs = new Dictionary<string, object>();
                LanguageConfigs.Add("languages", new Dictionary<string, string> { { "cn", "中文" } });
            }
            List<string> lagstrs = new List<string>();
            List<Dictionary<string, string>> Languages1 = JsonConvert.DeserializeObject<List<Dictionary<string, string>>>(JsonConvert.SerializeObject(LanguageConfigs["languages"]));
            foreach (Dictionary<string, string> kvp in Languages1)
            {
                lagstrs.Add(kvp.Values.ToList()[0]);
            }
            comboBox2.Items.AddRange(lagstrs.ToArray());
            CheckLanguage(true);
            Languages = LisDic2Dic(Languages1);
        }
        private void Form1_Load(object sender, EventArgs e)
        {
            //Thread th = new Thread(GetPortToPortList);
            GetPortToPortList();
            listBox1.HorizontalScrollbar = true;
            DeEnCode dec = new DeEnCode();
            dec.RSAKey(out privatekey, out publickey);
            string[] net = GetNetWork();
            foreach (string ip in net)
            {
                comboBox1.Items.Add(ip);
            }
            comboBox1.SelectedIndex = 0;
        }
        private void button1_Click(object sender, EventArgs e)
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
            {
                System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
                startInfo.UseShellExecute = true;
                startInfo.WorkingDirectory = Environment.CurrentDirectory;
                startInfo.FileName = Application.ExecutablePath;
                startInfo.Verb = "runas";
                System.Diagnostics.Process.Start(startInfo);
                Application.Exit();
            }
            else
            {
                MessageBox.Show(Warning.IsAdministrator, "Warning", MessageBoxButtons.OK);
                return;
            }
        }

        private void button5_Click(object sender, EventArgs e)
        {
            string destIP = comboBox1.SelectedItem.ToString();
            string destPort = textBox2.Text;
            string RIP = textBox3.Text;
            string RPort = textBox4.Text;
            Regex r = new Regex("^(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|[1-9])\\." + "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\." + "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\." + "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)$");
            if(!r.IsMatch(destIP) && !destIP.Trim().Equals("0.0.0.0") || !r.IsMatch(RIP))
            {
                MessageBox.Show(Warning.MustInputIPAdd, "Error", MessageBoxButtons.OK);
                return;
            }
            if(!int.TryParse(destPort,out int dport) || !int.TryParse(RPort,out int rp))
            {
                MessageBox.Show(Warning.MustInputNumber, "Error", MessageBoxButtons.OK);
                return;
            }
            if(dport<0 || dport > 65535|| rp <0 || rp>65535)
            {
                MessageBox.Show(Warning.MustInputNumber065535);
                return;
            }
            string scriptText = "netsh interface portproxy add v4tov4 listenaddress=" + destIP + " listenport=" + dport.ToString()
                + " connectaddress=" + RIP + " connectport=" + rp.ToString() + "";
            string report = RunScript(scriptText);
            GetPortToPortList();
        }

        private static string RunScript(string scriptText)
        {
            // create Powershell runspace  
            Runspace runspace = RunspaceFactory.CreateRunspace();
            // open it  
            runspace.Open();
            // create a pipeline and feed it the script text  
            Pipeline pipeline = runspace.CreatePipeline();
            pipeline.Commands.AddScript(scriptText);
            pipeline.Commands.Add("Out-String");

            // execute the script  
            Collection<PSObject> results = pipeline.Invoke();
            // close the runspace  
            runspace.Close();

            // convert the script result into a single string  
            StringBuilder stringBuilder = new StringBuilder();
            foreach (PSObject obj in results)
            {
                stringBuilder.AppendLine(obj.ToString());
            }
            return stringBuilder.ToString();
        }

        public void GetPortToPortList()
        {
            listBox1.Items.Clear();
            string comm = "netsh interface portproxy show v4tov4";
            string report = RunScript(comm);
            if (report != "\r\n\r\n")
            {
                report = report.Replace("\r\n", "|");
                List<string> resportlist = report.Split('|').ToList();
                resportlist.RemoveAll(m => m == "");
                resportlist.RemoveAt(0);
                resportlist.RemoveAt(0);
                resportlist.RemoveAt(0);
                foreach (string a in resportlist)
                {
                    listBox1.Items.Add(a);
                }
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            GetPortToPortList();
        }

        private void button3_Click(object sender, EventArgs e)
        {
            string item = string.Empty;
            try
            {
                item = listBox1.SelectedItem.ToString();
            }
            catch
            {
                MessageBox.Show(Warning.ChooseForNC, "Error", MessageBoxButtons.OK);
                return;
            }
            List<string> itemlist = item.Split(' ').ToList();
            itemlist.RemoveAll(m => m == "");
            string comm = "netsh interface portproxy delete v4tov4 listenaddress=" + itemlist[0] + " listenport=" + itemlist[1];
            RunScript(comm);
            GetPortToPortList();
        }

        private void button4_Click(object sender, EventArgs e)
        {
            if (listBox1.Items == null)
            {
                MessageBox.Show(Warning.NotneedSave, "Warning", MessageBoxButtons.OK);
                return;
            }
            string neirongencode = string.Empty;
            foreach (string bb in listBox1.Items)
            {
                neirongencode = bb + "," + neirongencode;
            }
            neirongencode.Substring(0, neirongencode.Count() - 1);
            string hexkey = publickey;
            DeEnCode dec = new DeEnCode();
            string encodething = dec.EncryptByRSA(neirongencode, hexkey);
            string base64encodeprivate = dec.Base64Code(privatekey);
            encodething = encodething + "&" + base64encodeprivate;
            SaveFileDialog sfd = new SaveFileDialog
            {
                Filter = "|*.txt"
            };
            DialogResult result = sfd.ShowDialog();
            if(result == DialogResult.OK)
            {
                DirectoryInfo di = new DirectoryInfo(Path.GetDirectoryName(sfd.FileName));
                DirectorySecurity ds = new DirectorySecurity(Path.GetDirectoryName(sfd.FileName), AccessControlSections.Access);
                object a = di.GetAccessControl();
                //判断权限
                if(ds.AreAccessRulesProtected)
                {
                    MessageBox.Show(Warning.MayBeError, "Warning", MessageBoxButtons.OKCancel);
                }
                string path = sfd.FileName.ToString();
                FileStream fs = (FileStream)sfd.OpenFile();
                Encoder enc = Encoding.UTF8.GetEncoder();
                char[] charData = encodething.ToCharArray();
                byte[] byData = new byte[charData.Length];
                enc.GetBytes(charData, 0, charData.Length, byData, 0, true);
                fs.Write(byData, 0, byData.Length);
                fs.Flush();
                fs.Close();
                MessageBox.Show("成功","Success",MessageBoxButtons.OK);
            }
        }

        private void button6_Click(object sender, EventArgs e)
        {
            try
            {
                OpenFileDialog ofd = new OpenFileDialog();
                ofd.Filter = "|*.txt";
                DialogResult dr = ofd.ShowDialog();
                if (dr != DialogResult.OK)
                {
                    MessageBox.Show(Warning.Errorfilechoose, "Error", MessageBoxButtons.OK);
                    return;
                }
                FileStream fs = (FileStream)ofd.OpenFile();
                byte[] readfilebyte = new byte[fs.Length];
                fs.Read(readfilebyte, 0, (int)fs.Length);
                fs.Close();
                Decoder dec = Encoding.UTF8.GetDecoder();
                char[] charData = new char[readfilebyte.Length];
                dec.GetChars(readfilebyte, 0, readfilebyte.Length, charData, 0);
                string neirong = new string(charData);
                string[] neirongandprivate = neirong.Split('&');
                if (neirongandprivate.Count() != 2)
                {
                    MessageBox.Show(Warning.Errorinputfile, "Error", MessageBoxButtons.OK);
                    return;
                }
                DeEnCode decode = new DeEnCode();
                string privatedecode = decode.Base64Decode(neirongandprivate[1]);
                neirong = decode.DecryptByRSA(neirongandprivate[0], privatedecode);
                List<string> peizhi = neirong.Split(',').ToList();
                peizhi.RemoveAll(m => m == "");
                int countall = peizhi.Count();
                int countok = 0;
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
                {
                    MessageBox.Show(Warning.MustAdministrator, "Error", MessageBoxButtons.OKCancel);
                    return;
                }
                foreach (string peizhione in peizhi)
                {
                    List<string> getipandport = peizhione.Split(' ').ToList();
                    getipandport.RemoveAll(m => m == "");
                    Regex rg = new Regex("^(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|[1-9])\\." + "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\." + "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\." + "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)$");
                    if (!rg.IsMatch(getipandport[0]) || !rg.IsMatch(getipandport[2]))
                    {
                        continue;
                    }
                    if (!int.TryParse(getipandport[1], out int lport) || !int.TryParse(getipandport[3], out int rport))
                    {
                        continue;
                    }
                    if (lport > 65535 || lport < 0 || rport > 65535 || rport < 0)
                    {
                        continue;
                    }
                    string comm = "netsh interface portproxy add v4tov4 listenaddress=" + getipandport[0] + " listenport=" + getipandport[1]
                    + " connectaddress=" + getipandport[2] + " connectport=" + getipandport[3] + "";
                    RunScript(comm);
                    countok++;
                }
                string mess = string.Empty;
                if (countall == countok)
                {
                    mess = Warning.OtherCannotExp;
                }
                GetPortToPortList();
                //MessageBox.Show("识别到" + countall + "条记录,\r\n" + countok + "条记录以添加," + mess, "Success", MessageBoxButtons.OK);
                MessageBox.Show(string.Format(Warning.AddError, new int[] { countall, countok }) + mess, "Success", MessageBoxButtons.OK);
            }
            catch
            {
                MessageBox.Show(Warning.NotKnowerrorFile, "Error", MessageBoxButtons.OK);
                return;
            }
        }

        public void GetAdministrator()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
            {
                System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
                startInfo.UseShellExecute = true;
                startInfo.WorkingDirectory = Environment.CurrentDirectory;
                startInfo.FileName = Application.ExecutablePath;
                startInfo.Verb = "runas";
                System.Diagnostics.Process.Start(startInfo);
                Application.Exit();
            }
            else
            {
                MessageBox.Show(Warning.IsAdministrator, "Warning", MessageBoxButtons.OK);
                return;
            }
        }

        public string[] GetNetWork()
        {
            List<string> net = new List<string>();
            NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface adapter in nics)
            {
                if (adapter.NetworkInterfaceType == NetworkInterfaceType.Ethernet || adapter.NetworkInterfaceType == NetworkInterfaceType.Wireless80211|| adapter.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                {
                    IPInterfaceProperties ip = adapter.GetIPProperties();
                    UnicastIPAddressInformationCollection ipCollection = ip.UnicastAddresses;
                    foreach (UnicastIPAddressInformation ipadd in ipCollection)
                    {
                        if (ipadd.Address.AddressFamily == AddressFamily.InterNetwork)
                            net.Add(ipadd.Address.ToString());
                    }
                }
            }
            if(ConfigurationManager.AppSettings["needipfor0000"]!= null && ConfigurationManager.AppSettings["needipfor0000"].ToString().Equals("yes") && !net.Contains("0.0.0.0"))
            {
                net.Add("0.0.0.0");
            }
            return net.ToArray();
        }

        private void button7_Click(object sender, EventArgs e)
        {
            string[] nets = GetNetWork();
            comboBox1.Items.Clear();
            foreach (string ne in nets)
            {
                comboBox1.Items.Add(ne);
            }
            comboBox1.SelectedIndex = 0;
        }
        private void CheckLanguage(bool isDef)
        {
            if (isDef)
            {
                string deflang = ConfigurationManager.AppSettings["language"];
                if (LanguageConfigs.ContainsKey(deflang))
                {
                    List<Dictionary<string, string>> languStrs = JsonConvert.DeserializeObject<List<Dictionary<string, string>>>(JsonConvert.SerializeObject(LanguageConfigs[deflang]));
                    OkChangeText(LisDic2Dic(languStrs));
                }
                else
                {
                    MessageBox.Show(ConfigurationManager.AppSettings["noLanguage"], "Error", MessageBoxButtons.OK);
                }
            }
            else
            {
                string lasel = comboBox2.SelectedItem.ToString();
                if (Languages.ContainsValue(lasel))
                {
                    string la = Languages.SingleOrDefault(m => m.Value == lasel).Key;
                    if (LanguageConfigs.ContainsKey(la))
                    {
                        List<Dictionary<string, string>> languStrs = JsonConvert.DeserializeObject<List<Dictionary<string, string>>>(JsonConvert.SerializeObject(LanguageConfigs[la]));
                        OkChangeText(LisDic2Dic(languStrs));
                    }
                    else
                    {
                        MessageBox.Show(ConfigurationManager.AppSettings["noLanguage"], "Error", MessageBoxButtons.OK);
                    }
                }
                else
                {
                    MessageBox.Show(ConfigurationManager.AppSettings["noLanguage"], "Error", MessageBoxButtons.OK);
                }
            }
        }
        private void OkChangeText(Dictionary<string, string> keyValuePairs)
        {
            try
            {
                this.Text = keyValuePairs["Title"];
                button1.Text = keyValuePairs["Identity"];
                label1.Text = keyValuePairs["language"];
                button5.Text = keyValuePairs["Add"];
                button7.Text = keyValuePairs["FlashNet"];
                button2.Text = keyValuePairs["FlashList"];
                button3.Text = keyValuePairs["DelSel"];
                button4.Text = keyValuePairs["OutCon"];
                button6.Text = keyValuePairs["InCon"];
                Warning.Errorfilechoose = keyValuePairs["Errorfilechoose"];
                Warning.Errorinputfile = keyValuePairs["InputErrorfile"];
                Warning.IsAdministrator = keyValuePairs["IsAdministrator"];
                Warning.AddError = keyValuePairs["AddError"];
                Warning.MayBeError = keyValuePairs["MayBeError"];
                Warning.OtherCannotExp = keyValuePairs["OtherCannotExp"];
                Warning.MustAdministrator = keyValuePairs["MustAdministrator"];
                Warning.NotKnowerrorFile = keyValuePairs["NotKnowerrorFile"];
                Warning.MustInputIPAdd = keyValuePairs["MustInputIPAdd"];
                Warning.MustInputNumber = keyValuePairs["MustInputNumber"];
                Warning.MustInputNumber065535 = keyValuePairs["MustInputNumber065535"];
                Warning.NotneedSave = keyValuePairs["NotneedSave"];
                Warning.ChooseForNC = keyValuePairs["ChooseForNC"];
            }
            catch
            {
                MessageBox.Show(ConfigurationManager.AppSettings["noLanguageSet"], "Error", MessageBoxButtons.OK);
            }
        }
        private Dictionary<string, string> LisDic2Dic(List<Dictionary<string, string>> diclist)
        {
            Dictionary<string, string> dic = new Dictionary<string, string>();
            foreach(Dictionary<string,string> d in diclist)
            {
                foreach(var kvp in d)
                {
                    dic.Add(kvp.Key, kvp.Value);
                }
            }
            return dic;
        }

        private void ComboBox2_SelectedIndexChanged(object sender, EventArgs e)
        {
            CheckLanguage(false);
        }
    }
}
