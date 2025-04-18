using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Diagnostics;

/*
    Создать приложение, следящее за работой пользователя на компьютере.

    Приложение (можно реализовать как комплекс приложений) работает в трех режимах.
    Первый режим позволяет пользователю настроить опции для слежения.
Второй режим приложения незаметно для текущего пользователя выполняет процесс слежения (статистика и модерирование). 
Третий режим позволяет посмотреть отчет о работе программы.
    Во втором режиме приложение может следить за нажатиями клавиш на клавиатуре, за списком запущенных приложений. 
Приложение собирает статистику и производит модерирование. Что конкретно выполнять, определяется пользователем на этапе настройки.
    Если активирована статистика, приложение записывает информацию о всех нажатиях клавиш в файл отчета 
(путь настраивается пользователем через визуальный интерфейс), о всех запускаемых приложениях 
(в файл отчета должна попадать информация о названии запущенного приложения и времени запуска).
    Если активировано модерирование, приложение анализирует клавиши, нажатые пользователем. 
В том случае, если было набрано слово из предопределённого списка (список слов указывается при настройке приложения), 
создаётся специальный файл отчета. При модерировании, если запускается запрещенная программа 
(список программ указывается при настройке приложения), приложение записывает информацию о запуске в файл отчета и закрывает запрещенную программу.
    В режиме отчетности пользователь может просмотреть информацию о клавишах и процессах (выбор пользовательского интерфейса остается за вами). 
 */

namespace UserActivityTracker
{
    public partial class MainWindow : Window
    {
        private AppConfiguration config = new AppConfiguration();
        private Thread keyboardThread;
        private Thread processMonitorThread;
        private bool monitoring;
        private StringBuilder keyBuffer = new StringBuilder();
        private object fileLock = new object();
        private LowLevelKeyboardProc hookCallback;

        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;

        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return : MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("user32.dll")]
        private static extern int GetAsyncKeyState(int vKey);

        [DllImport("user32.dll")]
        private static extern int ToUnicodeEx(uint wVritKey, uint wScanCode, byte[] lpKeyState,
            [Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pwsBuff, int cchBuff, uint wFlags, IntPtr swhkl);

        [DllImport("user32.dll")]
        private static extern IntPtr GetKeyboardLayout(uint idThread);

        [DllImport("user32.dll")]
        private static extern uint MapVirtualKey(uint uCode, uint uMapType);

        private IntPtr hookId = IntPtr.Zero;

        public MainWindow()
        {
            InitializeComponent();
            monitoring = false;
            UpdateMonitoringUi();
        }

        private void ButtonApplySettings_Click(object sender, RoutedEventArgs e)
        {
            config.ReportFilePath = TxtReportPath.Text;
            config.EnableStatistics = ChkStatistics.IsChecked ?? false;
            config.EnableModeration = ChkModeration.IsChecked ?? false;
            config.BannedWords = TxtBannedWords.Text.Split(new[] {','}, StringSplitOptions.RemoveEmptyEntries)
                .Select(x => x.Trim().ToLower())
                .ToList();
            config.BannedApps = TxtBannedApps.Text.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(x => x.Trim().ToLower())
                .ToList();

            MessageBox.Show("Настройки применены успешно!", "Настройки", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void ButtonStartMonitoring_Click(object sender, RoutedEventArgs e)
        {
            monitoring = true;
            UpdateMonitoringUi();

            keyboardThread = new Thread(KeyboardMonitoring);
            keyboardThread.IsBackground = true;
            keyboardThread.Start();

            processMonitorThread = new Thread(ProcessMonitoring);
            processMonitorThread.IsBackground = true;
            processMonitorThread.Start();
        }

        private void ButtonStopMonitoring_Click(object sender, RoutedEventArgs e)
        {
            monitoring = false;
            if (hookId != IntPtr.Zero)
            {
                UnhookWindowsHookEx(hookId);
                hookId = IntPtr.Zero;
            }
            UpdateMonitoringUi();
        }

        private void ButtonRefreshReport_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (File.Exists(config.ReportFilePath))
                {
                    TxtReportContent.Text = File.ReadAllText(config.ReportFilePath);
                }
                else
                {
                    TxtReportContent.Text = "Файл отчета не найден.";
                }
            }
            catch (Exception ex)
            {
                TxtReportContent.Text = $"Ошибка при чтении отчета: {ex.Message}";
            }
        }

        private void UpdateMonitoringUi()
        {
            LblMonitorStatus.Text = monitoring ? "Слежение запущено." : "Слежение не запущено.";
            ButtonStartMonitoring.IsEnabled = !monitoring;
            ButtonStopMonitoring.IsEnabled = monitoring;
        }

        private void KeyboardMonitoring()
        {
            hookCallback = HookCallback;
            hookId = SetHook(hookCallback);
            System.Windows.Forms.Application.Run();
        }

        private IntPtr SetHook(LowLevelKeyboardProc proc)
        {
            using (Process curProcess = Process.GetCurrentProcess())
            using (ProcessModule curModule = curProcess.MainModule)
            {
                return SetWindowsHookEx(WH_KEYBOARD_LL, proc, GetModuleHandle(curModule.ModuleName), 0);
            }
        }

        private IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN)
            {
                int vkCode = Marshal.ReadInt32(lParam);
                bool shift = (GetAsyncKeyState(0x10) & 0x8000) != 0;
                bool capsLock = Console.CapsLock;

                char keyChar = GetCharFromKey(vkCode, shift, capsLock);

                if (keyChar != '\0')
                {
                    if (config.EnableStatistics)
                    {
                        LogToReport($"Нажата клавиша: {keyChar} ({DateTime.Now})");
                    }

                    if (config.EnableModeration)
                    {
                        keyBuffer.Append(keyChar);
                        CheckForBannedWords();
                    }
                }
            }
            return CallNextHookEx(hookId, nCode, wParam, lParam);
        }

        private char GetCharFromKey(int vkCode, bool shift, bool capsLock)
        {
            byte[] keyboardState = new byte[256];
            if (shift)
            {
                keyboardState[0x10] = 0x80;
            }
            if (capsLock)
            {
                keyboardState[0x14] = 0x01;
            }

            IntPtr hkl = GetKeyboardLayout(0);
            uint scanCode = MapVirtualKey((uint)vkCode, 0);
            StringBuilder sb = new StringBuilder(5);
            int rc = ToUnicodeEx((uint)vkCode,scanCode,keyboardState,sb, sb.Capacity, 0, hkl);
            return rc > 0 ? sb[0] : '\0';
        }

        private void CheckForBannedWords()
        {
            string input = keyBuffer.ToString().ToLower();
            foreach (var word in config.BannedWords)
            {
                if (input.Contains(word.ToLower()))
                {
                    LogToReport($"Обнаружено запроещенное слово: {word} ({DateTime.Now})");
                    keyBuffer.Clear();
                    break;
                }
            }
        }

        private void ProcessMonitoring()
        {
            List<string> currentProcesses = new List<string>();
            while (monitoring)
            {
                // Мониторинг всех процессов и в случае нахождения запрещенного процесса попытка его закрыть
                try
                {
                    var processes = Process.GetProcesses()
                        .Select(p => p.ProcessName.ToLower())
                        .Distinct()
                        .ToList();

                    var newProcesses = processes.Except(currentProcesses).ToList();

                    foreach (var process in newProcesses)
                    {
                        if (config.BannedApps.Contains(process))
                        {
                            LogToReport($"Запрещенное приложение запущено: {process} ({DateTime.Now})");
                            KillProcess(process);
                        }
                        else if (config.EnableStatistics)
                        {
                            LogToReport($"Приложение запущено: {process} ({DateTime.Now})");
                        }    
                    }
                    currentProcesses = processes;
                }
                catch (Exception ex)
                {
                    LogToReport($"Ошибка при мониторинке процессов: {ex.Message} ({DateTime.Now})");
                }
                Thread.Sleep(1000);
            }
        }

        private void KillProcess(string processname)
        {
            foreach (var process in Process.GetProcessesByName(processname))
            {
                try
                {
                    process.Kill();
                }
                catch { }
            }
        }

        private void LogToReport(string msg)
        {
            lock (fileLock)
            {
                File.AppendAllText(config.ReportFilePath, msg + Environment.NewLine);
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            monitoring = false;
            if (hookId != IntPtr.Zero)
            {
                UnhookWindowsHookEx(hookId);
            }
            base.OnClosed(e);
        }
    }
}
