' 启动青柠杀毒.vbs
' 双击这个文件运行，不会有任何控制台窗口

Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")

' 获取当前目录
strPath = objFSO.GetParentFolderName(WScript.ScriptFullName)

' 运行Python程序（隐藏窗口）
objShell.Run "python """ & strPath & "\main.py""", 0, False

' 可选：等待一下确保程序启动
WScript.Sleep 1000