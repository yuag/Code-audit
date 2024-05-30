# -*- coding: utf-8 -*-

from PyQt5 import QtCore, QtWidgets
import openai
import re
import os
import sys
import multiprocessing  
import yaml
from concurrent.futures import ThreadPoolExecutor
import glob



class Ui_MainWindow(object):
    def __init__(self):
        self.rules = []
        self.API_KEY = os.getenv('KEY')  # 从环境变量中读取 API 密钥
        self.MODEL = "gpt-3.5-turbo"  # 更新模型名称
        self.API_ENDPOINT = "https://api.openai.com/v1/chat/completions"
    
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1077, 793)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.adadas = QtWidgets.QTabWidget(self.centralwidget)
        self.adadas.setGeometry(QtCore.QRect(0, 0, 1081, 761))
        self.adadas.setObjectName("adadas")
        
        self.setupGPTCodeAuditTab()
        self.setupGlobalKeywordSearchTab()
        self.setupDangerousFunctionSearchTab()
        self.setupAutomatedCodeAuditTab()


        MainWindow.setCentralWidget(self.centralwidget)
        self.retranslateUi(MainWindow)
        self.adadas.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    


    def load_config(self):
        try:
            with open('config.yaml', 'r') as file:
                import yaml
                return yaml.safe_load(file)
        except Exception as e:
            logging.error(f"Failed to load config file: {e}")
            return {}






    def setupGPTCodeAuditTab(self):
        self.tab_15 = QtWidgets.QWidget()
        self.label_70 = QtWidgets.QLabel(self.tab_15)
        self.label_70.setGeometry(QtCore.QRect(20, 30, 51, 20))
        self.label_70.setObjectName("label_70")
        self.lineEdit_windows_ip = QtWidgets.QLineEdit(self.tab_15)
        self.lineEdit_windows_ip.setGeometry(QtCore.QRect(80, 30, 261, 20))
        self.lineEdit_windows_ip.setObjectName("lineEdit_windows_ip")
        self.label_71 = QtWidgets.QLabel(self.tab_15)
        self.label_71.setGeometry(QtCore.QRect(360, 30, 111, 21))
        self.label_71.setObjectName("label_71")
        self.lineEdit_windows_port = QtWidgets.QLineEdit(self.tab_15)
        self.lineEdit_windows_port.setGeometry(QtCore.QRect(470, 30, 141, 20))
        self.lineEdit_windows_port.setObjectName("lineEdit_windows_port")
        self.plainTextEdit_windows_result = QtWidgets.QPlainTextEdit(self.tab_15)
        self.plainTextEdit_windows_result.setGeometry(QtCore.QRect(10, 100, 1051, 671))
        self.plainTextEdit_windows_result.setReadOnly(True)
        self.plainTextEdit_windows_result.setPlainText("")
        self.plainTextEdit_windows_result.setObjectName("plainTextEdit_windows_result")
        self.pushButton_windows_exe = QtWidgets.QPushButton(self.tab_15)
        self.pushButton_windows_exe.setGeometry(QtCore.QRect(660, 20, 91, 32))
        self.pushButton_windows_exe.setObjectName("pushButton_windows_exe")
        self.pushButton_windows_exe.clicked.connect(self.code_audit)
        self.adadas.addTab(self.tab_15, "")


        
    def setupGlobalKeywordSearchTab(self):
        self.tab = QtWidgets.QWidget()
        self.plainTextEdit_weblogic_result = QtWidgets.QPlainTextEdit(self.tab)
        self.plainTextEdit_weblogic_result.setGeometry(QtCore.QRect(10, 130, 1061, 621))
        self.plainTextEdit_weblogic_result.setReadOnly(True)
        self.plainTextEdit_weblogic_result.setObjectName("plainTextEdit_weblogic_result")
        self.pushButton_weblogic_uploadshell = QtWidgets.QPushButton(self.tab)
        self.pushButton_weblogic_uploadshell.setGeometry(QtCore.QRect(690, 50, 97, 32))
        self.pushButton_weblogic_uploadshell.setObjectName("pushButton_weblogic_uploadshell")
        self.pushButton_weblogic_uploadshell.clicked.connect(self.global_keyword_search)
        self.label_2 = QtWidgets.QLabel(self.tab)
        self.label_2.setGeometry(QtCore.QRect(10, 60, 65, 31))
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(self.tab)
        self.label_3.setGeometry(QtCore.QRect(360, 60, 41, 31))
        self.label_3.setObjectName("label_3")
        self.lineEdit_windows_ip_2 = QtWidgets.QLineEdit(self.tab)
        self.lineEdit_windows_ip_2.setGeometry(QtCore.QRect(70, 60, 261, 21))
        self.lineEdit_windows_ip_2.setObjectName("lineEdit_windows_ip_2")
        self.lineEdit_windows_ip_3 = QtWidgets.QLineEdit(self.tab)
        self.lineEdit_windows_ip_3.setGeometry(QtCore.QRect(400, 60, 261, 21))
        self.lineEdit_windows_ip_3.setObjectName("lineEdit_windows_ip_3")
        self.adadas.addTab(self.tab, "")
        
    def setupDangerousFunctionSearchTab(self):
        self.tab_3 = QtWidgets.QWidget()
        self.plainTextEdit_weblogic_result_2 = QtWidgets.QPlainTextEdit(self.tab_3)
        self.plainTextEdit_weblogic_result_2.setGeometry(QtCore.QRect(0, 140, 1061, 621))
        self.plainTextEdit_weblogic_result_2.setReadOnly(True)
        self.plainTextEdit_weblogic_result_2.setObjectName("plainTextEdit_weblogic_result_2")
        self.lineEdit_windows_ip_4 = QtWidgets.QLineEdit(self.tab_3)
        self.lineEdit_windows_ip_4.setGeometry(QtCore.QRect(110, 50, 261, 21))
        self.lineEdit_windows_ip_4.setObjectName("lineEdit_windows_ip_4")
        self.label_72 = QtWidgets.QLabel(self.tab_3)
        self.label_72.setGeometry(QtCore.QRect(20, 50, 81, 20))
        self.label_72.setObjectName("label_72")
        self.pushButton_weblogic_uploadshell_2 = QtWidgets.QPushButton(self.tab_3)
        self.pushButton_weblogic_uploadshell_2.setGeometry(QtCore.QRect(390, 40, 97, 32))
        self.pushButton_weblogic_uploadshell_2.setObjectName("pushButton_weblogic_uploadshell_2")
        self.pushButton_weblogic_uploadshell_2.clicked.connect(self.dangerous_function_search)
        self.adadas.addTab(self.tab_3, "")
        



    def search_implementation(self):

        keyword = self.lineEdit_search_keyword.text()
        
    
        print("Search Keyword:", keyword)
        

        self.plainTextEdit_search_result.setPlainText(f"Search result for '{keyword}'")

    def setupAutomatedCodeAuditTab(self):
        self.tab_auto_audit = QtWidgets.QWidget()

        self.label_auto_audit_path = QtWidgets.QLabel(self.tab_auto_audit)

        self.plainTextEdit_auto_audit_result = QtWidgets.QPlainTextEdit(self.tab_auto_audit)
        self.plainTextEdit_auto_audit_result.setGeometry(QtCore.QRect(10, 80, 1051, 671))
        self.plainTextEdit_auto_audit_result.setReadOnly(True)
        self.plainTextEdit_auto_audit_result.setPlainText("")
        self.plainTextEdit_auto_audit_result.setObjectName("plainTextEdit_auto_audit_result")
        
        self.pushButton_import_yaml = QtWidgets.QPushButton(self.tab_auto_audit)
        self.pushButton_import_yaml.setGeometry(QtCore.QRect(110, 40, 110, 32))
        self.pushButton_import_yaml.setObjectName("pushButton_import_yaml")
        self.pushButton_import_yaml.setText("导入YAML规则")
        self.pushButton_import_yaml.clicked.connect(self.import_yaml)

        self.pushButton_run_scan = QtWidgets.QPushButton(self.tab_auto_audit)
        self.pushButton_run_scan.setGeometry(QtCore.QRect(390, 40, 115, 32))
        self.pushButton_run_scan.setObjectName("pushButton_run_scan")
        self.pushButton_run_scan.setText("导入源码并扫描")
        self.pushButton_run_scan.clicked.connect(self.run_scan)

        self.adadas.addTab(self.tab_auto_audit, "")

        self.listWidget = QtWidgets.QListWidget(self.tab_auto_audit)  
        self.listWidget.setGeometry(QtCore.QRect(10, 130, 1051, 621))
        self.listWidget.setObjectName("listWidget")









    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("Code audit", "Code audit"))
        self.label_70.setText(_translate("MainWindow", "代码路径:"))
        self.label_71.setText(_translate("MainWindow", "OpenAI API 密钥"))
        self.pushButton_windows_exe.setText(_translate("MainWindow", "执行命令"))
        self.adadas.setTabText(self.adadas.indexOf(self.tab_15), _translate("MainWindow", "GPT代码审计"))
        self.plainTextEdit_weblogic_result.setPlainText(_translate("MainWindow", "支持：Java ，PHP，asp，aspx，jsp，jspx，python，go，全局搜索关键字。"))
        self.pushButton_weblogic_uploadshell.setText(_translate("MainWindow", "执行命令"))
        self.label_2.setText(_translate("MainWindow", "代码路径"))
        self.label_3.setText(_translate("MainWindow", "命令"))
        self.adadas.setTabText(self.adadas.indexOf(self.tab), _translate("MainWindow", "全局搜索关键字"))
        self.plainTextEdit_weblogic_result_2.setPlainText(_translate("MainWindow", "危险函数"))
        self.label_72.setText(_translate("MainWindow", "危险函数搜索"))
        self.pushButton_weblogic_uploadshell_2.setText(_translate("MainWindow", "搜索命令"))
        self.adadas.setTabText(self.adadas.indexOf(self.tab_3), _translate("MainWindow", "危险函数搜索"))


        self.adadas.setTabText(self.adadas.indexOf(self.tab_auto_audit), _translate("MainWindow", "自动化代码审计"))















    def code_audit(self):
        code_path = self.lineEdit_windows_ip.text()
        api_key = self.lineEdit_windows_port.text()

        if not code_path or not api_key:
            self.plainTextEdit_windows_result.setPlainText("请输入代码路径和API密钥")
            return

        if not os.path.exists(code_path):
            self.plainTextEdit_windows_result.setPlainText("错误：代码路径不存在")
            return

        if os.path.isfile(code_path):
            self.audit_single_file(code_path, api_key)
        elif os.path.isdir(code_path):
            self.audit_directory(code_path, api_key)

    def audit_single_file(self, file_path, api_key):
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                code = file.read()

            openai.api_key = api_key
            response = openai.ChatCompletion.create(
                model=self.MODEL,
                messages=[
                    {"role": "system", "content": "You are a code auditing assistant."},
                    {"role": "user", "content": f"请对以下代码进行安全审计并指出潜在的漏洞：\n\n{code}"}
                ],
                max_tokens=1024,
                n=1,
                stop=None,
                temperature=0.5,
            )

            result = response.choices[0].message['content']
            self.plainTextEdit_windows_result.appendPlainText(f"文件: {file_path}\n{result}\n")
        except openai.error.RateLimitError:
            self.plainTextEdit_windows_result.appendPlainText(f"文件: {file_path}\nAPI请求超出配额，请检查您的计划和计费详细信息。\n")
        except Exception as e:
            self.plainTextEdit_windows_result.appendPlainText(f"文件: {file_path}\n发生错误: {str(e)}\n")

    def audit_directory(self, dir_path, api_key):
        for root, _, files in os.walk(dir_path):
            for file in files:
                file_path = os.path.join(root, file)
                self.audit_single_file(file_path, api_key)

   










    def global_keyword_search(self):
        root_path = self.lineEdit_windows_ip_2.text().strip()
        keyword = self.lineEdit_windows_ip_3.text()

        if not root_path or not keyword:
            self.plainTextEdit_weblogic_result.setPlainText("请输入文件夹路径和关键词")
            return

        if not os.path.exists(root_path):
            self.plainTextEdit_weblogic_result.setPlainText("错误：路径不存在")
            return

        matched_files = []
        try:
            for foldername, _, filenames in os.walk(root_path):
                for filename in filenames:
                    file_path = os.path.join(foldername, filename)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                            code = file.read()
                            if re.search(keyword, code, re.IGNORECASE):
                                matched_files.append(file_path)
                    except Exception as e:
                        print(f"Error reading file {file_path}: {str(e)}")
                        continue

            if matched_files:
                result = "匹配的文件路径:\n" + "\n".join(matched_files)
            else:
                result = "未找到匹配的文件"
            self.plainTextEdit_weblogic_result.setPlainText(result)
        except Exception as e:
            self.plainTextEdit_weblogic_result.setPlainText(f"发生错误: {str(e)}")



   




    def dangerous_function_search(self):
        code = self.lineEdit_windows_ip_4.text()  # 使用用户输入的代码字符串

        if not code:
            self.plainTextEdit_weblogic_result_2.setPlainText("请输入代码")
            return

        try:
            results = {}

            
            java = [
                "Runtime\\.exec",                   # 允许执行外部命令，可能导致命令注入漏洞。
                "ProcessBuilder",                   # 类似于 Runtime.exec，可执行外部命令。
                "ObjectInputStream\\.readObject",   # 从不受信任的来源反序列化对象，可能导致反序列化漏洞。
                "javax\\.xml\\.transform\\.Transformer",  # 允许 XSLT 转换，可能导致 XML 外部实体 (XXE) 攻击。
                "java\\.sql\\.PreparedStatement",   # 通过预编译语句执行的 SQL 查询，如果未正确参数化，可能会受到 SQL 注入的影响。
                "java\\.io\\.File\\.delete",        # 删除文件或目录，如果使用不当，可能导致任意文件删除。
                "java\\.lang\\.Runtime\\.loadLibrary",  # 加载本地库，如果库不受信任，可能导致任意代码执行。
                "java\\.lang\\.reflect\\.Method\\.invoke",  # 动态调用方法，如果未正确保护，可能导致基于反射的攻击。
                "javax\\.script\\.ScriptEngineManager",  # 允许执行脚本，如果未正确验证，可能导致脚本注入。
                "java\\.util\\.zip\\.ZipInputStream",  # 处理 ZIP 文件，如果未正确清理，可能导致目录遍历或任意文件写入。
                "java\\.net\\.URL\\.openConnection",  # 打开到 URL 的连接，可能被用于 SSRF (Server-Side Request Forgery) 攻击。
                "java\\.util\\.Scanner\\.next",      # 读取用户输入，如果未正确清理，可能导致各种注入攻击。
                "java\\.util\\.Runtime\\.getRuntime",  # 检索当前运行时，可能被滥用以执行任意命令。
                "java\\.nio\\.file\\.Files\\.write",  # 向文件写入字节，如果未正确清理，可能导致任意文件写入。
                "java\\.nio\\.file\\.Files\\.delete",  # 删除文件或目录，如果使用不当，可能导致任意文件删除。
                "java\\.awt\\.Robot",                # 允许控制鼠标和键盘，可能导致 UI 篡改或自动化攻击。
                "java\\.lang\\.Runtime\\.exec",      # 执行系统命令，如果用户输入未经适当验证，容易受到命令注入攻击。
                "javax\\.management\\.MBeanServer",  # 允许管理 MBean (托管 Bean)，如果未适当保护，可能导致未经授权的访问或控制。
                "java\\.lang\\.ProcessBuilder",      # 类似于 Runtime.exec，可执行外部命令。
                "java\\.lang\\.System\\.loadLibrary",  # 加载本地库，如果库不受信任，可能导致任意代码执行。
                "java\\.rmi\\.Naming\\.lookup",      # 允许查找 RMI (远程方法调用) 对象，可能被用于未经授权的访问。
                "javax\\.management\\.remote\\.JMXConnectorFactory",  # 创建 JMX 连接器，可能被用于未经授权访问 JMX (Java 管理扩展) 服务。
                "java\\.net\\.Socket",               # 创建套接字连接，如果未适当保护，可能被用于基于网络的攻击。
                "java\\.net\\.DatagramSocket",       # 创建 UDP 套接字，如果未适当保护，可能被用于基于网络的攻击。
                "java\\.util\\.logging\\.LogManager",  # 管理日志配置，可能被滥用以记录敏感信息或禁用日志记录。
                "java\\.io\\.FileInputStream",       # 从文件读取，如果未正确清理，可能导致任意文件读取。
                "java\\.io\\.FileOutputStream",      # 写入文件，如果未正确清理，可能导致任意文件写入。
                "java\\.util\\.logging\\.Logger\\.log",  # 记录消息，如果未适当保护，可能被滥用以记录敏感信息。
                "java\\.util\\.zip\\.ZipOutputStream",  # 写入 ZIP 文件，如果未正确清理，可能导致 ZIP 文件提取漏洞。
                "java\\.security\\.KeyStore",        # 管理加密密钥和证书，如果未适当保护，可能导致密钥管理漏洞。
                "java\\.security\\.SecureRandom",     # 生成密码学安全的随机数，如果未正确初始化，可能导致可预测的随机数。
                "java\\.text\\.SimpleDateFormat",    # 格式化日期，如果未正确使用，可能导致日期解析漏洞，例如 SQL 注入或 XSS。
                "java\\.sql\\.Connection",           # 管理数据库连接，如果未适当保护，可能导致 SQL 注入或其他数据库漏洞。
                "java\\.sql\\.Statement",            # 执行 SQL 查询，如果未正确参数化，可能导致 SQL 注入漏洞。
                "java\\.sql\\.ResultSet",            # 表示数据库查询的结果集，如果未正确清理，可能导致数据泄漏或篡改。
                "java\\.sql\\.DatabaseMetaData",      # 检索有关数据库的元数据，如果未适当保护，可能泄漏有关数据库结构的敏感信息。
                "java\\.sql\\.DatabaseMetaData\\.getTables",  # 检索数据库中表的信息，如果未适当保护，可能泄漏敏感信息。
                "java\\.sql\\.DatabaseMetaData\\.getColumns",  # 检索表中列的信息，如果未适当保护，可能泄漏敏感信息。
                "java\\.util\\.zip\\.ZipFile", # 读取 ZIP 文件，如果未正确清理，可能导致 ZIP 文件提取漏洞。
                "java\\.nio\\.file\\.Paths\\.get", # 检索 Path 对象，如果未正确清理，可能导致目录遍历漏洞。
                "java\\.nio\\.file\\.Files\\.createDirectory", # 创建目录，如果未正确清理，可能导致目录遍历漏洞。
                "java\\.nio\\.file\\.Files\\.createFile", # 创建文件，如果未正确清理，可能导致任意文件创建漏洞。
                "java\\.nio\\.file\\.Files\\.deleteIfExists", # 如果存在则删除文件，如果未适当保护，可能导致任意文件删除漏洞。
                "java\\.nio\\.file\\.Files\\.createLink", # 创建硬链接，如果未适当保护，可能导致目录遍历或符号链接漏洞。
                "java\\.nio\\.file\\.Files\\.createSymbolicLink", # 创建符号链接，如果未适当保护，可能导致符号链接漏洞。
                "java\\.nio\\.file\\.Files\\.move", # 移动或重命名文件或目录，如果未适当保护，可能导致目录遍历或任意文件操作。
                "java\\.nio\\.file\\.Files\\.walkFileTree", # 遍历文件树，如果未正确保护，可能导致意外的文件访问或操作。
                "java\\.nio\\.file\\.FileVisitor", # 文件树遍历的访问者接口，如果未正确实现，可能导致意外的文件访问或操作。
                "java\\.nio\\.file\\.FileVisitor\\.visitFile", # 在文件树遍历期间访问文件，如果未正确实现，可能导致意外的文件访问或操作。
                "java\\.nio\\.file\\.Files\\.walk",  # 返回一个 Stream，通过遍历文件树懒加载 Path，如果未正确保护，可能导致意外的文件访问或操作。
                "java\\.nio\\.file\\.Files\\.list",  # 列出目录中的条目，如果未正确保护，可能导致信息泄露或意外的文件访问。
                "java\\.nio\\.file\\.Files\\.find",  # 在目录层次结构中查找文件，如果未正确保护，可能导致意外的文件访问或遍历。
                "java\\.nio\\.file\\.FileSystem",     # 表示文件系统，如果未正确保护，可能导致未经授权的访问或操纵文件系统。
                "java\\.nio\\.file\\.FileSystem\\.getPath",  # 通过转换路径字符串或 URI 返回 Path，如果未正确清理，可能导致目录遍历漏洞。
                "java\\.nio\\.file\\.FileSystems",    # 提供对默认文件系统和其他文件系统的访问，如果未正确保护，可能导致未经授权的访问或操纵。
                "java\\.nio\\.file\\.FileSystems\\.getDefault",  # 返回默认文件系统，如果未正确保护，可能导致未经授权的访问或操纵。
                "java\\.nio\\.file\\.FileSystems\\.getFileSystem",  # 返回 URI 方案的文件系统，如果未正确保护，可能导致未经授权的访问或操纵。
                "java\\.nio\\.file\\.FileStore",      # 表示存储池、设备、分区、卷、具体文件系统或其他实现特定的文件存储方式，如果未正确保护，可能导致未经授权的访问或操纵。
                "java\\.nio\\.file\\.FileStore\\.getAttribute",  # 返回文件存储属性，如果未正确保护，可能泄露有关文件系统的敏感信息。
                "java\\.nio\\.file\\.FileStore\\.getTotalSpace",  # 返回文件存储中的总字节数，如果未正确保护，可能泄露有关文件系统的敏感信息。
                "java\\.nio\\.file\\.FileStore\\.getUsableSpace",  # 返回此 Java 虚拟机在文件存储中可用的字节数，如果未正确保护，可能泄露有关文件系统的敏感信息。
                "java\\.nio\\.file\\.FileStore\\.getUnallocatedSpace",  # 返回此 Java 虚拟机在文件存储中未使用的字节数，如果未正确保护，可能泄露有关文件系统的敏感信息。
                "java\\.nio\\.file\\.FileStore\\.supportsFileAttributeView",  # 告知此文件存储是否支持给定文件属性视图识别的文件属性，如果未正确保护，可能泄露有关文件系统的敏感信息。
                "java\\.nio\\.file\\.FileStore\\.isReadOnly",  # 告知此文件存储是否为只读，如果未正确保护，可能导致未经授权的文件修改。
                "java\\.nio\\.file\\.FileStore\\.name",  # 返回此文件存储的名称，如果未正确保护，可能泄露有关文件系统的敏感信息。
                "java\\.nio\\.file\\.FileStore\\.type",  # 返回此文件存储的类型，如果未正确保护，可能泄露有关文件系统的敏感信息。
                "java\\.nio\\.file\\.FileStore\\.toString",  # 返回表示对象的字符串，如果未正确保护，可能泄露有关文件系统的敏感信息。
            ]

            results = {}

            for function in java:
                matches = re.findall(rf'\b{function}\b', code)
                if matches:
                    if function == "Runtime\\.exec":
                        results[f"java ：{function}(): 允许执行外部命令，可能导致命令注入漏洞。"] = len(matches)
                    elif function == "ProcessBuilder":
                        results[f"java ：{function}(): 类似于 Runtime.exec，可执行外部命令。"] = len(matches)
                    elif function == "ObjectInputStream\\.readObject":
                        results[f"java ：{function}(): 从不受信任的来源反序列化对象，可能导致反序列化漏洞。"] = len(matches)
                    elif function == "javax\\.xml\\.transform\\.Transformer":
                        results[f"java ：{function}(): 允许 XSLT 转换，可能导致 XML 外部实体 (XXE) 攻击。"] = len(matches)
                    elif function == "java\\.sql\\.PreparedStatement":
                        results[f"java ：{function}(): 通过预编译语句执行的 SQL 查询，如果未正确参数化，可能会受到 SQL 注入的影响。"] = len(matches)
                    elif function == "java\\.io\\.File\\.delete":
                        results[f"java ：{function}(): 删除文件或目录，如果使用不当，可能导致任意文件删除。"] = len(matches)
                    elif function == "java\\.lang\\.Runtime\\.loadLibrary":
                        results[f"java ：{function}(): 加载本地库，如果库不受信任，可能导致任意代码执行。"] = len(matches)
                    elif function == "java\\.lang\\.reflect\\.Method\\.invoke":
                        results[f"java ：{function}(): 动态调用方法，如果未正确保护，可能导致基于反射的攻击。"] = len(matches)
                    elif function == "javax\\.script\\.ScriptEngineManager":
                        results[f"java ：{function}(): 允许执行脚本，如果未正确验证，可能导致脚本注入。"] = len(matches)
                    elif function == "java\\.util\\.zip\\.ZipInputStream":
                        results[f"java ：{function}(): 处理 ZIP 文件，如果未正确清理，可能导致目录遍历或任意文件写入。"] = len(matches)
                    elif function == "java\\.net\\.URL\\.openConnection":
                        results[f"java ：{function}(): 打开到 URL 的连接，可能被用于 SSRF (Server-Side Request Forgery) 攻击。"] = len(matches)
                    elif function == "java\\.util\\.Scanner\\.next":
                        results[f"java ：{function}(): 读取用户输入，如果未正确清理，可能导致各种注入攻击。"] = len(matches)
                    elif function == "java\\.util\\.Runtime\\.getRuntime":
                        results[f"java ：{function}(): 检索当前运行时，可能被滥用以执行任意命令。"] = len(matches)
                    elif function == "java\\.nio\\.file\\.Files\\.write":
                        results[f"java ：{function}(): 向文件写入字节，如果未正确清理，可能导致任意文件写入。"] = len(matches)
                    elif function == "java\\.nio\\.file\\.Files\\.delete":
                        results[f"java ：{function}(): 删除文件或目录，如果使用不当，可能导致任意文件删除。"] = len(matches)
                    elif function == "java\\.awt\\.Robot":
                        results[f"java ：{function}(): 允许控制鼠标和键盘，可能导致 UI 篡改或自动化攻击。"] = len(matches)
                    elif function == "java\\.lang\\.Runtime\\.exec":
                        results[f"java ：{function}(): 执行系统命令，如果用户输入未经适当验证，容易受到命令注入攻击。"] = len(matches)
                    elif function == "javax\\.management\\.MBeanServer":
                        results[f"java ：{function}(): 允许管理 MBean (托管 Bean)，如果未适当保护，可能导致未经授权的访问或控制。"] = len(matches)
                    elif function == "java\\.lang\\.ProcessBuilder":
                        results[f"java ：{function}(): 类似于 Runtime.exec，可执行外部命令。"] = len(matches)
                    elif function == "java\\.lang\\.System\\.loadLibrary":
                        results[f"java ：{function}(): 加载本地库，如果库不受信任，可能导致任意代码执行。"] = len(matches)
                    elif function == "java\\.rmi\\.Naming\\.lookup":
                        results[f"java ：{function}(): 允许查找 RMI (远程方法调用) 对象，可能被用于未经授权的访问。"] = len(matches)
                    elif function == "javax\\.management\\.remote\\.JMXConnectorFactory":
                        results[f"java ：{function}(): 创建 JMX 连接器，可能被用于未经授权访问 JMX (Java 管理扩展) 服务。"] = len(matches)
                    elif function == "java\\.net\\.Socket":
                        results[f"java ：{function}(): 创建套接字连接，如果未适当保护，可能被用于基于网络的攻击。"] = len(matches)
                    elif function == "java\\.net\\.DatagramSocket":
                        results[f"java ：{function}(): 创建 UDP 套接字，如果未适当保护，可能被用于基于网络的攻击。"] = len(matches)
                    elif function == "java\\.util\\.logging\\.LogManager":
                        results[f"java ：{function}(): 管理日志配置，可能被滥用以记录敏感信息或禁用日志记录。"] = len(matches)
                    elif function == "java\\.io\\.FileInputStream":
                        results[f"java ：{function}(): 从文件读取，如果未正确清理，可能导致任意文件读取。"] = len(matches)
                    elif function == "java\\.io\\.FileOutputStream":
                        results[f"java ：{function}(): 写入文件，如果未正确清理，可能导致任意文件写入。"] = len(matches)
                    elif function == "java\\.util\\.logging\\.Logger\\.log":
                        results[f"java ：{function}(): 记录消息，如果未适当保护，可能被滥用以记录敏感信息。"] = len(matches)
                    elif function == "java\\.util\\.zip\\.ZipOutputStream":
                        results[f"java ：{function}(): 写入 ZIP 文件，如果未正确清理，可能导致 ZIP 文件提取漏洞。"] = len(matches)
                    elif function == "java\\.security\\.KeyStore":
                        results[f"java ：{function}(): 管理加密密钥和证书，如果未适当保护，可能导致密钥管理漏洞。"] = len(matches)
                    elif function == "java\\.security\\.SecureRandom":
                        results[f"java ：{function}(): 生成密码学安全的随机数，如果未正确初始化，可能导致可预测的随机数。"] = len(matches)
                    elif function == "java\\.text\\.SimpleDateFormat":
                        results[f"java ：{function}(): 格式化日期，如果未正确使用，可能导致日期解析漏洞，例如 SQL 注入或 XSS。"] = len(matches)
                    elif function == "java\\.sql\\.Connection":
                        results[f"java ：{function}(): 管理数据库连接，如果未适当保护，可能导致 SQL 注入或其他数据库漏洞。"] = len(matches)
                    elif function == "java\\.sql\\.Statement":
                        results[f"java ：{function}(): 执行 SQL 查询，如果未正确参数化，可能导致 SQL 注入漏洞。"] = len(matches)
                    elif function == "java\\.sql\\.ResultSet":
                        results[f"java ：{function}(): 表示数据库查询的结果集，如果未正确清理，可能导致数据泄漏或篡改。"] = len(matches)
                    elif function == "java\\.sql\\.DatabaseMetaData":
                        results[f"java ：{function}(): 检索有关数据库的元数据，如果未适当保护，可能泄漏有关数据库结构的敏感信息。"] = len(matches)
                    elif function == "java\\.sql\\.DatabaseMetaData\\.getTables":
                        results[f"java ：{function}(): 检索数据库中表的信息，如果未适当保护，可能泄漏敏感信息。"] = len(matches)
                    elif function == "java\\.sql\\.DatabaseMetaData\\.getColumns":
                        results[f"java ：{function}(): 检索表中列的信息，如果未适当保护，可能泄漏敏感信息。"] = len(matches)
                    elif function == "java\\.util\\.zip\\.ZipFile":
                        results[f"java ：{function}(): 读取 ZIP 文件，如果未正确清理，可能导致 ZIP 文件提取漏洞。"] = len(matches)
                    elif function == "java\\.nio\\.file\\.Paths\\.get":
                        results[f"java ：{function}(): 检索 Path 对象，如果未正确清理，可能导致目录遍历漏洞。"] = len(matches)
                    elif function == "java\\.nio\\.file\\.Files\\.createDirectory":
                        results[f"java ：{function}(): 创建目录，如果未正确清理，可能导致目录遍历漏洞。"] = len(matches)
                    elif function == "java\\.nio\\.file\\.Files\\.createFile":
                        results[f"java ：{function}(): 创建文件，如果未正确清理，可能导致任意文件创建漏洞。"] = len(matches)
                    elif function == "java\\.nio\\.file\\.Files\\.deleteIfExists":
                        results[f"java ：{function}(): 如果存在则删除文件，如果未适当保护，可能导致任意文件删除漏洞。"] = len(matches)
                    elif function == "java\\.nio\\.file\\.Files\\.createLink":
                        results[f"java ：{function}(): 创建硬链接，如果未适当保护，可能导致目录遍历或符号链接漏洞。"] = len(matches)
                    elif function == "java\\.nio\\.file\\.Files\\.createSymbolicLink":
                        results[f"java ：{function}(): 创建符号链接，如果未适当保护，可能导致符号链接漏洞。"] = len(matches)
                    elif function == "java\\.nio\\.file\\.Files\\.move":
                        results[f"java ：{function}(): 移动或重命名文件或目录，如果未适当保护，可能导致目录遍历或任意文件操作。"] = len(matches)
                    elif function == "java\\.nio\\.file\\.Files\\.walkFileTree":
                        results[f"java ：{function}(): 遍历文件树，如果未正确保护，可能导致意外的文件访问或操作。"] = len(matches)
                    elif function == "java\\.nio\\.file\\.FileVisitor":
                        results[f"java ：{function}(): 文件树遍历的访问者接口，如果未正确实现，可能导致意外的文件访问或操作。"] = len(matches)
                    elif function == "java\\.nio\\.file\\.FileVisitor\\.visitFile":
                        results[f"java ：{function}(): 在文件树遍历期间访问文件，如果未正确实现，可能导致意外的文件访问或操作。"] = len(matches)
                    elif function == "java\\.nio\\.file\\.Files\\.walk":
                        results[f"java ：{function}(): 返回一个 Stream，通过遍历文件树懒加载 Path，如果未正确保护，可能导致意外的文件访问或操作。"] = len(matches)
                    elif function == "java\\.nio\\.file\\.Files\\.list":
                        results[f"java ：{function}(): 列出目录中的条目，如果未正确保护，可能导致信息泄露或意外的文件访问。"] = len(matches)
                    elif function == "java\\.nio\\.file\\.Files\\.find":
                        results[f"java ：{function}(): 在目录层次结构中查找文件，如果未正确保护，可能导致意外的文件访问或遍历。"] = len(matches)
                    elif function == "java\\.nio\\.file\\.FileSystem":
                        results[f"java ：{function}(): 表示文件系统，如果未正确保护，可能导致未经授权的访问或操纵文件系统。"] = len(matches)
                    elif function == "java\\.nio\\.file\\.FileSystem\\.getPath":
                        results[f"java ：{function}(): 通过转换路径字符串或 URI 返回 Path，如果未正确清理，可能导致目录遍历漏洞。"] = len(matches)
                    elif function == "java\\.nio\\.file\\.FileSystems":
                        results[f"java ：{function}(): 提供对默认文件系统和其他文件系统的访问，如果未正确保护，可能导致未经授权的访问或操纵。"] = len(matches)
                    elif function == "java\\.nio\\.file\\.FileSystems\\.getDefault":
                        results[f"java ：{function}(): 返回默认文件系统，如果未正确保护，可能导致未经授权的访问或操纵。"] = len(matches)
                    elif function == "java\\.nio\\.file\\.FileSystems\\.getFileSystem":
                        results[f"java ：{function}():  返回 URI 方案的文件系统，如果未正确保护，可能导致未经授权的访问或操纵。"] = len(matches)

                    elif function == "java\\.nio\\.file\\.FileStore":
                        results[f"java ：{function}():  表示存储池、设备、分区、卷、具体文件系统或其他实现特定的文件存储方式，如果未正确保护，可能导致未经授权的访问或操纵。"] = len(matches)

                    elif function == "java\\.nio\\.file\\.FileStore\\.getAttribute":
                        results[f"java ：{function}(): 返回文件存储属性，如果未正确保护，可能泄露有关文件系统的敏感信息。"] = len(matches)

                    elif function == "java\\.nio\\.file\\.FileStore\\.getTotalSpace":
                        results[f"java ：{function}():  返回文件存储中的总字节数，如果未正确保护，可能泄露有关文件系统的敏感信息。"] = len(matches)

                    elif function == "java\\.nio\\.file\\.FileStore\\.getUsableSpace":
                        results[f"java ：{function}():  返回此 Java 虚拟机在文件存储中可用的字节数，如果未正确保护，可能泄露有关文件系统的敏感信息。"] = len(matches)

                    elif function == "java\\.nio\\.file\\.FileStore\\.getUnallocatedSpace":
                        results[f"java ：{function}():  返回此 Java 虚拟机在文件存储中未使用的字节数，如果未正确保护，可能泄露有关文件系统的敏感信息。"] = len(matches)

                    elif function == "java\\.nio\\.file\\.FileStore\\.supportsFileAttributeView":
                        results[f"java ：{function}():  告知此文件存储是否支持给定文件属性视图识别的文件属性，如果未正确保护，可能泄露有关文件系统的敏感信息。"] = len(matches)

                    elif function == "java\\.nio\\.file\\.FileStore\\.isReadOnly":
                        results[f"java ：{function}():  告知此文件存储是否为只读，如果未正确保护，可能导致未经授权的文件修改。"] = len(matches)

                    elif function == "java\\.nio\\.file\\.FileStore\\.name":
                        results[f"java ：{function}(): 返回此文件存储的名称，如果未正确保护，可能泄露有关文件系统的敏感信息。"] = len(matches)

                    elif function == "java\\.nio\\.file\\.FileStore\\.type":
                        results[f"java ：{function}(): 返回此文件存储的类型，如果未正确保护，可能泄露有关文件系统的敏感信息。"] = len(matches)

                    elif function == "java\\.nio\\.file\\.FileStore\\.toString":
                        results[f"java ：{function}(): 返回表示对象的字符串，如果未正确保护，可能泄露有关文件系统的敏感信息。"] = len(matches)








            php = [
                "eval", 
                "system", 
                "exec", 
                "popen", 
                "shell_exec", 
                "passthru", 
                "include", 
                "require", 
                "serialize", 
                "unserialize", 
                "extract", 
                "parse_str", 
                "file_get_contents", 
                "file", 
                "assert", 
                "proc_open", 
                "pcntl_exec", 
                "pcntl_alarm", 
                "move_uploaded_file", 
                "chmod", 
                "chown", 
                "chgrp", 
                "fwrite", 
                "fputs", 
                "header", 
                "session_start", 
                "include_once", 
                "require_once", 
                "rename", 
                "mkdir", 
                "rmdir", 
                "copy", 
                "file_put_contents", 
                "fopen", 
                "fread", 
                "fgets", 
                "fgetc"
            ]
            for function in php:
                matches = re.findall(rf'\b{function}\b', code)
                if matches:
                    if function == "eval":
                        results[f"PHP ：{function}(): 允许执行字符串作为 PHP 代码，可能导致代码注入漏洞。"] = len(matches)
                    elif function == "system":
                        results[f"PHP ：{function}(): 执行外部系统命令，可能导致命令注入漏洞。"] = len(matches)
                    elif function == "exec":
                        results[f"PHP ：{function}(): 与system()类似，也是用于执行外部系统命令，存在命令注入漏洞。"] = len(matches)
                    elif function == "popen":
                        results[f"PHP ：{function}(): 打开一个进程，并返回一个文件指针，可能导致命令注入漏洞。"] = len(matches)
                    elif function == "shell_exec":
                        results[f"PHP ：{function}(): 执行外部系统命令，并返回输出，可能导致命令注入漏洞。"] = len(matches)
                    elif function == "passthru":
                        results[f"PHP ：{function}(): 执行外部系统命令并直接将输出打印到标准输出，可能导致命令注入漏洞。"] = len(matches)
                    elif function == "include":
                        results[f"PHP ：{function}(): 包含并执行指定文件，可能导致文件包含漏洞。"] = len(matches)
                    elif function == "require":
                        results[f"PHP ：{function}(): 与include()类似，也可能导致文件包含漏洞。"] = len(matches)
                    elif function == "serialize":
                        results[f"PHP ：{function}(): serialize()函数将 PHP 变量转换为字符串表示形式，而unserialize()函数则将其反序列化回 PHP 值。恶意用户可能构造恶意序列化数据，导致对象注入、代码执行等漏洞。"] = len(matches)
                    elif function == "unserialize":
                        results[f"PHP ：{function}(): serialize()函数将 PHP 变量转换为字符串表示形式，而unserialize()函数则将其反序列化回 PHP 值。恶意用户可能构造恶意序列化数据，导致对象注入、代码执行等漏洞。"] = len(matches)
                    elif function == "extract":
                        results[f"PHP ：{function}(): 将数组中的键名作为变量名，对应的键值作为变量值导入到符号表中，可能导致变量覆盖或执行未授权的操作。"] = len(matches)
                    elif function == "parse_str":
                        results[f"PHP ：{function}(): 解析查询字符串为变量，并将其存储在符号表中，可能导致变量覆盖或执行未授权的操作。"] = len(matches)
                    elif function == "file_get_contents":
                        results[f"PHP ：{function}(): 用于读取文件内容，如果文件路径是由用户提供的数据构成，可能导致路径遍历漏洞。"] = len(matches)
                    elif function == "file":
                        results[f"PHP ：{function}(): 用于读取文件内容，如果文件路径是由用户提供的数据构成，可能导致路径遍历漏洞。"] = len(matches)
                    elif function == "assert":
                        results[f"PHP ：{function}(): 用于执行字符串作为 PHP 代码。如果字符串是由用户提供的数据构成，可能导致代码注入漏洞。"] = len(matches)
                    elif function == "proc_open":
                        results[f"PHP ：{function}(): 打开进程，并返回一个进程标识符。与 popen() 函数类似，可能导致命令注入漏洞。"] = len(matches)
                    elif function == "pcntl_exec":
                        results[f"PHP ：{function}(): 用于执行外部程序。如果执行的程序路径是由用户提供的数据构成，可能导致命令注入漏洞。"] = len(matches)
                    elif function == "pcntl_alarm":
                        results[f"PHP ：{function}(): 设置在给定秒数后发送一个 SIGALRM 信号。如果信号处理程序不正确实现，可能导致拒绝服务（DoS）漏洞。"] = len(matches)
                    elif function == "move_uploaded_file":
                        results[f"PHP ：{function}(): 用于将上传的文件移动到新位置。如果目标路径是由用户提供的数据构成，可能导致路径遍历漏洞或将恶意文件放置到服务器上。"] = len(matches)
                    elif function == "chmod":
                        results[f"PHP ：{function}(): 用于更改文件的权限。如果文件路径是由用户提供的数据构成，可能导致路径遍历漏洞或意外更改重要文件的权限。"] = len(matches)
                    elif function == "chown":
                        results[f"PHP ：{function}(): 用于更改文件的所有者和组。如果文件路径是由用户提供的数据构成，可能导致路径遍历漏洞或意外更改文件的所有者和组。"] = len(matches)
                    elif function == "chgrp":
                        results[f"PHP ：{function}(): 用于更改文件的所有者和组。如果文件路径是由用户提供的数据构成，可能导致路径遍历漏洞或意外更改文件的所有者和组。"] = len(matches)
                    elif function == "fwrite":
                        results[f"PHP ：{function}(): 用于将数据写入文件。如果文件路径是由用户提供的数据构成，可能导致路径遍历漏洞或写入恶意数据到文件中。"] = len(matches)
                    elif function == "fputs":
                        results[f"PHP ：{function}(): 用于将数据写入文件。如果文件路径是由用户提供的数据构成，可能导致路径遍历漏洞或写入恶意数据到文件中。"] = len(matches)
                    elif function == "header":
                        results[f"PHP ：{function}(): 用于发送 HTTP 头。如果未正确验证用户提供的数据，可能导致 HTTP 头注入漏洞，进而导致跨站脚本（XSS）攻击或其他安全问题。"] = len(matches)
                    elif function == "session_start":
                        results[f"PHP ：{function}(): 用于启动会话。如果会话 ID 是由用户提供的数据构成，可能导致会话固定攻击（Session Fixation）漏洞。"] = len(matches)
                    elif function == "include_once":
                        results[f"PHP ：{function}(): 与 include() 和 require() 类似，但只包含文件一次。如果文件路径是由用户提供的数据构成，可能导致文件包含漏洞。"] = len(matches)
                    elif function == "require_once":
                        results[f"PHP ：{function}(): 与 include() 和 require() 类似，但只包含文件一次。如果文件路径是由用户提供的数据构成，可能导致文件包含漏洞。"] = len(matches)
                    elif function == "rename":
                        results[f"PHP ：{function}(): 用于重命名文件或目录。如果目标路径是由用户提供的数据构成，可能导致路径遍历漏洞或意外重命名重要文件或目录。"] = len(matches)
                    elif function == "mkdir":
                        results[f"PHP ：{function}(): 用于创建目录。如果目录名称是由用户提供的数据构成，可能导致路径遍历漏洞或创建恶意目录。"] = len(matches)
                    elif function == "rmdir":
                        results[f"PHP ：{function}(): 用于删除目录。如果目录路径是由用户提供的数据构成，可能导致路径遍历漏洞或意外删除重要目录。"] = len(matches)
                    elif function == "copy":
                        results[f"PHP ：{function}(): 用于复制文件。如果源文件路径或目标路径是由用户提供的数据构成，可能导致路径遍历漏洞或意外复制文件到重要目录。"] = len(matches)
                    elif function == "file_put_contents":
                        results[f"PHP ：{function}(): 用于将数据写入文件。如果文件路径是由用户提供的数据构成，可能导致路径遍历漏洞或写入恶意数据到文件中。"] = len(matches)
                    elif function == "fopen":
                        results[f"PHP ：{function}(): 用于打开文件或 URL。如果文件路径是由用户提供的数据构成，可能导致路径遍历漏洞或意外打开恶意文件。"] = len(matches)
                    elif function == "fread":
                        results[f"PHP ：{function}(): 用于从文件中读取数据。如果文件路径是由用户提供的数据构成，可能导致路径遍历漏洞或读取敏感数据。"] = len(matches)
                    elif function == "fgets":
                        results[f"PHP ：{function}(): 用于从文件中读取数据。如果文件路径是由用户提供的数据构成，可能导致路径遍历漏洞或读取敏感数据。"] = len(matches)
                    elif function == "fgetc":
                        results[f"PHP ：{function}(): 用于从文件中读取数据。如果文件路径是由用户提供的数据构成，可能导致路径遍历漏洞或读取敏感数据。"] = len(matches)






            python = [
                "pickle\\.load",  # 反序列化pickle数据，可能导致远程代码执行漏洞。
                "os\\.popen",  # 执行系统命令，可能导致命令注入漏洞。
                "subprocess\\.run",  # 执行外部命令，可能导致命令注入漏洞。
                "subprocess\\.Popen",  # 与 subprocess.run 类似，也可执行外部命令。
                "xml\\.etree\\.parse",  # 解析XML数据，可能导致XML外部实体(XXE)攻击。
                "xml\\.dom\\.minidom\\.parse",  # 解析XML数据，可能导致XML外部实体(XXE)攻击。
                "xml\\.sax\\.make_parser",  # 解析XML数据，可能导致XML外部实体(XXE)攻击。
            ]

            for function in python:
                matches = re.findall(rf'\b{function}\b', code)
                if matches:
                    if function == "pickle\\.load":
                        results[f"Python ：{function}(): 反序列化pickle数据，可能导致远程代码执行漏洞。"] = len(matches)
                    elif function == "os\\.popen":
                        results[f"Python ：{function}(): 执行系统命令，可能导致命令注入漏洞。"] = len(matches)
                    elif function == "subprocess\\.run":
                        results[f"Python ：{function}(): 执行外部命令，可能导致命令注入漏洞。"] = len(matches)
                    elif function == "subprocess\\.Popen":
                        results[f"Python ：{function}(): 与 subprocess.run 类似，也可执行外部命令。"] = len(matches)
                    elif function == "xml\\.etree\\.parse":
                        results[f"Python ：{function}(): 解析XML数据，可能导致XML外部实体(XXE)攻击。"] = len(matches)
                    elif function == "xml\\.dom\\.minidom\\.parse":
                        results[f"Python ：{function}(): 解析XML数据，可能导致XML外部实体(XXE)攻击。"] = len(matches)
                    elif function == "xml\\.sax\\.make_parser":
                        results[f"Python ：{function}(): 解析XML数据，可能导致XML外部实体(XXE)攻击。"] = len(matches)

          



                go = [
                    "os/exec\\.Command",               # 用于执行外部命令。如果未正确过滤用户输入，可能导致命令注入漏洞。
                    "os/exec\\.LookPath",              # 用于在 PATH 中搜索可执行文件。如果路径是由用户提供的数据构成，可能导致路径遍历漏洞。
                    "os/exec\\.Start",                 # 用于启动命令。如果命令是由用户提供的数据构成，可能导致命令注入漏洞。
                    "html/template\\.ParseFiles",      # 用于解析模板文件。如果文件路径是由用户提供的数据构成，可能导致路径遍历漏洞。
                    "html/template\\.ParseGlob",       # 类似于 ParseFiles，用于解析模板文件。如果文件路径是由用户提供的数据构成，可能导致路径遍历漏洞。
                    "net/http\\.ServeFile",            # 用于提供文件服务。如果文件路径是由用户提供的数据构成，可能导致路径遍历漏洞。
                    "net/http\\.Get",                  # 用于执行 HTTP GET 请求。如果 URL 是由用户提供的数据构成，可能导致请求劫持、跨站脚本（XSS）等安全问题。
                    "encoding/xml\\.Unmarshal",        # 用于将 XML 数据解析为 Go 结构体。如果 XML 数据是由不受信任的来源提供的，可能导致 XML 外部实体 (XXE) 攻击。
                    "database/sql\\.Query",            # 用于执行 SQL 查询。如果 SQL 查询是由用户提供的数据构成，可能导致 SQL 注入漏洞。
                    "database/sql\\.Exec",             # 用于执行 SQL 命令。如果 SQL 命令是由用户提供的数据构成，可能导致 SQL 注入漏洞。
                    "syscall\\.Syscall",               # 用于调用操作系统底层函数。如果未正确处理系统调用参数，可能导致操作系统层面的安全问题。
                    "crypto\\.Decrypter",              # 用于解密数据。如果密钥是由用户提供的数据构成，可能导致信息泄露或数据篡改漏洞。
                    "path/filepath\\.Join",            # 用于拼接文件路径。如果路径是由用户提供的数据构成，可能导致路径遍历漏洞。
                ]

                for function in go:
                    matches = re.findall(rf'\b{function}\b', code)
                    if matches:
                        if function == "os/exec\\.Command":
                            results[f"go ：{function}: 用于执行外部命令。如果未正确过滤用户输入，可能导致命令注入漏洞。"] = len(matches)
                        elif function == "os/exec\\.LookPath":
                            results[f"go ：{function}: 用于在 PATH 中搜索可执行文件。如果路径是由用户提供的数据构成，可能导致路径遍历漏洞。"] = len(matches)
                        elif function == "os/exec\\.Start":
                            results[f"go ：{function}: 用于启动命令。如果命令是由用户提供的数据构成，可能导致命令注入漏洞。"] = len(matches)
                        elif function == "html/template\\.ParseFiles":
                          results[f"go ：{function}: 用于解析模板文件。如果文件路径是由用户提供的数据构成，可能导致路径遍历漏洞。"] = len(matches)
                        elif function == "html/template\\.ParseGlob":
                            results[f"go ：{function}: 类似于 ParseFiles，用于解析模板文件。如果文件路径是由用户提供的数据构成，可能导致路径遍历漏洞。"] = len(matches)
                        elif function == "net/http\\.ServeFile":
                            results[f"go ：{function}: 用于提供文件服务。如果文件路径是由用户提供的数据构成，可能导致路径遍历漏洞。"] = len(matches)
                        elif function == "net/http\\.Get":
                            results[f"go ：{function}: 用于执行 HTTP GET 请求。如果 URL 是由用户提供的数据构成，可能导致请求劫持、跨站脚本（XSS）等安全问题。"] = len(matches)
                        elif function == "encoding/xml\\.Unmarshal":
                            results[f"go ：{function}: 用于将 XML 数据解析为 Go 结构体。如果 XML 数据是由不受信任的来源提供的，可能导致 XML 外部实体 (XXE) 攻击。"] = len(matches)
                        elif function == "database/sql\\.Query":
                            results[f"go ：{function}: 用于执行 SQL 查询。如果 SQL 查询是由用户提供的数据构成，可能导致 SQL 注入漏洞。"] = len(matches)
                        elif function == "database/sql\\.Exec":
                            results[f"go ：{function}: 用于执行 SQL 命令。如果 SQL 命令是由用户提供的数据构成，可能导致 SQL 注入漏洞。"] = len(matches)
                        elif function == "syscall\\.Syscall":
                            results[f"go ：{function}: 用于调用操作系统底层函数。如果未正确处理系统调用参数，可能导致操作系统层面的安全问题。"] = len(matches)
                        elif function == "crypto\\.Decrypter":
                            results[f"go ：{function}: 用于解密数据。如果密钥是由用户提供的数据构成，可能导致信息泄露或数据篡改漏洞。"] = len(matches)
                        elif function == "path/filepath\\.Join":
                            results[f"go ：{function}: 用于拼接文件路径。如果路径是由用户提供的数据构成，可能导致路径遍历漏洞。"] = len(matches)


            result_text = "危险函数搜索结果:\n"
            for func, description in results.items():
                result_text += f"{func} ({description} 次)\n"

            if not results:
                result_text += "未找到任何危险函数"

            self.plainTextEdit_weblogic_result_2.setPlainText(result_text)

        except Exception as e:
            self.plainTextEdit_weblogic_result_2.setPlainText(f"发生错误: {str(e)}")







    def import_yaml(self):
        options = QtWidgets.QFileDialog.Options()
        options |= QtWidgets.QFileDialog.DontUseNativeDialog
        directory = QtWidgets.QFileDialog.getExistingDirectory(None, "选择包含yaml文件的文件夹")
        if directory:
            yaml_files = glob.glob(os.path.join(directory, "*.yaml"))
            if yaml_files:
                for yaml_file in yaml_files:
                    rules = load_rules(yaml_file)
                    if rules:
                        self.rules.extend(rules)
                        self.listWidget.addItem(f"导入规则: {yaml_file}")
                    else:
                        self.listWidget.addItem(f"未能导入规则: {yaml_file}")
            else:
                self.listWidget.addItem("所选文件夹中没有 YAML 文件")
        else:
            self.listWidget.addItem("未选择任何文件夹")





    def run_scan(self):
        directory = QtWidgets.QFileDialog.getExistingDirectory(None, "选择扫描目录")
        if directory:
            self.listWidget.addItem(f"扫描目录: {directory}")
            vulnerabilities, lines_with_vulnerabilities = scan_directory(directory, self.rules)  
            if vulnerabilities:
                export_to_html(vulnerabilities, lines_with_vulnerabilities, 'dm.html')  
                self.listWidget.addItem("扫描完成，漏洞报告已导出为 dm.html")
                self.listWidget.addItem(f"发现漏洞数量: {len(vulnerabilities)}")
            else:
                self.listWidget.addItem("扫描完成，未发现任何漏洞")
        else:
            self.listWidget.addItem("未选择任何目录")







def load_rules(rule_file):
    try:
        with open(rule_file, 'r') as stream:
            rules = yaml.safe_load(stream)
            return rules['rules']
    except FileNotFoundError:
        print(f"Error: Rule file '{rule_file}' not found.")
        return []

def scan_code(php_code, rules, file_path):
    vulnerabilities = []
    lines_with_vulnerabilities = set()  
    for rule in rules:
        if 'only-regex' in rule:
            vulns, vuln_lines = only_regex_match(php_code, rule, file_path)
            vulnerabilities += vulns
            lines_with_vulnerabilities.update(vuln_lines)
        elif 'function-param-regex' in rule:
            vulns, vuln_lines = function_param_regex_match(php_code, rule, file_path)
            vulnerabilities += vulns
            lines_with_vulnerabilities.update(vuln_lines)
        elif 'customize-match' in rule:
            vulns, vuln_lines = customize_match(php_code, rule, file_path)
            vulnerabilities += vulns
            lines_with_vulnerabilities.update(vuln_lines)
    return vulnerabilities, lines_with_vulnerabilities


def only_regex_match(php_code, rule, file_path):
    vulnerabilities = []
    vuln_lines = set()
    pattern = re.compile(rule['only-regex']['pattern'], re.IGNORECASE)
    exclude_patterns = [re.compile(p, re.IGNORECASE) for p in rule.get('exclude-patterns', [])]
    lines = php_code.split('\n')
    for i, line in enumerate(lines, start=1):
        matches = pattern.finditer(line)
        for match in matches:
            if any(ep.match(match.group()) for ep in exclude_patterns):
                continue
            code_snippet = line[max(match.start() - 50, 0):min(match.end() + 50, len(line))]
            vulnerabilities.append({
                'name': rule['name'],
                'description': rule['description'],
                'file_path': file_path,
                'code_snippet': code_snippet
            })
            vuln_lines.add(i)
    return vulnerabilities, vuln_lines


def function_param_regex_match(php_code, rule, file_path):
    vulnerabilities = []
    vuln_lines = set()
    func_pattern = re.compile(rule['function-param-regex']['function_pattern'], re.IGNORECASE)
    param_pattern = re.compile(rule['function-param-regex']['param_pattern'], re.IGNORECASE)
    exclude_functions = [re.compile(p, re.IGNORECASE) for p in rule.get('exclude-functions', [])]
    lines = php_code.split('\n')
    for i, line in enumerate(lines, start=1):
        matches = func_pattern.finditer(line)
        for match in matches:
            if any(ef.match(match.group()) for ef in exclude_functions):
                continue
            params = param_pattern.findall(match.group())
            for param in params:
                if is_tainted(param):
                    code_snippet = line[max(match.start() - 50, 0):min(match.end() + 50, len(line))]
                    vulnerabilities.append({
                        'name': rule['name'],
                        'description': rule['description'],
                        'file_path': file_path,
                        'code_snippet': code_snippet
                    })
                    vuln_lines.add(i)
    return vulnerabilities, vuln_lines


def customize_match(php_code, rule, file_path):
    vulnerabilities = []
    vuln_lines = set()
    custom_pattern = re.compile(rule['customize-match']['pattern'], re.IGNORECASE)
    exclude_patterns = [re.compile(p, re.IGNORECASE) for p in rule.get('exclude-patterns', [])]
    lines = php_code.split('\n')
    for i, line in enumerate(lines, start=1):
        matches = custom_pattern.finditer(line)
        for match in matches:
            if any(ep.match(match.group()) for ep in exclude_patterns):
                continue
            main_func = globals()[rule['customize-match']['main']]
            params = main_func(match.group())
            if any(is_tainted(param) for param in params):
                code_snippet = line[max(match.start() - 50, 0):min(match.end() + 50, len(line))]
                vulnerabilities.append({
                    'name': rule['name'],
                    'description': rule['description'],
                    'file_path': file_path,
                    'code_snippet': code_snippet
                })
                vuln_lines.add(i)
    return vulnerabilities, vuln_lines


def is_tainted(param):

    return True

def scan_file(file_path, rules):
    vulnerabilities = []
    lines_with_vulnerabilities = set()  
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        php_code = file.read()
        vulns, vuln_lines = scan_code(php_code, rules, file_path)
        vulnerabilities += vulns
        lines_with_vulnerabilities.update(vuln_lines)
    return vulnerabilities, lines_with_vulnerabilities


def scan_directory(directory, rules):
    vulnerabilities = []
    max_workers = min(2 * os.cpu_count(), 80)
    lines_with_vulnerabilities = {}  
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for root, _, files in os.walk(directory):
            for file_name in files:
                if file_name.endswith('.php'):
                    file_path = os.path.join(root, file_name)
                    future = executor.submit(scan_file, file_path, rules)
                    futures.append((file_path, future))
        for file_path, future in futures:
            vulns, vuln_lines = future.result()
            vulnerabilities += vulns
            lines_with_vulnerabilities[file_path] = vuln_lines
    return vulnerabilities, lines_with_vulnerabilities


def categorize_vulnerabilities(vulnerabilities):
    categories = {}
    for vuln in vulnerabilities:
        category = vuln.get('category', 'Uncategorized')
        if category not in categories:
            categories[category] = []
        categories[category].append(vuln)
    return categories


def export_to_html(vulnerabilities, lines_with_vulnerabilities, output_file):
    with open(output_file, 'w', encoding='utf-8') as html_file:
        html_file.write("<html>\n<head>\n<title>漏洞报告</title>\n</head>\n<body>\n")
        if vulnerabilities:
            categorized_vulns = categorize_vulnerabilities(vulnerabilities)
            html_file.write("<h1>发现漏洞:</h1>\n")
            for category, vulns in categorized_vulns.items():
                html_file.write(f"<h2>Category: {category}</h2>\n")
                for i, vulnerability in enumerate(vulns):  
                    html_file.write("<div>\n")
                    html_file.write(f"<p><strong>漏洞名称:</strong> {vulnerability['name']}</p>\n")
                    html_file.write(f"<p><strong>漏洞描述:</strong> {vulnerability['description']}</p>\n")
                    html_file.write(f"<p><strong>文件路径:</strong> {vulnerability['file_path']}</p>\n")
                    html_file.write(f"<p><strong>漏洞行数:</strong> {lines_with_vulnerabilities.get(vulnerability['file_path'], [])}</p>\n")
                    html_file.write(f"<p><strong>漏洞代码:</strong> {vulnerability['code_snippet']}</p>\n")
                    html_file.write("</div>\n")
         
                    if i < len(vulns) - 1:
                        html_file.write("<hr>\n")
        else:
            html_file.write("<p>No vulnerabilities found.</p>\n")
        html_file.write("</body>\n</html>")





if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
















