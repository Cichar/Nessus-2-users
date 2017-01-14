Nessus-2-users使用说明：

函数retry是一个捕获到连接异常后会自动重试的装饰器，
重试次数默认为4次。

类Nessus_api，如名字所示，是Nessus的API集合类。
其中包含了99%的Nessus-API，剩下的1%我也不确定有没有遗漏。

因需求不同，函数getclearResult同样会下载完整的CSV文件，
但函数本身只会返回漏洞名、漏洞描述、漏洞编号、漏洞细节、漏洞地址、HOST等几项。
并不会返回完整的结果，但并不影响CSV结果文件的完整性。

函数downloadAndClear2csv,会删除原本文件不需要的列。
内部包含了一个清洗CSV文件并返回一个清洗过的CSV文件的处理步骤。
如果需要可以自行去掉注释。
并指明文件中不需要的列，在变量cols中设定。


类control，实现了单机切换多账户开启并进行多个扫描任务。

函数showscanmethod可以查看Nessus中的方法，
同时添加任务时只需要输入方法对应的ID。不需要输入完整的方法名。

函数addtask为control类的主要功能函数，
会根据初始化control类时传入的用户列表数量，
判断各个用户当前执行的任务数，并将任务分配给执行任务数最少的用户。
以达到用户执行数的动态平衡。
任务可以批量用已经编辑好的txt文件传入。

格式如下：
任务名，描述，HOST，方法ID
task1,txt,192.168.200.1-10,7
task2,txt,192.168.200.11-20,7
task3,txt,192.168.200.21-30,7
task4,txt,192.168.200.31-40,7
task5,txt,192.168.200.41-50,7
task6,txt,192.168.200.51-60,7
task7,txt,192.168.200.61-70,7
task8,txt,192.168.200.71-80,7

如不使用文件批量添加任务，则可以手动逐个添加任务。

函数getallstatus，用于获取各个用户的任务执行情况。
函数getalldata，用于获取已经完成的任务的任务结果。
函数delallscan，用于删除各个用户上已经完成的任务。
函数getmintaskIp,会返回当前执行任务数最少的用户对象(登录状态)。

使用举例：
#首先定义用户列表。
nessconfig = [{'services':'127.0.0.1','username':'Cichar','password':'xxxx'},
	              {'services':'127.0.0.1','username':'admin','password':'xxxxx'},
	              {'services': '127.0.0.1', 'username': 'admin2', 'password': 'xxxxxx'}]
#然后初始化control类，并传入定义好的用户列表
p = control(nessconfig)
#接着调用control类的login函数进行多用户的批量登录。
p.login()
#如果对方法的对应ID不熟悉，可以调用showscanmethod函数
p.showscanmethod()
#如果要使用文件导入任务，则：
p.addtask('X:/xxxxx/xxxxx/scanfile.txt')
#如手动添加任务，则不传入参数：
p.addtask()

添加完一批任务后，脚本此时已经停止。
如果想继续添加，再次运行脚本即可继续添加。

版本日志：
2017-01-14：上传了 v-0.1