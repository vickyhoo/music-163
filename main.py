import urllib.request
import requests
import os
import sys
import binascii
import json
import random
import base64

from bs4 import BeautifulSoup
from datetime import date
from Crypto.Cipher import AES
from urllib.parse import urlencode


download_path = "/Users/vic.zhang/Downloads/music-" + str(date.today())
user_agent = 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.82 Safari/537.36'


class Crawler():
    def __init__(self):
        super(Crawler, self).__init__()
        if not os.path.exists(download_path):
            os.mkdir(download_path)

    def get(self, values):
        print('**** Total ' + str(len(values)) + '****')

        downNum = 0

        none_url_list = []
        for x in values:
            if x['url'] is not None:
                if not os.path.exists(download_path + '/' + x['name'] + '.mp3'):
                    print('***** ' + x['name'] + '.mp3 ***** Downloading...')
                    # url = 'http://music.163.com/song/media/outer/url?id=' + x['id'] + '.mp3'
                    try:
                        urllib.request.urlretrieve(
                            x['url'], download_path + '/' + x['name'].replace('/', '') + '.mp3')
                        downNum = downNum + 1
                    except:
                        print('Download wrong~')
                else:
                    print('***** ' + x['name'] + '.mp3 exists ***** Skip...')
            else:
                none_url_list.append(x)
        print('Download complete ' + str(downNum) + ' files !')
        if len(none_url_list) > 0:
            print('** No resource found for these songs. **')
            for x in none_url_list:
                print('    ' + x['name'])
        pass

    # aes
    def aes_encrypt(self, text, key):
        # 对长度不是16倍数的字符串进行补全，然后在转为bytes数据
        # 如果接到bytes数据（如第一次aes加密得到的密文）要解码再进行补全
        pad = 16 - len(text) % 16
        try:
            text = text.decode()
        except:
            pass
        text = text + pad * chr(pad)
        try:
            text = text.encode()
        except:
            pass
        encryptor = AES.new(key, AES.MODE_CBC, b'0102030405060708')
        ciphertext = encryptor.encrypt(text)
        # 得到的密文还要进行base64编码
        ciphertext = base64.b64encode(ciphertext)
        return ciphertext

    # rsa
    def rsa_encrypt(self, ran_16, pub_key, modulus):
        # 明文处理，反序并hex编码
        text = ran_16[::-1]
        rsa = int(binascii.hexlify(text),
                  16) ** int(pub_key, 16) % int(modulus, 16)
        return format(rsa, 'x').zfill(256)

    def encrypt_data(self, payload):
        secret_key = b'0CoJUm6Qyw8W8jud'
        base62 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        # 第二参数，rsa公匙组成
        pub_key = "010001"
        modulus = "00e0b509f6259df8642dbc35662901477df22677ec152b5ff68ace615bb7b725152b3ab17a876aea8a5aa76d2e417629ec4ee341f56135fccf695280104e0312ecbda92557c93870114af6c9d05c4f7f0c3685b7a46bee255932575cce10b424d813cfe4875d3e82047b97ddef52741d546b8e289dc6935b3ece0462db0a22b8e7"
        ran_16 = bytes(''.join(random.sample(base62, 16)), 'utf-8')
        text = json.dumps(payload)
        # 两次aes加密
        params = self.aes_encrypt(text, secret_key)
        params = self.aes_encrypt(params, ran_16)
        encSecKey = self.rsa_encrypt(ran_16, pub_key, modulus)
        return {'params': params.decode(), 'encSecKey': encSecKey}

    def get_music_url(self, id_list):
        payload = {'ids': '[' + ','.join(id_list) + ']', 'br': 999000}
        payload = self.encrypt_data(payload)
        headers = {'Cookie': '_ntes_nuid=' + binascii.hexlify(os.urandom(32)).decode(
        ), 'User-Agent': user_agent, 'Referer': 'https://music.163.com', 'Content-Type': 'application/x-www-form-urlencoded'}
        url = 'https://music.163.com/weapi/song/enhance/player/url'
        r = requests.post(url, data=payload, headers=headers)
        music_info = r.json()
        song_url_list = list(
            map(lambda x: {'id': x['id'], 'url': x['url']}, music_info['data']))
        return song_url_list

    def get_music_data(self, url):
        headers = {'User-Agent': user_agent}
        webData = requests.get(url, headers=headers).text
        soup = BeautifulSoup(webData, 'lxml')
        find_list = soup.find('ul', class_="f-hide").find_all('a')

        data_list = []
        for a in find_list:
            music_id = a['href'].replace('/song?id=', '')
            music_name = a.text
            data_list.append({'id': music_id, 'name': music_name, 'url': url})

        id_list = list(map(lambda x: x['id'], data_list))
        url_list = self.get_music_url(id_list)
        for idx, d in enumerate(data_list):
            u = next((x for x in url_list if x['id'] == int(d['id'])), {
                     'url': 'None'})
            d['url'] = u['url']
            data_list[idx] = d
        return data_list


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Please input playlist id.")
        # print("Example: https://music.163.com/playlist?id=xxx")
        sys.exit()

    print("playlist: " + sys.argv[1])
    playlist = 'https://music.163.com/playlist?id=' + sys.argv[1]
    crawler = Crawler()
    music_data = crawler.get_music_data(playlist)
    crawler.get(music_data)
    print('Done')
