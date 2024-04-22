import argparse
import hashlib
import json
import logging
import os

from typing import NoReturn

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from qcloud_cos import CosConfig, CosS3Client

logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    filemode='a', filename='logs')


class CosClientBase(object):

    def auth(self) -> CosS3Client:
        try:
            config = CosConfig(
                Region=os.getenv('COS_REGION'),
                SecretId=os.getenv('SECRET_ID'),
                SecretKey=os.getenv('SECRET_KEY'),
            )
            return CosS3Client(config)
        except ValueError as e:
            print(e)

    @staticmethod
    def get_encrypt_key(key: str) -> bytes:
        if len(key) in (32, 64):
            try:
                return bytes.fromhex(key)
            except ValueError:
                pass
        return hashlib.sha256(key.encode('utf-8')).digest()


class Lister(CosClientBase):
    def __init__(self, bucket: str = 'honeychen-1318372326', prefix: str = '') -> NoReturn:
        self.bucket = bucket
        self.prefix = prefix

    def lister(self) -> NoReturn:
        choices = None
        while choices != 'a':
            choices = input(
                'Select one of the following action: \n[1].list bucket info;\n[2].list objects in bucket;\n'
                '[3].quit\nyou choose:')
            match choices:
                case '1':
                    print(self.auth().list_buckets()['Buckets'])
                case '2':
                    obj_list: dict = self.auth().list_objects(Bucket=self.bucket, Prefix=self.prefix)
                    if 'Contents' in obj_list:
                        for content in obj_list["Contents"]:
                            print(content["Key"], sep='\n')
                case '3':
                    break
                case _:
                    assert False, 'Invalid input'


class Uploader(CosClientBase):
    def __init__(self, bucket: str, files: list | tuple, encrypt_key: str, prefix: str = '') -> NoReturn:
        self.bucket = bucket
        self.files = files
        self.prefix = prefix
        self.encrypt_key = self.get_encrypt_key(encrypt_key)

    def collect_files(self, files: list[str]) -> list:
        ret: list = []
        for file in files:
            if not os.path.exists(file):
                raise FileNotFoundError(f'File not found: {file}')
            if os.path.isdir(file):
                for root, _, filenames in os.walk(file):
                    for filename in filenames:
                        filepath = os.path.join(root, filename)
                        key = os.path.relpath(filepath, file)
                        ret.append((filepath, key))
            else:
                ret.append((file, os.path.basename(file)))
        return ret

    def upload(self) -> NoReturn:
        files: list = self.collect_files(self.files)
        choice = None

        for file, key in files:
            key += self.prefix
            if self.auth().object_exists(Key=key, Bucket=self.bucket):
                while choice != 'a':
                    choice = input(
                        f'File {key} already exists, select an action: [o]verwrite, [s]kip, [a]lways overwrite, [q]uit:'
                    )
                    if choice in ('a', 'o', 's', 'q'):
                        break
                if choice == 's':
                    continue
                if choice == 'q':
                    return
            with open(file, 'rb') as f:
                data = f.read()
                print(f'Uploading {file} to {self.bucket}:{key} with {len(data)} bytes')
                self.auth().put_object(Bucket=self.bucket, Key=key, Body=self.encrypt(data), Expires='3600')

    def encrypt(self, data) -> bytes:
        nonce = get_random_bytes(8)
        cipher = AES.new(self.encrypt_key, AES.MODE_CTR, nonce=nonce)
        enc_data = cipher.encrypt(data)
        return cipher.nonce + enc_data


class Downloader(CosClientBase):
    def __init__(self, bucket: str, files: list | tuple, encrypt_key: str, output_dir='./Downloads') -> NoReturn:
        self.bucket = bucket
        self.files = files
        self.encrypt_key = self.get_encrypt_key(encrypt_key)
        self.output_dir = output_dir

    def download(self) -> NoReturn:
        for file in self.files:
            for obj in self.auth().list_objects(Bucket=self.bucket, Prefix=file)['Contents']:
                path = os.path.join(self.output_dir, obj['Key'])
                if not os.path.exists(path):
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                data = self.auth().get_object(Bucket=self.bucket, Key=obj['Key'])['Body'].read(
                    chunk_size=(int(obj['Size'])))
                print(f'Downloading {obj['Key']} to {path}')
                with open(path, 'wb') as f:
                    f.write(self.decrypt(data))

    def decrypt(self, data) -> bytes:
        nonce = data[:8]
        cipher = AES.new(self.encrypt_key, AES.MODE_CTR, nonce=nonce)
        return cipher.decrypt(data[8:])


def parse():
    config = {}
    if os.path.exists('config.json'):
        with open('config.json', 'r') as f:
            config = json.load(f)
    parser = argparse.ArgumentParser(description='SCOS: Secure Cloud Object Storage for Tencent Cloud')
    subparsers = parser.add_subparsers(dest='command', required=True)

    uploader_parser = subparsers.add_parser('upload')
    uploader_parser.add_argument('files', nargs='+', help='需上传的文件名称')
    uploader_parser.add_argument('--encrypt_key', '-k', help='加密密钥', required=True)
    uploader_parser.add_argument('--endpoint', '-e', help='存储桶地址', default=config['RequestUrl'])
    uploader_parser.add_argument('--bucket', '-b', help='存储桶名称', default=config['BucketName'])
    uploader_parser.add_argument('--prefix', '-p', help='添加到文件名的前缀', default='')

    downloader_parser = subparsers.add_parser('download')
    downloader_parser.add_argument('files', nargs='+', help='需下载的文件在存储桶中的路径')
    downloader_parser.add_argument('--bucket', '-b', help='存储桶名称', default=config['BucketName'])
    downloader_parser.add_argument('--output_dir', '-o', help='下载文件保存地址', default='./Downloads')
    downloader_parser.add_argument('--encrypt_key', '-k', help='加密密钥', required=True)
    downloader_parser.add_argument('--endpoint', '-e', help='存储桶地址', default=config['RequestUrl'])

    list_parser = subparsers.add_parser('list')
    list_parser.add_argument('--endpoint', '-e', help='endpoint to upload to', default=config['RequestUrl'])
    list_parser.add_argument('--bucket', '-b', help='bucket to list', default=config['BucketName'])
    list_parser.add_argument('--prefix', '-p', help='object prefix to list', default='')

    return parser.parse_args()


def main():
    options = parse()
    if options.command == 'upload':
        uploader = Uploader(options.bucket, options.files, options.encrypt_key, options.prefix)
        uploader.upload()
    elif options.command == 'download':
        downloader = Downloader(options.bucket, options.files, options.encrypt_key, options.output_dir)
        downloader.download()
    elif options.command == 'list':
        lister = Lister(options.bucket, options.prefix)
        lister.lister()
    else:
        assert False, 'Unknown command'


if __name__ == '__main__':
    main()


