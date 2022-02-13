from distutils.log import ERROR
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import MD5
from pathlib import Path
import os
import sys
import pickle #序列化保存
import hashlib
import argparse
from enum import Enum

EXCLUDE_FILES=['.hash',os.path.basename(sys.argv[0]),'.tree','.sign']

#检查结果状态
class CHECK_STATUS(Enum):
    SUCCESS=0
    ERROR=1
    MISSING_HASH=2
    MISSING_SIGN=3

#树节点
class Node:
    def __init__(self,name:str,value:bytearray=None,parent=None) -> None:
        self.child_list=[]#子列表
        self.parent=parent#父节点
        self.name=name#文件名/文件夹名
        self.value=value#hash值
        self.check_status=CHECK_STATUS.SUCCESS#用于保存检查结果

    def AddChild(self,Node):
        Node.parent=self
        self.child_list.append(Node)

    def __str__(self) -> str:#打印函数
        return f'节点名: {self.name} ==> Hash值: {self.value.hex()}'

    def ShowTree(self,padding="",only_error=False):
        """显示树结构，only_error仅显示检查错误的节点"""

        #打印根结构
        if only_error:
            if self.check_status==CHECK_STATUS.SUCCESS:
                return 
            else:
                error_msg=str(self.check_status).replace("CHECK_STATUS.",'')
                print(self.name,end="┐   "+error_msg+"\n")
        else:
            print(self.name,end="┐"+"\n")

        #打印子树结构
        padding+=" " *(GetShowLen(self.name))
        for child in self.child_list:

            if not only_error:#显示完整结构
                print(padding,end='├')
                if len(child.child_list)>0:#如果存在子节点，递归显示
                    child.ShowTree(padding+'│')
                else:#不存在子节点则直接显示文件
                    print(child.name)

            elif only_error and child.check_status!=CHECK_STATUS.SUCCESS:#仅显示检查发现错误的结构
                print(padding,end='├')
                if len(child.child_list)>0:#如果存在子节点，递归显示
                    child.ShowTree(padding+'│',only_error)
                else:#不存在子节点则直接显示文件
                    error_msg=str(child.check_status).replace("CHECK_STATUS.",'')
                    print(child.name+"   "+error_msg)



def GetShowLen(s:str):
    """用于计算包含中文字符的 str 的命令行显示长度"""
    len1=len(s)#每个字符(包括中文)视为1
    len2=len(s.encode())#英文字符视为1 中文字符视为3
    ch_num=(len2-len1)//2#中文字数
    len3=len1+ch_num
    return len3
    

def Hash_file(path,hash_method=MD5) -> bytearray : 
    """
    计算单个文件的Hash值，返回Hash值的Node
    hash不能通过默认值方式传递，否则会所有函数使用同一个hash对象
    
    """
    hash=hash_method.new()
    path=Path(path)
    with open(path,'rb') as f:
        while True:#分块读取并计算hash 避免大文件处理
            content=f.read(10240)
            if not content:
                break
            hash.update(content)

    
    node=Node(path.name,hash.digest())

    return node

def Hash_Dir(root,hash_method=MD5,sign=False,exclude_files=EXCLUDE_FILES,flash=True) -> Node:
    """
    计算一个目录的Hash值，并且构造Hash树
    hash不能通过默认值方式传递，否则会所有函数使用同一个hash对象
    sign=True则此目录hash值使用RSA进行数字签名再保存
    """
    root_node=Node(root)
    hash=hash_method.new()
    root_path,dir_names,file_names=next(os.walk(root))#拿到当前目录下的文件夹和文件，不包含子目录


    #递归获得所有当前目录下的文件夹的Hash值
    for dir in dir_names:
        dir_path=os.path.join(root_path,dir)
        dir_node=Hash_Dir(dir_path)
        #添加子节点
        root_node.AddChild(dir_node)
        hash.update(dir_node.value)

    #获得所有当前目录文件的Hash值
    for file in file_names:
        if file not in exclude_files:
            file_path=os.path.join(root_path,file)
            file_node=Hash_file(file_path)
            #添加子节点
            root_node.AddChild(file_node)
            hash.update(file_node.value)

    root_node.value=hash.digest()

    if flash:#需要刷新保存的hash值
        #在当前目录创建.hash文件，保存当前目录的hash节点值
        with open(Path(root)/".hash",'w') as f:
            f.write(root_node.value.hex())

        #需要签名
        if sign:
            with open(Path(root)/".sign",'wb') as f:
                f.write(Signature(hash))
        
        #序列化保存子树，便于检查文件尺度的错误
        with open(Path(root)/".tree",'wb') as f:
            pickle.dump(root_node,f)

    return root_node

def Check_Dir(root,hash_method=MD5,sign=False,exclude_files=EXCLUDE_FILES,check_file=False):
    """
    检查当前目录以及子目录的hash
    hash不能通过默认值方式传递，否则会所有函数使用同一个hash对象
    sign=True 则检查当前目录下的.sign以及.hash文件进行签名验证
    """
    hash=hash_method.new()
    # print(root,hash)
    root_node=Node(root)
    root_path,dir_names,file_names=next(os.walk(root))#拿到当前目录下的文件夹和文件，不包含子目录

    if check_file:
        with open(Path(root)/".tree",'rb') as f:
            save_node=pickle.load(f)
        
    
    #递归检查所有当前目录子目录的hash
    for dir in dir_names:
        dir_path=os.path.join(root_path,dir)
        dir=Check_Dir(dir_path)
        root_node.AddChild(dir)
        hash.update(dir.value)

        if dir.check_status==CHECK_STATUS.ERROR:#如果子目录有错误，则继承错误状态
            root_node.check_status=CHECK_STATUS.ERROR

    #将所有当前目录文件加入此目录的hash计算
    for file in file_names:
        if file not in exclude_files:
            file_path=os.path.join(root_path,file)
            file_node=Hash_file(file_path)
            root_node.AddChild(file_node)
            hash.update(file_node.value)
    
    #最终检查当前目录的Hash
    root_node.value=hash.digest()

    #此目录选择使用签名进行检查
    if sign:
        if os.path.exists(Path(root)/".sign"):
            with open(Path(root)/".sign",'rb') as f:
                sign=f.read()
            
            if not VerifySign(hash,sign):
                root_node.check_status=CHECK_STATUS.ERROR
                print("根目录签名验证失败")
            else:
                print("根目录签名验证成功")
        else:#不存在sign文件视为MISSING错误
            if root_node.check_status!=CHECK_STATUS.ERROR:
                root_node.check_status=CHECK_STATUS.MISSING_SIGN

    #不使用签名的目录使用Hash进行检查
    else:
        if os.path.exists(Path(root)/".hash"):
            #hash验证处理
            with open(Path(root)/".hash",'rb') as f:
                save_hash=f.read()
            if root_node.value.hex()!=save_hash.decode():
                root_node.check_status=CHECK_STATUS.ERROR

        #丢失本目录Hash文件 且子目录没有检查到错误，只是无法验证当前目录，视为MISSING。
        elif root_node.check_status!=CHECK_STATUS.ERROR:
            root_node.check_status=CHECK_STATUS.MISSING_HASH



    return root_node

def Compare_Tree(tree1,tree2):
    """比较两棵树"""


def MakeKeys_RSA():
    """生成RSA秘钥对"""
    key=RSA.generate(2048)
    private_key=key.export_key()
    public_key=key.public_key().export_key()

    with open("./sign_key",'wb') as f:
        f.write(private_key)
    with open("./sign_key.pub",'wb') as f:
        f.write(public_key)
    



def Signature(hash_obj):
    """使用RSA对Hash对象进行数字签名"""
    if not os.path.exists("./sign_key"):
        MakeKeys_RSA()

    with open("./sign_key",'rb') as f:
        private_key=f.read()

    key=RSA.import_key(private_key)
    signer=PKCS1_v1_5.new(key)
    return signer.sign(hash_obj)
        

def VerifySign(hash_obj,sign):
    """使用RSA对Hash对象进行签名验证,sign为签名bytes"""
    if os.path.exists("./sign_key.pub"):
        with open("./sign_key.pub",'rb') as f:
            public_key=f.read()

        key=RSA.import_key(public_key)
        verifier=PKCS1_v1_5.new(key)
        return verifier.verify(hash_obj,sign)
    else:
        return False



def parse_args():
    """解析命令行参数"""
    parser=argparse.ArgumentParser()
    parser.add_argument('-c','--check',default=False,help='是否进行验证操作',action='store_true')
    parser.add_argument('-g','--generateKey',default=False,help='进行签名秘钥生成',action='store_true')

    return parser.parse_args()


if __name__== '__main__':
    args=parse_args()

    if not args.check:
        tree=Check_Dir("./",sign=False)
        error_msg=str(tree.check_status).replace("CHECK_STATUS.",'')
        print("检查结果：",error_msg)
        tree.ShowTree(only_error=True)
    else:
        tree=Hash_Dir("./",sign=True,flash=True)
        print("树顶点:",end='')
        print(tree)
        print("完整树结构如下：")
        tree.ShowTree()
    # MakeKeys_RSA()
    # Signature(tree.value)
