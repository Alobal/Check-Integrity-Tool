from ast import arg
from importlib import import_module
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import MD5
from pathlib import Path
import os
import sys
import pickle #序列化保存
import hashlib
import argparse
import enum

EXCLUDE_FILES=['.hash',os.path.basename(sys.argv[0]),'.tree','.sign']

#检查结果状态
class CHECK_STATUS(enum.IntEnum):
    SUCCESS=0
    MISSING_HASH=1
    MISSING_SIGN=2
    MISSING_FILE=3
    ERROR=4

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

    def SetCheckStatus(self,status:CHECK_STATUS):
        """设置检查状态"""
        #不存在赋值SUCCESS
        if status> CHECK_STATUS.SUCCESS:
            #ERROR为最高优先级
            if self.check_status< CHECK_STATUS.ERROR:
                self.check_status=status
            

    def ShowTree(self,padding="",only_error=False):
        """显示树结构，only_error仅显示检查错误的节点"""

        #打印根结构
        if only_error:
            if self.check_status==CHECK_STATUS.SUCCESS:
                return 
            else:
                error_msg=f"""[{str(self.check_status).replace("CHECK_STATUS.",'')}]"""
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
                    error_msg=f"""[{str(self.check_status).replace("CHECK_STATUS.",'')}]"""
                    print(child.name+"   "+error_msg)



def GetShowLen(s:str):
    """用于计算包含中文字符的 str 的命令行显示长度"""
    len1=len(s)#每个字符(包括中文)视为1
    len2=len(s.encode())#英文字符视为1 中文字符视为3
    ch_num=(len2-len1)//2#中文字数
    len3=len1+ch_num
    return len3
    

def Hash_File(path,hash_method) -> Node : 
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

def Hash_Dir(root,hash_method,sign=False,exclude_files=EXCLUDE_FILES,flash=True) -> Node:
    """
    计算一个目录的Hash值，并且构造Hash树

    hash不能通过默认值方式传递，否则会所有函数使用同一个hash对象

    sign=True则此目录hash值使用RSA进行数字签名再保存
    """
    root_node=Node(Path(root).name)
    hash=hash_method.new()
    root_path,dir_names,file_names=next(os.walk(root))#拿到当前目录下的文件夹和文件，不包含子目录


    #递归获得所有当前目录下的文件夹的Hash值
    for dir in dir_names:
        dir_path=os.path.join(root_path,dir)
        dir_node=Hash_Dir(dir_path,hash_method)
        #添加子节点
        root_node.AddChild(dir_node)
        hash.update(dir_node.value)

    #获得所有当前目录文件的Hash值
    for file in file_names:
        if file not in exclude_files:
            file_path=os.path.join(root_path,file)
            file_node=Hash_File(file_path,hash_method)
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

def Check_Dir(root,hash_method,sign=False,exclude_files=EXCLUDE_FILES):
    """
    检查当前目录以及子目录的hash

    hash不能通过默认值方式传递，否则会所有函数使用同一个hash对象

    sign=True 则检查当前目录下的.sign以及.hash文件进行签名验证
    """
    hash=hash_method.new()
    # print(root,hash)
    root_node=Node(root)
    root_path,dir_names,file_names=next(os.walk(root))#拿到当前目录下的文件夹和文件，不包含子目录

    #递归检查所有当前目录子目录的hash
    for dir in dir_names:
        dir_path=os.path.join(root_path,dir)
        dir=Check_Dir(dir_path,hash_method)
        root_node.AddChild(dir)
        hash.update(dir.value)

        if dir.check_status>CHECK_STATUS.SUCCESS:#如果子目录有错误，则继承错误状态
            root_node.SetCheckStatus(dir.check_status)

    #将所有当前目录文件加入此目录的hash计算
    for file in file_names:
        if file not in exclude_files:
            file_path=os.path.join(root_path,file)
            file_node=Hash_File(file_path,hash_method)
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
            root_node.SetCheckStatus(CHECK_STATUS.MISSING_SIGN)

    #不使用签名的目录使用Hash进行检查
    else:
        if os.path.exists(Path(root)/".hash"):
            #hash验证处理
            with open(Path(root)/".hash",'rb') as f:
                save_hash=f.read()
            if root_node.value.hex()!=save_hash.decode():
                root_node.SetCheckStatus(CHECK_STATUS.ERROR)

        #丢失本目录Hash文件 视为MISSING。
        else: 
            root_node.SetCheckStatus(CHECK_STATUS.MISSING_HASH)



    return root_node

def Check_Tree(root,hash_method,save_tree=None)-> Node:
    """
    从save_tree树结构检查文件,没有传参则从./.tree文件读取。
    
    返回检查结果树save_tree

    name_padding用于递归填充文件路径
    """
    if save_tree==None:#最上层，从文件读取树。非最上层直接继承save_tree
        if os.path.exists(Path(root)/".tree"):
            with open(Path(root)/".tree",'rb') as f:
                save_tree=pickle.load(f)
        else:
            print("找不到.tree文件，树检查失败")
            save_tree.check_status=CHECK_STATUS.MISSING_FILE
            return save_tree

    #对这棵树的孩子进行遍历检查
    for child in save_tree.child_list:
        file_path=Path(root)/child.name
        #是一个文件 计算Hash并比较
        if os.path.isfile(file_path):
            if Hash_File(file_path,hash_method).value!=child.value:
                child.SetCheckStatus(CHECK_STATUS.ERROR)
                save_tree.SetCheckStatus(CHECK_STATUS.ERROR)
        #是一个目录
        elif os.path.isdir(file_path):
            child.SetCheckStatus(Check_Tree(file_path,hash_method,child).check_status)
        #找不到文件
        else:
            child.SetCheckStatus(CHECK_STATUS.MISSING_FILE)
        
        #父节点状态低于ERROR，则继承子节点错误状态
        if child.check_status>CHECK_STATUS.SUCCESS :
            save_tree.SetCheckStatus(child.check_status)
    
    #返回根树
    return save_tree


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
    parser.add_argument('-d','--dir',default="./",help='指定目录',type=str)
    parser.add_argument('--hash',default="MD5",help='指定Hash方法 支持HMAC, MD2, MD4, MD5, RIPEMD160, SHA1,SHA224, SHA256, SHA384, SHA512, CMAC, Poly1305,cSHAKE128, cSHAKE256, KMAC128, KMAC256,TupleHash128, TupleHash256, KangarooTwelve',type=str)
    parser.add_argument('-c','--check',default=False,help='是否进行验证',action='store_true')
    parser.add_argument('-f','--file',help='指定文件,仅对该文件进行Hash计算')
    parser.add_argument('-cx','--checkplus',default=False,help='是否进行文件树验证',action='store_true')
    parser.add_argument('-g','--generateKey',default=False,help='进行签名秘钥生成',action='store_true')

    return parser.parse_args()


if __name__== '__main__':
    args=parse_args()
    #指定hash方法
    hash_method=import_module("Cryptodome.Hash."+args.hash)
    #指定目录
    path=args.dir

    if args.file:
        print(Hash_File(args.file,hash_method).value.hex())

    elif  args.checkplus:
        tree=Check_Tree(path,hash_method)
        error_msg=str(tree.check_status).replace("CHECK_STATUS.",'')
        print("检查结果：",error_msg)
        tree.ShowTree(only_error=True)

    elif args.check:
        tree=Check_Dir(path,hash_method,sign=True)
        error_msg=str(tree.check_status).replace("CHECK_STATUS.",'')
        print("检查结果：",error_msg)
        tree.ShowTree(only_error=True)
    else:
        tree=Hash_Dir(path,hash_method,sign=True,flash=True)
        print("树顶点:",end='')
        print(tree)
        print("完整树结构如下：")
        tree.ShowTree()