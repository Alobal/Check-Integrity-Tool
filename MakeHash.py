from pathlib import Path
import os
import hashlib



#树节点
class Node:
    def __init__(self,name:str,value:bytearray=None,parent=None) -> None:
        self.child_list=[]#子列表
        self.parent=parent#父节点
        self.name=name#文件名/文件夹名
        self.value=value#hash值

    def AddChild(self,Node):
        self.child_list.append(Node)

    def __str__(self) -> str:#打印函数
        return f'name: {self.name} || value: {self.value}'


def Hash_file(path,hash=hashlib.md5()) -> bytearray : 
    """计算单个文件的Hash值，返回Hash值的字节序列"""
    value=None
    with open(path,'rb') as f:
        while True:
            content=f.read(10240)#分块读取 避免大文件处理
            if not content:
                break
            hash.update(content)

    value=hash.digest()
    return value

def Hash_Dir(root,hash=hashlib.md5()):
    tree_root=Node(root)

    for root_path,dir_names,file_names in os.walk(root):#不包含子目录
        
        """获得所有目录的Hash值"""
        for dir in dir_names:
            dir_path=os.path.join(root_path,dir)
            dir_hash=Hash_Dir(dir_path)
            hash.update(dir_hash)

        """获得所有当前目录文件的Hash值"""
        for file in file_names:
            file_path=os.path.join(root_path,file)
            file_hash=Hash_file(file_path)
            hash.update(file_hash)


Hash_Dir("./")