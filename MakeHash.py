from pathlib import Path
import os
import sys
import pickle #序列化保存
import hashlib




#树节点
class Node:
    def __init__(self,name:str,value:bytearray=None,parent=None) -> None:
        self.child_list=[]#子列表
        self.parent=parent#父节点
        self.name=name#文件名/文件夹名
        self.value=value#hash值

    def AddChild(self,Node):
        Node.parent=self
        self.child_list.append(Node)

    def __str__(self) -> str:#打印函数
        return f'name: {self.name} || value: {self.value.hex()}'


def Hash_file(path,hash=hashlib.md5()) -> bytearray : 
    """计算单个文件的Hash值，返回Hash值的Node"""
    path=Path(path)
    with open(path,'rb') as f:
        while True:#分块读取并计算hash 避免大文件处理
            content=f.read(10240)
            if not content:
                break
            hash.update(content)

    
    node=Node(path.name,hash.digest())

    return node

def Hash_Dir(root,hash=hashlib.md5(),exclude_files=['.hash',os.path.basename(sys.argv[0])],flash=True) -> Node:
    """计算一个目录的Hash值，并且构造Hash树"""
    root_node=Node(root)

    root_path,dir_names,file_names=next(os.walk(root))#不包含子目录


    """获得所有当前目录下的文件夹的Hash值"""
    for dir in dir_names:
        dir_path=os.path.join(root_path,dir)
        dir_node=Hash_Dir(dir_path)
        #添加子节点
        root_node.AddChild(dir_node)
        hash.update(dir_node.value)

    """获得所有当前目录文件的Hash值"""
    for file in file_names:
        if file not in exclude_files:
            file_path=os.path.join(root_path,file)
            file_node=Hash_file(file_path)
            #添加子节点
            root_node.AddChild(file_node)
            hash.update(file_node.value)

    root_node.value=hash.digest()

    if flash:#需要刷新保存的hash值
        """在当前目录创建.hash文件，保存当前目录的hash节点值"""
        with open(Path(root)/".hash",'w') as f:
            f.write(root_node.value.hex())
        
        """序列化保存子树，便于检查文件尺度的错误"""
        with open(Path(root)/".tree",'w') as f:
            pickle.dump(root_node,f)

    return root_node

def Check_Dir(root,hash=hashlib.md5(),exclude_files=['.hash',os.path.basename(sys.argv[0])]):
    """检查当前目录以及子目录的hash"""

    """读取保存的hash值"""
    with open(Path(root)/".hash",'rb') as f:
        save_hash=f.read()
    
    """递归检查所有当前目录子目录的hash"""

    """递归检查所有当前目录文件的hash"""

if __name__== '__main__':
    tree=Hash_Dir("./")