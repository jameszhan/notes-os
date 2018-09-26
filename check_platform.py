import platform

print("操作系统信息字符串: {}".format(platform.platform()))
print("操作系统类型: {}".format(platform.system()))
print("操作系统版本: {}".format(platform.version()))
print("操作系统发布号: {}".format(platform.release()))
print("uname: {}".format(platform.uname()))
print("网络名称: {}".format(platform.node()))
print("处理器: {}".format(platform.processor()))
print("操作系统位数: {}".format(platform.architecture()))
print("计算机类型: {}".format(platform.machine()))