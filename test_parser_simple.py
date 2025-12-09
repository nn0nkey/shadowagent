#!/usr/bin/env python3
"""简单测试全局解析器"""

import sys
sys.path.insert(0, '/Users/liaojialin.6/PyCharmMiscProject/agentproject/shadowagent')

print("开始测试...")

try:
    from src.utils.global_parser import get_global_parser
    print("✅ 导入成功")
    
    parser = get_global_parser()
    print("✅ 解析器初始化成功")
    
    test_response = "<strong>Username:</strong> demo\n<strong>Password:</strong> demo"
    print(f"✅ 测试数据准备完成 (长度: {len(test_response)})")
    
    result = parser.parse(test_response)
    print(f"✅ 解析完成，提取到 {sum(len(v) for v in result.values() if isinstance(v, list))} 条信息")
    
    if result.get('credentials'):
        print(f"✅ 发现凭证: {result['credentials']}")
    
    print("\n测试通过！")
    
except Exception as e:
    print(f"❌ 错误: {e}")
    import traceback
    traceback.print_exc()
