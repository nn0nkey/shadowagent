"""
全局解析器管理器
在每次工具执行后自动解析响应，提取关键信息
支持缓存，相同响应只解析一次
"""
import hashlib
from typing import Dict, Optional
from src.utils.rule_based_extractor import RuleBasedExtractor
from src.utils.logger import default_logger
from pathlib import Path


class GlobalParserManager:
    """全局解析器管理器"""
    
    def __init__(self, rules_file: Optional[str] = None):
        """
        初始化全局解析器
        
        Args:
            rules_file: 规则文件路径，默认使用 HaE 规则
        """
        if rules_file is None:
            # 默认使用 HaE 的规则文件
            hae_rules = Path(__file__).parent.parent.parent.parent / 'HaE-main' / 'src' / 'main' / 'resources' / 'rules' / 'Rules.yml'
            if hae_rules.exists():
                rules_file = str(hae_rules)
                default_logger.info(f"🔍 使用 HaE 规则文件: {rules_file}")
            else:
                # 使用自定义规则
                rules_file = Path(__file__).parent / 'extraction_rules.yaml'
                default_logger.info(f"🔍 使用自定义规则文件: {rules_file}")
        
        self.extractor = RuleBasedExtractor(rules_file)
        self.cache = {}  # 缓存：response_hash -> 解析结果
        self.enabled = True
        self.seen_items = {  # 全局去重：已提取过的信息
            'credentials': set(),
            'privilege_fields': set(),
            'idor_points': set(),
            'fingerprints': set(),
            'vulnerabilities': set(),
        }
    
    def _hash_response(self, response: str) -> str:
        """计算响应的哈希值（用于缓存）"""
        return hashlib.md5(response.encode('utf-8')).hexdigest()
    
    def _deduplicate_results(self, results: Dict) -> Dict:
        """
        全局去重：移除已经提取过的信息
        
        Args:
            results: 解析结果
            
        Returns:
            去重后的结果
        """
        deduplicated = {}
        
        for key, items in results.items():
            if not isinstance(items, list):
                deduplicated[key] = items
                continue
            
            unique_items = []
            
            for item in items:
                # 生成唯一标识
                if key == 'credentials':
                    if 'username' in item and 'password' in item:
                        item_id = f"{item['username']}:{item['password']}"
                    elif 'type' in item:
                        item_id = f"{item['type']}:{item.get('value', '')[:20]}"
                    else:
                        item_id = str(item)
                
                elif key == 'privilege_fields':
                    item_id = item.get('field', str(item))
                
                elif key == 'idor_points':
                    item_id = item.get('id', str(item))
                
                elif key == 'fingerprints':
                    item_id = f"{item.get('name', '')}:{item.get('value', '')[:20]}"
                
                elif key == 'vulnerabilities':
                    item_id = f"{item.get('name', '')}:{item.get('indicator', '')[:20]}"
                
                else:
                    item_id = str(item)[:50]
                
                # 检查是否已存在
                if key in self.seen_items:
                    if item_id not in self.seen_items[key]:
                        self.seen_items[key].add(item_id)
                        unique_items.append(item)
                    else:
                        default_logger.debug(f"🔄 跳过重复项: {key} - {item_id[:30]}")
                else:
                    unique_items.append(item)
            
            deduplicated[key] = unique_items
        
        return deduplicated
    
    def parse(self, response: str, force: bool = False) -> Dict:
        """
        解析响应内容
        
        Args:
            response: 工具输出/HTTP响应
            force: 是否强制重新解析（忽略缓存）
            
        Returns:
            解析结果字典
        """
        if not self.enabled:
            return {}
        
        # 检查缓存
        response_hash = self._hash_response(response)
        if not force and response_hash in self.cache:
            default_logger.debug(f"📦 使用缓存的解析结果 (hash: {response_hash[:8]}...)")
            return self.cache[response_hash]
        
        # 执行解析
        try:
            default_logger.debug(f"🔍 开始解析响应 (长度: {len(response)} 字符)")
            results = self.extractor.extract(response)
            
            # 全局去重：移除已经提取过的信息 ⭐
            results = self._deduplicate_results(results)
            
            # 统计提取到的信息
            total_items = sum(len(v) for v in results.values() if isinstance(v, list))
            if total_items > 0:
                default_logger.info(f"✅ 提取到 {total_items} 条新的关键信息")
                
                # 显示摘要
                summary_parts = []
                if results.get('credentials'):
                    summary_parts.append(f"凭证×{len(results['credentials'])}")
                if results.get('fingerprints'):
                    summary_parts.append(f"指纹×{len(results['fingerprints'])}")
                if results.get('vulnerabilities'):
                    summary_parts.append(f"漏洞×{len(results['vulnerabilities'])}")
                if results.get('secrets'):
                    summary_parts.append(f"敏感信息×{len(results['secrets'])}")
                if results.get('api_endpoints'):
                    summary_parts.append(f"API×{len(results['api_endpoints'])}")
                
                if summary_parts:
                    default_logger.info(f"   📊 {', '.join(summary_parts)}")
            
            # 缓存结果
            self.cache[response_hash] = results
            
            return results
        except Exception as e:
            default_logger.warning(f"⚠️ 解析失败: {e}")
            return {}
    
    def get_summary(self, results: Dict) -> str:
        """获取解析结果的可读摘要"""
        return self.extractor.to_summary(results)
    
    def clear_cache(self):
        """清空缓存"""
        self.cache.clear()
        default_logger.info("🗑️ 已清空解析缓存")
    
    def clear_seen_items(self):
        """清空去重记录（用于新任务）"""
        for key in self.seen_items:
            self.seen_items[key].clear()
        default_logger.info("🗑️ 已清空去重记录")
    
    def clear_all(self):
        """清空所有缓存和去重记录"""
        self.clear_cache()
        self.clear_seen_items()
    
    def enable(self):
        """启用全局解析"""
        self.enabled = True
        default_logger.info("✅ 全局解析已启用")
    
    def disable(self):
        """禁用全局解析"""
        self.enabled = False
        default_logger.info("⏸️ 全局解析已禁用")
    
    def get_cache_stats(self) -> Dict:
        """获取缓存统计"""
        return {
            'cache_size': len(self.cache),
            'total_items': sum(
                sum(len(v) for v in result.values() if isinstance(v, list))
                for result in self.cache.values()
            )
        }


# 全局单例
_global_parser = None

def get_global_parser() -> GlobalParserManager:
    """获取全局解析器实例"""
    global _global_parser
    if _global_parser is None:
        _global_parser = GlobalParserManager()
    return _global_parser


def parse_response(response: str, force: bool = False) -> Dict:
    """
    便捷函数：解析响应
    
    Args:
        response: 响应内容
        force: 是否强制重新解析
        
    Returns:
        解析结果
    """
    parser = get_global_parser()
    return parser.parse(response, force=force)


def get_parsed_summary(results: Dict) -> str:
    """
    便捷函数：获取解析结果摘要
    
    Args:
        results: 解析结果
        
    Returns:
        可读摘要
    """
    parser = get_global_parser()
    return parser.get_summary(results)
