# MetaFusion Storage

MetaFusion 高保真多媒体物理资产归档、哈希校验、S3 接入与下载分发中心微服务。

## 📦 核心定位

负责管理实体媒体的实际物理二进制文件（4K原盘、无损音频、高精度扫描画册）。采用基于内容寻址（CAS）的 SHA-256 唯一指纹，提供预签名直传直取、BT 种子/磁力链聚合与下载带宽鉴权。通过单向只读实体 UUID（`target_entity_id`）与元数据目录解耦。

- **主项目 (Core Catalog)**: [MetaFusion](https://github.com/MoeclubM/MetaFusion)

## 🚀 启动运行

```bash
go run cmd/server/main.go
```
